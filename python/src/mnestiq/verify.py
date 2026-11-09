"""Verify an evidence chain: schema, hash links, redactable digests, Merkle roots, signatures."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import re
import stat
from datetime import datetime, timezone
from dataclasses import asdict, dataclass, field
from functools import lru_cache
from importlib import resources
from pathlib import Path
from collections.abc import Iterable
from typing import TYPE_CHECKING, Any

from cryptography.exceptions import InvalidSignature
from jsonschema import Draft202012Validator
from jsonschema.exceptions import best_match

from .canonical import CanonicalizationError, canonical_json, parse_json
from .hashing import (
    GENESIS_HASH,
    SALT_SUFFIX,
    digest_bytes,
    iter_redactable_paths,
    record_hash,
    signing_payload,
    slot_digest,
)
from .keys import ED25519, SIG_ALGS, key_id, verify_signature
from .merkle import merkle_root

if TYPE_CHECKING:
    from cryptography import x509


@dataclass
class Issue:
    code: str
    message: str
    line: int | None = None
    seq: int | None = None


@dataclass
class Report:
    ok: bool = True
    chain_id: str | None = None
    records: int = 0
    events: int = 0
    checkpoints: int = 0
    signed_through_seq: int | None = None
    unsigned_tail: int = 0
    head_seq: int | None = None  # set when the chain matched a head checkpoint kept elsewhere
    signer_keys: list[str] = field(default_factory=list)
    rotations: list[dict] = field(default_factory=list)  # signed hand-overs: seq, from_key, to_key
    quiet: list[dict] = field(default_factory=list)  # gaps longer than the heartbeat allows: from, to, seconds
    timestamps: list[dict] = field(default_factory=list)  # verified RFC 3161 tokens: seq, time (UTC)
    errors: list[Issue] = field(default_factory=list)
    warnings: list[Issue] = field(default_factory=list)
    restarts: list[dict] = field(default_factory=list)  # signed only after a restart: from_seq, to_seq, checkpoint_seq
    unclean_restarts: list[dict] = field(default_factory=list)  # resumes with no clean close: note_seq, checkpoint_seq
    continues_from: list[dict] = field(default_factory=list)  # chains started in place of a file: note_seq, file, ...
    witness: dict | None = None  # how far a witness log reached, when one was given: entries, highest_seq, ...

    def error(self, code: str, message: str, line: int | None = None, seq: int | None = None) -> None:
        self.ok = False
        self.errors.append(Issue(code, message, line, seq))

    def warn(self, code: str, message: str, line: int | None = None, seq: int | None = None) -> None:
        self.warnings.append(Issue(code, message, line, seq))

    def to_dict(self) -> dict:
        return asdict(self)


SUPPORTED_VERSIONS = ("0.1", "0.2", "1.0")  # the versions this verifier implements in full
EVENT_TYPES = frozenset({"run_start", "run_end", "llm_call", "tool_call", "approval", "egress", "note", "heartbeat"})
RESTART_FIELD = "inherited_unsigned"  # in the attributes of the note a recorder writes when it resumes an unsigned end
CLEAN_CLOSE_FIELD = "clean_close"  # in the attributes of the heartbeat a recorder writes before its last checkpoint
UNCLEAN_RESUME_FIELD = "resumed_without_clean_close"  # in the note of a recorder that found no clean close to resume
CONTINUES_FIELD = "continues_from"  # in the note of a recorder that started a new chain and set the old file aside


def is_blank(line: bytes | str) -> bool:
    """Whether a line of an evidence file holds nothing: JSON's own whitespace only. Every reader skips by this
    one test, so a line cannot be nothing to one and a record to another. Any other line is read, and refused."""
    return not (line.strip(b" \t\r\n") if isinstance(line, bytes) else line.strip(" \t\r\n"))


def version_key(version: Any) -> tuple[int, int] | None:
    """(major, minor) of a version this verifier can read: 0.1, 0.2 and any 1.x. A newer minor version
    of 1 adds only what older verifiers can skip, so it is read as far as this verifier understands it."""
    if version in ("0.1", "0.2"):
        return (0, int(version[2]))
    if isinstance(version, str) and _MINOR.fullmatch(version):
        return (1, int(version[2:]))
    return None


_MINOR = re.compile(r"1\.(0|[1-9][0-9]{0,3})")


def _unknown_fields(rec: dict) -> list[str]:
    """Top-level fields, and an event type, that this verifier's version does not define."""
    kind = rec.get("kind")
    if kind not in ("event", "checkpoint"):
        return []
    unknown = sorted(k for k in rec if not k.startswith("x-") and k not in known_fields()[kind])
    event_type = rec.get("event_type")
    if kind == "event" and isinstance(event_type, str) and event_type not in EVENT_TYPES:
        unknown.append(f"event_type {event_type}")
    return unknown


@lru_cache(maxsize=1)
def known_fields() -> dict[str, frozenset[str]]:
    """The top-level fields of each kind of record, as this verifier's schema defines them."""
    schema = json.loads(resources.files("mnestiq.schema").joinpath("record.schema.json").read_text("utf-8"))
    defs = schema["$defs"]
    chain = set(defs["chainFields"]["properties"])
    return {kind: frozenset(chain | set(defs[kind]["properties"])) for kind in ("event", "checkpoint")}


@dataclass
class _Keys:
    """Which key signs the chain, and which keys the user's pins extend to."""

    trusted: set[str]  # pinned, plus keys a trusted key handed over to
    pinned: bool
    expected: str | None = None  # the key the next checkpoint must be signed by
    tsa_roots: list[x509.Certificate] | None = None  # roots for RFC 3161 tokens; None means the defaults


@lru_cache(maxsize=1)
def _validators() -> dict[str | None, Draft202012Validator]:
    """The whole schema (under None), and one validator per kind of record.

    The schema says a record is one of an event or a checkpoint, and each requires its own ``kind``.
    Checked as a whole, every record is checked against both. A record whose ``kind`` names one can
    only ever match that one, so it is checked against it alone: the same verdict at about half the
    cost, with the error a reader needs (the field that is wrong) rather than "not valid under any
    of the given schemas". Any other record goes through the whole schema."""
    schema = json.loads(resources.files("mnestiq.schema").joinpath("record.schema.json").read_text("utf-8"))
    out: dict[str | None, Draft202012Validator] = {None: Draft202012Validator(schema)}
    for kind in ("event", "checkpoint"):
        branch = {k: v for k, v in schema.items() if k != "oneOf"}
        branch["$ref"] = f"#/$defs/{kind}"
        out[kind] = Draft202012Validator(branch)
    return out


def _validator(record: Any = None) -> Draft202012Validator:
    kind = record.get("kind") if isinstance(record, dict) else None
    return _validators()[kind if kind in ("event", "checkpoint") else None]


def schema_problem(record: dict, show_value: bool = True) -> str | None:
    """The first way a record breaks the schema, or None if it is valid. ``show_value=False`` names the
    field and the rule only: the message is then safe for an application log, since a schema error
    otherwise quotes the value, which can be anything the agent handled (an API key, a document)."""
    instance = json.loads(canonical_json(record))
    error = best_match(_validator(instance).iter_errors(instance))
    if error is None:
        # The schema leaves room for what later minor versions add. A record of a version this verifier
        # implements may hold only what that version defines.
        unknown = _unknown_fields(instance) if (version_key(instance.get("spec_version")) or (9, 9)) <= (1, 0) else []
        return f"unknown field(s): {', '.join(unknown)}" if unknown else None
    where = "/".join(map(str, error.absolute_path)) or "record"
    if show_value:
        return f"{where}: {error.message}"
    return f"{where}: breaks the schema's {error.validator} rule ({json.dumps(error.validator_value)[:80]})"


def verify_file(path: str | Path, trusted_keys: Iterable[str] = (), head: dict | None = None,
                tsa_roots: Iterable[x509.Certificate] | None = None, witness: str | Path | None = None) -> Report:
    with open(path, "rb") as fh:
        return verify_lines(fh, trusted_keys, head, tsa_roots, witness)


def verify_lines(lines: Iterable[bytes | str], trusted_keys: Iterable[str] = (), head: dict | None = None,
                 tsa_roots: Iterable[x509.Certificate] | None = None, witness: str | Path | None = None) -> Report:
    """Verify a chain. ``head`` is a checkpoint kept elsewhere (``HeadFile``): the chain must
    contain exactly that checkpoint, which detects a file cut back to an earlier one.
    ``tsa_roots`` are the roots RFC 3161 timestamp tokens must chain to (default: those of
    the default timestamp authorities, see ``mnestiq.timestamps``).
    ``witness`` is a witness log of a signing service, or a folder holding them: the chain must agree
    with what the service saw of it, as far as it saw."""
    verifier = ChainVerifier(trusted_keys, tsa_roots, witness=witness)
    verifier.feed(lines)
    return verifier.result(head)


class ChainVerifier:
    """A chain verified as its lines arrive: ``feed`` the lines of a growing file pass after pass,
    and ask for the ``result`` at any point. The result for lines fed in several parts is exactly
    the result for all of them at once (``verify_lines``). ``schema=False`` leaves out the schema check
    of each record, which the caller then makes itself on the records that need it."""

    restart: tuple[int, int, int | None] | None = None  # the widest restart note since the last checkpoint

    def __init__(self, trusted_keys: Iterable[str] = (),
                 tsa_roots: Iterable[x509.Certificate] | None = None, schema: bool = True,
                 witness: str | Path | None = None) -> None:
        self.report = Report()
        self.schema = schema
        self.witness = _WitnessCheck(witness) if witness is not None else None
        self.pins = {_full_id(k) for k in trusted_keys}
        self.keys = _Keys(trusted=set(self.pins), pinned=bool(self.pins),
                          tsa_roots=list(tsa_roots) if tsa_roots is not None else None)
        self.version: str | None = None
        self.expected_seq = 0
        self.redacted = 0
        self.prev_hash: str | None = GENESIS_HASH
        self.pending: list[tuple[int, str | None]] = []  # (seq, stored record_hash) since last checkpoint
        self.checkpoint_hashes: dict[int, str | None] = {}  # seq -> stored record_hash, for the head check
        self.last_seq: int | None = None
        self.last_wall: str | None = None
        self.heartbeat_s: float | None = None  # set once the chain has heartbeats on
        self.model_calls: dict[int, tuple[Any, int]] = {}  # seq -> (run_id, full context length), for context_base
        self.not_checked: set[str] = set()  # fields and kinds of a newer minor version this verifier doesn't know
        self.newest: str | None = None  # the newest minor version seen, when newer than this verifier's
        self.unverifiable = 0  # records covered only by checkpoints signed with an algorithm this verifier lacks
        self.unverified_tail = 0  # of those, the ones after the last checkpoint this verifier could check
        self.restart = None
        self.last_checkpoint: int | None = None  # the seq of the latest checkpoint seen
        self.lines = 0  # lines read so far, blank ones included: error line numbers count on from here

    def feed(self, lines: Iterable[bytes | str]) -> None:
        report = self.report
        for raw in lines:
            self.lines += 1
            line_no = self.lines
            if isinstance(raw, bytes):
                try:
                    raw = raw.decode("utf-8")
                except UnicodeDecodeError:  # the recorder writes UTF-8 only: other bytes were put there later
                    report.error("parse", "line is not valid UTF-8", line_no)
                    continue
            if is_blank(raw):
                continue
            try:
                rec = parse_json(raw)
            except (ValueError, RecursionError) as exc:  # also duplicate keys, NaN, and nesting too deep
                report.error("parse", f"line is not valid JSON: {str(exc)[:200]}", line_no)
                continue
            if not isinstance(rec, dict):
                report.error("parse", "record is not a JSON object", line_no)
                continue
            self._take(rec, line_no)

    def feed_parsed(self, rec: dict) -> None:
        """One record a sink has already parsed, as the next line of the chain."""
        self.lines += 1
        self._take(rec, self.lines)

    def _take(self, rec: dict, line_no: int) -> None:
        report = self.report
        report.records += 1
        seq = rec.get("seq") if isinstance(rec.get("seq"), int) and not isinstance(rec.get("seq"), bool) else None
        try:
            self._check_record(rec, line_no, seq)
        except Exception as exc:  # a line of a file can hold anything: what was found so far must survive it
            report.error("unreadable", f"this record could not be checked ({type(exc).__name__}), so it cannot "
                                       "count as valid", line_no, seq)
            if seq is not None:  # the records after it are still checked against where it stood
                self.expected_seq = seq + 1
            self.prev_hash = rec.get("record_hash") if isinstance(rec.get("record_hash"), str) else self.prev_hash

    def _check_record(self, rec: dict, line_no: int, seq: int | None) -> None:
        report, keys = self.report, self.keys
        schema_errors = sorted(_validator(rec).iter_errors(rec),
                               key=lambda e: [(isinstance(p, str), p) for p in e.absolute_path]) if self.schema else []
        if schema_errors:
            for err in schema_errors[:5]:
                where = "/".join(map(str, err.absolute_path)) or "(record)"
                report.error("schema", f"{where}: {err.message}", line_no, seq)
            if not isinstance(rec.get("record_hash"), str) or seq is None:
                return  # too malformed to check links

        # A chain may move to a newer version (a recorder upgraded mid-chain), never back.
        record_version = rec.get("spec_version")
        vkey = version_key(record_version)
        if vkey is not None:
            if self.version is not None and vkey < (version_key(self.version) or (0, 0)):
                report.error("spec_version", f"spec_version went back from {self.version} to {record_version}",
                             line_no, seq)
            else:
                self.version = record_version
        newer = vkey is not None and vkey > (1, 0)
        if vkey is not None and newer and (self.newest is None or vkey > (version_key(self.newest) or (0, 0))):
            self.newest = record_version
        self._check_fields(rec, newer, report, line_no, seq)

        # Chain identity and ordering.
        chain_id = rec.get("chain_id")
        if report.chain_id is None:
            report.chain_id = chain_id if isinstance(chain_id, str) else None  # the schema error names anything else
        elif chain_id != report.chain_id:
            shown = repr(chain_id) if isinstance(chain_id, str) else f"a value of type {type(chain_id).__name__}"
            report.error("chain_id", f"record belongs to chain {shown}, expected {report.chain_id!r}", line_no, seq)
        if seq != self.expected_seq:
            report.error("seq", f"expected seq {self.expected_seq}, found {seq} (records missing, duplicated, "
                                "or reordered)", line_no, seq)
        self.expected_seq = (seq if seq is not None else self.expected_seq) + 1

        if rec.get("prev_hash") != self.prev_hash:
            report.error("link", "prev_hash does not match the previous record's record_hash", line_no, seq)
        stored: str | None = rec.get("record_hash")
        try:
            actual = record_hash(rec)
        except (CanonicalizationError, ValueError, RecursionError) as exc:  # e.g. a key that is not valid text
            report.error("canonical", str(exc)[:200], line_no, seq)
            actual = None
        if actual is not None and actual != stored:
            report.error("record_hash", "record_hash does not match record contents (record was modified)",
                         line_no, seq)
        # Link onward from the *stored* hash so one tampered record yields one error, not a cascade.
        self.prev_hash = stored

        # Redactable content must match its committed digest when present. Since 1.0 every value
        # has its own salt, so a short value can't be found again from its digest by guessing.
        v1 = vkey is None or vkey >= (1, 0)
        omitted = _omitted_paths(rec, report, line_no, seq)
        for obj, fld, path in iter_redactable_paths(rec):
            committed = obj.get(f"{fld}_hash")
            has_salt = fld + SALT_SUFFIX in obj
            if has_salt and not v1:
                report.error("spec_version", f"{fld}{SALT_SUFFIX} needs spec_version 1.0", line_no, seq)
            if fld in obj:
                if v1 and not has_salt:
                    report.error("salt", f"{fld} has no {fld}{SALT_SUFFIX}: its digest could be guessed",
                                 line_no, seq)
                try:
                    ok = committed == slot_digest(obj, fld)
                except (CanonicalizationError, ValueError, RecursionError):
                    ok = False
                if not ok:
                    report.error("content_hash", f"{fld} does not match {fld}_hash (content was modified)",
                                 line_no, seq)
            elif committed is None:
                report.error("content_hash", f"{fld}_hash missing", line_no, seq)
            else:
                self.redacted += 1
                if has_salt and path not in omitted:
                    report.warn("salt", f"{path} was redacted but its salt was kept, so its digest can be "
                                        "checked against guesses. Remove the salt too", line_no, seq)
        if rec.get("event_type") == "llm_call" and seq is not None:
            self._check_context_base(rec, v1, report, line_no, seq)
        elif "context_base" in rec:
            report.error("context_base", "context_base belongs to model calls (llm_call) only", line_no, seq)
        if "agent_identity" in rec and not v1:
            report.error("spec_version", "agent_identity needs spec_version 1.0", line_no, seq)

        ts = rec.get("ts")
        wall = ts.get("wall") if isinstance(ts, dict) else None
        if isinstance(wall, str):
            if self.last_wall is not None and wall < self.last_wall:
                report.warn("clock", f"wall clock went backwards ({self.last_wall} -> {wall})", line_no, seq)
            if self.last_wall is not None and self.heartbeat_s:
                _check_quiet(self.last_wall, wall, self.heartbeat_s, report, line_no, seq)
            self.last_wall = wall
        if rec.get("event_type") == "heartbeat":
            if rec.get("spec_version") == "0.1":
                report.error("spec_version", "heartbeat events need spec_version 0.2", line_no, seq)
            attributes = rec.get("attributes")
            interval = attributes.get("interval_s") if isinstance(attributes, dict) else None
            if isinstance(interval, (int, float)) and not isinstance(interval, bool) and interval > 0:
                self.heartbeat_s = float(interval)

        if self.witness is not None:
            self.witness.see(rec, seq, stored, self.pending)
        if seq is not None:
            self.last_seq = seq
        if rec.get("kind") == "checkpoint":
            checked = not (newer and rec.get("sig_alg") not in SIG_ALGS)
            if not checked:
                # A later minor version may sign with an algorithm this verifier lacks: what it covers
                # counts as unsigned here, never as valid, and stays in the unsigned tail.
                _check_range(rec, self.pending, report, line_no, seq)
                _check_unknown_signer(rec, keys, report, line_no, seq)
                self.not_checked.add(f"signatures with {rec.get('sig_alg')}")
                self.unverifiable += len(self.pending)
                self.unverified_tail += len(self.pending)
            else:
                report.checkpoints += 1
                _check_checkpoint(rec, self.pending, keys, report, line_no, seq, newer)
                self.unverified_tail = 0
                if seq is not None:
                    report.signed_through_seq = seq
            if seq is not None:
                self.checkpoint_hashes[seq] = stored
                self.last_checkpoint = seq
            if self.restart is not None:
                last, note_line, note_seq = self.restart
                first = self.pending[0][0]
                if checked:
                    report.restarts.append({"from_seq": first, "to_seq": last, "checkpoint_seq": seq})
                    said = (f"were signed only after a restart, by the checkpoint at seq {seq}. Until then they "
                            "rested on the hash chain alone, so a change to them, or records removed from their "
                            "end, before that signature cannot be detected")
                else:
                    said = ("were taken over unsigned after a restart, and this verifier cannot check the checkpoint "
                            f"at seq {seq} that covers them. They rest on the hash chain alone")
                report.warn("signed_after_restart", f"records {first}..{last} {said}", note_line, note_seq)
                self.restart = None
            self.pending = []
        else:
            report.events += 1
            self._note_restart(rec, line_no, seq)
            self._note_unclean_resume(rec, line_no, seq)
            self._note_continues(rec, line_no, seq)
            self.pending.append((seq if seq is not None else -1, stored))

    def _note_unclean_resume(self, rec: dict, line_no: int, seq: int | None) -> None:
        """Warn about a recorder's note that it resumed after a checkpoint with no clean close before it. The note
        must name the latest checkpoint: a write that failed may put it a few records later, but never past the next
        checkpoint. It only ever adds a warning. Any other note of this shape is a note."""
        claim = recorder_claim(rec, UNCLEAN_RESUME_FIELD)
        after = claim.get("after_checkpoint_seq") if isinstance(claim, dict) else None
        if type(after) is not int or after != self.last_checkpoint:
            return
        self.report.unclean_restarts.append({"note_seq": seq, "checkpoint_seq": after})
        self.report.warn(UNCLEAN_RESUME_FIELD,
                         f"a recorder restarted after the checkpoint at seq {after}, and the chain does not show a "
                         "clean close before it. It may have crashed right after signing, or records after that "
                         "checkpoint may have been removed, or the file comes from an older recorder, which never "
                         "wrote that marker. Check this against other records of the run",
                         line_no, seq)

    def _note_continues(self, rec: dict, line_no: int, seq: int | None) -> None:
        """Warn about a recorder's note that this chain replaced a file it could not continue. Without this, a file
        damaged on purpose, set aside and then deleted leaves a new chain that looks clean. The note comes before the
        chain's first checkpoint. It only ever adds a warning. Any other note of this shape is a note."""
        claim = recorder_claim(rec, CONTINUES_FIELD)
        if not isinstance(claim, dict) or self.checkpoint_hashes:
            return
        said = [claim.get(name) for name in ("file", "sha256", "reason")]
        if not all(isinstance(value, str) for value in said):
            return
        name, digest, reason = (plain_text(str(value)) for value in said)
        self.report.continues_from.append({"note_seq": seq, "file": name, "sha256": digest, "reason": reason})
        self.report.warn(CONTINUES_FIELD,
                         f"this chain was started in place of a file that could not be continued ({reason}). That "
                         f"file was renamed {name}, digest {digest}. Keep it and check it. If it is gone, nothing "
                         "here shows what it held", line_no, seq)

    def _note_restart(self, rec: dict, line_no: int, seq: int | None) -> None:
        """Keep a recorder's restart note if it names exactly the start of what is unsigned here. It only ever
        adds a warning, and the numbers shown are the chain's. Any other note of this shape is just a note."""
        claim = recorder_claim(rec, RESTART_FIELD)
        if not isinstance(claim, dict):
            return
        first, last, count = claim.get("first_seq"), claim.get("last_seq"), claim.get("count")
        if not (type(first) is int and type(last) is int and type(count) is int):
            return
        if (1 <= count <= len(self.pending) and count == last - first + 1 and self.pending[0][0] == first
                and self.pending[count - 1][0] == last and (self.restart is None or last > self.restart[0])):
            self.restart = (last, line_no, seq)

    def _check_fields(self, rec: dict, newer: bool, report: Report, line_no: int, seq: int | None) -> None:
        """A field or event type this verifier doesn't know is an error in a version it implements. In a
        newer minor version it is covered by the record hash but not checked, and the report says so."""
        unknown = _unknown_fields(rec)
        if not unknown:
            return
        if newer:
            self.not_checked.update(unknown)
        else:
            report.error("schema", f"unknown field(s) for spec_version {rec.get('spec_version')}: "
                                   f"{', '.join(unknown)}", line_no, seq)

    def _check_context_base(self, rec: dict, v1: bool, report: Report, line_no: int, seq: int) -> None:
        """A call that records only what changed must point back to an earlier model call of the same run
        that had at least that many segments. Every such call is noted so later ones can point to it."""
        context = rec.get("context")
        own = len(context) if isinstance(context, list) else 0
        base = rec.get("context_base")
        carried = 0
        if base is not None:
            base_seq, segments = (base.get("seq"), base.get("segments")) if isinstance(base, dict) else (None, None)
            known = self.model_calls.get(base_seq) if isinstance(base_seq, int) else None
            if not v1:
                report.error("spec_version", "context_base needs spec_version 1.0", line_no, seq)
            elif not isinstance(base_seq, int) or base_seq >= seq:
                report.error("context_base", "context_base must point to an earlier record", line_no, seq)
            elif known is None:
                report.error("context_base", f"context_base points to seq {base_seq}, which is not a model call "
                                             "in this file", line_no, seq)
            elif known[0] != rec.get("run_id"):
                report.error("context_base", f"context_base points to seq {base_seq}, a model call of another run",
                             line_no, seq)
            elif not isinstance(segments, int) or segments > known[1]:
                report.error("context_base", f"context_base takes {segments} segments from seq {base_seq}, which "
                                             f"had {known[1]}", line_no, seq)
            else:
                carried = segments
        self.model_calls[seq] = (rec.get("run_id"), carried + own)

    def result(self, head: dict | None = None) -> Report:
        """The report for the lines fed so far. Feeding can go on afterwards: the verifier keeps its own
        state, and each result is a separate copy."""
        report = copy.deepcopy(self.report)
        report.unsigned_tail = len(self.pending) + self.unverified_tail
        if self.not_checked:
            report.warn("newer_version", f"written by a newer minor version ({self.newest or 'later than 1.0'}): "
                                         f"not checked by this verifier: {', '.join(sorted(self.not_checked))}. "
                                         "Upgrade mnestiq to check them")
        if self.unverifiable and self.pins:
            # The user asked for proof by a trusted key, and this verifier cannot give it for these records:
            # that is a failure to verify, not a detail, whatever newer version wrote them.
            report.error("unverifiable", f"{self.unverifiable} record(s) are covered only by checkpoints signed with "
                                         "an algorithm this verifier cannot check, so the trusted key does not vouch "
                                         "for them here. Upgrade mnestiq to verify them")
        elif self.unverifiable:
            report.warn("unverifiable", f"{self.unverifiable} record(s) are covered only by checkpoints this verifier "
                                        "cannot check, so they count as unsigned")
        if self.redacted:  # still verifies, by design: but the content, and what rules find in it, is gone
            report.warn("redacted", f"{self.redacted} field(s) are redacted: their content cannot be checked, and "
                                    "detection rules cannot see it")
        if report.records == 0:
            report.error("empty", "no records found")
        elif report.checkpoints == 0 and self.pins:
            # A pinned key that signed nothing proves nothing: anyone can write a consistent unsigned file.
            report.error("unsigned", "no signed checkpoints, so nothing in this file was signed by the trusted key. "
                                     "Anyone could have written it")
        elif report.checkpoints == 0:
            report.warn("unsigned", "chain has no signed checkpoints. The hash chain alone does not stop someone "
                                    "from rewriting the entire file consistently")
        elif report.unsigned_tail:
            report.warn("unsigned_tail", f"{report.unsigned_tail} record(s) after the last checkpoint this verifier "
                                         "could check are not signed. Changes to them, and deletion of trailing "
                                         "records, cannot be detected")
        if report.checkpoints and not self.pins:
            report.warn("untrusted_key", "no --trusted-key given; signatures prove internal consistency only, "
                                         "not who signed. Pin the recorder's public key.")
        if head is not None:
            _check_head(head, report, self.checkpoint_hashes, self.last_seq)
        if self.witness is not None:
            self.witness.finish(report, self.last_seq, self.pending)
        return report


def plain_text(text: str, limit: int = 200) -> str:
    """``text`` as printable ASCII of bounded length, for words that came out of a file or an exception."""
    return "".join(ch if " " <= ch <= "~" else "?" for ch in text[:limit])


def recorder_claim(rec: dict, name: str, event_type: str = "note") -> Any:
    """The attribute ``name`` of an event a recorder wrote about itself, under its own run id. None otherwise."""
    attributes = rec.get("attributes")
    chain = rec.get("chain_id")
    if (rec.get("event_type") != event_type or not isinstance(attributes, dict) or not isinstance(chain, str)
            or rec.get("run_id") != f"recorder-{chain[:8]}"):
        return None
    return attributes.get(name)


def _omitted_paths(rec: dict, report: Report, line_no: int, seq: int | None) -> set[str]:
    """The slots a record says were too large to store. ``x-omitted`` is an array of text (spec section 5)."""
    if "x-omitted" not in rec:
        return set()
    listed = rec["x-omitted"]
    if not isinstance(listed, list) or not all(isinstance(entry, str) for entry in listed):
        report.error("schema", "x-omitted must be an array of text", line_no, seq)
    return {entry.split(" (")[0] for entry in listed if isinstance(entry, str)} if isinstance(listed, list) else set()


def _check_quiet(before: str, after: str, interval: float, report: Report, line_no: int, seq: int | None) -> None:
    """With heartbeats every ``interval`` seconds, a longer silence means the recorder was not running."""
    try:
        fmt = "%Y-%m-%dT%H:%M:%S.%fZ"
        gap = (datetime.strptime(after, fmt) - datetime.strptime(before, fmt)).total_seconds()
    except ValueError:
        return
    if gap > 2 * interval + 60:
        report.quiet.append({"from": before, "to": after, "seconds": round(gap)})
        report.warn("quiet", f"no records from {before} to {after} ({gap / 60:.0f} min) although heartbeats "
                             f"were on every {interval:g}s: the recorder was not running", line_no, seq)


def _check_head(head: Any, report: Report, checkpoint_hashes: dict[int, str | None], last_seq: int | None) -> None:
    seq = head.get("seq") if isinstance(head, dict) else None
    if not isinstance(head, dict) or head.get("kind") != "checkpoint" or not isinstance(seq, int):
        report.error("head", "the head is not a checkpoint record")
    elif head.get("chain_id") != report.chain_id:
        report.error("head", f"the head belongs to chain {head.get('chain_id')!r}, not {report.chain_id!r}")
    elif seq not in checkpoint_hashes:
        if last_seq is None or seq > last_seq:
            report.error("truncated", f"the file ends at seq {last_seq} but the head records a checkpoint at "
                                      f"seq {seq}: records were removed from the end", seq=seq)
        else:
            report.error("head", f"the file has no checkpoint at seq {seq}, where the head has one", seq=seq)
    elif checkpoint_hashes[seq] != head.get("record_hash"):
        report.error("head", f"the checkpoint at seq {seq} differs from the head (the file was rewritten)", seq=seq)
    else:
        report.head_seq = seq


# The witness log. A service file, not the evidence format. A signing service keeps one per chain, and a log only
# ever says what the service was told, so it is read here as data that may be wrong.
WITNESS_VERSION = 1
WITNESS_KIND = "mnestiq-witness"
WITNESS_FOLDER = "witness"  # inside a signing service's folder
MAX_WITNESS_BYTES = 1 << 24  # far more than a service keeps for one chain
_RECORD_HASH = re.compile(r"sha256:[0-9a-f]{64}")
_REQUEST_HASH = re.compile(r"[0-9a-f]{64}")
_WITNESS_HEADER = frozenset({"chain_id", "kind", "thinned", "version"})
_WITNESSED_HEAD = frozenset({"at", "by", "record_hash", "seq"})
_WITNESSED_CHECKPOINT = frozenset({"at", "by", "covers", "merkle_root", "request", "seq"})
_MAX_WITNESS_ERRORS = 5  # a rewrite changes every later hash, so one change can show at every witnessed seq
_MAX_WITNESS_ROOT_CHECKS = 64  # signed checkpoints missing from a file: a real one comes from a rare crash
_MAX_WITNESS_BAD_LINES = 1000  # past this a log is not read on: a line that cannot be parsed is the slow case


def witness_file_name(chain_id: str) -> str:
    """The name of a chain's witness log. A chain id can hold anything, a file name cannot."""
    return hashlib.sha256(chain_id.encode("utf-8", "surrogatepass")).hexdigest() + ".jsonl"


def read_regular_file(path: str | Path, limit: int) -> bytes:
    """At most ``limit`` bytes of a regular file. A link or a pipe raises OSError: it is not followed or waited on."""
    if stat.S_ISLNK(os.lstat(path).st_mode):  # Windows has no O_NOFOLLOW
        raise OSError("this is a link, not a file")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
    with open(os.open(path, flags), "rb") as fh:
        if not stat.S_ISREG(os.fstat(fh.fileno()).st_mode):
            raise OSError("this is not a regular file")
        return fh.read(limit)


def _matches(pattern: re.Pattern[str], value: Any) -> bool:
    return isinstance(value, str) and pattern.fullmatch(value) is not None


@dataclass
class WitnessLog:
    """A witness log as read from disk: only what passed validation. Nothing in it is taken on trust elsewhere."""

    chain_id: str | None = None
    thinned: int = 0  # entries a service dropped to keep the log small
    entries: list[dict] = field(default_factory=list)
    heads: dict[int, str] = field(default_factory=dict)  # seq -> record_hash sent by a recorder
    checkpoints: dict[int, dict] = field(default_factory=dict)  # seq -> the entry for a checkpoint the service signed
    damaged_lines: int = 0  # lines that cannot be used, other than a torn last one
    reasons: list[str] = field(default_factory=list)  # why lines were skipped, the first few
    problem: str | None = None  # set when nothing in the log can be used
    torn: bool = False  # the last line has no line end, so a write stopped halfway. It is not read


def read_witness_log(path: str | Path) -> WitnessLog:
    """A witness log. This never raises: what is wrong with the log is in the result."""
    log = WitnessLog()
    try:
        data = read_regular_file(path, MAX_WITNESS_BYTES + 1)
    except OSError as exc:
        log.problem = f"it could not be read ({type(exc).__name__})"
        return log
    if len(data) > MAX_WITNESS_BYTES:
        log.problem = f"it is larger than {MAX_WITNESS_BYTES} bytes, more than a service keeps for one chain"
        return log
    lines = data.split(b"\n")
    log.torn = bool(lines.pop())
    try:
        header = parse_json(lines[0]) if lines else None
    except (ValueError, RecursionError):
        header = None
    log.problem = _witness_header_problem(header)
    if log.problem is not None or not isinstance(header, dict):
        return log
    log.chain_id, log.thinned = header["chain_id"], header.get("thinned", 0)
    for line in lines[1:]:
        try:
            reason = _take_witness_entry(log, parse_json(line))
        except (ValueError, RecursionError):
            reason = "a line is not JSON"
        if reason is not None:
            log.damaged_lines += 1
            if len(log.reasons) < _MAX_WITNESS_ERRORS:
                log.reasons.append(reason)
            if log.damaged_lines > _MAX_WITNESS_BAD_LINES:
                log.problem = f"more than {_MAX_WITNESS_BAD_LINES} of its lines cannot be read"
                break
    return log


def _witness_header_problem(header: Any) -> str | None:
    if not isinstance(header, dict) or header.get("kind") != WITNESS_KIND:
        return "it does not start with a witness log header"
    version = header.get("version")
    if version != WITNESS_VERSION or type(version) is not int:
        return f"it has version {str(version)[:20]}, and this verifier reads version {WITNESS_VERSION}"
    chain, thinned = header.get("chain_id"), header.get("thinned", 0)
    if not isinstance(chain, str) or not header.keys() <= _WITNESS_HEADER or type(thinned) is not int or thinned < 0:
        return "its header is malformed"
    return None


def _take_witness_entry(log: WitnessLog, entry: Any) -> str | None:
    """Add one line to ``log``. The reason it cannot be used, or None."""
    if not isinstance(entry, dict) or not isinstance(entry.get("at"), str):
        return "a line is not a witness entry"
    seq, by = entry.get("seq"), entry.get("by")
    if type(seq) is not int or seq < 0:
        return "a line has no usable seq"
    if by == "head":
        if entry.keys() != _WITNESSED_HEAD or not _matches(_RECORD_HASH, entry["record_hash"]):
            return f"the line for seq {seq} is malformed"
        if log.heads and seq <= next(reversed(log.heads)):
            return f"the line for seq {seq} does not move forward"
        log.heads[seq] = entry["record_hash"]
    elif by == "checkpoint":
        covers = entry.get("covers")
        low = covers.get("from_seq") if isinstance(covers, dict) else None
        if (entry.keys() != _WITNESSED_CHECKPOINT or not isinstance(covers, dict)
                or covers.keys() != {"from_seq", "to_seq"}
                or type(low) is not int or low < 0 or type(covers["to_seq"]) is not int
                or covers["to_seq"] != seq - 1 or low > seq - 1
                or not _matches(_RECORD_HASH, entry["merkle_root"]) or not _matches(_REQUEST_HASH, entry["request"])):
            return f"the line for seq {seq} is malformed"
        if log.checkpoints and seq <= next(reversed(log.checkpoints)):
            return f"the line for seq {seq} does not move forward"
        log.checkpoints[seq] = entry
    else:
        return "a line has an unknown kind"
    log.entries.append(entry)
    return None


def _witnessed_root_matches(pending: list[tuple[int, str | None]], signed: dict) -> bool:
    """Whether the records a witnessed checkpoint covers are the ones in ``pending``."""
    if not pending:
        return False
    low, high = signed["covers"]["from_seq"], signed["covers"]["to_seq"]
    start, end = low - pending[0][0], high - pending[0][0]  # by position: a long chain must not cost a scan per entry
    if start < 0 or end >= len(pending) or pending[start][0] != low or pending[end][0] != high:
        return False
    hashes = [h for _, h in pending[start:end + 1]]
    try:
        return "sha256:" + merkle_root([digest_bytes(h or "") for h in hashes]).hex() == signed["merkle_root"]
    except (ValueError, TypeError):
        return False


class _WitnessCheck:
    """One chain compared with its witness log as its lines go past.

    A recorder sends the newest head now and then, and the service notes every checkpoint it signs. A record's hash
    covers the one before it, so a matching head vouches for everything up to it. Records written after the last send
    were not witnessed, and neither is any record a hijacked agent sent a false head for."""

    def __init__(self, source: str | Path) -> None:
        self.source = source
        self.loaded = False
        self.log: WitnessLog | None = None  # None: a folder with no log for this chain
        self.differs: list[int] = []
        self.lost: list[int] = []  # signed checkpoints that never reached the file, its records unchanged
        self.seen: set[int] = set()
        self.matched: int | None = None
        self.root_checks = 0
        self.not_checked = 0  # missing checkpoints past the limit on root checks

    def _load(self, chain: Any) -> None:
        self.loaded = True
        path = Path(self.source)
        if path.is_dir():
            if not isinstance(chain, str):
                return
            name = witness_file_name(chain)
            found = [p for p in (path / WITNESS_FOLDER / name, path / name) if p.is_file()]
            if not found:
                return
            path = found[0]
        self.log = read_witness_log(path)
        if self.log.problem is None and self.log.chain_id != chain:
            self.log.problem = f"it belongs to chain {str(self.log.chain_id)[:80]!r}, not this one"

    def _usable(self) -> WitnessLog | None:
        return self.log if self.log is not None and self.log.problem is None else None

    def see(self, rec: dict, seq: int | None, stored: str | None, pending: list[tuple[int, str | None]]) -> None:
        """One record as the verifier reaches it. ``pending`` holds the records since the last checkpoint."""
        if not self.loaded:
            self._load(rec.get("chain_id"))
        log = self._usable()
        if log is None or seq is None or seq in self.seen:
            return
        head, signed = log.heads.get(seq), log.checkpoints.get(seq)
        if head is None and signed is None:
            return
        self.seen.add(seq)
        good = head is None or head == stored
        reached = seq
        if signed is not None:
            if rec.get("kind") == "checkpoint":
                good = good and _request_hash(rec) == signed["request"]
            elif self.root_checks >= _MAX_WITNESS_ROOT_CHECKS:
                self.not_checked += 1
                return
            elif self._root_check(pending, signed):
                self.lost.append(seq)
                reached = seq if head is not None else seq - 1
            else:
                good = False
        if good:
            self.matched = max(self.matched if self.matched is not None else -1, reached)
        else:
            self.differs.append(seq)

    def _root_check(self, pending: list[tuple[int, str | None]], signed: dict) -> bool:
        self.root_checks += 1
        return _witnessed_root_matches(pending, signed)

    def finish(self, report: Report, last_seq: int | None, pending: list[tuple[int, str | None]]) -> None:
        """Add what the comparison found to ``report``, a copy. The state here stays as it was."""
        if not self.loaded:  # no records at all: that is reported anyway
            return
        log = self.log
        common = {"source": str(self.source), "entries": 0, "thinned": 0, "highest_seq": None, "matched_through": None}
        if log is None:
            report.witness = common
            report.warn("witness_none", "the witness holds no log for this chain, so the file was not compared with "
                                        "it. Every chain a signing service signs for gets one")
            return
        if log.problem is not None:
            report.witness = common
            report.error("witness_unusable", f"the witness log cannot be used: {log.problem}. The file was not "
                                             "compared with it")
            return
        if log.damaged_lines:  # a service writes whole lines only, so this is not a crash
            report.error("witness_damaged", f"{log.damaged_lines} line(s) of the witness log could not be used and "
                                            f"were skipped: {', '.join(log.reasons)}")
        if log.torn:
            report.warn("witness_torn", "the last line of the witness log was cut short, as when the service stops "
                                        "while writing. It was not read")
        witnessed = [*log.heads, *log.checkpoints]
        common["entries"], common["thinned"] = len(log.entries), log.thinned
        if not witnessed:
            report.witness = common
            report.error("witness_unusable", "the witness log holds no entries, though a log is made only to hold "
                                             "one. It may have been cut down. The file was not compared with it")
            return
        if log.thinned:
            report.warn("witness_thinned", f"the witness dropped {log.thinned} of its older entries to stay small, "
                                           "keeping some from each stretch of time. Between the entries kept, it "
                                           "cannot show a change. A holder of the service token could have caused this")
        if self.not_checked:
            report.error("witness_unusable", f"{self.not_checked} checkpoint(s) the witness holds are missing from "
                                             "the file, more than a crash leaves, so they were not all checked")
        top = max(witnessed)
        ends = -1 if last_seq is None else last_seq
        self._report_differences(report)
        self._report_gaps(report, sorted(s for s in set(witnessed) if s <= ends and s not in self.seen))
        lost, matched = list(self.lost), self.matched
        if top > ends:
            signed = log.checkpoints.get(top)
            if signed is not None and top == ends + 1 and top not in log.heads:
                if _witnessed_root_matches(pending, signed):
                    lost.append(top)
                    matched = max(matched if matched is not None else -1, ends)
                else:
                    report.error("witness_rewritten", f"the records the signing service signed at seq {top} are not "
                                                      "the ones in the file, or are no longer all there", seq=top)
            else:
                report.error("witness_cut_back", f"the file ends at seq {ends}, but the witness saw seq {top}: "
                                                 "records it saw are gone from the end. The recorder puts each "
                                                 "record on disk before sending it, so a crash explains this only "
                                                 "if the storage lost what it had confirmed. A holder of the "
                                                 "service token could also have sent a false head", seq=top)
        for seq in lost:
            report.warn("witness_checkpoint_lost", f"the signing service signed a checkpoint at seq {seq} that is not "
                                                   "in the file. The records it covers are unchanged. The recorder "
                                                   "most likely stopped, or lost the answer, before writing it. "
                                                   "Removing that one line would look the same", seq=seq)
        common["highest_seq"], common["matched_through"] = top, matched
        common["not_witnessed"] = max(0, ends - top)
        report.witness = common
        if ends > top:
            report.warn("witness_tail", f"records {top + 1}..{ends} came after the last send the witness received, "
                                        "so it says nothing about them. Changes to them, and records removed from "
                                        "there, cannot be detected")
        self._report_restarts(report, log)

    def _report_differences(self, report: Report) -> None:
        for seq in self.differs[:_MAX_WITNESS_ERRORS]:
            report.error("witness_rewritten", f"the record at seq {seq} is not the one the witness saw: this record, "
                                              "or one before it, since each hash covers the one before, was rewritten "
                                              "after it was sent. A crash explains this only if the storage lost "
                                              "what it had confirmed and the recorder then wrote that seq again. A "
                                              "holder of the service token could also have sent a false head",
                         seq=seq)
        if len(self.differs) > _MAX_WITNESS_ERRORS:
            report.error("witness_rewritten", f"{len(self.differs) - _MAX_WITNESS_ERRORS} more witnessed records do "
                                              "not match the file")

    def _report_gaps(self, report: Report, missing: list[int]) -> None:
        if missing:
            report.error("witness_missing", f"the witness saw seq {missing[0]}, which is not in the file: the record "
                                            f"is gone ({len(missing)} witnessed seq(s) missing)", seq=missing[0])

    def _report_restarts(self, report: Report, log: WitnessLog) -> None:
        """Tell a crash from a change, for records signed only after a restart, as far as the witness reached."""
        for span in report.restarts:
            first, last = span["from_seq"], span["to_seq"]
            wrong = [s for s in self.differs if first <= s <= last]
            inside = [s for s in log.heads if first <= s <= last]
            if wrong:
                report.error("witness_restart", f"records {first}..{last} were signed only after a restart, and the "
                                                f"witness saw something else at seq {wrong[0]}: they were changed "
                                                "while the agent was down, not just left by a crash", seq=wrong[0])
            elif inside:
                self._say_restart_matches(report, first, last, max(inside))

    def _say_restart_matches(self, report: Report, first: int, last: int, reached: int) -> None:
        said = f" The witness matches them up to seq {reached}, so up to there this was a crash, not a change"
        if reached < last:
            said += f". Records {reached + 1}..{last} were written after the last send and were not witnessed"
        for issue in report.warnings:
            if issue.code == "signed_after_restart" and issue.message.startswith(f"records {first}..{last} "):
                issue.message += "." + said
                return
        report.warn("signed_after_restart", f"records {first}..{last}: {said.strip()}")


def _request_hash(rec: dict) -> str | None:
    """The digest of a checkpoint's signing payload, the request the service saw. None if it has no such form."""
    try:
        return hashlib.sha256(signing_payload(rec)).hexdigest()
    except (ValueError, RecursionError, TypeError):
        return None


def _check_range(rec: dict, pending: list[tuple[int, str | None]], report: Report, line_no: int,
                 seq: int | None) -> bool:
    """The checkpoint covers exactly the records since the last one, and its Merkle root matches them."""
    raw_covers = rec.get("covers")
    covers: dict = raw_covers if isinstance(raw_covers, dict) else {}
    if not pending:
        report.error("checkpoint_range", "checkpoint covers no records", line_no, seq)
        return False
    want_from, want_to = pending[0][0], pending[-1][0]
    if covers.get("from_seq") != want_from or covers.get("to_seq") != want_to:
        report.error("checkpoint_range",
                     f"checkpoint covers {covers.get('from_seq')}..{covers.get('to_seq')}, "
                     f"but records {want_from}..{want_to} precede it", line_no, seq)
    try:
        root = "sha256:" + merkle_root([digest_bytes(h or "") for _, h in pending]).hex()
    except (ValueError, TypeError):
        root = None
    if root != rec.get("merkle_root"):
        report.error("merkle_root", "merkle_root does not match the covered records", line_no, seq)
    return True


def _check_unknown_signer(rec: dict, keys: _Keys, report: Report, line_no: int, seq: int | None) -> None:
    """A checkpoint signed with an algorithm this verifier lacks must still be by the key the chain expects:
    a chain signed by a known key moves to another only by a hand-over (next_key) that key signed."""
    full = _generic_id(rec.get("key_id"), rec.get("public_key"))
    if full is None:
        report.error("signature", "key_id does not match public_key", line_no, seq)
        return
    if keys.expected is not None and full != keys.expected:
        report.error("signer_changed", f"checkpoint signed with {rec.get('sig_alg')} by {rec.get('key_id')}, but the "
                                       f"chain is signed by {_short(keys.expected)} and no checkpoint handed it "
                                       "over (next_key)", line_no, seq)
    keys.expected = full


def _generic_id(kid: Any, public_b64: Any) -> str | None:
    """The whole-key id of a key of any algorithm, from its key_id prefix and the SHA-256 of its raw bytes,
    when the key_id matches the key. The same form as ``_full_id`` for the algorithms this verifier knows."""
    if not isinstance(kid, str) or not isinstance(public_b64, str) or kid.count(":") != 1:
        return None
    try:
        digest = hashlib.sha256(base64.b64decode(public_b64, validate=True)).hexdigest()
    except ValueError:
        return None
    prefix, short = kid.split(":")
    return f"{prefix}:{digest}" if short == digest[:16] else None


def _check_checkpoint(rec: dict, pending: list[tuple[int, str | None]], keys: _Keys,
                      report: Report, line_no: int, seq: int | None, newer: bool = False) -> None:
    if not _check_range(rec, pending, report, line_no, seq):
        return
    pub = str(rec.get("public_key") or "")
    sig_alg = rec.get("sig_alg")
    v01 = rec.get("spec_version") == "0.1"
    if v01 and (sig_alg != ED25519 or "next_key" in rec):
        report.error("spec_version", "P-256 signatures and key hand-overs need spec_version 0.2", line_no, seq)
    try:
        kid = key_id(pub)
    except (ValueError, KeyError):
        report.error("signature", "public_key is not a valid Ed25519 or P-256 key", line_no, seq)
        return
    if rec.get("key_id") != kid:
        report.error("signature", "key_id does not match public_key", line_no, seq)
    full = _full_id(pub)  # trust is decided on the whole key: a 64-bit key_id could be matched by another key
    signed = True
    try:
        verify_signature(str(sig_alg), pub, _exact_b64(str(rec.get("signature", ""))), signing_payload(rec))
    except (InvalidSignature, ValueError, TypeError):
        signed = False
        report.error("signature", "checkpoint signature is invalid", line_no, seq)
    if kid not in report.signer_keys:
        report.signer_keys.append(kid)

    if keys.expected is not None and full != keys.expected:
        message = (f"checkpoint signed by {kid}, but the chain is signed by {_short(keys.expected)} and no checkpoint "
                   "handed it over (next_key)")
        if v01:
            report.warn("signer_changed", message, line_no, seq)
        else:
            report.error("signer_changed", message, line_no, seq)
    if keys.pinned and full not in keys.trusted:
        report.error("untrusted_key", f"checkpoint signed by {kid}, which is not a trusted key", line_no, seq)
    keys.expected = full

    nxt = rec.get("next_key")
    if isinstance(nxt, dict) and newer and nxt.get("sig_alg") not in SIG_ALGS:
        # A hand-over to an algorithm a later minor version added: checked by its key_id alone.
        next_full = _generic_id(nxt.get("key_id"), nxt.get("public_key"))
        if next_full is None:
            report.error("next_key", "next_key is not a valid key (key_id must match public_key)", line_no, seq)
        elif signed:
            keys.expected = next_full
            report.rotations.append({"seq": seq, "from_key": kid, "to_key": nxt.get("key_id")})
            if full in keys.trusted:
                keys.trusted.add(next_full)
    elif isinstance(nxt, dict):
        try:
            next_kid = key_id(str(nxt.get("public_key") or ""))
        except (ValueError, KeyError):
            next_kid = None
        if next_kid is None or nxt.get("key_id") != next_kid or nxt.get("sig_alg") not in ("ed25519",
                                                                                            "ecdsa-p256-sha256"):
            report.error("next_key", "next_key is not a valid key (key_id must match public_key)", line_no, seq)
        elif signed:
            next_full = _full_id(str(nxt.get("public_key")))
            keys.expected = next_full
            report.rotations.append({"seq": seq, "from_key": kid, "to_key": next_kid})
            if full in keys.trusted:  # a trusted key vouches for its successor
                keys.trusted.add(next_full)
    if "timestamp_token" in rec:
        _check_timestamp(rec, keys, report, line_no, seq)


def _exact_b64(text: str) -> bytes:
    """Base64 in the one spelling a recorder writes. The last character has spare bits, and without this check anyone
    could change them, and so the record's hash, while the signature bytes stay the same."""
    raw = base64.b64decode(text, validate=True)
    if base64.b64encode(raw).decode("ascii") != text:
        raise ValueError("not in canonical base64")
    return raw


def _full_id(public_b64: str) -> str:
    """The whole key, for deciding trust: its algorithm and the full SHA-256 of its raw bytes."""
    return key_id(public_b64).split(":", 1)[0] + ":" + hashlib.sha256(base64.b64decode(public_b64)).hexdigest()


def _short(full: str) -> str:
    """The key_id of a key given as ``_full_id``: the same digest, cut to 16 hex digits."""
    alg, digest = full.split(":", 1)
    return f"{alg}:{digest[:16]}"


def _check_timestamp(rec: dict, keys: _Keys, report: Report, line_no: int, seq: int | None) -> None:
    """An RFC 3161 token proves the checkpoint's signature existed at the time it states."""
    from .timestamps import TimestampError, TimestampsNotInstalled, default_roots, verify_token

    token = rec["timestamp_token"]
    if not isinstance(token, str) or not token:  # the schema lets null through, but a recorder leaves the field out
        report.error("timestamp", "the RFC 3161 timestamp token is empty or not text", line_no, seq)
        return
    try:
        roots = keys.tsa_roots if keys.tsa_roots is not None else default_roots()
        when = verify_token(_exact_b64(token), _exact_b64(str(rec.get("signature", ""))), roots)
    except TimestampsNotInstalled as exc:
        report.warn("timestamp_unverified", f"RFC 3161 timestamp token not checked: {exc}", line_no, seq)
        return
    except TimestampError as exc:
        report.error("timestamp", f"the RFC 3161 timestamp token is not valid for this checkpoint: {exc}",
                     line_no, seq)
        return
    except ValueError:
        report.error("timestamp", "the RFC 3161 timestamp token is not base64", line_no, seq)
        return
    when = when.astimezone(timezone.utc)
    report.timestamps.append({"seq": seq, "time": when.strftime("%Y-%m-%dT%H:%M:%SZ")})
    try:
        ts = rec.get("ts")
        claimed = datetime.strptime(str(ts.get("wall") if isinstance(ts, dict) else None), "%Y-%m-%dT%H:%M:%S.%fZ")
    except ValueError:
        return
    drift = (claimed.replace(tzinfo=timezone.utc) - when).total_seconds()
    if drift > 300:
        report.warn("clock", f"the checkpoint says {claimed:%Y-%m-%dT%H:%M:%SZ} but a timestamp authority saw it "
                             f"at {when:%Y-%m-%dT%H:%M:%SZ}: the recorder's clock was {drift / 60:.0f} min fast",
                    line_no, seq)
    elif drift < -600:
        report.warn("clock", f"the checkpoint says {claimed:%Y-%m-%dT%H:%M:%SZ} but was timestamped only at "
                             f"{when:%Y-%m-%dT%H:%M:%SZ}: its time is proven only from then", line_no, seq)
