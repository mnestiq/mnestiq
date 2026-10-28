"""Verify an evidence chain: schema, hash links, redactable digests, Merkle roots, signatures."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import re
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

    def error(self, code: str, message: str, line: int | None = None, seq: int | None = None) -> None:
        self.ok = False
        self.errors.append(Issue(code, message, line, seq))

    def warn(self, code: str, message: str, line: int | None = None, seq: int | None = None) -> None:
        self.warnings.append(Issue(code, message, line, seq))

    def to_dict(self) -> dict:
        return asdict(self)


SUPPORTED_VERSIONS = ("0.1", "0.2", "1.0")  # the versions this verifier implements in full
EVENT_TYPES = frozenset({"run_start", "run_end", "llm_call", "tool_call", "approval", "egress", "note", "heartbeat"})


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
                tsa_roots: Iterable[x509.Certificate] | None = None) -> Report:
    with open(path, "rb") as fh:
        return verify_lines(fh, trusted_keys, head, tsa_roots)


def verify_lines(lines: Iterable[bytes | str], trusted_keys: Iterable[str] = (), head: dict | None = None,
                 tsa_roots: Iterable[x509.Certificate] | None = None) -> Report:
    """Verify a chain. ``head`` is a checkpoint kept elsewhere (``HeadFile``): the chain must
    contain exactly that checkpoint, which detects a file cut back to an earlier one.
    ``tsa_roots`` are the roots RFC 3161 timestamp tokens must chain to (default: those of
    the default timestamp authorities, see ``mnestiq.timestamps``)."""
    verifier = ChainVerifier(trusted_keys, tsa_roots)
    verifier.feed(lines)
    return verifier.result(head)


class ChainVerifier:
    """A chain verified as its lines arrive: ``feed`` the lines of a growing file pass after pass,
    and ask for the ``result`` at any point. The result for lines fed in several parts is exactly
    the result for all of them at once (``verify_lines``)."""

    def __init__(self, trusted_keys: Iterable[str] = (),
                 tsa_roots: Iterable[x509.Certificate] | None = None) -> None:
        self.report = Report()
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
        self.lines = 0  # lines read so far, blank ones included: error line numbers count on from here

    def feed(self, lines: Iterable[bytes | str]) -> None:
        report, keys = self.report, self.keys
        for raw in lines:
            self.lines += 1
            line_no = self.lines
            if isinstance(raw, bytes):
                try:
                    raw = raw.decode("utf-8")
                except UnicodeDecodeError:  # the recorder writes UTF-8 only: other bytes were put there later
                    report.error("parse", "line is not valid UTF-8", line_no)
                    continue
            if not raw.strip():
                continue
            try:
                rec = parse_json(raw)
            except (ValueError, RecursionError) as exc:  # also duplicate keys, NaN, and nesting too deep
                report.error("parse", f"line is not valid JSON: {str(exc)[:200]}", line_no)
                continue
            if not isinstance(rec, dict):
                report.error("parse", "record is not a JSON object", line_no)
                continue

            report.records += 1
            seq = rec.get("seq") if isinstance(rec.get("seq"), int) else None

            schema_errors = sorted(_validator(rec).iter_errors(rec), key=lambda e: list(e.absolute_path))
            if schema_errors:
                for err in schema_errors[:5]:
                    where = "/".join(map(str, err.absolute_path)) or "(record)"
                    report.error("schema", f"{where}: {err.message}", line_no, seq)
                if not isinstance(rec.get("record_hash"), str) or seq is None:
                    continue  # too malformed to check links

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
            if report.chain_id is None:
                report.chain_id = rec.get("chain_id")
            elif rec.get("chain_id") != report.chain_id:
                report.error("chain_id", f"record belongs to chain {rec.get('chain_id')!r}, expected "
                                         f"{report.chain_id!r}", line_no, seq)
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
            omitted = {str(o).split(" (")[0] for o in rec.get("x-omitted") or [] if isinstance(o, str)}
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
                interval = (rec.get("attributes") or {}).get("interval_s")
                if isinstance(interval, (int, float)) and not isinstance(interval, bool) and interval > 0:
                    self.heartbeat_s = float(interval)

            if seq is not None:
                self.last_seq = seq
            if rec.get("kind") == "checkpoint":
                if newer and rec.get("sig_alg") not in SIG_ALGS:
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
                self.pending = []
            else:
                report.events += 1
                self.pending.append((seq if seq is not None else -1, stored))

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
        return report


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
        verify_signature(str(sig_alg), pub, base64.b64decode(str(rec.get("signature", "")), validate=True),
                         signing_payload(rec))
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
    if rec.get("timestamp_token"):
        _check_timestamp(rec, keys, report, line_no, seq)


def _full_id(public_b64: str) -> str:
    """The whole key, for deciding trust: its algorithm and the full SHA-256 of its raw bytes."""
    return key_id(public_b64).split(":", 1)[0] + ":" + hashlib.sha256(base64.b64decode(public_b64)).hexdigest()


def _short(full: str) -> str:
    """The key_id of a key given as ``_full_id``: the same digest, cut to 16 hex digits."""
    alg, digest = full.split(":", 1)
    return f"{alg}:{digest[:16]}"


def _check_timestamp(rec: dict, keys: _Keys, report: Report, line_no: int, seq: int | None) -> None:
    """An RFC 3161 token proves the checkpoint's signature existed at the time it states."""
    from .timestamps import TimestampError, default_roots, verify_token

    try:
        roots = keys.tsa_roots if keys.tsa_roots is not None else default_roots()
        when = verify_token(base64.b64decode(str(rec["timestamp_token"]), validate=True),
                            base64.b64decode(str(rec.get("signature", "")), validate=True), roots)
    except TimestampError as exc:
        if "pip install" in str(exc):
            report.warn("timestamp_unverified", f"RFC 3161 timestamp token not checked: {exc}", line_no, seq)
        else:
            report.error("timestamp", f"the RFC 3161 timestamp token is not valid for this checkpoint: {exc}",
                         line_no, seq)
        return
    except ValueError:
        report.error("timestamp", "the RFC 3161 timestamp token is not base64", line_no, seq)
        return
    when = when.astimezone(timezone.utc)
    report.timestamps.append({"seq": seq, "time": when.strftime("%Y-%m-%dT%H:%M:%SZ")})
    try:
        claimed = datetime.strptime(str((rec.get("ts") or {}).get("wall")), "%Y-%m-%dT%H:%M:%S.%fZ")
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
