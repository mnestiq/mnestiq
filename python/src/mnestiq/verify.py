"""Verify an evidence chain: schema, hash links, redactable digests, Merkle roots, signatures."""

from __future__ import annotations

import base64
import json
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

from .canonical import CanonicalizationError, canonical_json
from .hashing import (
    GENESIS_HASH,
    digest_bytes,
    iter_redactable,
    record_hash,
    signing_payload,
    value_digest,
)
from .keys import ED25519, key_id, verify_signature
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


SUPPORTED_VERSIONS = ("0.1", "0.2")


@dataclass
class _Keys:
    """Which key signs the chain, and which keys the user's pins extend to."""

    trusted: set[str]  # pinned, plus keys a trusted key handed over to
    pinned: bool
    expected: str | None = None  # the key the next checkpoint must be signed by
    tsa_roots: list[x509.Certificate] | None = None  # roots for RFC 3161 tokens; None means the defaults


@lru_cache(maxsize=1)
def _validator() -> Draft202012Validator:
    schema = json.loads(resources.files("mnestiq.schema").joinpath("record.schema.json").read_text("utf-8"))
    return Draft202012Validator(schema)


def schema_problem(record: dict) -> str | None:
    """The first way a record breaks the schema, or None if it is valid."""
    error = best_match(_validator().iter_errors(json.loads(canonical_json(record))))
    if error is None:
        return None
    return f"{'/'.join(map(str, error.absolute_path)) or 'record'}: {error.message}"


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
    report = Report()
    pins = {key_id(k) for k in trusted_keys}
    keys = _Keys(trusted=set(pins), pinned=bool(pins),
                 tsa_roots=list(tsa_roots) if tsa_roots is not None else None)
    validator = _validator()
    version: str | None = None

    expected_seq = 0
    prev_hash: str | None = GENESIS_HASH
    pending: list[tuple[int, str | None]] = []  # (seq, stored record_hash) since last checkpoint
    checkpoint_hashes: dict[int, str | None] = {}  # seq -> stored record_hash, for the head check
    last_seq: int | None = None
    last_wall: str | None = None
    heartbeat_s: float | None = None  # set once the chain has heartbeats on

    for line_no, raw in enumerate(lines, start=1):
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8", errors="replace")
        if not raw.strip():
            continue
        try:
            rec = json.loads(raw)
        except json.JSONDecodeError as exc:
            report.error("parse", f"line is not valid JSON: {exc}", line_no)
            continue
        if not isinstance(rec, dict):
            report.error("parse", "record is not a JSON object", line_no)
            continue

        report.records += 1
        seq = rec.get("seq") if isinstance(rec.get("seq"), int) else None

        schema_errors = sorted(validator.iter_errors(rec), key=lambda e: list(e.absolute_path))
        if schema_errors:
            for err in schema_errors[:5]:
                where = "/".join(map(str, err.absolute_path)) or "(record)"
                report.error("schema", f"{where}: {err.message}", line_no, seq)
            if not isinstance(rec.get("record_hash"), str) or seq is None:
                continue  # too malformed to check links

        # A chain may move to a newer version (a recorder upgraded mid-chain), never back.
        record_version = rec.get("spec_version")
        if record_version in SUPPORTED_VERSIONS:
            if version is not None and SUPPORTED_VERSIONS.index(record_version) < SUPPORTED_VERSIONS.index(version):
                report.error("spec_version", f"spec_version went back from {version} to {record_version}",
                             line_no, seq)
            else:
                version = record_version

        # Chain identity and ordering.
        if report.chain_id is None:
            report.chain_id = rec.get("chain_id")
        elif rec.get("chain_id") != report.chain_id:
            report.error("chain_id", f"record belongs to chain {rec.get('chain_id')!r}, expected {report.chain_id!r}",
                         line_no, seq)
        if seq != expected_seq:
            report.error("seq", f"expected seq {expected_seq}, found {seq} (records missing, duplicated, or reordered)",
                         line_no, seq)
        expected_seq = (seq if seq is not None else expected_seq) + 1

        if rec.get("prev_hash") != prev_hash:
            report.error("link", "prev_hash does not match the previous record's record_hash", line_no, seq)
        stored: str | None = rec.get("record_hash")
        try:
            actual = record_hash(rec)
        except CanonicalizationError as exc:
            report.error("canonical", str(exc), line_no, seq)
            actual = None
        if actual is not None and actual != stored:
            report.error("record_hash", "record_hash does not match record contents (record was modified)",
                         line_no, seq)
        # Link onward from the *stored* hash so one tampered record yields one error, not a cascade.
        prev_hash = stored

        # Redactable content must match its committed digest when present.
        for obj, fld in iter_redactable(rec):
            committed = obj.get(f"{fld}_hash")
            if fld in obj:
                try:
                    ok = committed == value_digest(obj[fld])
                except CanonicalizationError:
                    ok = False
                if not ok:
                    report.error("content_hash", f"{fld} does not match {fld}_hash (content was modified)",
                                 line_no, seq)
            elif committed is None:
                report.error("content_hash", f"{fld}_hash missing", line_no, seq)

        wall = (rec.get("ts") or {}).get("wall")
        if isinstance(wall, str):
            if last_wall is not None and wall < last_wall:
                report.warn("clock", f"wall clock went backwards ({last_wall} -> {wall})", line_no, seq)
            if last_wall is not None and heartbeat_s:
                _check_quiet(last_wall, wall, heartbeat_s, report, line_no, seq)
            last_wall = wall
        if rec.get("event_type") == "heartbeat":
            if rec.get("spec_version") == "0.1":
                report.error("spec_version", "heartbeat events need spec_version 0.2", line_no, seq)
            interval = (rec.get("attributes") or {}).get("interval_s")
            if isinstance(interval, (int, float)) and not isinstance(interval, bool) and interval > 0:
                heartbeat_s = float(interval)

        if seq is not None:
            last_seq = seq
        if rec.get("kind") == "checkpoint":
            report.checkpoints += 1
            _check_checkpoint(rec, pending, keys, report, line_no, seq)
            if seq is not None:
                report.signed_through_seq = seq
                checkpoint_hashes[seq] = stored
            pending = []
        else:
            report.events += 1
            pending.append((seq if seq is not None else -1, stored))

    report.unsigned_tail = len(pending)
    if report.records == 0:
        report.error("empty", "no records found")
    elif report.checkpoints == 0:
        report.warn("unsigned", "chain has no signed checkpoints; the hash chain alone does not stop someone "
                                "from rewriting the entire file consistently")
    elif pending:
        report.warn("unsigned_tail", f"{len(pending)} record(s) after the last checkpoint are not signed; "
                                     "deletion of trailing records cannot be detected")
    if report.checkpoints and not pins:
        report.warn("untrusted_key", "no --trusted-key given; signatures prove internal consistency only, "
                                     "not who signed. Pin the recorder's public key.")
    if head is not None:
        _check_head(head, report, checkpoint_hashes, last_seq)
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


def _check_checkpoint(rec: dict, pending: list[tuple[int, str | None]], keys: _Keys,
                      report: Report, line_no: int, seq: int | None) -> None:
    covers = rec.get("covers") or {}
    if not pending:
        report.error("checkpoint_range", "checkpoint covers no records", line_no, seq)
        return
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
    signed = True
    try:
        verify_signature(str(sig_alg), pub, base64.b64decode(rec.get("signature", ""), validate=True),
                         signing_payload(rec))
    except (InvalidSignature, ValueError):
        signed = False
        report.error("signature", "checkpoint signature is invalid", line_no, seq)
    if kid not in report.signer_keys:
        report.signer_keys.append(kid)

    if keys.expected is not None and kid != keys.expected:
        message = (f"checkpoint signed by {kid}, but the chain is signed by {keys.expected} and no checkpoint "
                   "handed it over (next_key)")
        if v01:
            report.warn("signer_changed", message, line_no, seq)
        else:
            report.error("signer_changed", message, line_no, seq)
    if keys.pinned and kid not in keys.trusted:
        report.error("untrusted_key", f"checkpoint signed by {kid}, which is not a trusted key", line_no, seq)
    keys.expected = kid

    nxt = rec.get("next_key")
    if isinstance(nxt, dict):
        try:
            next_kid = key_id(str(nxt.get("public_key") or ""))
        except (ValueError, KeyError):
            next_kid = None
        if next_kid is None or nxt.get("key_id") != next_kid or nxt.get("sig_alg") not in ("ed25519",
                                                                                            "ecdsa-p256-sha256"):
            report.error("next_key", "next_key is not a valid key (key_id must match public_key)", line_no, seq)
        elif signed:
            keys.expected = next_kid
            report.rotations.append({"seq": seq, "from_key": kid, "to_key": next_kid})
            if kid in keys.trusted:  # a trusted key vouches for its successor
                keys.trusted.add(next_kid)
    if rec.get("timestamp_token"):
        _check_timestamp(rec, keys, report, line_no, seq)


def _check_timestamp(rec: dict, keys: _Keys, report: Report, line_no: int, seq: int | None) -> None:
    """An RFC 3161 token proves the checkpoint's signature existed at the time it states."""
    from .timestamps import TimestampError, default_roots, verify_token

    try:
        roots = keys.tsa_roots if keys.tsa_roots is not None else default_roots()
        when = verify_token(base64.b64decode(rec["timestamp_token"], validate=True),
                            base64.b64decode(rec.get("signature", ""), validate=True), roots)
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
