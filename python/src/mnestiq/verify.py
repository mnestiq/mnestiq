"""Verify an evidence chain: schema, hash links, redactable digests, Merkle roots, signatures."""

from __future__ import annotations

import base64
import json
from dataclasses import asdict, dataclass, field
from functools import lru_cache
from importlib import resources
from pathlib import Path
from collections.abc import Iterable
from typing import Any

from cryptography.exceptions import InvalidSignature
from jsonschema import Draft202012Validator

from .canonical import CanonicalizationError
from .hashing import (
    GENESIS_HASH,
    digest_bytes,
    iter_redactable,
    record_hash,
    signing_payload,
    value_digest,
)
from .keys import key_id, public_key_from_b64
from .merkle import merkle_root


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
    errors: list[Issue] = field(default_factory=list)
    warnings: list[Issue] = field(default_factory=list)

    def error(self, code: str, message: str, line: int | None = None, seq: int | None = None) -> None:
        self.ok = False
        self.errors.append(Issue(code, message, line, seq))

    def warn(self, code: str, message: str, line: int | None = None, seq: int | None = None) -> None:
        self.warnings.append(Issue(code, message, line, seq))

    def to_dict(self) -> dict:
        return asdict(self)


@lru_cache(maxsize=1)
def _validator() -> Draft202012Validator:
    schema = json.loads(resources.files("mnestiq.schema").joinpath("record.schema.json").read_text("utf-8"))
    return Draft202012Validator(schema)


def verify_file(path: str | Path, trusted_keys: Iterable[str] = (), head: dict | None = None) -> Report:
    with open(path, "rb") as fh:
        return verify_lines(fh, trusted_keys, head)


def verify_lines(lines: Iterable[bytes | str], trusted_keys: Iterable[str] = (), head: dict | None = None) -> Report:
    """Verify a chain. ``head`` is a checkpoint kept elsewhere (``HeadFile``): the chain must
    contain exactly that checkpoint, which detects a file cut back to an earlier one."""
    report = Report()
    trusted = {key_id(k) for k in trusted_keys}
    validator = _validator()

    expected_seq = 0
    prev_hash: str | None = GENESIS_HASH
    pending: list[tuple[int, str | None]] = []  # (seq, stored record_hash) since last checkpoint
    checkpoint_hashes: dict[int, str | None] = {}  # seq -> stored record_hash, for the head check
    last_seq: int | None = None
    last_wall: str | None = None

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
            last_wall = wall

        if seq is not None:
            last_seq = seq
        if rec.get("kind") == "checkpoint":
            report.checkpoints += 1
            _check_checkpoint(rec, pending, trusted, report, line_no, seq)
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
    if report.checkpoints and not trusted:
        report.warn("untrusted_key", "no --trusted-key given; signatures prove internal consistency only, "
                                     "not who signed. Pin the recorder's public key.")
    if head is not None:
        _check_head(head, report, checkpoint_hashes, last_seq)
    return report


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


def _check_checkpoint(rec: dict, pending: list[tuple[int, str | None]], trusted: set[str],
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
    try:
        public_key = public_key_from_b64(pub)
    except Exception:
        report.error("signature", "public_key is not a valid Ed25519 key", line_no, seq)
        return
    kid = key_id(pub)
    if rec.get("key_id") != kid:
        report.error("signature", "key_id does not match public_key", line_no, seq)
    try:
        public_key.verify(base64.b64decode(rec.get("signature", "")), signing_payload(rec))
    except (InvalidSignature, ValueError):
        report.error("signature", "checkpoint signature is invalid", line_no, seq)
    if kid not in report.signer_keys:
        report.signer_keys.append(kid)
    if trusted and kid not in trusted:
        report.error("untrusted_key", f"checkpoint signed by {kid}, which is not a trusted key", line_no, seq)
    if rec.get("timestamp_token"):
        report.warn("timestamp_unverified",
                    "RFC 3161 timestamp token present but not verified by this version", line_no, seq)
