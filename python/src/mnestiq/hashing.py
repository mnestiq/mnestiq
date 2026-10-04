"""Record hashing, redactable fields, and the checkpoint signing payload."""

from __future__ import annotations

import copy
import hashlib
from typing import Any
from collections.abc import Iterator

from .canonical import canonical_json

HASH_PREFIX = "sha256:"
GENESIS_HASH = HASH_PREFIX + "0" * 64

# Fields whose *values* are excluded from the record hash. Each has a sibling
# "<field>_hash" that is included. This lets an investigator strip sensitive
# content (prompts, tool arguments, tool results) from an evidence file before
# sharing it, and the chain still verifies.
#
# (container key, field name). The container is an object or a list of objects.
REDACTABLE_FIELDS: tuple[tuple[str, str], ...] = (
    ("context", "content"),
    ("output", "content"),
    ("tool_calls", "arguments"),
    ("tool_calls", "result"),
)

# Fields never covered by the checkpoint signature: the record hash is computed
# after signing, and the RFC 3161 token is obtained over the signature.
UNSIGNED_CHECKPOINT_FIELDS = ("record_hash", "signature", "timestamp_token")


def digest(data: bytes) -> str:
    return HASH_PREFIX + hashlib.sha256(data).hexdigest()


def value_digest(value: Any) -> str:
    """Digest of a JSON value: sha256 over its canonical encoding."""
    return digest(canonical_json(value))


def digest_bytes(prefixed: str) -> bytes:
    if not prefixed.startswith(HASH_PREFIX):
        raise ValueError(f"unsupported hash algorithm in {prefixed!r}")
    return bytes.fromhex(prefixed[len(HASH_PREFIX):])


def iter_redactable(record: dict) -> Iterator[tuple[dict, str]]:
    """Yield (object, field) for every redactable slot present in ``record``."""
    for container_key, field in REDACTABLE_FIELDS:
        container = record.get(container_key)
        objects = container if isinstance(container, list) else [container]
        for obj in objects:
            if isinstance(obj, dict) and (field in obj or f"{field}_hash" in obj):
                yield obj, field


def hashed_form(record: dict) -> dict:
    """The part of a record covered by ``record_hash``."""
    form = copy.deepcopy(record)
    form.pop("record_hash", None)
    for obj, field in iter_redactable(form):
        obj.pop(field, None)
    return form


def record_hash(record: dict) -> str:
    return value_digest(hashed_form(record))


def signing_payload(checkpoint: dict) -> bytes:
    body = {k: v for k, v in checkpoint.items() if k not in UNSIGNED_CHECKPOINT_FIELDS}
    return canonical_json(body)


def redact(record: dict, fields: tuple[tuple[str, str], ...] = REDACTABLE_FIELDS) -> dict:
    """Return a copy of ``record`` with the given redactable values removed."""
    out = copy.deepcopy(record)
    wanted = set(fields)
    for container_key, field in REDACTABLE_FIELDS:
        if (container_key, field) not in wanted:
            continue
        container = out.get(container_key)
        for obj in container if isinstance(container, list) else [container]:
            if isinstance(obj, dict) and field in obj:
                # A redacted slot is simply "<field>_hash" without "<field>".
                obj.setdefault(f"{field}_hash", value_digest(obj[field]))
                del obj[field]
    return out
