"""Record hashing, redactable fields, and the checkpoint signing payload."""

from __future__ import annotations

import base64
import copy
import hashlib
import os
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

# Since spec 1.0 every redactable value has a sibling "<field>_salt": 16 random bytes, base64, mixed
# into its digest. Without it a short value (an amount, "yes", an email address) could be found again
# from its digest by guessing. The salt is removed with the value, and disclosed with it.
SALT_SUFFIX = "_salt"
SALT_BYTES = 16

# Fields never covered by the checkpoint signature: the record hash is computed
# after signing, and the RFC 3161 token is obtained over the signature.
UNSIGNED_CHECKPOINT_FIELDS = ("record_hash", "signature", "timestamp_token")


def digest(data: bytes) -> str:
    return HASH_PREFIX + hashlib.sha256(data).hexdigest()


def value_digest(value: Any) -> str:
    """Digest of a JSON value: sha256 over its canonical encoding."""
    return digest(canonical_json(value))


def new_salt() -> str:
    return base64.b64encode(os.urandom(SALT_BYTES)).decode("ascii")


def salted_digest(salt: str, value: Any) -> str:
    """Digest of a redactable value since spec 1.0: sha256 over the salt bytes, then the value's
    canonical encoding."""
    return digest(base64.b64decode(salt, validate=True) + canonical_json(value))


def slot_digest(obj: dict, field: str) -> str:
    """The digest ``obj[field]`` should have: salted when the slot has a salt, plain before 1.0."""
    salt = obj.get(field + SALT_SUFFIX)
    return salted_digest(salt, obj[field]) if isinstance(salt, str) else value_digest(obj[field])


def digest_bytes(prefixed: str) -> bytes:
    if not prefixed.startswith(HASH_PREFIX):
        raise ValueError(f"unsupported hash algorithm in {prefixed!r}")
    return bytes.fromhex(prefixed[len(HASH_PREFIX):])


def iter_redactable(record: dict) -> Iterator[tuple[dict, str]]:
    """Yield (object, field) for every redactable slot present in ``record``."""
    for obj, field, _ in iter_redactable_paths(record):
        yield obj, field


def iter_redactable_paths(record: dict) -> Iterator[tuple[dict, str, str]]:
    """Yield (object, field, path) for every redactable slot, the path as ``x-omitted`` writes it
    (``context[2].content``)."""
    for container_key, field in REDACTABLE_FIELDS:
        container = record.get(container_key)
        objects = container if isinstance(container, list) else [container]
        for i, obj in enumerate(objects):
            if isinstance(obj, dict) and (field in obj or f"{field}_hash" in obj or field + SALT_SUFFIX in obj):
                where = f"{container_key}[{i}]" if isinstance(container, list) else container_key
                yield obj, field, f"{where}.{field}"


def hashed_form(record: dict) -> dict:
    """The part of a record covered by ``record_hash``."""
    form = copy.deepcopy(record)
    form.pop("record_hash", None)
    for obj, field in iter_redactable(form):
        obj.pop(field, None)
        obj.pop(field + SALT_SUFFIX, None)
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
                # A redacted slot is simply "<field>_hash" without "<field>" (or its salt).
                obj.setdefault(f"{field}_hash", slot_digest(obj, field))
                del obj[field]
                obj.pop(field + SALT_SUFFIX, None)
            elif isinstance(obj, dict):
                # A value the producer omitted keeps its salt in the original. A copy for someone else
                # does not need it, and without it the digest can't be checked against guesses.
                obj.pop(field + SALT_SUFFIX, None)
    return out
