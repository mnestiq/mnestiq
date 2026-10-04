"""Ed25519 key handling for checkpoint signatures."""

from __future__ import annotations

import base64
import hashlib
import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


def generate_private_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def public_key_b64(key: Ed25519PrivateKey | Ed25519PublicKey) -> str:
    if isinstance(key, Ed25519PrivateKey):
        key = key.public_key()
    raw = key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.b64encode(raw).decode("ascii")


def key_id(public_b64: str) -> str:
    raw = base64.b64decode(public_b64)
    return "ed25519:" + hashlib.sha256(raw).hexdigest()[:16]


def public_key_from_b64(public_b64: str) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(base64.b64decode(public_b64))


def save_keypair(key: Ed25519PrivateKey, directory: str | Path, name: str = "signing") -> tuple[Path, Path]:
    """Write ``<name>.key`` (PKCS#8 PEM, unencrypted) and ``<name>.pub`` (base64 raw)."""
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    priv_path, pub_path = directory / f"{name}.key", directory / f"{name}.pub"
    if priv_path.exists():
        raise FileExistsError(f"{priv_path} already exists; refusing to overwrite a signing key")
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    fd = os.open(priv_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(pem)
    pub_path.write_text(public_key_b64(key) + "\n", encoding="ascii")
    return priv_path, pub_path


def load_private_key(path: str | Path) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(Path(path).read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError(f"{path} is not an Ed25519 private key")
    return key


def load_public_key_b64(value: str) -> str:
    """Accept a path to a .pub file or a literal base64 key; return base64."""
    candidate = Path(value)
    if candidate.is_file():
        value = candidate.read_text(encoding="ascii")
    value = value.strip()
    public_key_from_b64(value)  # validates length/encoding
    return value
