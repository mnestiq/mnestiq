"""Keys for checkpoint signatures: Ed25519, and ECDSA P-256 for key stores without Ed25519.

Public keys travel as base64 of their raw encoding: 32 bytes for Ed25519, the 65-byte
uncompressed point (0x04 || X || Y) for P-256. The length tells the two apart.
ECDSA signatures are the 64 bytes r || s with s in its low form, so each payload has
exactly one valid signature per key.
"""

from __future__ import annotations

import base64
import hashlib
import os
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature

ED25519 = "ed25519"
P256 = "ecdsa-p256-sha256"
SIG_ALGS = (ED25519, P256)
_KEY_ID_PREFIX = {ED25519: "ed25519", P256: "p256"}

# Order of the P-256 group. A signature (r, s) is also valid as (r, n - s): only the lower is accepted.
P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

PrivateKey = Ed25519PrivateKey | ec.EllipticCurvePrivateKey
PublicKey = Ed25519PublicKey | ec.EllipticCurvePublicKey


def generate_private_key(alg: str = ED25519) -> PrivateKey:
    if alg == ED25519:
        return Ed25519PrivateKey.generate()
    if alg == P256:
        return ec.generate_private_key(ec.SECP256R1())
    raise ValueError(f"unknown signature algorithm {alg!r}; expected one of {', '.join(SIG_ALGS)}")


def sig_alg_of(key: PrivateKey | PublicKey) -> str:
    if isinstance(key, (Ed25519PrivateKey, Ed25519PublicKey)):
        return ED25519
    if isinstance(key, (ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey)) and isinstance(key.curve, ec.SECP256R1):
        return P256
    raise ValueError("only Ed25519 and P-256 keys can sign checkpoints")


def public_key_b64(key: PrivateKey | PublicKey) -> str:
    if isinstance(key, (Ed25519PrivateKey, ec.EllipticCurvePrivateKey)):
        key = key.public_key()
    if sig_alg_of(key) == ED25519:
        raw = key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    else:
        raw = key.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    return base64.b64encode(raw).decode("ascii")


def alg_of_public(public_b64: str) -> str:
    raw = base64.b64decode(public_b64, validate=True)
    if len(raw) == 32:
        return ED25519
    if len(raw) == 65 and raw[0] == 4:
        return P256
    raise ValueError("not an Ed25519 (32 bytes) or uncompressed P-256 (65 bytes) public key")


def key_id(public_b64: str) -> str:
    """``ed25519:`` or ``p256:``, then the first 16 hex digits of SHA-256 over the raw public key."""
    raw = base64.b64decode(public_b64)
    return _KEY_ID_PREFIX[alg_of_public(public_b64)] + ":" + hashlib.sha256(raw).hexdigest()[:16]


def public_key_from_b64(public_b64: str) -> Ed25519PublicKey:
    """An Ed25519 public key. ``load_public_key`` accepts either kind."""
    return Ed25519PublicKey.from_public_bytes(base64.b64decode(public_b64))


def load_public_key(public_b64: str) -> PublicKey:
    raw = base64.b64decode(public_b64, validate=True)
    if alg_of_public(public_b64) == ED25519:
        return Ed25519PublicKey.from_public_bytes(raw)
    return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), raw)


def verify_signature(sig_alg: str, public_b64: str, signature: bytes, payload: bytes) -> None:
    """Raise ``InvalidSignature`` unless ``signature`` is ``public_b64``'s valid signature over ``payload``."""
    try:
        alg = alg_of_public(public_b64)
        key = load_public_key(public_b64)
    except ValueError:
        raise InvalidSignature("not a valid public key") from None
    if alg != sig_alg:
        raise InvalidSignature(f"a {sig_alg} signature cannot come from a {alg} key")
    if isinstance(key, Ed25519PublicKey):
        key.verify(signature, payload)
        return
    if len(signature) != 64:
        raise InvalidSignature("a P-256 signature is 64 bytes, r || s")
    r, s = int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big")
    if not (0 < r < P256_ORDER and 0 < s <= P256_ORDER // 2):
        raise InvalidSignature("P-256 signature out of range (s must be in its low form)")
    key.verify(encode_dss_signature(r, s), payload, ec.ECDSA(hashes.SHA256()))


def p256_raw_signature(der: bytes) -> bytes:
    """A DER ECDSA signature as the 64 bytes r || s, with s in its low form."""
    r, s = decode_dss_signature(der)
    return normalize_p256(r.to_bytes(32, "big") + s.to_bytes(32, "big"))


def normalize_p256(signature: bytes) -> bytes:
    """Turn r || s into its low-s form. Key stores such as Azure Key Vault may return either."""
    if len(signature) != 64:
        raise ValueError("a P-256 signature is 64 bytes, r || s")
    s = int.from_bytes(signature[32:], "big")
    if s > P256_ORDER // 2:
        s = P256_ORDER - s
    return signature[:32] + s.to_bytes(32, "big")


def save_keypair(key: PrivateKey, directory: str | Path, name: str = "signing") -> tuple[Path, Path]:
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
    try:
        if os.name == "nt":  # the mode does nothing on Windows: an access list naming only this user
            from .signer_service import restrict_to_owner

            restrict_to_owner(priv_path)
    except Exception:
        os.close(fd)
        priv_path.unlink()
        raise
    with os.fdopen(fd, "wb") as fh:  # the key is written only once nobody else can read the file
        fh.write(pem)
    pub_path.write_text(public_key_b64(key) + "\n", encoding="ascii")
    return priv_path, pub_path


def load_private_key(path: str | Path) -> PrivateKey:
    key = serialization.load_pem_private_key(Path(path).read_bytes(), password=None)
    if not isinstance(key, (Ed25519PrivateKey, ec.EllipticCurvePrivateKey)):
        raise ValueError(f"{path} is not an Ed25519 or P-256 private key")
    sig_alg_of(key)  # rejects other curves
    return key


def load_public_key_b64(value: str) -> str:
    """Accept a path to a .pub file or a literal base64 key; return base64."""
    candidate = Path(value)
    if candidate.is_file():
        value = candidate.read_text(encoding="ascii")
    value = value.strip()
    load_public_key(value)  # validates length/encoding
    return value
