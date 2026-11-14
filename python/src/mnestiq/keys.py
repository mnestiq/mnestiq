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
from functools import lru_cache
from pathlib import Path

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
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
KEY_ID_PREFIXES = frozenset(_KEY_ID_PREFIX.values())  # how the key_id of a key of a known algorithm starts

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


class WeakKeyError(ValueError):
    """An Ed25519 public key that must not be used. The message says why."""


_ED_P = 2**255 - 19  # the field of Curve25519
_ED_D = -121665 * pow(121666, -1, _ED_P) % _ED_P  # the curve: -x^2 + y^2 = 1 + d x^2 y^2
_ED_SQRT_M1 = pow(2, (_ED_P - 1) // 4, _ED_P)


@lru_cache(maxsize=1024)
def ed25519_problem(raw: bytes) -> str | None:
    """Why 32 bytes must not be used as an Ed25519 public key, or None for a usable one.

    The curve has eight points of small order, the neutral point among them. Such a key has no private half.
    Under the neutral point a signature anyone can write (R the neutral point, S zero) checks for every message,
    in this library as in most, and under the other seven for one message in a few. A chain handed over to such
    a key could be continued by anybody. The bytes are decoded as RFC 8032 section 5.1.3 says and refused if they
    are not a point of the curve in its one encoding, or if eight times the point is the neutral point. A key
    made from a private key is never either."""
    y = int.from_bytes(raw, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    if len(raw) != 32 or y >= _ED_P:
        return "these bytes are not the encoding of an Ed25519 point"
    p = _ED_P
    u, v = (y * y - 1) % p, (_ED_D * y * y + 1) % p
    x2 = u * pow(v, -1, p) % p  # v is never 0: -1/d is not a square
    x = pow(x2, (p + 3) // 8, p)
    if (x * x - x2) % p:
        x = x * _ED_SQRT_M1 % p
    if (x * x - x2) % p or (x == 0 and sign):
        return "these bytes are not the encoding of an Ed25519 point"
    if x & 1 != sign:
        x = p - x
    for _ in range(3):  # double three times: eight times the point
        xy, shared = x * y % p, _ED_D * x * x * y * y % p
        x, y = 2 * xy * pow(1 + shared, -1, p) % p, (y * y + x * x) * pow(1 - shared, -1, p) % p
    if (x, y) == (0, 1):
        return "this Ed25519 key is a point of small order, and anyone can write a signature that it accepts"
    return None


def alg_of_public(public_b64: str) -> str:
    """The algorithm of a public key, by its length. Raises ``ValueError`` for anything that is not a key of
    either kind, and ``WeakKeyError`` (a ``ValueError``) for an Ed25519 key of small order."""
    raw = base64.b64decode(public_b64, validate=True)
    if len(raw) == 32:
        problem = ed25519_problem(raw)
        if problem is not None:
            raise WeakKeyError(problem)
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
    try:
        return normalize_p256(r.to_bytes(32, "big") + s.to_bytes(32, "big"))
    except OverflowError:
        raise ValueError("a P-256 signature holds numbers of at most 32 bytes") from None


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
    try:
        key = serialization.load_pem_private_key(Path(path).read_bytes(), password=None)
    except TypeError:  # what the library raises for a key that has a passphrase
        raise ValueError(f"{path} is protected by a passphrase: use a key file without one") from None
    except UnsupportedAlgorithm:
        raise ValueError(f"{path} uses an algorithm this installation cannot read") from None
    if not isinstance(key, (Ed25519PrivateKey, ec.EllipticCurvePrivateKey)):
        raise ValueError(f"{path} is not an Ed25519 or P-256 private key")
    sig_alg_of(key)  # rejects other curves
    return key


def load_public_key_b64(value: str) -> str:
    """Accept a path to a .pub file or a literal base64 key, with spaces or a line end around it. Returns the
    base64 text. The key must be in the canonical base64 of its bytes: any other spelling is refused."""
    candidate = Path(value)
    if candidate.is_file():
        value = candidate.read_text(encoding="ascii")
    value = value.strip()
    try:
        canonical = base64.b64encode(base64.b64decode(value, validate=True)).decode("ascii") == value
    except ValueError:  # also text that is not ASCII
        canonical = False
    if not canonical:
        raise ValueError(f"the public key {value[:12]}... is refused: it is not a file, and it is not a public key "
                         "written in canonical base64")
    try:
        load_public_key(value)  # validates length/encoding
    except WeakKeyError as exc:
        raise WeakKeyError(f"the public key {value[:12]}... is refused: {exc}") from None
    return value
