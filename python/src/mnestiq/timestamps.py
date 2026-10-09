"""RFC 3161 timestamps: an outside authority's signed statement that a checkpoint existed at a time.

A checkpoint carries its own time, but the machine that wrote it sets that clock. A
timestamp authority (TSA) signs "this signature existed at T" with a certificate it gets
from a public certificate authority, so the time does not depend on anyone's clock but
the TSA's.

``Timestamper`` asks a TSA (DigiCert, then Sectigo, by default) and is passed to
``Recorder(timestamper=...)``. Only SHA-256 of the checkpoint's signature is sent.
``verify_token`` checks a token: the TSA's signature, its certificate chain up to a
trusted root, the time-stamping key usage, and that the token covers this signature.

The checks are done by ``rfc3161-client`` (Trail of Bits, also used by Sigstore). It
only reads strict DER, and the certificate lists many TSAs send are not sorted the way
DER requires. They are not covered by the TSA's signature, so they are taken out before
parsing and handed to the verifier separately. Install with ``pip install mnestiq[timestamps]``.
"""

from __future__ import annotations

import logging
import urllib.parse
import urllib.request
from collections.abc import Iterable, Sequence
from datetime import datetime
from importlib import resources
from typing import Any

from cryptography import x509
from cryptography.exceptions import InvalidSignature

_log = logging.getLogger("mnestiq")

DEFAULT_TSAS = ("http://timestamp.digicert.com", "http://timestamp.sectigo.com")


class TimestampError(Exception):
    pass


def default_roots() -> list[x509.Certificate]:
    """The roots of the default TSAs: DigiCert Trusted Root G4 and USERTrust RSA (Sectigo)."""
    pem = resources.files("mnestiq").joinpath("tsa_roots.pem").read_bytes()
    return x509.load_pem_x509_certificates(pem)


def _rfc3161() -> Any:
    try:
        import rfc3161_client
    except ImportError as exc:
        raise TimestampError("timestamps need: pip install mnestiq[timestamps]") from exc
    return rfc3161_client


class Timestamper:
    """Gets a TimeStampToken over a checkpoint signature. Tries each TSA in turn.

    Pass it as ``Recorder(timestamper=Timestamper())``. A failure never stops a
    checkpoint: the recorder writes it without a token and logs a warning.
    """

    def __init__(self, urls: Sequence[str] = DEFAULT_TSAS, timeout: float = 10.0,
                 roots: Iterable[x509.Certificate] | None = None) -> None:
        if not urls:
            raise ValueError("at least one TSA URL is needed")
        self.urls = list(urls)
        self.timeout = timeout
        self.roots = list(roots) if roots is not None else default_roots()

    def __call__(self, signature: bytes) -> bytes:
        rfc = _rfc3161()
        # SHA-256, as the spec says (the library would pick SHA-512).
        request = rfc.TimestampRequestBuilder().data(signature).hash_algorithm(rfc.HashAlgorithm.SHA256).nonce(
            nonce=True).cert_request(cert_request=True).build()
        problems = []
        for url in self.urls:
            try:
                reply = self._post(url, request.as_bytes())
                token = token_from_response(reply)
                # A token we cannot verify is no use later: check it now, while another TSA can be tried.
                verify_token(token, signature, self.roots, nonce=request.nonce)
                return token
            except Exception as exc:
                shown = _without_credentials(url)  # this goes to logs and into error messages
                problems.append(f"{shown}: {exc}")
                _log.info("mnestiq: timestamp from %s failed: %r", shown, exc)
        raise TimestampError("no timestamp authority answered: " + "; ".join(problems))

    def _post(self, url: str, body: bytes) -> bytes:
        req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/timestamp-query"})
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            data: bytes = resp.read(1 << 20)
        return data


def verify_token(token: bytes, signature: bytes, roots: Iterable[x509.Certificate],
                 nonce: int | None = None) -> datetime:
    """Check a TimeStampToken over ``signature`` and return the time it states (UTC).

    Raises ``TimestampError`` if the token is not over this signature, the TSA's signature
    is wrong, or its certificate does not chain to one of ``roots`` with time-stamping usage.
    """
    rfc = _rfc3161()
    roots = list(roots)
    if not roots:
        raise TimestampError("no trusted timestamp roots")
    try:
        certs, bare = split_certificates(token)
        response = rfc.decode_timestamp_response(_der(0x30, _der(0x30, b"\x02\x01\x00") + bare))
        infos = list(response.signed_data.signer_infos)
        if len(infos) != 1:
            raise TimestampError(f"expected one signer, found {len(infos)}")
        leaf = next((c for c in certs if c.issuer == infos[0].issuer
                     and c.serial_number == infos[0].serial_number), None)
        if leaf is None:
            raise TimestampError("the token does not include the TSA's certificate")
        # The certificates come from the token, which anyone can edit. The library treats every
        # certificate it is given as trusted, so it only gets the path checked here: from the
        # TSA's certificate up to one of ``roots``.
        intermediates = _chain_to_root(leaf, [c for c in certs if c != leaf], roots, response.tst_info.gen_time)
        builder = rfc.VerifierBuilder(tsa_certificate=leaf, roots=roots, intermediates=intermediates, nonce=nonce)
        builder.build().verify_message(response, signature)
    except TimestampError:
        raise
    except Exception as exc:  # parse errors and rfc3161_client.VerificationError
        raise TimestampError(str(exc) or type(exc).__name__) from None
    gen_time: datetime = response.tst_info.gen_time
    return gen_time


MAX_CHAIN = 4


def _chain_to_root(leaf: x509.Certificate, candidates: list[x509.Certificate],
                   roots: list[x509.Certificate], at: datetime) -> list[x509.Certificate]:
    """The intermediates linking ``leaf`` to one of ``roots``, each signed by the next and valid
    at ``at``. Raises if there is no such path: a certificate the token brings cannot end it."""
    root_keys = {_spki(r) for r in roots}
    path: list[x509.Certificate] = []
    current = leaf
    for _ in range(MAX_CHAIN + 1):
        _valid_at(current, at)
        if any(_issued_by(current, r) for r in roots):
            return path
        if _spki(current) in root_keys or current.issuer == current.subject:
            break  # a copy of a root signed by something else, or a self-signed certificate
        issuer = next((c for c in candidates if c not in path and c != current and _is_ca(c)
                       and _issued_by(current, c)), None)
        if issuer is None:
            break
        path.append(issuer)
        current = issuer
    raise TimestampError("the TSA's certificate does not chain to a trusted root")


def _issued_by(cert: x509.Certificate, issuer: x509.Certificate) -> bool:
    if cert.issuer != issuer.subject:
        return False
    try:
        cert.verify_directly_issued_by(issuer)
    except (ValueError, TypeError, InvalidSignature):
        return False
    return True


def _is_ca(cert: x509.Certificate) -> bool:
    try:
        return bool(cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca)
    except x509.ExtensionNotFound:
        return False


def _valid_at(cert: x509.Certificate, at: datetime) -> None:
    if not cert.not_valid_before_utc <= at <= cert.not_valid_after_utc:
        raise TimestampError(f"certificate {cert.subject.rfc4514_string()} was not valid at {at:%Y-%m-%d %H:%M:%S}Z")


def _spki(cert: x509.Certificate) -> bytes:
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    return cert.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)


def token_from_response(reply: bytes) -> bytes:
    """The TimeStampToken in a TimeStampResp, after checking the TSA granted the request."""
    tag, body, _ = _read(reply, 0)
    if tag != 0x30:
        raise TimestampError("the TSA's answer is not a TimeStampResp")
    status, rest = _children(body)[0], _children(body)[1:]
    status_tag, status_body, _ = _read(status, 0)
    code_tag, code, _ = _read(status_body, 0)
    if status_tag != 0x30 or code_tag != 0x02 or int.from_bytes(code, "big") not in (0, 1):
        raise TimestampError(f"the TSA refused the request (status {int.from_bytes(code, 'big')})")
    if not rest:
        raise TimestampError("the TSA's answer holds no token")
    return rest[0]


def split_certificates(token: bytes) -> tuple[list[x509.Certificate], bytes]:
    """The certificates in a TimeStampToken, and the token without them.

    The certificate list is outside what the TSA signs, so removing it changes nothing
    the signature covers.
    """
    tag, body, _ = _read(token, 0)
    oid, explicit = _children(body)[:2]
    _, inner, _ = _read(explicit, 0)
    _, signed_data, _ = _read(inner, 0)
    kept, certs = [], []
    for child in _children(signed_data):
        child_tag = child[0]
        if child_tag == 0xA0:  # certificates [0] IMPLICIT
            certs = [x509.load_der_x509_certificate(c) for c in _children(_read(child, 0)[1])]
        elif child_tag != 0xA1:  # crls [1] are dropped too
            kept.append(child)
    bare_signed = _der(0x30, b"".join(kept))
    return certs, _der(tag, oid + _der(explicit[0], bare_signed))


# A few lines of DER: enough to walk the structures above. Definite lengths only.


def _read(buf: bytes, pos: int) -> tuple[int, bytes, int]:
    """(tag, content, end) of the element at ``pos``."""
    if pos + 2 > len(buf):
        raise TimestampError("truncated ASN.1")
    tag, first = buf[pos], buf[pos + 1]
    pos += 2
    if first < 0x80:
        length = first
    elif first == 0x80 or first > 0x84:
        raise TimestampError("unsupported ASN.1 length")
    else:
        n = first & 0x7F
        length = int.from_bytes(buf[pos:pos + n], "big")
        pos += n
    end = pos + length
    if end > len(buf):
        raise TimestampError("truncated ASN.1")
    return tag, buf[pos:end], end


def _children(content: bytes) -> list[bytes]:
    """The complete encodings of each element in ``content``."""
    out, pos = [], 0
    while pos < len(content):
        _, _, end = _read(content, pos)
        out.append(content[pos:end])
        pos = end
    return out


def _der(tag: int, content: bytes) -> bytes:
    n = len(content)
    if n < 0x80:
        return bytes([tag, n]) + content
    size = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(size)]) + size + content


def _without_credentials(url: str) -> str:
    """The URL without a user:password@ part, for logs."""
    parts = urllib.parse.urlsplit(url)
    if "@" not in parts.netloc:
        return url
    return urllib.parse.urlunsplit(parts._replace(netloc=parts.netloc.rsplit("@", 1)[1]))
