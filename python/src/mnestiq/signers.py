"""Who signs checkpoints. The recorder only needs ``sig_alg``, ``public_key`` and ``sign(payload)``.

- ``LocalSigner``: a key in this process. Fine for trying things out. In production the key
  should be somewhere the agent cannot read it, so a hijacked agent cannot copy it and re-sign
  history later.
- ``SignerClient``: asks a ``mnestiq signer serve`` process, running under another account,
  to sign. The agent never holds the key.
- ``AzureKeyVaultSigner``: the key lives in Azure Key Vault and never leaves it. Only the
  32-byte SHA-256 of each checkpoint is sent. Key Vault has no Ed25519, so this signs P-256.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import socket
import struct
import threading
import time
from typing import Any, Protocol, runtime_checkable

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .keys import ED25519, P256, PrivateKey, normalize_p256, p256_raw_signature, public_key_b64, sig_alg_of


@runtime_checkable
class Signer(Protocol):
    sig_alg: str
    public_key: str  # base64, raw encoding (see keys.py)

    def sign(self, payload: bytes) -> bytes: ...


class SignerError(Exception):
    pass


class WitnessUnsupported(SignerError):
    """This signer does not keep a witness log, for example a service older than the witness endpoint."""


WITNESS_TIMEOUT_S = 3.0  # how long one witness send waits for an answer, on its own connection
IDLE_REUSE_S = 120.0  # a connection idle longer is not reused: the service closes idle ones (300 s by default)
# Sent again after a failure even when the service may have read them: a repeated sign is answered with the
# signature already given for that exact request, and the others change nothing.
_SAFE_TO_RESEND = frozenset({"public_key", "sign", "repeat"})
WITNESS_BEHIND = "must move forward"  # in the service's refusal of a head at or behind one it already holds


class LocalSigner:
    """Signs with a private key held in this process."""

    def __init__(self, key: PrivateKey) -> None:
        self.sig_alg = sig_alg_of(key)
        self.public_key = public_key_b64(key)
        self._key = key

    def sign(self, payload: bytes) -> bytes:
        if isinstance(self._key, Ed25519PrivateKey):
            return self._key.sign(payload)
        return p256_raw_signature(self._key.sign(payload, ec.ECDSA(hashes.SHA256())))


def as_signer(value: Signer | PrivateKey) -> Signer:
    """A ``Signer`` as is, or a private key wrapped in a ``LocalSigner``."""
    if isinstance(value, Signer):
        return value
    return LocalSigner(value)


class AzureKeyVaultSigner:
    """Signs with a P-256 key in Azure Key Vault (or Managed HSM).

    ``key_url`` must name one version of the key, such as
    ``https://myvault.vault.azure.net/keys/mnestiq/0123abcd...``: if Key Vault rotated the key
    underneath, evidence would change signer without the signed hand-over the verifier
    requires. Rotate with ``Recorder.rotate_signer`` instead.

    The identity needs two permissions on the key, nothing more: read the public key
    (``Microsoft.KeyVault/vaults/keys/read``) and sign (``.../keys/sign/action``).
    Install the Azure libraries with ``pip install mnestiq[azure]``. ``credential`` defaults to
    ``DefaultAzureCredential`` (managed identity, environment, Azure CLI, ...).
    """

    sig_alg = P256

    def __init__(self, key_url: str, credential: Any = None, *, client: Any = None,
                 public_key: str | None = None, client_options: dict[str, Any] | None = None,
                 credential_options: dict[str, Any] | None = None) -> None:
        options = client_options or {}  # passed as they are to the Azure clients: retries and timeouts
        if client is None:
            try:
                from azure.identity import DefaultAzureCredential
                from azure.keyvault.keys import KeyClient, KeyVaultKeyIdentifier
                from azure.keyvault.keys.crypto import CryptographyClient
            except ImportError as exc:
                raise SignerError("Azure Key Vault signing needs: pip install mnestiq[azure]") from exc
            try:
                ident = KeyVaultKeyIdentifier(key_url)
            except ValueError:
                raise SignerError(f"{key_url} is not the URL of a Key Vault key") from None
            if not ident.version:
                raise SignerError(f"{key_url} names no key version; use the full URL of one version")
            credential = credential or DefaultAzureCredential(**(credential_options or {}))
            jwk: Any = KeyClient(ident.vault_url, credential, **options).get_key(ident.name, ident.version).key
            if getattr(jwk.crv, "value", jwk.crv) != "P-256" or not jwk.x or not jwk.y:
                raise SignerError(f"{key_url} is not a P-256 key (Key Vault has no Ed25519; create it with "
                                  "--kty EC --curve P-256)")
            public_key = base64.b64encode(b"\x04" + bytes(jwk.x).rjust(32, b"\0") + bytes(jwk.y).rjust(32, b"\0")
                                          ).decode("ascii")
            client = CryptographyClient(key_url, credential, **options)
        if public_key is None:
            raise SignerError("public_key is required with a custom client")
        self.key_url = key_url
        self.public_key = public_key
        self._client = client

    def sign(self, payload: bytes) -> bytes:
        digest = hashlib.sha256(payload).digest()
        try:
            from azure.keyvault.keys.crypto import SignatureAlgorithm

            algorithm: Any = SignatureAlgorithm.es256
        except ImportError:  # a test double needs no Azure libraries
            algorithm = "ES256"
        result = self._client.sign(algorithm, digest)
        return normalize_p256(bytes(result.signature))


class SignerClient:
    """Asks a ``mnestiq signer serve`` process to sign. See ``signer_service.py``.

    ``address`` is ``"127.0.0.1:8741"`` (any platform) or a Unix socket path. ``token`` is the
    shared secret from the service's ``signer.token``. It is never sent: both sides prove they
    hold it with a challenge and response.

    ``witness`` goes over its own connection, so a witness send that hangs cannot hold up a signature.
    """

    def __init__(self, address: str, token: str | bytes, timeout: float = 10.0) -> None:
        self.address = address
        self._token = token.encode("ascii") if isinstance(token, str) else token
        self._timeout = timeout
        self._line = _Line()
        self._witness_line = _Line()
        info = self._call({"op": "public_key"})
        sig_alg, public_key = info.get("sig_alg"), info.get("public_key")
        if not isinstance(sig_alg, str) or not isinstance(public_key, str) or not public_key:
            raise SignerError(f"the signer at {address} did not say which key it holds")
        self.sig_alg = sig_alg
        self.public_key = public_key
        if self.sig_alg not in (ED25519, P256):
            raise SignerError(f"the signer uses {self.sig_alg}, which this version cannot verify")

    @classmethod
    def from_env(cls) -> SignerClient:
        """``MNESTIQ_SIGNER`` (address, default 127.0.0.1:8741) and ``MNESTIQ_SIGNER_TOKEN``."""
        token = os.environ.get("MNESTIQ_SIGNER_TOKEN")
        if not token:
            raise SignerError("set MNESTIQ_SIGNER_TOKEN to the signer's token")
        return cls(os.environ.get("MNESTIQ_SIGNER", "127.0.0.1:8741"), token.strip())

    # The service can extend a checkpoint it signed that never reached the file, given the records' hashes.
    can_extend = True

    def sign(self, payload: bytes, leaves: list[str] | None = None) -> bytes:
        request: dict[str, Any] = {"op": "sign", "payload": base64.b64encode(payload).decode("ascii")}
        if leaves is not None:
            request["leaves"] = leaves
        return self._signature_in(self._call(request))

    def repeat(self, payload: bytes) -> bytes:
        """The signature the service already gave for exactly this request. It never makes a new one."""
        return self._signature_in(self._call({"op": "repeat", "payload": base64.b64encode(payload).decode("ascii")}))

    def _signature_in(self, reply: dict) -> bytes:
        signature = reply.get("signature")
        if not isinstance(signature, str):
            raise SignerError(f"the signer at {self.address} answered without a signature")
        try:
            return base64.b64decode(signature, validate=True)
        except ValueError:
            raise SignerError(f"the signer at {self.address} answered with a signature that is not base64") from None

    def witness(self, chain_id: str, seq: int, record_hash: str) -> bool:
        """Tell the service a chain's newest record. True if it was noted, False if the service refused it, because
        it holds that position or a later one, the jump is too far, or heads come too fast. Raises
        ``WitnessUnsupported`` if the service has no witness log."""
        request = {"op": "witness", "chain_id": chain_id, "seq": seq, "record_hash": record_hash}
        reply = self._call(request, self._witness_line, min(self._timeout, WITNESS_TIMEOUT_S), raw=True)
        if reply.get("refused"):
            return False
        error = reply.get("error")
        if error == "unknown op 'witness'":
            raise WitnessUnsupported(f"the signer at {self.address} has no witness log")
        if error:
            raise SignerError(f"the signer refused: {error}")
        return True

    def close(self) -> None:
        self._line.close()
        self._witness_line.close()

    def _call(self, request: dict, line: _Line | None = None, timeout: float | None = None, raw: bool = False) -> dict:
        from multiprocessing import AuthenticationError

        line = line if line is not None else self._line
        seconds = timeout if timeout is not None else self._timeout
        with line.lock:
            for attempt in (1, 2):  # one reconnect if the service restarted, or closed a connection left idle
                if line.conn is not None and time.monotonic() - line.used > IDLE_REUSE_S:
                    line.drop()  # the service may have closed it by now
                reused, sent = line.conn is not None, False
                try:
                    if line.conn is None:
                        line.conn = _connect(parse_address(self.address), self._token, seconds)
                    line.conn.send_bytes(json.dumps(request).encode("utf-8"))
                    sent = True
                    if not line.conn.poll(seconds):
                        raise TimeoutError("the signer did not answer")
                    reply = json.loads(line.conn.recv_bytes(1 << 20))
                    line.used = time.monotonic()
                    break
                except (ValueError, RecursionError):
                    raise SignerError(f"the signer at {self.address} answered something that is not JSON") from None
                except AuthenticationError:
                    raise SignerError(f"the signer at {self.address} did not accept the token") from None
                except (OSError, EOFError, TimeoutError) as exc:
                    line.drop()
                    # A kept connection the service closed was closed before it read this. Anything else may have
                    # been acted on, so only a request that is safe to repeat is sent again.
                    closed = reused and isinstance(exc, (EOFError, ConnectionError))
                    resend = not sent or closed or request.get("op") in _SAFE_TO_RESEND
                    if attempt == 2 or not resend:
                        raise SignerError(f"the signer at {self.address} is not reachable: {exc!r}") from exc
        if raw and isinstance(reply, dict):  # the caller reads the fields of a refusal
            return reply
        if not isinstance(reply, dict) or reply.get("error"):
            raise SignerError(f"the signer refused: {reply.get('error') if isinstance(reply, dict) else reply}")
        return reply


class _Line:
    """One connection to the service and the lock that keeps its requests one at a time."""

    def __init__(self) -> None:
        self.conn: Any = None
        self.used = 0.0  # when its last answer came
        self.lock = threading.Lock()

    def drop(self) -> None:
        if self.conn is not None:
            self.conn.close()
            self.conn = None

    def close(self) -> None:
        # A request stuck on a hung service gives up on its own within its timeout. Closing does not wait that long.
        if self.lock.acquire(timeout=1.0):
            try:
                self.drop()
            finally:
                self.lock.release()


def _connect(address: Any, token: bytes, timeout: float) -> Any:
    """Connect to the signer and prove the token both ways. The read timeout stays on afterwards: a signer
    that stays silent, even halfway through an answer, is given up on instead of holding the agent forever."""
    from multiprocessing.connection import Client, answer_challenge, deliver_challenge

    conn = Client(address)
    try:
        read_timeout(conn, timeout)
        answer_challenge(conn, token)
        deliver_challenge(conn, token)
    except BaseException:
        conn.close()
        raise
    return conn


def read_timeout(conn: Any, seconds: float | None) -> None:
    """Make reads on a connection's socket fail with OSError after ``seconds`` without data.
    None waits for ever."""
    sock = socket.socket(fileno=conn.fileno())
    try:
        if os.name == "nt":  # a DWORD of milliseconds
            value = struct.pack("=L", int((seconds or 0) * 1000))
        else:  # a struct timeval
            value = struct.pack("ll", int(seconds or 0), int(((seconds or 0) % 1) * 1_000_000))
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVTIMEO, value)
    finally:
        sock.detach()  # the connection still owns the socket


def parse_address(address: str) -> Any:
    """``host:port`` for TCP on this machine, or a filesystem path for a Unix socket."""
    host, sep, port = address.rpartition(":")
    if sep and port.isdecimal() and host and "/" not in address and "\\" not in address:
        if host not in ("127.0.0.1", "localhost"):
            raise SignerError(f"the signer listens on this machine only (127.0.0.1), not on {host}")
        return (host, int(port))
    return address
