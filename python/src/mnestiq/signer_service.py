"""A signing service that keeps the key away from the agent: ``mnestiq signer serve``.

Run it under its own operating-system account, with its folder readable by that account
only. The agent connects with ``SignerClient`` and a shared token. Someone who takes over
the agent can then ask for signatures while they are in control, but cannot copy the key,
and cannot use it to rewrite what was already signed. The service only signs:

- checkpoint records for its own key, nothing else;
- with a timestamp close to its own clock (``max_skew``, 5 minutes by default);
- moving forward: per chain, each checkpoint must start right after the last one it signed.

Every signature is appended to ``signatures.jsonl``, a record the agent cannot change, to
compare with the evidence later.
"""

from __future__ import annotations

import base64
import contextlib
import json
import logging
import os
import secrets
import subprocess
import threading
from datetime import datetime, timezone
from multiprocessing import AuthenticationError
from multiprocessing.connection import Listener, answer_challenge, deliver_challenge
from pathlib import Path
from typing import Any, TypeGuard

from .canonical import canonical_json, parse_json
from .hashing import digest_bytes
from .keys import ED25519, generate_private_key, key_id, load_private_key, save_keypair
from .merkle import merkle_root
from .signers import LocalSigner, SignerError, parse_address, read_timeout

_log = logging.getLogger("mnestiq.signer")
MAX_REQUEST = 1 << 20
HANDSHAKE_SECONDS = 5.0  # a client that has not proven the token by then is cut off


def init_signer(directory: str | Path, alg: str = ED25519) -> LocalSigner:
    """Create a key, a token and an empty state in ``directory``."""
    directory = Path(directory)
    if (directory / "signer.key").exists():
        raise FileExistsError(f"{directory} already holds a signer")
    directory.mkdir(parents=True, exist_ok=True)
    key = generate_private_key(alg)
    priv, _ = save_keypair(key, directory, "signer")
    token = directory / "signer.token"
    fd = os.open(token, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="ascii") as fh:
        fh.write(secrets.token_hex(32) + "\n")
    for path in (priv, token):
        restrict_to_owner(path)
    return LocalSigner(key)


class SignerService:
    def __init__(self, directory: str | Path, max_skew: float = 300.0) -> None:
        self.dir = Path(directory)
        self.signer = LocalSigner(load_private_key(self.dir / "signer.key"))
        self.key_id = key_id(self.signer.public_key)
        self.token = (self.dir / "signer.token").read_text("ascii").strip().encode("ascii")
        self.max_skew = max_skew
        self._state_path = self.dir / "state.json"
        self._state: dict[str, dict[str, Any]] = (
            json.loads(self._state_path.read_text("utf-8")) if self._state_path.exists() else {})
        self._lock = threading.Lock()

    def handle(self, request: Any) -> dict[str, Any]:
        """Answer one request. Refusals come back as ``{"error": ...}``."""
        if not isinstance(request, dict):
            return {"error": "a request is a JSON object"}
        if request.get("op") == "public_key":
            return {"sig_alg": self.signer.sig_alg, "public_key": self.signer.public_key, "key_id": self.key_id}
        if request.get("op") != "sign":
            return {"error": f"unknown op {request.get('op')!r}"}
        try:
            payload = base64.b64decode(str(request.get("payload", "")), validate=True)
            leaves = request.get("leaves")
            if leaves is not None and not (isinstance(leaves, list) and all(isinstance(x, str) for x in leaves)):
                raise SignerError("leaves is a list of record hashes")
            return {"signature": base64.b64encode(self.sign(payload, leaves)).decode("ascii")}
        except (SignerError, ValueError) as exc:
            _log.warning("mnestiq signer: refused: %s", exc)
            return {"error": str(exc)}

    def sign(self, payload: bytes, leaves: list[str] | None = None) -> bytes:
        try:
            cp = parse_json(payload)
        except ValueError:
            raise SignerError("the payload is not JSON") from None
        if not isinstance(cp, dict) or cp.get("kind") != "checkpoint":
            raise SignerError("only checkpoint records are signed")
        if canonical_json(cp) != payload:
            raise SignerError("the payload is not in canonical form")
        if (cp.get("sig_alg"), cp.get("public_key"), cp.get("key_id")) != (
                self.signer.sig_alg, self.signer.public_key, self.key_id):
            raise SignerError(f"the checkpoint names another key; this signer is {self.key_id}")
        chain, seq, covers = cp.get("chain_id"), cp.get("seq"), cp.get("covers")
        if not isinstance(chain, str) or not _is_int(seq) or not isinstance(covers, dict):
            raise SignerError("the checkpoint has no chain_id, seq or covers")
        first, last_covered = covers.get("from_seq"), covers.get("to_seq")
        # A checkpoint covers the records just before it. The state below is this seq, so it must
        # follow from the range, or a client could move the state back and have history signed again.
        if not (_is_int(first) and _is_int(last_covered) and 0 <= first <= last_covered and seq == last_covered + 1):
            raise SignerError(f"the checkpoint at seq {seq!r} does not cover the records just before it "
                              f"({first!r}..{last_covered!r})")
        skew = abs((datetime.now(timezone.utc) - _parse_wall((cp.get("ts") or {}).get("wall"))).total_seconds())
        if skew > self.max_skew:
            raise SignerError(f"the checkpoint's time is {skew:.0f}s from this signer's clock "
                              f"(at most {self.max_skew:.0f}s)")
        with self._lock:
            last = self._state.get(chain)
            # The same records asked for again, after an answer was lost on the way back: signing
            # them again rewrites nothing, and refusing would stop the chain for good.
            again = (last is not None and last["seq"] == seq and last.get("covers") == covers
                     and last.get("merkle_root") == cp.get("merkle_root"))
            moves_on = last is None or first == last["seq"] + 1
            extends = (last is not None and not (moves_on or again)
                       and _extends(last, covers, cp.get("merkle_root"), leaves))
            if not (moves_on or again or extends):
                signed_to = last["seq"] if last is not None else None
                raise SignerError(f"chain {chain} was signed up to seq {signed_to}, and this checkpoint covers "
                                  f"from {first} (only the next checkpoint is signed)")
            signature = self.signer.sign(payload)
            self._append_log({"signed_at": _now(), "chain_id": chain, "seq": seq, "covers": covers,
                              "merkle_root": cp.get("merkle_root"), "key_id": self.key_id,
                              "signature": base64.b64encode(signature).decode("ascii")})
            if not again:
                self._state[chain] = {"seq": seq, "covers": covers, "merkle_root": cp.get("merkle_root"),
                                      "signed_at": _now()}
                write_durably(self._state_path, json.dumps(self._state, sort_keys=True))
        return signature

    def _append_log(self, entry: dict[str, Any]) -> None:
        with open(self.dir / "signatures.jsonl", "ab") as fh:
            fh.write(canonical_json(entry) + b"\n")
            fh.flush()
            os.fsync(fh.fileno())

    def start(self, address: str = "127.0.0.1:8741") -> SignerServer:
        return SignerServer(self, address)


class SignerServer:
    """Accepts connections on a background thread until ``close()``."""

    def __init__(self, service: SignerService, address: str) -> None:
        self.service = service
        target = parse_address(address)
        if isinstance(target, str) and os.name == "nt":
            raise SignerError("on Windows the signer listens on 127.0.0.1:<port>")
        # The token is checked on each connection's own thread, not in accept(), so a client that
        # connects and says nothing cannot hold up everyone after it.
        self._listener = Listener(target)
        self._token = service.token
        bound = self._listener.address
        self.address = f"{bound[0]}:{bound[1]}" if isinstance(bound, tuple) else str(bound)
        self._closed = False
        self._thread = threading.Thread(target=self._accept_loop, name="mnestiq-signer", daemon=True)
        self._thread.start()

    def _accept_loop(self) -> None:
        while not self._closed:
            try:
                conn = self._listener.accept()
            except OSError:
                if self._closed:
                    return
                continue
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, conn: Any) -> None:
        with contextlib.closing(conn):
            try:
                read_timeout(conn, HANDSHAKE_SECONDS)
                deliver_challenge(conn, self._token)
                answer_challenge(conn, self._token)
                read_timeout(conn, None)
            except (AuthenticationError, OSError, EOFError) as exc:  # wrong token, or silent too long
                _log.warning("mnestiq signer: rejected a connection: %r", exc)
                return
            while True:
                try:
                    raw = conn.recv_bytes(MAX_REQUEST)
                except (EOFError, OSError):
                    return
                try:
                    reply = self.service.handle(json.loads(raw))
                except ValueError:
                    reply = {"error": "the request is not JSON"}
                try:
                    conn.send_bytes(json.dumps(reply).encode("utf-8"))
                except OSError:
                    return

    def close(self) -> None:
        self._closed = True
        self._listener.close()

    def wait(self) -> None:
        self._thread.join()


def write_durably(path: Path, text: str) -> None:
    """Replace ``path`` with ``text`` so that a crash or power cut leaves the old or the new
    content, never an empty or older file: write a copy, flush it to disk, swap it in, and on
    POSIX flush the folder so the swap itself is kept."""
    tmp = path.with_name(path.name + ".tmp")
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(text)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)
    if os.name != "nt":
        fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def _parse_wall(wall: Any) -> datetime:
    if not isinstance(wall, str):
        raise SignerError("the checkpoint has no ts.wall")
    try:
        return datetime.strptime(wall, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
    except ValueError:
        raise SignerError(f"ts.wall {wall!r} is not RFC 3339 UTC") from None


def _extends(last: dict[str, Any], covers: dict, root: Any, leaves: list[str] | None) -> bool:
    """True if this checkpoint covers the records the last one signed, unchanged, and more after them.

    That happens when a signed checkpoint never reached the file (the agent crashed, the disk was
    full) and the agent wrote more records meanwhile: the last checkpoint's place is taken, so the
    next one starts where it started. The record hashes prove the earlier records are the ones
    signed: their Merkle root must be the root signed before. Nothing signed is rewritten.
    """
    old = last.get("covers")
    if not leaves or not isinstance(old, dict) or not last.get("merkle_root"):
        return False
    start, end, old_end = covers.get("from_seq"), covers.get("to_seq"), old.get("to_seq")
    if not (_is_int(start) and _is_int(end) and _is_int(old_end)) or start != old.get("from_seq") or end <= old_end:
        return False
    if len(leaves) != end - start + 1:
        return False
    try:
        digests = [digest_bytes(h) for h in leaves]
    except ValueError:
        return False
    old_n = old_end - start + 1
    return ("sha256:" + merkle_root(digests).hex() == root
            and "sha256:" + merkle_root(digests[:old_n]).hex() == last["merkle_root"])


def _is_int(value: Any) -> TypeGuard[int]:
    return isinstance(value, int) and not isinstance(value, bool)


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


_RESTRICT_SCRIPT = (
    "$me = [Security.Principal.WindowsIdentity]::GetCurrent().User; "
    "$acl = New-Object System.Security.AccessControl.FileSecurity; "
    "$acl.SetAccessRuleProtection($true, $false); "
    "$acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($me, 'FullControl', 'Allow'))); "
    "[System.IO.File]::SetAccessControl($env:MNESTIQ_ACL_PATH, $acl)")


def restrict_to_owner(path: Path) -> None:
    """Only the current user may read ``path``: mode 600, or on Windows an access list naming only them."""
    if os.name != "nt":
        os.chmod(path, 0o600)
        return
    # Plain .NET calls through Windows PowerShell, so no PowerShell module has to load.
    env = {k: v for k, v in os.environ.items() if k.upper() != "PSMODULEPATH"}
    result = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", _RESTRICT_SCRIPT],
                            capture_output=True, text=True, check=False, timeout=60,
                            env={**env, "MNESTIQ_ACL_PATH": str(path)})
    if result.returncode != 0:
        raise SignerError(f"could not restrict {path.name} to the current user: {result.stderr.strip()[:300]}")
