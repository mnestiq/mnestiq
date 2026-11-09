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

The service is also a witness. ``SignerClient.witness`` tells it a chain's newest record, and it notes every
checkpoint it signs, in ``witness/<sha256 of the chain id>.jsonl``. ``mnestiq verify --witness`` compares the
evidence with that log, so a file rewritten or cut back after a send shows, as far as the sends reached. No key
is involved. Each log is bounded: heads per chain are rate-limited, and a full log is thinned by age, so a burst
of heads only displaces entries of its own moment. Checkpoints have their own quota that heads cannot touch.
Chains known only from heads have a ``max_chains`` budget of their own and never use up signing's.

The key is the folder's own, or one in Azure Key Vault (``key_vault_signer``). With Key Vault
these rules hold only if the agent's identity has no sign permission on the key.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import json
import logging
import math
import os
import re
import secrets
import subprocess
import sys
import threading
import time
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime, timezone
from multiprocessing import AuthenticationError
from multiprocessing.connection import Listener, answer_challenge, deliver_challenge
from pathlib import Path
from typing import Any, TypeGuard

from cryptography.exceptions import InvalidSignature

from .canonical import MAX_SAFE_INTEGER, canonical_json, parse_json
from .hashing import digest_bytes
from .keys import ED25519, generate_private_key, key_id, load_private_key, save_keypair, verify_signature
from .merkle import merkle_root
from .signers import (
    WITNESS_BEHIND,
    AzureKeyVaultSigner,
    LocalSigner,
    Signer,
    SignerError,
    parse_address,
    read_timeout,
)
from .verify import WITNESS_FOLDER, WITNESS_KIND, WITNESS_VERSION, read_witness_log, witness_file_name

_log = logging.getLogger("mnestiq.signer")
MAX_REQUEST = 1 << 20
HANDSHAKE_SECONDS = 5.0  # a client that has not proven the token by then is cut off
_MERKLE_ROOT = re.compile(r"sha256:[0-9a-f]{64}")
MIN_TOKEN_CHARS = 32  # signer init writes 64
MAX_COVERED = 1 << 40  # records in one checkpoint: their hashes alone would fill over 100 TB of the recorder's memory
MAX_CHAIN_ID = 1024
# One try and no waiting on Retry-After: a throttled or failing vault comes back as an error at once, and the
# recorder tries again later. VAULT_DEADLINE_S is the bound on a whole request, whatever the Azure libraries do.
_VAULT_CLIENT_OPTIONS = {"retry_total": 0, "connection_timeout": 3, "read_timeout": 4}
_VAULT_CREDENTIAL_OPTIONS = {"process_timeout": 5, **_VAULT_CLIENT_OPTIONS}
VAULT_DEADLINE_S = 8.0  # inside the 10 seconds SignerClient waits
VAULT_START_DEADLINE_S = 30.0  # the key read at start-up: sign-in can try several credentials first
_VAULT_CALLS_AT_ONCE = 8  # a call given up on keeps its slot until the Azure libraries return
DEFAULT_MAX_CHAINS = 10_000  # far more than one machine's agents make in years, small enough to bound the disk
MAX_WITNESS_HEADS = 1024  # per chain, and heads can never displace a checkpoint
MAX_WITNESS_CHECKPOINTS = 1024  # with a line at most some 300 bytes, a chain takes at most some 600 KB
WITNESS_HEADS_PER_S = 8.0  # per chain. A recorder sends at most 4 a second
WITNESS_HEAD_BURST = 32.0
WITNESS_JUMP_FLOOR = 10_000  # how far a head may move forward at once, plus what the time since allows
WITNESS_RECORDS_PER_S = 50_000  # more than a recorder can write
_MAX_FIRST_ASKED = 4096  # chains refused before their first entry, whose wait is remembered
# Thinning: (entries younger than this many seconds, how much of their time names the bucket, kept at each end).
_WITNESS_KEEP = ((600, 18, 2), (3600, 16, 2), (86400, 13, 2), (None, 10, 1))  # 10 seconds, minute, hour, day
_WITNESS_LOCKS = 64  # one chain's slow disk write holds up only the chains that share its lock
_RECORD_HASH = re.compile(r"sha256:[0-9a-f]{64}")
_UNAVAILABLE = "the signing key is not available right now, so nothing was signed"
_RECORD_DAMAGED = "the signer's record of this checkpoint is damaged, so it was not sent again"
_LOG_PENDING = "the checkpoint is signed but the signer could not write its log: send the identical request again"


def init_signer(directory: str | Path, alg: str = ED25519) -> LocalSigner:
    """Create a key, a token and an empty state in ``directory``."""
    directory = Path(directory)
    _refuse_a_used_folder(directory)
    directory.mkdir(parents=True, exist_ok=True)
    key = generate_private_key(alg)
    priv, _ = save_keypair(key, directory, "signer")
    restrict_to_owner(priv)
    _write_token(directory)
    return LocalSigner(key)


def init_token(directory: str | Path) -> Path:
    """Create only a token in ``directory``, for a service whose key is held elsewhere."""
    directory = Path(directory)
    _refuse_a_used_folder(directory)
    directory.mkdir(parents=True, exist_ok=True)
    return _write_token(directory)


def _refuse_a_used_folder(directory: Path) -> None:
    if (directory / "signer.key").exists() or (directory / "signer.token").exists():
        raise FileExistsError(f"{directory} already holds a signer")


def _write_token(directory: Path) -> Path:
    token = directory / "signer.token"
    fd = os.open(token, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="ascii") as fh:
        fh.write(secrets.token_hex(32) + "\n")
    restrict_to_owner(token)
    return token


def key_vault_signer(key_url: str, deadline: float = VAULT_START_DEADLINE_S) -> AzureKeyVaultSigner:
    """The Key Vault key at ``key_url``, for ``SignerService(signer=...)``. Azure's own credential chain signs in.
    The whole read is given up on at ``deadline`` seconds, whatever the Azure libraries do."""
    try:
        return _read_vault_key(key_url, deadline)
    except SignerError:
        raise
    except (ValueError, FileNotFoundError, PermissionError):  # the URL is checked first, so this is the certificate
        raise SignerError("Azure sign-in could not be set up: check AZURE_CLIENT_CERTIFICATE_PATH and the "
                          "certificate it names, which must hold an RSA private key") from None
    except Exception as exc:
        raise SignerError(f"could not read {key_url} from Key Vault: {_describe(exc)}") from None


def _read_vault_key(key_url: str, deadline: float) -> AzureKeyVaultSigner:
    """Read the key on a thread of its own and stop waiting at ``deadline``. An answer that comes later is dropped."""
    answer: dict[str, Any] = {}
    done = threading.Event()

    def read() -> None:
        try:
            answer["signer"] = AzureKeyVaultSigner(key_url, client_options=_VAULT_CLIENT_OPTIONS,
                                                   credential_options=_VAULT_CREDENTIAL_OPTIONS)
        except Exception as exc:
            answer["error"] = exc
        finally:
            done.set()

    _own_thread(read, "mnestiq-signer-key").start()
    if not done.wait(deadline):
        raise SignerError(f"Key Vault did not answer within {deadline:g} seconds while reading {key_url}: check the "
                          "vault's address, the network and the service's Azure sign-in")
    if "error" in answer:
        raise answer["error"]
    return answer["signer"]


@dataclass
class _ChainWitness:
    """What is known of one chain's witness log, read from disk once."""

    head_seq: int | None = None
    head_hash: str | None = None
    checkpoint_seq: int | None = None
    heads: int = 0
    checkpoints: int = 0
    thinned: int = 0
    torn: bool = False  # the last write may have stopped halfway: the piece is cut off before the next line
    since: float | None = None  # when the last entry was added
    tokens: float = WITNESS_HEAD_BURST
    filled_at: float = 0.0

    def take_token(self, now: float) -> bool:
        self.tokens = min(WITNESS_HEAD_BURST, self.tokens + max(0.0, now - self.filled_at) * WITNESS_HEADS_PER_S)
        self.filled_at = now
        if self.tokens < 1.0:
            return False
        self.tokens -= 1.0
        return True


class _WitnessRefused(SignerError):
    """A head that was not taken. The reply names the reason in a field of its own."""

    def __init__(self, reason: str, message: str) -> None:
        super().__init__(message)
        self.reason = reason


class SignerService:
    def __init__(self, directory: str | Path, max_skew: float = 300.0, allow_handover: bool = False,
                 signer: Signer | None = None, sign_deadline: float = VAULT_DEADLINE_S,
                 max_chains: int = DEFAULT_MAX_CHAINS) -> None:
        if not (math.isfinite(max_skew) and max_skew > 0):
            raise SignerError(f"max_skew must be a positive number of seconds, not {max_skew!r}")
        if not _is_int(max_chains) or max_chains < 1:
            raise SignerError(f"max_chains must be a whole number of at least 1, not {max_chains!r}")
        self.dir = Path(directory)
        self.max_chains = max_chains
        self.signer: Signer = signer if signer is not None else LocalSigner(load_private_key(self.dir / "signer.key"))
        self.key_id = key_id(self.signer.public_key)
        self.token = (self.dir / "signer.token").read_text("ascii").strip().encode("ascii")
        if len(self.token) < MIN_TOKEN_CHARS:
            raise SignerError(f"signer.token holds fewer than {MIN_TOKEN_CHARS} characters: replace it with a long "
                              "random value (see docs/signing.md)")
        self.max_skew = max_skew
        self.allow_handover = allow_handover
        self._deadline = None if signer is None else sign_deadline  # a key in this process cannot hang
        self._state_path = self.dir / "state.json"
        self._state: dict[str, dict[str, Any]] = (
            _checked_state(json.loads(self._state_path.read_text("utf-8"))) if self._state_path.exists() else {})
        self._refuse_another_keys_chains()
        self._lock = threading.Lock()  # the state and the log, held only briefly and never across a signature
        self._turns: dict[str, list[Any]] = {}  # per chain in use: its lock and how many requests want it
        self._vault_calls = threading.Semaphore(_VAULT_CALLS_AT_ONCE)
        self._witness_dir = self.dir / WITNESS_FOLDER
        self._witnessed: dict[str, _ChainWitness] = {}  # by file name, at most one per chain
        self._witness_locks = [threading.Lock() for _ in range(_WITNESS_LOCKS)]  # never held across a signature
        # Signing and heads have separate budgets of max_chains each, so cheap heads cannot use up signing's.
        self._chains = {witness_file_name(chain) for chain in self._state}  # signed, or being signed right now
        self._head_only: set[str] = set()  # known only from heads
        with contextlib.suppress(OSError):
            self._head_only.update(path.name for path in self._witness_dir.glob("*.jsonl")
                                   if path.name not in self._chains)
        self._first_asked: dict[str, float] = {}

    def _refuse_another_keys_chains(self) -> None:
        """A key is a folder: its chains cannot be continued by another key without a signed hand-over."""
        named = {entry["key_id"] for entry in self._state.values() if isinstance(entry.get("key_id"), str)}
        if self._state and not all("key_id" in entry for entry in self._state.values()):  # written before keys were
            with contextlib.suppress(OSError, ValueError):
                named.add(key_id((self.dir / "signer.pub").read_text("ascii").strip()))
        others = named - {self.key_id}
        if others:
            raise SignerError(f"{self.dir} holds chains signed by {', '.join(sorted(others))}, not {self.key_id}: "
                              "use a new folder for a new key (see docs/signing.md)")

    def handle(self, request: Any) -> dict[str, Any]:
        """Answer one request. Refusals come back as ``{"error": ...}``."""
        if not isinstance(request, dict):
            return {"error": "a request is a JSON object"}
        if request.get("op") == "public_key":
            return {"sig_alg": self.signer.sig_alg, "public_key": self.signer.public_key, "key_id": self.key_id}
        if request.get("op") == "witness":
            return self._answer_witness(request)
        if request.get("op") not in ("sign", "repeat"):
            return {"error": f"unknown op {request.get('op')!r}"}
        try:
            payload = base64.b64decode(str(request.get("payload", "")), validate=True)
            leaves = request.get("leaves")
            if leaves is not None and not (isinstance(leaves, list) and all(isinstance(x, str) for x in leaves)):
                raise SignerError("leaves is a list of record hashes")
            signature = self.sign(payload, leaves, repeat_only=request.get("op") == "repeat")
            return {"signature": base64.b64encode(signature).decode("ascii")}
        except (SignerError, ValueError) as exc:
            _log.warning("mnestiq signer: refused: %s", exc)
            return {"error": str(exc)}
        except RecursionError:
            return {"error": "the request is nested too deep to read"}
        except OSError as exc:  # its log or state could not be written: nothing is signed without them
            _log.error("mnestiq signer: could not write its records: %r", exc)
            return {"error": "the signer could not write its log or state, so it did not sign"}

    def sign(self, payload: bytes, leaves: list[str] | None = None, repeat_only: bool = False) -> bytes:
        """``repeat_only`` gives back a signature already given for exactly this payload, and never makes one."""
        try:
            cp = parse_json(payload)
        except (ValueError, RecursionError):
            raise SignerError("the payload is not JSON") from None
        if not isinstance(cp, dict) or cp.get("kind") != "checkpoint":
            raise SignerError("only checkpoint records are signed")
        if canonical_json(cp) != payload:
            raise SignerError("the payload is not in canonical form")
        if (cp.get("sig_alg"), cp.get("public_key"), cp.get("key_id")) != (
                self.signer.sig_alg, self.signer.public_key, self.key_id):
            raise SignerError(f"the checkpoint names another key; this signer is {self.key_id}")
        # A pinned key trusts whatever it hands over to. Anyone holding the token could otherwise name their own
        # key and sign the rest of the chain with no further access, so this is the operator's decision.
        if "next_key" in cp and not self.allow_handover:
            raise SignerError("this signer does not hand a chain over to another key: start it with --allow-handover")
        chain, seq, covers = cp.get("chain_id"), cp.get("seq"), cp.get("covers")
        if not isinstance(chain, str) or not _is_int(seq) or not isinstance(covers, dict):
            raise SignerError("the checkpoint has no chain_id, seq or covers")
        first, last_covered = covers.get("from_seq"), covers.get("to_seq")
        # A checkpoint covers the records just before it. The state below is this seq, so it must
        # follow from the range, or a client could move the state back and have history signed again.
        if not (_is_int(first) and _is_int(last_covered) and 0 <= first <= last_covered and seq == last_covered + 1):
            raise SignerError(f"the checkpoint at seq {seq!r} does not cover the records just before it "
                              f"({first!r}..{last_covered!r})")
        # One request could otherwise claim every position up to the largest integer and end the chain.
        if last_covered - first >= MAX_COVERED:
            raise SignerError(f"the checkpoint covers more than {MAX_COVERED} records")
        if len(chain) > MAX_CHAIN_ID:
            raise SignerError(f"the chain_id is longer than {MAX_CHAIN_ID} characters")
        covers = {"from_seq": first, "to_seq": last_covered}  # only this is kept, whatever else came with it
        ts = cp.get("ts")
        wall = _parse_wall(ts.get("wall") if isinstance(ts, dict) else None)
        root = cp.get("merkle_root")
        request = hashlib.sha256(payload).hexdigest()
        deadline = None if self._deadline is None else time.monotonic() + self._deadline
        with self._chain_turn(chain, deadline):
            last = self._state.get(chain)
            # The very same request again, after an answer was lost on the way back: it gets the answer already
            # given, which says nothing new. Anything else at this position would be a new statement about it.
            given = self._given_before(chain, last, seq, request, covers, root, payload)
            if given is not None and last is not None:
                encoded = base64.b64encode(given).decode("ascii")
                with self._resend_if_unlogged():
                    if not (last.get("unlogged") and self._finish_log(chain, {**last, "signature": encoded})):
                        self._log_signed(chain, {"seq": seq, "covers": covers, "merkle_root": root,
                                                 "signature": encoded}, repeat=True)
                self._witness_signed(chain, seq, covers, root, request)  # in case the first time could not write it
                return given
            if repeat_only:
                raise SignerError(f"chain {chain!r} was signed up to seq {last['seq'] if last else None}, and never "
                                  "for this exact request, so nothing is given back")
            self._check_clock(wall)  # here, not on arrival: the request may have waited its turn
            if not isinstance(root, str) or not _MERKLE_ROOT.fullmatch(root):
                raise SignerError("the checkpoint has no usable merkle_root")
            moves_on = last is None or first == last["seq"] + 1
            extends = last is not None and not moves_on and _extends(last, covers, root, leaves)
            if not (moves_on or extends):
                signed_to = last["seq"] if last is not None else None
                raise SignerError(f"chain {chain!r} was signed up to seq {signed_to}, and this checkpoint covers "
                                  f"from {first} (only the next checkpoint is signed)")
            if last is not None and last.get("unlogged"):  # an earlier line first, or the log would have a gap
                self._finish_log(chain, last)
            signature = self._key_signs(payload, deadline)
            self._check_clock(wall)  # and after a slow key store: a signature too late to use is dropped unsaved
            entry = {"seq": seq, "covers": covers, "merkle_root": root, "request": request, "key_id": self.key_id,
                     "signature": base64.b64encode(signature).decode("ascii"), "signed_at": _now(), "unlogged": True}
            with self._lock:  # on disk first: if it cannot be saved, nothing has moved and nothing is handed out
                state = {**self._state, chain: entry}
                write_durably(self._state_path, json.dumps(state, sort_keys=True))
                self._state = state
            with self._resend_if_unlogged():
                self._log_signed(chain, entry)
            self._mark_logged(chain, entry)
            self._witness_signed(chain, seq, covers, root, request)
        return signature

    def _answer_witness(self, request: dict) -> dict[str, Any]:
        try:
            chain, seq, record_hash = _checked_witness(request)
            self._witness_head(chain, seq, record_hash)
            return {"witnessed": seq}
        except _WitnessRefused as exc:
            _log.debug("mnestiq signer: witness refused: %s", exc)
            return {"error": str(exc), "refused": exc.reason}
        except SignerError as exc:
            _log.debug("mnestiq signer: witness refused: %s", exc)
            return {"error": str(exc)}
        except (OSError, ValueError) as exc:
            _log.error("mnestiq signer: could not write its witness log: %r", exc)
            return {"error": "the signer could not write its witness log"}

    def _witness_head(self, chain: str, seq: int, record_hash: str) -> None:
        """Note a recorder's newest head. Never touches the key. Each chain's heads only move forward."""
        name = witness_file_name(chain)
        with self._witness_lock(name):  # also over the count: two first requests of one chain go one at a time
            new = self._admit_head_only(name)
            try:
                log = self._witness_of(name, chain)
                if seq == log.head_seq and record_hash == log.head_hash:
                    return  # the same head again, after an answer was lost
                if log.head_seq is not None and seq <= log.head_seq:
                    raise _WitnessRefused("behind", f"chain {chain[:80]!r} was witnessed up to seq {log.head_seq}: "
                                                    f"seq {WITNESS_BEHIND}")
                now = time.time()
                # One request could otherwise claim a far position and leave every real head behind it.
                reached = max(log.head_seq if log.head_seq is not None else -1,
                              log.checkpoint_seq if log.checkpoint_seq is not None else -1)
                allowed = self._jump_allowed(name, log, now)
                if seq - reached > allowed:
                    raise _WitnessRefused("too_far", f"seq {seq} is too far ahead: at most {allowed} records past "
                                                     f"seq {reached} are allowed now")
                if not log.take_token(now):
                    raise _WitnessRefused("rate", "heads for this chain are coming too fast")
                self._witness_append(name, chain, log,
                                     {"at": _now(), "by": "head", "record_hash": record_hash, "seq": seq})
                log.head_seq, log.head_hash, log.since = seq, record_hash, now
            except (SignerError, OSError):
                self._release_head_only(name, new)
                raise

    def _jump_allowed(self, name: str, log: _ChainWitness, now: float) -> int:
        """How far a head may move forward now. A chain that is new here starts its clock at the first request, so
        a long chain's first head gets in after a short wait, and a false one stays bounded."""
        since = log.since
        if since is None:
            with self._lock:
                since = self._first_asked.setdefault(name, now)
                if len(self._first_asked) > _MAX_FIRST_ASKED:
                    del self._first_asked[next(iter(self._first_asked))]
        return min(MAX_COVERED, WITNESS_JUMP_FLOOR + int(max(0.0, now - since) * WITNESS_RECORDS_PER_S))

    def _witness_signed(self, chain: str, seq: int, covers: dict, root: Any, request: str) -> None:
        """Note a checkpoint this service signed, so a file cut back to an earlier one shows even if every send from
        the agent was lost. The record hash is not known here, since the signature and any timestamp are added to the
        record later. The digest of the signed request is what can be compared with the file."""
        name = witness_file_name(chain)
        try:
            with self._witness_lock(name):
                log = self._witness_of(name, chain)
                if log.checkpoint_seq is not None and seq <= log.checkpoint_seq:
                    return
                entry = {"at": _now(), "by": "checkpoint", "covers": covers, "merkle_root": root, "request": request,
                         "seq": seq}
                self._witness_append(name, chain, log, entry)
                log.checkpoint_seq, log.since = seq, time.time()
        except (SignerError, OSError, ValueError) as exc:  # the signature exists and is saved: this must not undo that
            _log.error("mnestiq signer: could not note checkpoint %s in the witness log: %r", seq, exc)

    def _witness_lock(self, name: str) -> threading.Lock:
        return self._witness_locks[int(name[:8], 16) % len(self._witness_locks)]

    def _witness_of(self, name: str, chain: str) -> _ChainWitness:
        """This chain's witness log so far. The caller holds its lock."""
        known = self._witnessed.get(name)
        if known is not None:
            return known
        path = self._witness_dir / name
        known = _ChainWitness()
        if path.exists():
            log = read_witness_log(path)
            if log.problem is not None or log.chain_id != chain:
                _log.error("mnestiq signer: the witness log of chain %r is damaged, so nothing is added to it",
                           chain[:80])
                raise SignerError("the witness log of this chain is damaged, so nothing was added to it")
            known = _ChainWitness(head_seq=next(reversed(log.heads), None),
                                  head_hash=log.heads[next(reversed(log.heads))] if log.heads else None,
                                  checkpoint_seq=next(reversed(log.checkpoints), None),
                                  heads=len(log.heads), checkpoints=len(log.checkpoints), thinned=log.thinned,
                                  torn=log.torn, since=_time_of(log.entries[-1]["at"]) if log.entries else None)
        self._witnessed[name] = known
        return known

    def _witness_append(self, name: str, chain: str, log: _ChainWitness, entry: dict[str, Any]) -> None:
        path = self._witness_dir / name
        if not path.exists():
            self._witness_dir.mkdir(parents=True, exist_ok=True)
            write_durably(path, _witness_header(chain, 0))
        elif log.heads >= MAX_WITNESS_HEADS or log.checkpoints >= MAX_WITNESS_CHECKPOINTS:
            self._thin_witness(path, chain, log)
        try:
            if log.torn:
                _cut_torn_tail(path)
            with open(path, "ab") as fh:
                fh.write(canonical_json(entry) + b"\n")
                fh.flush()
                os.fsync(fh.fileno())
        except OSError:
            log.torn = True
            raise
        log.torn = False
        if entry["by"] == "head":
            log.heads += 1
        else:
            log.checkpoints += 1

    def _thin_witness(self, path: Path, chain: str, log: _ChainWitness) -> None:
        """The only rewrite a log ever gets, so a client that sends without end cannot fill the disk. Each kind is
        thinned only when it is full itself, and by age, so a burst displaces only entries of its own moment."""
        read = read_witness_log(path)
        if read.problem is not None or read.chain_id != chain:
            raise SignerError("the witness log of this chain is damaged, so nothing was added to it")
        now = time.time()
        kept = _thinned_kind(read.entries, "head", MAX_WITNESS_HEADS, now)
        kept += _thinned_kind(read.entries, "checkpoint", MAX_WITNESS_CHECKPOINTS, now)
        place = {id(entry): i for i, entry in enumerate(read.entries)}
        kept.sort(key=lambda entry: place[id(entry)])
        thinned = log.thinned + len(read.entries) - len(kept)
        write_durably(path, _witness_header(chain, thinned) + "".join(
            canonical_json(entry).decode("utf-8") + "\n" for entry in kept))
        log.heads = sum(1 for entry in kept if entry["by"] == "head")
        log.checkpoints = len(kept) - log.heads
        log.thinned, log.torn = thinned, False

    def _admit_head_only(self, name: str) -> bool:
        """Count a chain the first time a head names it. True if it is new. The caller holds its witness lock."""
        with self._lock:
            if name in self._chains or name in self._head_only:
                return False
            if len(self._head_only) >= self.max_chains:
                raise SignerError(f"this signer already holds {len(self._head_only)} chains known only from heads, "
                                  "the most it keeps (--max-chains), so a new chain was refused")
            self._head_only.add(name)
            return True

    def _release_head_only(self, name: str, new: bool) -> None:
        """Give back the place of a chain whose first head came to nothing. The caller holds its witness lock."""
        if new and not (self._witness_dir / name).exists():
            with self._lock:
                self._head_only.discard(name)
                self._witnessed.pop(name, None)

    @contextlib.contextmanager
    def _resend_if_unlogged(self) -> Iterator[None]:
        """For a signature that already exists and is saved: saying it was not signed would be untrue."""
        try:
            yield
        except OSError as exc:
            _log.error("mnestiq signer: could not write its log: %r", exc)
            raise SignerError(_LOG_PENDING) from None

    @contextlib.contextmanager
    def _chain_turn(self, chain: str, deadline: float | None) -> Iterator[None]:
        """One request at a time per chain, so a slow vault holds up only the chain it is signing for."""
        name = witness_file_name(chain)
        with self._lock:  # a chain being signed holds its place until the last request for it has left
            if name not in self._chains and len(self._chains) >= self.max_chains:
                raise SignerError(f"this signer already holds {len(self._chains)} chains, the most it keeps "
                                  "(--max-chains), so a new chain was refused")
            self._chains.add(name)
            turn = self._turns.setdefault(chain, [threading.Lock(), 0])
            turn[1] += 1
        try:
            if not turn[0].acquire(timeout=-1 if deadline is None else max(0.0, deadline - time.monotonic())):
                raise SignerError(f"another request for chain {chain!r} is still being signed: send this one again")
            try:
                yield
            finally:
                turn[0].release()
        finally:
            with self._lock:
                turn[1] -= 1
                if not turn[1]:
                    del self._turns[chain]
                    if chain in self._state:
                        self._head_only.discard(name)
                    else:  # nothing was signed: it counts as what it was before
                        self._chains.discard(name)
                        if (self._witness_dir / name).exists():
                            self._head_only.add(name)

    def _check_clock(self, wall: datetime) -> None:
        skew = abs((datetime.now(timezone.utc) - wall).total_seconds())
        if skew > self.max_skew:
            raise SignerError(f"the checkpoint's time is {skew:.0f}s from this signer's clock "
                              f"(at most {self.max_skew:.0f}s)")

    def _given_before(self, chain: str, last: dict[str, Any] | None, seq: int, request: str, covers: dict[str, int],
                      root: Any, payload: bytes) -> bytes | None:
        """The signature already handed out for exactly ``payload``, or None if this request is no repeat of one.

        No second signature is made for a position: a P-256 signature differs on every call and the evidence
        holds only one. A signature that checks out against this payload proves the request is the same one."""
        if last is None or last["seq"] != seq:
            return None
        if "request" not in last and "signature" not in last:  # written before repeats had to be identical
            same = last.get("covers") == covers and last.get("merkle_root") == root
            return self._logged_signature(chain, seq, payload) if same else None
        if last.get("request") != request:
            return None
        stored = last.get("signature")
        if stored is None:
            logged = self._logged_signature(chain, seq, payload)
            if logged is None:
                _log.error("mnestiq signer: chain %r seq %s has no signature on record", chain, seq)
                raise SignerError(_RECORD_DAMAGED)
            return logged
        signature = self._valid_signature(stored, payload)
        if signature is None:
            _log.error("mnestiq signer: chain %r seq %s has a damaged signature on record", chain, seq)
            raise SignerError(_RECORD_DAMAGED)
        return signature

    def _valid_signature(self, encoded: Any, payload: bytes) -> bytes | None:
        try:
            if not isinstance(encoded, str):
                return None
            signature = base64.b64decode(encoded, validate=True)
            verify_signature(self.signer.sig_alg, self.signer.public_key, signature, payload)
        except (ValueError, InvalidSignature):
            return None
        return signature

    def _log_lines(self, chain: str, seq: int) -> Iterator[dict[str, Any]]:
        with contextlib.suppress(FileNotFoundError), open(self.dir / "signatures.jsonl", "rb") as fh:
            for line in fh:
                try:
                    entry = json.loads(line)
                except (ValueError, RecursionError):
                    continue  # a line cut short by a crash
                if isinstance(entry, dict) and entry.get("chain_id") == chain and entry.get("seq") == seq:
                    yield entry

    def _logged_signature(self, chain: str, seq: int, payload: bytes) -> bytes | None:
        for entry in self._log_lines(chain, seq):
            signature = self._valid_signature(entry.get("signature"), payload)
            if signature is not None:
                return signature
        return None

    def _finish_log(self, chain: str, last: dict[str, Any]) -> bool:
        """Write the log line a saved signature is still missing. True if this call wrote it."""
        if not isinstance(last.get("signature"), str):  # a damaged record: no line is better than a false one
            return False
        logged = any(e.get("signature") == last["signature"] for e in self._log_lines(chain, last["seq"]))
        if not logged:
            self._log_signed(chain, last)
        self._mark_logged(chain, last)
        return not logged

    def _mark_logged(self, chain: str, entry: dict[str, Any]) -> None:
        # In memory only. If the service stops before the next save, the log is read to see the line is there.
        with self._lock:
            self._state = {**self._state, chain: {k: v for k, v in entry.items() if k != "unlogged"}}

    def _log_signed(self, chain: str, entry: dict[str, Any], repeat: bool = False) -> None:
        line = {"signed_at": _now(), "chain_id": chain, "seq": entry["seq"], "covers": entry.get("covers"),
                "merkle_root": entry.get("merkle_root"), "key_id": self.key_id, "signature": entry.get("signature")}
        if repeat:
            line["repeat"] = True
        with self._lock:
            self._append_log(line)

    def _key_signs(self, payload: bytes, deadline: float | None = None) -> bytes:
        """A signature checked against the public key. On any failure nothing is logged and nothing moves."""
        try:
            signature = self.signer.sign(payload) if deadline is None else self._sign_by(payload, deadline)
            verify_signature(self.signer.sig_alg, self.signer.public_key, signature, payload)
        except Exception as exc:
            _log.error("mnestiq signer: the key did not sign: %s", _describe(exc))
            raise SignerError(_UNAVAILABLE) from None
        return signature

    def _sign_by(self, payload: bytes, deadline: float) -> bytes:
        """Ask the key store on a thread of its own, and stop waiting at ``deadline``. An answer that comes
        later is dropped: nothing was logged or saved for it, so the same request can simply be sent again."""
        if not self._vault_calls.acquire(timeout=max(0.0, deadline - time.monotonic())):
            raise TimeoutError("every call to the key store is in use")
        answer: dict[str, Any] = {}
        done = threading.Event()

        def call() -> None:
            try:
                answer["signature"] = self.signer.sign(payload)
            except Exception as exc:
                answer["error"] = exc
            finally:
                self._vault_calls.release()
                done.set()

        _own_thread(call, "mnestiq-signer-key").start()
        if not done.wait(max(0.0, deadline - time.monotonic())):
            raise TimeoutError("the key store did not answer in time")
        if "error" in answer:
            raise answer["error"]
        return answer["signature"]

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
        self._folder_lock = _lock_folder(service.dir)
        # The token is checked on each connection's own thread, not in accept(), so a client that
        # connects and says nothing cannot hold up everyone after it.
        try:
            # The default queue holds one connection. On Linux a burst past it is dropped with the client left waiting.
            self._listener = Listener(target, backlog=128)
        except BaseException:
            self._folder_lock.close()
            raise
        self._token = service.token
        bound = self._listener.address
        self.address = f"{bound[0]}:{bound[1]}" if isinstance(bound, tuple) else str(bound)
        self._closed = False
        self._thread = _own_thread(self._accept_loop, "mnestiq-signer")
        self._thread.start()

    def _accept_loop(self) -> None:
        while not self._closed:
            try:
                conn = self._listener.accept()
            except OSError:
                if self._closed:
                    return
                continue
            _own_thread(self._serve, "mnestiq-signer-client", conn).start()

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
                except (ValueError, RecursionError):
                    reply = {"error": "the request is not JSON"}
                try:
                    conn.send_bytes(json.dumps(reply).encode("utf-8"))
                except OSError:
                    return

    def close(self) -> None:
        self._closed = True
        self._listener.close()
        self._folder_lock.close()

    def wait(self) -> None:
        self._thread.join()


def _own_thread(target: Any, name: str, *args: Any) -> threading.Thread:
    thread = threading.Thread(target=target, name=name, args=args, daemon=True)
    thread.__dict__["_mnestiq_own"] = True  # the egress hooks leave the recorder's own threads alone
    return thread


def _lock_folder(directory: Path) -> Any:
    """Two services on one folder would each trust their own copy of the state. The lock lasts as long as
    the returned file stays open, and the operating system drops it if the process dies."""
    fh = open(directory / "signer.lock", "a+b")  # noqa: SIM115
    try:
        if sys.platform == "win32":
            import msvcrt

            fh.seek(0)
            msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl

            fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        fh.close()
        raise SignerError(f"another signer is already serving {directory}") from None
    return fh


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


def _checked_state(state: Any) -> dict[str, dict[str, Any]]:
    """The state as read from disk. A damaged one stops the service: it could not tell what it has signed."""
    if not isinstance(state, dict) or not all(isinstance(v, dict) and _is_int(v.get("seq")) for v in state.values()):
        raise SignerError("state.json is damaged: restore it from a backup, or the signer cannot go on")
    return state


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


def _thinned_kind(entries: list[dict], kind: str, cap: int, now: float) -> list[dict]:
    """The entries of one kind to keep. A kind under its cap stays whole. Otherwise each stretch of time keeps its
    first and last few, with coarser stretches for older entries. The newest entries are always among them."""
    mine = [entry for entry in entries if entry["by"] == kind]
    if len(mine) < cap:
        return mine
    tiers = [("" if age is None else _wall_at(now - age), width, ends) for age, width, ends in _WITNESS_KEEP]
    buckets: dict[str, tuple[list[dict], int]] = {}
    for entry in mine:
        width, ends = next((w, e) for cutoff, w, e in tiers if entry["at"] >= cutoff)
        buckets.setdefault(entry["at"][:width], ([], ends))[0].append(entry)
    kept: list[dict] = []
    for bucket, ends in buckets.values():
        kept += bucket if len(bucket) <= 2 * ends else bucket[:ends] + bucket[-ends:]
    # Only when the stretches alone do not fit: a chain so old that its days fill the log. The oldest go first.
    return kept if len(kept) < cap else kept[-max(1, cap * 3 // 4):]


def _wall_at(moment: float) -> str:
    return datetime.fromtimestamp(moment, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _time_of(wall: Any) -> float | None:
    try:
        return datetime.strptime(wall, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc).timestamp()
    except (ValueError, TypeError):
        return None


def _cut_torn_tail(path: Path) -> None:
    """Remove the piece a write left when it stopped halfway. It was never a whole entry."""
    with open(path, "r+b") as fh:
        fh.truncate(fh.read().rfind(b"\n") + 1)


def _witness_header(chain: str, thinned: int) -> str:
    header: dict[str, Any] = {"chain_id": chain, "kind": WITNESS_KIND, "version": WITNESS_VERSION}
    if thinned:
        header["thinned"] = thinned
    return canonical_json(header).decode("utf-8") + "\n"


def _checked_witness(request: dict) -> tuple[str, int, str]:
    """The fields of a witness request. Everything kept on disk is one of these, so its size is bounded here."""
    if set(request) - {"op", "chain_id", "seq", "record_hash"}:
        raise SignerError("a witness request holds only chain_id, seq and record_hash")
    chain, seq, record_hash = request.get("chain_id"), request.get("seq"), request.get("record_hash")
    if not isinstance(chain, str) or not chain or len(chain) > MAX_CHAIN_ID:
        raise SignerError(f"the chain_id must be text of at most {MAX_CHAIN_ID} characters")
    try:
        chain.encode("utf-8")
    except UnicodeEncodeError:
        raise SignerError("the chain_id is not valid text") from None
    if not _is_int(seq) or not 0 <= seq <= MAX_SAFE_INTEGER:
        raise SignerError("the seq must be a whole number that JSON can carry")
    if not isinstance(record_hash, str) or not _RECORD_HASH.fullmatch(record_hash):
        raise SignerError("the record_hash must be a sha256 digest")
    return chain, seq, record_hash


def _describe(exc: Exception) -> str:
    """A key store failure by kind only: its message can carry tenant and request details."""
    status = getattr(exc, "status_code", None)
    return type(exc).__name__ + (f" (HTTP {status})" if status else "")


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
