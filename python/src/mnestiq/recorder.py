"""The flight recorder: turns agent activity into a hash-chained, signed evidence log."""

from __future__ import annotations

import base64
import contextvars
import functools
import hashlib
import inspect
import logging
import os
import re
import threading
import time
import uuid
import warnings
import weakref
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from collections.abc import Callable, Iterable, Iterator

from cryptography.exceptions import InvalidSignature

from .canonical import MAX_SAFE_INTEGER, CanonicalizationError, canonical_json, parse_json
from .hashing import (
    GENESIS_HASH,
    REDACTABLE_FIELDS,
    SALT_SUFFIX,
    digest_bytes,
    new_salt,
    record_hash,
    salted_digest,
    signing_payload,
    value_digest,
)
from .identity import detect_sandbox_id
from .jsonable import exception_text, to_jsonable, valid_texts
from .keys import SIG_ALGS, PrivateKey, key_id, verify_signature
from .merkle import merkle_root
from .signers import Signer, SignerError, WitnessUnsupported, as_signer
from .sinks import FileSink, RecorderError, Sink, SinkError
from .timestamps import split_certificates
from .verify import (
    CLEAN_CLOSE_FIELD,
    CONTINUES_FIELD,
    EVENT_TYPES,
    RESTART_FIELD,
    UNCLEAN_RESUME_FIELD,
    ChainVerifier,
    plain_text,
    read_regular_file,
    recorder_claim,
    schema_problem,
)

SPEC_VERSION = "1.0"
_log = logging.getLogger("mnestiq")

SOURCES = frozenset(
    {"system", "user", "internal", "model", "tool_output", "retrieved_doc", "web", "agent_msg", "memory", "unknown"}
)

_MISSING = object()
_MAX_CONTEXTS = 10_000  # runs whose last model call is kept for context_delta
TIMESTAMP_RETRY_S = 300  # after a failed timestamp, checkpoints skip it this long
_current_run: contextvars.ContextVar[Run | None] = contextvars.ContextVar("mnestiq_run", default=None)
_carried_run: contextvars.ContextVar[Run | None] = contextvars.ContextVar("mnestiq_carried_run", default=None)
_before_close: list[Callable[[], None]] = []  # run by Recorder.close: writes that were left for a safe point


def current_run() -> Run | None:
    """The run active in this thread / async task, if any."""
    run = _current_run.get()
    if run is not None and run is _carried_run.get() and run.recorder._closed:
        # A thread the egress hooks carried this run into, and its recorder has closed since:
        # from here on it is a thread that was never given one.
        _current_run.set(None)
        _carried_run.set(None)
        return None
    return run


def now_ts() -> dict:
    ns = time.time_ns()
    dt = datetime.fromtimestamp(ns // 1_000_000_000, tz=timezone.utc)
    wall = dt.strftime("%Y-%m-%dT%H:%M:%S") + f".{(ns // 1000) % 1_000_000:06d}Z"
    return {"wall": wall, "mono_us": time.monotonic_ns() // 1000}


@dataclass
class Segment:
    """One piece of model context and the source it came from.

    Sources are recorded at capture time so later analysis can tell instructions
    from untrusted input.
    """

    source: str
    content: Any
    role: str | None = None
    name: str | None = None

    def __post_init__(self) -> None:
        if self.source not in SOURCES:
            raise ValueError(f"unknown source {self.source!r}; expected one of {sorted(SOURCES)}")

    def to_dict(self) -> dict:
        out: dict[str, Any] = {"source": self.source, "content": to_jsonable(self.content)}
        if self.role is not None:
            out["role"] = _text(self.role)
        if self.name is not None:
            out["name"] = _text(self.name)
        return out


SAME_ATTEMPT_S = 240  # a retry keeps its time for this long, inside the signing service's five minutes either way
MAX_EARLIER_TIMES = 8  # earlier tries at one range whose request can be sent again, the newest ones
_SCHEMA_WINDOW = 256  # records held back on resume for the schema check: past this they are checked as they come
WITNESS_INTERVAL_S = 0.25  # the most often a recorder tells a witness its newest head
WITNESS_MAX_PAUSE_S = 30.0  # the longest wait between tries while the service is not answering
WITNESS_CLOSE_WAIT_S = 2.0  # how long close() waits for the last send
_swap_file = os.replace
_TIMES_SUFFIX = ".checkpoint-times"  # beside the evidence file: the times of a checkpoint still being asked for
_MAX_TIMES_BYTES = 1 << 12
_TIMES_WALL = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z")


class _WitnessSender:
    """Tells a signing service the chain's newest record, on a thread of its own.

    ``note`` only swaps the newest head into a slot, so the agent is never held up and only the newest head is sent.
    The sender runs outside the chain's lock and fails open: a service that hangs costs this thread its time and
    nothing else. Records written after the last send that got through are not witnessed.

    Before each send the file is flushed to disk here, so the service never holds a head the file could lose in a
    power cut. It holds no reference to the Recorder, so a Recorder that is never closed can still be collected."""

    def __init__(self, send: Callable[[str, int, str], Any], sync: Callable[[], Any] | None = None) -> None:
        self.send = send
        self.refused = 0  # heads the service would not take
        self._sync = sync
        self._head: tuple[str, int, str] | None = None
        self._wake = threading.Event()
        self._closing = threading.Event()
        self._thread = threading.Thread(target=self._run, name="mnestiq-witness", daemon=True)
        self._thread.__dict__["_mnestiq_own"] = True  # the egress hooks leave the recorder's own threads alone
        self._thread.start()

    def note(self, chain_id: str, seq: int, head_hash: str) -> None:
        self._head = (chain_id, seq, head_hash)
        if not self._wake.is_set():
            self._wake.set()

    def stop(self) -> None:
        """Send what is newest once more, and end."""
        self._closing.set()
        self._wake.set()

    def finish(self, wait: float) -> None:
        """Give the last send up to ``wait`` seconds. It goes on in the background if the service is slow."""
        self.stop()
        if self._thread is not threading.current_thread():
            self._thread.join(wait)

    def _run(self) -> None:
        from .egress import suppress_egress

        sent: tuple[str, int, str] | None = None
        pause = WITNESS_INTERVAL_S
        failing = refused = False
        while True:
            self._wake.wait()
            self._wake.clear()
            closing = self._closing.is_set()
            head = self._head
            if head is not None and head != sent:
                try:
                    with suppress_egress():
                        if self._sync is not None:
                            self._sync()
                        noted = self.send(*head)
                except WitnessUnsupported:  # an older service: it is not asked again
                    _log.info("mnestiq: the signing service keeps no witness log, so no more heads are sent")
                    return
                except Exception as exc:  # a witness is a help, never a reason to disturb the agent
                    if not failing:
                        _log.warning("mnestiq: could not reach the witness, tries go on in the background: %r", exc)
                    failing, pause = True, min(pause * 2, WITNESS_MAX_PAUSE_S)
                else:
                    if noted is False:  # not sent: the next try is the newest head by then
                        self.refused += 1
                        if not refused:
                            _log.warning("mnestiq: the witness refused the head at seq %d. It may already hold a "
                                         "later one, which this recorder never sent. Check who holds the token",
                                         head[1])
                        refused, pause = True, min(pause * 2, WITNESS_MAX_PAUSE_S)
                    else:
                        sent, failing, refused, pause = head, False, False, WITNESS_INTERVAL_S
            if closing:
                return
            self._closing.wait(pause)
            if self._head != sent:
                self._wake.set()


class _RepeatOnly:
    """A signer for a restart: it hands back only what the service already signed, and never signs anything new.
    The first request is the one with a new time, which cannot be a repeat, so it is refused here."""

    can_extend = True

    def __init__(self, signer: Any) -> None:
        self._signer = signer
        self.sig_alg, self.public_key = signer.sig_alg, signer.public_key
        self._first = True

    def sign(self, payload: bytes, leaves: list[str] | None = None) -> bytes:
        if leaves is not None or self._first:
            self._first = False
            raise SignerError("this was signed up to a later point, or never: only an exact repeat is asked for here")
        return self._signer.repeat(payload)


def _sync_for_witness(sink: Sink) -> Callable[[], Any] | None:
    """What puts the records on disk before a head is sent. ``FileSink.sync`` holds the lock every append waits for,
    so a file is flushed through a handle of its own, and a slow disk costs the sender's thread and not the agent."""
    if not isinstance(sink, FileSink):
        return getattr(sink, "sync", None)
    path = sink.path

    def flush() -> None:
        fd = os.open(path, os.O_WRONLY | getattr(os, "O_BINARY", 0))
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    return flush


def _read_times(path: Path, chain_id: str, covers: tuple[int, int]) -> list[Any]:
    """The times kept for this exact range, oldest first. The file is not trusted: whatever is wrong with it means
    nothing is read from it, and a time from it only ever asks the service for an answer it already gave."""
    try:
        raw = read_regular_file(path, _MAX_TIMES_BYTES + 1)
        if len(raw) > _MAX_TIMES_BYTES:
            return []
        kept = parse_json(raw)
    except (OSError, ValueError, RecursionError):
        return []
    if (not isinstance(kept, dict) or kept.get("version") != 1 or kept.get("chain_id") != chain_id
            or kept.get("covers") != list(covers) or not isinstance(kept.get("times"), list)):
        return []
    return [t for t in kept["times"] if _is_a_time(t)][-(MAX_EARLIER_TIMES + 1):]


def _is_a_time(ts: Any) -> bool:
    return (isinstance(ts, dict) and ts.keys() == {"wall", "mono_us"} and isinstance(ts["wall"], str)
            and _TIMES_WALL.fullmatch(ts["wall"]) is not None and type(ts["mono_us"]) is int
            and 0 <= ts["mono_us"] <= MAX_SAFE_INTEGER)


def _checkpoint_events(wanted: Iterable[str] | str | bool | None) -> frozenset[str]:
    if not wanted:
        return frozenset()
    names = {"tool_call", "egress"} if wanted is True else {wanted} if isinstance(wanted, str) else set(wanted)
    unknown = names - EVENT_TYPES
    if unknown:
        raise ValueError(f"checkpoint_on names unknown event type(s) {sorted(map(str, unknown))}, "
                         f"expected any of {sorted(EVENT_TYPES)}")
    return frozenset(names)


class Recorder:
    """Writes evidence records to a sink.

    Thread-safe. If the sink already holds records (e.g. the process restarted),
    the recorder resumes that chain instead of starting a new one.

    Recording never breaks the agent unless you ask it to: by default a failed
    write (disk full, closed sink, unserializable value) is counted in
    ``failures``, logged on the ``mnestiq`` logger and warned about once, and the
    agent carries on. ``strict=True`` raises instead, for deployments where an
    unrecorded action is worse than a failed one.

    Opening a sink that already holds evidence is the exception, with or without ``strict``: if what
    it holds does not verify (an edited record or checkpoint, a broken chain, another chain's key),
    ``Recorder()`` raises ``RecorderError``, because carrying on would sign over a file that does
    not verify. Keep that file as evidence and start a new one. Every record gets every check
    except the schema, which is checked only from the last checkpoint on: what comes before it is
    covered by a signature that was checked.

    ``on_damaged="new_file"`` is the opt-in way past that refusal, so that write access to a file cannot stop a
    restart. With a ``FileSink``, a file that cannot be continued (it does not verify, or holds a chain of another
    key or another ``chain_id``) is renamed to ``<name>.damaged-<UTC time>`` and left unchanged, and a new chain with
    a new id starts at its path. A note names the old file and its digest, and ``verify`` warns about it. A file that
    cannot be renamed is still refused. Other sinks always refuse.

    Redactable values (prompts, tool arguments and results) larger than
    ``max_content_bytes`` are recorded as their hash only, and the record lists them
    under ``x-omitted``.

    ``on_checkpoint`` is called with every checkpoint after it is written. Pass a
    ``HeadFile`` to keep the latest checkpoint in a second place, so cutting the
    evidence file back to an earlier checkpoint is detected (``verify --head``).

    ``signer`` signs checkpoints (see ``mnestiq.signers``). In production it should keep the
    key out of the agent's reach: ``SignerClient`` or ``AzureKeyVaultSigner``. ``signing_key``
    is the same with a key held in this process. A remote signer is asked once per
    checkpoint, and if it fails the recorder carries on and tries again after
    ``retry_after`` seconds; records are never lost, only signed later.

    ``checkpoint_interval`` (seconds) makes the recorder speak up when the agent is quiet:
    if nothing was signed for that long, it writes a ``heartbeat`` event and signs it. A
    stopped recorder then shows as a gap in the file (``verify`` warns) and as a chain that
    went quiet wherever its checkpoints are sent.

    ``checkpoint_on`` (off by default) signs right after the given event types, such as ``("tool_call", "egress")``,
    or ``True`` for those two, so that the part of the file that rests on the hash chain alone stays as small as you
    want. It waits for ``retry_after`` like every other signing, and each one costs a round trip to the signer.

    A signer that can keep a witness (``SignerClient``) is told the newest record now and then, from a background
    thread and never at the agent's cost. ``mnestiq verify --witness`` then shows a file rewritten or cut back, as far
    as those sends reached. ``AzureKeyVaultSigner`` used directly has no witness.

    ``context_delta`` (on by default) keeps files small for long runs: a model call whose context
    starts with the previous call's context, as most do, records only the new segments and points
    back to that call (``context_base``). ``mnestiq.context.expand`` puts the full context back.

    ``agent_identity`` names the agent in a directory, for example its Microsoft Entra Agent ID:
    ``{"provider": "entra", "app_id": "<app id>", "object_id": "<object id>", "tenant_id": "<tenant>"}``.
    Every event carries it. Without it, ``MNESTIQ_ENTRA_AGENT_APP_ID``, ``MNESTIQ_ENTRA_AGENT_OBJECT_ID``,
    ``MNESTIQ_ENTRA_BLUEPRINT_ID`` and ``MNESTIQ_ENTRA_TENANT_ID`` fill it in.
    """

    def __init__(
        self,
        sink: Sink,
        *,
        agent_id: str,
        operator_id: str | None = None,
        sandbox_id: str | None = "auto",
        public_ip: str | None = None,
        signing_key: PrivateKey | None = None,
        signer: Signer | None = None,
        checkpoint_every: int = 100,
        timestamper: Callable[[bytes], bytes] | None = None,
        chain_id: str | None = None,
        strict: bool = False,
        max_content_bytes: int = 1_048_576,
        on_checkpoint: Callable[[dict], None] | None = None,
        retry_after: float = 30.0,
        checkpoint_interval: float | None = None,
        context_delta: bool = True,
        agent_identity: dict | None = None,
        on_damaged: str = "refuse",
        checkpoint_on: Iterable[str] | str | bool | None = None,
    ) -> None:
        if on_damaged not in ("refuse", "new_file"):
            raise ValueError('on_damaged must be "refuse" or "new_file"')
        if checkpoint_every < 1:
            raise ValueError("checkpoint_every must be >= 1")
        if checkpoint_interval is not None and checkpoint_interval <= 0:
            raise ValueError("checkpoint_interval must be > 0 seconds")
        if max_content_bytes < 0:
            raise ValueError("max_content_bytes must be >= 0")
        self.strict = strict
        self.max_content_bytes = max_content_bytes
        self.failures = 0
        self._warned = False
        self._warned_note = False
        self._closed = False
        self._sink = sink
        self.agent_id = agent_id
        self.operator_id = operator_id
        # "auto" detects container / pod / host, None omits it.
        self.sandbox_id = detect_sandbox_id() if sandbox_id == "auto" else sandbox_id
        # The NAT / gateway address the outside world sees. Not auto-detected: that
        # would mean the recorder making its own network calls.
        self.public_ip = public_ip or os.environ.get("MNESTIQ_PUBLIC_IP") or None
        self.agent_identity = agent_identity if agent_identity is not None else _identity_from_env()
        if self.agent_identity is not None:
            _check_identity(self.agent_identity)  # a bad one would make every event fail the schema
        self._context_delta = context_delta
        # run_id -> (seq of its last recorded model call, fingerprints of that call's full context)
        self._contexts: dict[str, tuple[int, list[bytes]]] = {}
        if signing_key is not None and signer is not None:
            raise ValueError("pass signing_key or signer, not both")
        self._signer: Signer | None = as_signer(signing_key) if signing_key is not None else signer
        self._checkpoint_on = _checkpoint_events(checkpoint_on)
        self._witness: _WitnessSender | None = None
        self._watch_signer()
        self._retry_after = retry_after
        self._attempt: tuple[tuple[int, int], float, Any] | None = None  # the last checkpoint tried: range, when, ts
        self._earlier_times: list[Any] = []  # the ts of earlier tries at that range, oldest first
        sink_path = getattr(sink, "path", None)
        self._times_path = Path(str(sink_path) + _TIMES_SUFFIX) if isinstance(sink_path, (str, os.PathLike)) else None
        self._times_kept = False  # whether that file may exist
        self._next_try = 0.0
        self._interval = checkpoint_interval
        self._last_signed = time.monotonic()
        self._stop = threading.Event()
        self._checkpoint_every = checkpoint_every
        self._timestamper = timestamper
        self._timestamp_next_try = 0.0
        self._on_checkpoint = on_checkpoint
        self._lock = threading.RLock()
        # While a checkpoint is being signed, an event written from the same thread (a hook seeing
        # the signer's or the timestamp authority's traffic, say) would take the checkpoint's place
        # in the chain. Such events wait here and are written right after the checkpoint.
        self._checkpointing = False
        self._deferred: list[dict] = []
        # Maps tool name -> provenance of its output, filled by @recorder.tool.
        self.tool_sources: dict[str, str] = {}

        continues_from: dict | None = None
        try:
            last, before_last, pending, chain_key = _read_chain(sink)
            if chain_key and self._signer is not None and key_id(self._signer.public_key) != chain_key:
                raise RecorderError(
                    f"this evidence file is signed by {chain_key}, not by the configured key "
                    f"{key_id(self._signer.public_key)}. Change keys with Recorder.rotate_signer, or use a new file")
            if (last is not None and chain_id is not None and chain_id != last["chain_id"]
                    and not (on_damaged == "new_file" and str(last["chain_id"]).startswith(_renewed(chain_id)))):
                raise ValueError(
                    f"sink already holds chain {last['chain_id']!r}; cannot write chain {chain_id!r} to it"
                )
        except (RecorderError, ValueError) as damage:
            if on_damaged != "new_file":
                raise
            if not isinstance(sink, FileSink):
                raise RecorderError(f"{damage} (on_damaged=\"new_file\" needs a FileSink)") from damage
            continues_from = _set_aside(sink, damage)
            last, before_last, pending, chain_key = None, None, [], None
        if last is not None:
            self.chain_id = last["chain_id"]
            self._seq = last["seq"] + 1
            self._prev = last["record_hash"]
        else:
            self.chain_id = chain_id or uuid.uuid4().hex
            if continues_from is not None:  # a signing service refuses a chain that goes back to its start
                self.chain_id = _renewed(chain_id) + uuid.uuid4().hex[:8] if chain_id else uuid.uuid4().hex
            self._seq = 0
            self._prev = GENESIS_HASH
        self._pending = pending
        self._pending_from = self._seq - len(pending)
        self._opened_at = self._seq  # with no record written since, a close has nothing new to say

        # Nothing here can tell whether those records were changed while the agent was down, and the next
        # checkpoint signs them: the chain says so first. No checkpoint is made until it has (_sign_checkpoint).
        self._inherited: dict | None = None
        if pending and self._signer is not None and not self._repeat_lost_checkpoint():
            self._inherited = {"first_seq": self._pending_from, "last_seq": self._seq - 1, "count": len(pending)}
            try:
                self._note_inherited()
            except Exception as exc:  # the agent still starts
                if strict:
                    raise
                self._record_failure(exc)

        # What this start found must reach the chain, or a later clean close would make it look clean. Like the note
        # above, it is tried again before anything is signed (_sign_checkpoint).
        self._owed: dict | None = None
        if continues_from is not None:
            self._owed = {"message": "started a new file because the one at this path could not be continued",
                          CONTINUES_FIELD: continues_from}
        elif not pending and self._signer is not None and (after := _no_clean_close(last, before_last)) is not None:
            # A crash right after a checkpoint looks just like records removed after it. The chain says so.
            self._owed = {"message": "resumed without a clean close, check this",
                          UNCLEAN_RESUME_FIELD: {"after_checkpoint_seq": after}}
        try:
            self._note_owed()
        except Exception as exc:  # the agent still starts
            if strict:
                raise
            self._record_failure(exc)

        recovered = getattr(sink, "recovered", None)
        if recovered:
            # Record the recovery in the chain. The torn bytes stay in the sidecar file.
            try:
                self.append_event({
                    "event_type": "note", "run_id": f"recorder-{self.chain_id[:8]}", "agent_id": self.agent_id,
                    "sandbox_id": self.sandbox_id,
                    "attributes": {"message": "recovered from an interrupted write", **recovered},
                })
            except Exception as exc:  # a torn file often means a full disk: the agent still starts
                if strict:
                    raise
                self._record_failure(exc)
        if self._interval is not None:
            # A first beat now: it puts the interval in the evidence, so a recorder stopped before
            # its first quiet spell still shows as a silence.
            try:
                self.heartbeat()
            except Exception as exc:
                if strict:
                    raise
                self._record_failure(exc)
            beat = threading.Thread(target=self._heartbeats, name="mnestiq-heartbeat", daemon=True)
            beat.__dict__["_mnestiq_own"] = True  # the egress hooks leave the recorder's own threads alone
            beat.start()
        # A forked child shares this file and this chain's position: if it wrote too, the chain
        # would break. It records nothing until it makes its own Recorder.
        if hasattr(os, "register_at_fork"):
            me = weakref.ref(self)

            def in_child() -> None:
                recorder = me()
                if recorder is not None:
                    recorder._forked()

            os.register_at_fork(after_in_child=in_child)

    def _forked(self) -> None:
        self._closed = True
        self._stop.set()
        warnings.warn("mnestiq: this process was forked; the parent's Recorder records nothing here. "
                      "Make a new Recorder with its own file in the child.", RuntimeWarning, stacklevel=1)

    def _heartbeats(self) -> None:
        interval = float(self._interval or 0)
        while not self._stop.wait(min(interval, max(1.0, interval - (time.monotonic() - self._last_signed)))):
            if time.monotonic() - self._last_signed < interval:
                continue
            try:
                self.heartbeat()
            except Exception as exc:
                self._record_failure(exc)

    def heartbeat(self) -> dict | None:
        """Write a ``heartbeat`` event and sign everything pending. Called on a timer with
        ``checkpoint_interval``. Returns the checkpoint, or None without a signer."""
        with self._lock:
            if self._closed:
                return None
            self._last_signed = time.monotonic()  # also paces retries while a signer is down
            self._append({
                "event_type": "heartbeat", "run_id": f"recorder-{self.chain_id[:8]}", "agent_id": self.agent_id,
                "sandbox_id": self.sandbox_id,
                "attributes": {"interval_s": self._interval} if self._interval is not None else None,
            })
            if self._signer is None or time.monotonic() < self._next_try:
                return None
            try:
                return self.checkpoint()
            except Exception as exc:  # the beat is written; signing is tried again later
                if self.strict:
                    raise
                self._record_failure(exc)
                return None

    def _record_failure(self, exc: BaseException) -> None:
        self.failures += 1
        # Called from the handlers that keep failures away from the agent, so nothing here may raise:
        # warnings can be errors (python -W error), the stack can be nearly used up, a repr can fail.
        try:
            shown = repr(exc)
        except Exception:
            shown = f"<{type(exc).__name__}>"
        try:
            if isinstance(exc, _NoteNotWritten):  # events may well be written: it is the signing that waits
                _log.error("mnestiq: signing is waiting (%d failure(s) so far): %s", self.failures, shown)
                if not self._warned_note:
                    self._warned_note = True
                    warnings.warn(f"mnestiq: {exc}. No checkpoint is signed until it is written (further failures "
                                  f"are logged on the 'mnestiq' logger; see Recorder.failures)", RuntimeWarning,
                                  stacklevel=3)
                return
            _log.error("mnestiq: failed to record evidence (%d failure(s) so far): %s", self.failures, shown)
            if not self._warned:
                self._warned = True
                warnings.warn(f"mnestiq: evidence is not being recorded: {shown} (further failures are logged "
                              f"on the 'mnestiq' logger; see Recorder.failures)", RuntimeWarning, stacklevel=3)
        except Exception:
            pass

    def _write(self, record: dict) -> dict:
        record["record_hash"] = record_hash(record)
        problem = schema_problem(record, show_value=False)  # the failure is logged: never the agent's data
        if problem:
            raise RecorderError(f"record would not pass verification, not written: {problem}")
        from .egress import suppress_egress

        with suppress_egress():  # a sink's traffic is the recorder's own, and this runs under its lock
            self._sink.append(record)
        self._seq += 1
        self._prev = record["record_hash"]
        if self._witness is not None:  # a slot and a wake-up: the sender's thread does the rest
            self._witness.note(record["chain_id"], record["seq"], record["record_hash"])
        return record

    def _header(self, kind: str) -> dict:
        return {
            "spec_version": SPEC_VERSION,
            "kind": kind,
            "chain_id": self.chain_id,
            "seq": self._seq,
            "ts": now_ts(),
            "prev_hash": self._prev,
        }

    def append_event(self, body: dict) -> dict:
        """Append one event. ``body`` holds event fields (event_type, run_id, ...). Raises on failure."""
        with self._lock:
            record = self._append(body)
            due = len(self._pending) >= self._checkpoint_every or body.get("event_type") in self._checkpoint_on
            if self._signer is not None and due and time.monotonic() >= self._next_try:
                try:
                    self.checkpoint()
                except Exception as exc:  # the event is written; signing is tried again later
                    if self.strict:
                        raise
                    self._record_failure(exc)
            return record

    def _append(self, body: dict) -> dict:
        if self._closed:
            raise RecorderError("recorder is closed")
        if self._checkpointing:
            self._deferred.append(dict(body))
            return dict(body)
        record = self._header("event")
        record.update({k: v for k, v in body.items() if v is not None})
        v1 = _writes_v1()
        if not v1:
            record.pop("agent_identity", None)
        remember = (v1 and self._context_delta and record.get("event_type") == "llm_call"
                    and isinstance(record.get("context"), list))
        if remember:
            full = record["context"]
            prints = [hashlib.sha256(canonical_json(seg)).digest() for seg in full]
            known = self._contexts.get(record["run_id"])
            if known is not None:
                base_seq, base_prints = known
                same = 0
                while same < min(len(prints), len(base_prints)) and prints[same] == base_prints[same]:
                    same += 1
                if same:
                    record["context_base"] = {"seq": base_seq, "segments": same}
                    record["context"] = full[same:]
        self._hash_and_cap(record)
        self._write(record)
        self._pending.append(record["record_hash"])
        if remember:
            self._contexts.pop(record["run_id"], None)
            self._contexts[record["run_id"]] = (record["seq"], prints)
            if len(self._contexts) > _MAX_CONTEXTS:  # forget the run that went longest without a model call
                self._contexts.pop(next(iter(self._contexts)))
        elif record.get("event_type") == "run_end":
            self._contexts.pop(record["run_id"], None)
        return record

    def _hash_and_cap(self, record: dict) -> None:
        """Set ``<field>_hash`` for redactable values and drop values over the size cap."""
        # On copies: the caller's body is written again if this attempt fails, and must still hold its values.
        for key in ("context", "output", "tool_calls", "egress"):
            value = record.get(key)
            if isinstance(value, list):
                record[key] = [dict(obj) if isinstance(obj, dict) else obj for obj in value]
            elif isinstance(value, dict):
                record[key] = dict(value)
        self._cap_errors(record)
        omitted = []
        salted = _writes_v1()
        for container_key, field in REDACTABLE_FIELDS:
            container = record.get(container_key)
            objects = container if isinstance(container, list) else [container]
            for i, obj in enumerate(objects):
                if not isinstance(obj, dict) or field not in obj:
                    continue
                encoded = canonical_json(obj[field])
                if salted:
                    salt = new_salt()
                    obj[field + SALT_SUFFIX] = salt
                    obj[f"{field}_hash"] = salted_digest(salt, obj[field])
                else:
                    obj[f"{field}_hash"] = value_digest(obj[field])
                if len(encoded) > self.max_content_bytes:
                    # The salt stays: whoever holds the original can still check it against the digest,
                    # and a value this large can't be found by guessing.
                    del obj[field]
                    where = f"{container_key}[{i}]" if isinstance(container, list) else container_key
                    omitted.append(f"{where}.{field} ({len(encoded)} bytes)")
        if omitted:
            record["x-omitted"] = omitted

    def _cap_errors(self, record: dict) -> None:
        """Exception text can quote prompts and tool data, and ``error`` is not a redactable slot, so it
        takes the size cap too."""
        objects = [record, *record.get("tool_calls", []), *record.get("egress", [])]
        for obj in objects:
            if isinstance(obj, dict) and isinstance(obj.get("error"), str):
                obj["error"] = _capped_error(obj["error"], self.max_content_bytes)

    def checkpoint(self) -> dict | None:
        """Sign everything since the last checkpoint. No-op without a signer or new records."""
        with self._lock:
            if self._signer is None or not self._pending or self._closed or self._checkpointing:
                return None
            return self._sign_checkpoint(self._signer, None)

    def rotate_signer(self, new: Signer | PrivateKey, reason: str = "key rotation") -> dict:
        """Hand the chain over to a new key.

        Writes a note, then a checkpoint signed by the current key that names the new one
        (``next_key``). Verifiers accept the new key from there on, and only because the old
        key said so: a key change without this hand-over is reported as an error.
        """
        signer = as_signer(new)
        with self._lock:
            if self._closed:
                raise RecorderError("recorder is closed")
            if self._signer is None:
                raise RecorderError("this recorder has no signer to hand over from; pass signer= instead")
            self._append({
                "event_type": "note", "run_id": f"recorder-{self.chain_id[:8]}", "agent_id": self.agent_id,
                "sandbox_id": self.sandbox_id,
                "attributes": {"message": reason, "from_key": key_id(self._signer.public_key),
                               "to_key": key_id(signer.public_key)},
            })
            next_key = {"sig_alg": signer.sig_alg, "public_key": signer.public_key,
                        "key_id": key_id(signer.public_key)}
            record = self._sign_checkpoint(self._signer, next_key, retry=False)
            self._signer = signer
            self._watch_signer()
            return record

    def _watch_signer(self) -> None:
        """Tell a signer that keeps a witness log the newest head. One that does not is not asked."""
        send = getattr(self._signer, "witness", None)
        if not callable(send):
            if self._witness is not None:
                self._witness.stop()
            self._witness = None
        elif self._witness is not None:
            self._witness.send = send
        else:
            self._witness = _WitnessSender(send, _sync_for_witness(self._sink))
            weakref.finalize(self, self._witness.stop).atexit = False

    @property
    def witness_refused(self) -> int:
        """How many heads the signing service would not take. Above zero, someone else may be sending heads."""
        return self._witness.refused if self._witness is not None else 0

    def _keep_times(self) -> None:
        """Before a request goes out: if this process dies waiting for the answer, a restart can still ask for it."""
        if self._times_path is None or self._attempt is None:
            return
        kept = {"version": 1, "chain_id": self.chain_id, "covers": list(self._attempt[0]),
                "times": [*self._earlier_times, self._attempt[2]]}
        tmp = self._times_path.with_name(self._times_path.name + ".tmp")
        try:
            tmp.unlink(missing_ok=True)  # with O_EXCL below, a planted link is removed, never followed
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
            with open(fd, "wb") as fh:
                fh.write(canonical_json(kept))
            _swap_file(tmp, self._times_path)  # atomic, not flushed: a power cut can lose it, and then the note says so
            self._times_kept = True
        except (OSError, ValueError) as exc:  # only a help after a crash, and never a reason to stop signing
            _log.debug("mnestiq: could not keep the checkpoint's times: %r", exc)

    def _forget_times(self) -> None:
        if self._times_kept and self._times_path is not None:
            self._times_kept = False
            try:
                self._times_path.unlink(missing_ok=True)
            except OSError as exc:
                _log.debug("mnestiq: could not remove the checkpoint's times: %r", exc)

    def _repeat_lost_checkpoint(self) -> bool:
        """After a restart, ask the service for a signature it gave for exactly the records taken over, whose answer
        was lost. The service gives one only for the identical request, so a changed record gets nothing. True if
        that checkpoint is now written, which leaves nothing inherited to say."""
        if self._times_path is None or not os.path.lexists(self._times_path):
            return False
        self._times_kept = True
        covers = (self._pending_from, self._seq - 1)
        kept = _read_times(self._times_path, self.chain_id, covers)
        if not kept or not callable(getattr(self._signer, "repeat", None)):
            self._forget_times()
            return False
        self._attempt = (covers, time.monotonic() - SAME_ATTEMPT_S - 1, kept[-1])
        self._earlier_times = kept[:-1]
        self._owed = None  # set for real below, once this start has decided what it owes the chain
        try:
            self._sign_checkpoint(_RepeatOnly(self._signer), None, retry=False)
        except Exception as exc:  # most often it was never signed, and the note says so as for any restart
            _log.info("mnestiq: no earlier signature to take over after the restart: %r", exc)
            self._attempt, self._earlier_times = None, []
            self._forget_times()
            return False
        return True

    def _note(self, attributes: dict, event_type: str = "note") -> None:
        body = {"event_type": event_type, "run_id": f"recorder-{self.chain_id[:8]}",
                "agent_id": _text(self.agent_id) or _UNKNOWN, "sandbox_id": self.sandbox_id,
                "agent_identity": self.agent_identity, "attributes": attributes}
        try:
            self._append(body)
        except CanonicalizationError:  # a name that is not valid Unicode: keep the record, mend the text
            self._append(valid_texts(body))

    def _note_clean_close(self) -> None:
        """Say in the chain that this recorder stopped as intended, as the last record before its last checkpoint.
        A heartbeat, with no interval: readers take those for the recorder being alive, not for agent activity.
        A recorder with no signer has nothing to sign it with, and one that wrote nothing has nothing to add."""
        if self._checkpointing:
            return
        try:  # these go first, so that the clean-close beat is right before the checkpoint
            self._note_inherited()
            self._note_owed()
        except _NoteNotWritten:  # nothing can be signed, which the checkpoint attempt reports
            return
        if SPEC_VERSION != "0.1" and self._signer is not None and (self._pending or self._seq != self._opened_at):
            self._note({"message": "recorder closed normally", CLEAN_CLOSE_FIELD: True}, "heartbeat")

    def _note_owed(self) -> None:
        if self._owed is None:
            return
        try:
            self._note(self._owed)
        except Exception as exc:
            self._next_try = time.monotonic() + self._retry_after
            raise _NoteNotWritten(f"the note about how this recorder started could not be written: {exc!r}") from exc
        self._owed = None

    def _note_inherited(self) -> None:
        if self._inherited is None:
            return
        try:
            self._append({
                "event_type": "note", "run_id": f"recorder-{self.chain_id[:8]}",
                "agent_id": _text(self.agent_id) or _UNKNOWN,  # runs can name their own agent and leave this empty
                "sandbox_id": self.sandbox_id,
                "attributes": {"message": "resumed with records not yet signed", RESTART_FIELD: self._inherited},
            })
        except Exception as exc:
            self._next_try = time.monotonic() + self._retry_after
            raise _NoteNotWritten(f"the note naming the records taken over unsigned could not be written: {exc!r}"
                                  ) from exc
        self._inherited = None

    def _sign_checkpoint(self, signer: Signer, next_key: dict | None, retry: bool = True) -> dict:
        self._note_inherited()  # if it cannot be written this raises, and nothing is signed
        self._note_owed()  # and the same for this one
        self._checkpointing = True
        try:
            return self._make_checkpoint(signer, next_key, retry)
        finally:
            self._checkpointing = False
            deferred, self._deferred = self._deferred, []
            for body in deferred:
                self._append(body)

    def _signature_of_an_earlier_try(self, signer: Signer, record: dict) -> bytes | None:
        """The service already signed these records under an earlier time and its answer was lost: only that very
        request gets the signature back. Each kept time is asked for once, newest first, and anything but a
        refusal ends the search, so a signer in trouble is not waited on again and again."""
        for earlier in reversed(self._earlier_times):
            try:
                signature = signer.sign(signing_payload({**record, "ts": earlier}))
            except SignerError as exc:
                if "was signed up to" in str(exc) or "from this signer's clock" in str(exc):
                    continue
                raise
            record["ts"] = earlier
            if self._attempt is not None:  # if the write fails, the next try is this same request
                self._attempt = (self._attempt[0], time.monotonic(), earlier)
            self._earlier_times = [t for t in self._earlier_times if t is not earlier]
            return signature
        return None

    def _make_checkpoint(self, signer: Signer, next_key: dict | None, retry: bool) -> dict:
        # The signer's and the timestamp authority's traffic is the recorder's own, not the agent's.
        from .egress import suppress_egress

        record = self._header("checkpoint")
        # A signing service repeats only an identical request, so if its answer was lost a retry must not differ.
        attempt = (self._pending_from, self._seq - 1)
        now = time.monotonic()
        if self._attempt is not None and self._attempt[0] == attempt and now - self._attempt[1] < SAME_ATTEMPT_S:
            record["ts"] = self._attempt[2]
        else:
            previous = self._attempt
            kept = [*self._earlier_times, previous[2]] if previous is not None and previous[0] == attempt else []
            self._earlier_times = kept[-MAX_EARLIER_TIMES:]
            self._attempt = (attempt, now, record["ts"])
        if retry and getattr(signer, "can_extend", False):
            self._keep_times()
        record.update(
            {
                "covers": {"from_seq": self._pending_from, "to_seq": self._seq - 1},
                "merkle_root": "sha256:" + merkle_root([digest_bytes(h) for h in self._pending]).hex(),
                "sig_alg": signer.sig_alg,
                "key_id": key_id(signer.public_key),
                "public_key": signer.public_key,
            }
        )
        if next_key is not None:
            record["next_key"] = next_key
        payload = signing_payload(record)
        try:
            with suppress_egress():
                try:
                    signature = signer.sign(payload)
                except SignerError as exc:
                    # A checkpoint the service signed never reached the file: show it the records,
                    # so it can see the ones it signed are unchanged and sign them with the new ones.
                    if not (getattr(signer, "can_extend", False) and "was signed up to" in str(exc)):
                        raise
                    found = self._signature_of_an_earlier_try(signer, record)
                    if found is not None:
                        signature, payload = found, signing_payload(record)
                    else:
                        extending: Any = signer  # SignerClient takes the records' hashes too
                        signature = extending.sign(payload, leaves=list(self._pending))
            # A remote signer's answer is checked before it goes into the evidence.
            try:
                verify_signature(signer.sig_alg, signer.public_key, signature, payload)
            except InvalidSignature:
                raise RecorderError("the signer returned a signature that does not match its public key; "
                                    "checkpoint not written") from None
        except Exception:
            if retry:
                self._next_try = time.monotonic() + self._retry_after
            raise
        self._next_try = 0.0
        self._last_signed = time.monotonic()
        record["signature"] = base64.b64encode(signature).decode("ascii")
        if self._timestamper is not None and time.monotonic() >= self._timestamp_next_try:
            try:
                with suppress_egress():
                    token = self._timestamper(signature)
                split_certificates(token)  # what is not even a token would fail the file at verify
                record["timestamp_token"] = base64.b64encode(token).decode("ascii")
            except Exception as exc:  # write the checkpoint without a token
                # Every checkpoint waits for the authorities: after a failure, leave them alone a while.
                self._timestamp_next_try = time.monotonic() + TIMESTAMP_RETRY_S
                _log.warning("mnestiq: timestamping failed, checkpoint written without a token (next try in "
                             "%d s): %r", TIMESTAMP_RETRY_S, exc)
        self._write(record)
        self._forget_times()
        self._pending = []
        self._pending_from = self._seq
        if self._on_checkpoint is not None:  # e.g. HeadFile: a copy of the head kept elsewhere
            try:
                with suppress_egress():
                    sync = getattr(self._sink, "sync", None)
                    if sync is not None:  # after a power cut the head must not be ahead of the file
                        sync()
                    self._on_checkpoint(dict(record))
            except Exception as exc:
                if self.strict:
                    raise
                self._record_failure(exc)
        return record

    def close(self) -> None:
        """Write a clean-close heartbeat and a final checkpoint, and close the sink. Safe to call more than once."""
        for flush in _before_close:
            try:
                flush()
            except Exception as exc:
                self._record_failure(exc)
        self._stop.set()
        with self._lock:
            if self._closed:
                return
            try:
                try:
                    self._note_clean_close()
                except Exception as exc:  # the records are still worth signing without it
                    if self.strict:
                        raise
                    self._record_failure(exc)
                self.checkpoint()
            except Exception as exc:
                if self.strict:
                    raise
                self._record_failure(exc)
            finally:
                self._closed = True
                if self._witness is not None:
                    self._witness.stop()
                try:
                    self._sink.close()
                except Exception as exc:  # e.g. the disk is still full: the agent goes on
                    if self.strict:
                        raise
                    self._record_failure(exc)
        if self._witness is not None:  # outside the lock, and bounded
            self._witness.finish(WITNESS_CLOSE_WAIT_S)

    def __enter__(self) -> Recorder:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    @contextmanager
    def run(
        self,
        run_id: str | None = None,
        *,
        parent_run_id: Any = _MISSING,
        agent_id: str | None = None,
        operator_id: Any = _MISSING,
        effective_permissions: dict | None = None,
        attributes: dict | None = None,
    ) -> Iterator[Run]:
        """Scope a run. Nested runs record the enclosing run as their parent."""
        parent = current_run()
        run = Run(
            self,
            run_id=run_id or uuid.uuid4().hex,
            parent_run_id=(parent.run_id if parent and not parent.ended else None)
            if parent_run_id is _MISSING else parent_run_id,
            agent_id=agent_id or self.agent_id,
            operator_id=self.operator_id if operator_id is _MISSING else operator_id,
        )
        run.emit("run_start", effective_permissions=to_jsonable(effective_permissions),
                 attributes=to_jsonable(attributes))
        token = _current_run.set(run)
        try:
            yield run
        except BaseException as exc:
            run.emit("run_end", status="error", error=exception_text(exc))
            raise
        else:
            run.emit("run_end", status="ok")
        finally:
            _restore_run(token, parent)

    @contextmanager
    def ensure_run(self) -> Iterator[Run]:
        """Use the active run, or open a one-off run for a single call."""
        run = current_run()
        if run is not None and run.recorder is self:
            yield run
        else:
            with self.run() as run:
                yield run

    def tool(self, name: str | None = None, *, source: str = "tool_output", sensitive: bool | None = None) -> Callable:
        """Decorator: record every call of a tool function, with its output's provenance.

        ``sensitive=True`` marks a tool whose effect matters on its own (credentials,
        permissions, deletion, payments) for finding MNQ-004. ``False`` opts a tool out of
        the name-based guess. Unset, the finding guesses from the tool's name.

        >>> @recorder.tool(source="web")
        ... def fetch_page(url: str) -> str: ...
        """
        if source not in SOURCES:
            raise ValueError(f"unknown source {source!r}")
        marks = None if sensitive is None else {"sensitive": sensitive}

        def decorate(fn: Callable) -> Callable:
            tool_name = str(name or getattr(fn, "__name__", type(fn).__name__))  # a partial or callable object has none
            self.tool_sources[tool_name] = source
            try:
                sig: inspect.Signature | None = inspect.signature(fn)
            except (ValueError, TypeError):  # builtins may publish no signature
                sig = None

            params = list(sig.parameters) if sig is not None else []
            # On a method, self (or cls) is the object, with whatever it holds (clients, keys):
            # not an argument the model chose.
            bound_to = params[0] if params and params[0] in ("self", "cls") else None

            def arguments(args: tuple, kwargs: dict) -> dict:
                try:
                    if sig is None:
                        raise TypeError("no signature")
                    found = dict(sig.bind(*args, **kwargs).arguments)
                except TypeError:
                    return {"args": list(args[1:] if bound_to else args), "kwargs": kwargs}
                if bound_to:
                    found.pop(bound_to, None)
                return found

            if inspect.iscoroutinefunction(fn):

                @functools.wraps(fn)
                async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                    with self.ensure_run() as run:
                        start = time.perf_counter()
                        try:
                            result = await fn(*args, **kwargs)
                        except BaseException as exc:  # cancelled too: the tool may have acted already
                            run.tool_call(tool_name, arguments(args, kwargs), error=exception_text(exc),
                                          result_source=source, latency_ms=_ms_since(start), attributes=marks)
                            raise
                        run.tool_call(tool_name, arguments(args, kwargs), result,
                                      result_source=source, latency_ms=_ms_since(start), attributes=marks)
                        return result

                return async_wrapper

            @functools.wraps(fn)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                with self.ensure_run() as run:
                    start = time.perf_counter()
                    try:
                        result = fn(*args, **kwargs)
                    except BaseException as exc:  # cancelled too: the tool may have acted already
                        run.tool_call(tool_name, arguments(args, kwargs), error=exception_text(exc),
                                      result_source=source, latency_ms=_ms_since(start), attributes=marks)
                        raise
                    run.tool_call(tool_name, arguments(args, kwargs), result,
                                  result_source=source, latency_ms=_ms_since(start), attributes=marks)
                    return result

            return wrapper

        return decorate


def _ms_since(start: float) -> int:
    return int((time.perf_counter() - start) * 1000)


def _restore_run(token: contextvars.Token, previous: Run | None) -> None:
    """Put back the run that was active before. A stream may be finished in another task than the one
    that opened it (a web framework streaming the answer), where the token cannot be used: there,
    setting the previous run back does the same, and the agent never sees an error."""
    try:
        _current_run.reset(token)
    except ValueError:
        _current_run.set(previous)


_HASH_CHECKS = frozenset({"link", "record_hash", "content_hash", "salt"})
_REFUSED = "It will not be signed: keep this file as evidence and start a new one"
_MAX_REASON = 200  # characters of why a file failed that its replacement's first note repeats


class _NoteNotWritten(RecorderError):
    """The note about records taken over unsigned could not be written, so nothing can be signed yet."""


def _read_chain(sink: Sink) -> tuple[dict | None, dict | None, list[str], str | None]:
    """Check everything a sink already holds. Returns its last record, the record before that, the hashes of the
    records after the last checkpoint, and the key the chain expects next. Raises ``RecorderError`` if it is damaged."""
    last: dict | None = None
    before_last: dict | None = None
    pending: list[str] = []
    chain_key: str | None = None  # the key the chain expects next, from its last checkpoint
    # The next checkpoint signs the records after the last one: it must not vouch for a record someone
    # changed while the agent was down, so what is taken over gets every check verify makes. Timestamp
    # tokens are the exception: their roots are the verifier's to choose, so none are given here.
    # The schema is most of the time this takes, and a signature that checks already covers what it signed.
    checker = ChainVerifier(tsa_roots=[], schema=False)
    unsealed: list[dict] = []  # the last checkpoint whose signature can be checked, and the records after it
    for rec in sink.existing():
        if not isinstance(rec, dict) or not {"chain_id", "seq", "record_hash"} <= rec.keys():
            raise RecorderError("the sink already holds data that is not Mnestiq evidence, use a new file")
        _refuse_damage(checker, rec)
        if rec.get("kind") != "checkpoint":
            pending.append(rec["record_hash"])
        else:
            pending = []
            handed_to = rec.get("next_key")
            chain_key = (handed_to.get("key_id") if isinstance(handed_to, dict) else None) or rec.get("key_id")
            if rec.get("sig_alg") in SIG_ALGS:
                unsealed = []
        unsealed.append(rec)
        if len(unsealed) >= _SCHEMA_WINDOW:
            _refuse_bad_schema(unsealed)
            unsealed = []
        before_last, last = last, rec
    _refuse_bad_schema(unsealed)
    if checker.unverified_tail:  # what no check here can vouch for must not be counted as signed
        raise RecorderError(f"the last {checker.unverified_tail} record(s) rest on a checkpoint this version cannot "
                            f"check. {_REFUSED}")
    return last, before_last, pending, chain_key


def _no_clean_close(last: dict | None, before_last: dict | None) -> int | None:
    """The seq of the last checkpoint, if no clean-close heartbeat is right before it. None if it closed cleanly.
    A chain from an older recorder never has that beat, so its first resume here says so too. The verifier's warning
    names that case. Nothing in such a file tells it from a new one that crashed."""
    if last is None or last.get("kind") != "checkpoint":
        return None
    closed = before_last is not None and recorder_claim(before_last, CLEAN_CLOSE_FIELD, "heartbeat") is True
    return None if closed else last["seq"]


def _set_aside(sink: FileSink, damage: Exception) -> dict:
    """Rename a damaged file out of the way and open a new one at its path. The old file is never changed. Returns
    what the new chain's first note says about it. Raises ``RecorderError``, with the file left in place, if the
    file cannot be renamed. On Windows a file another process holds open cannot, so two recorders can't both win."""
    path = sink.path
    aside: Path | None = None
    try:
        digest = _file_digest(path)  # before the rename, while this sink still holds the lock
        aside = _reserve_aside_name(path)
        if os.name == "nt":  # Windows cannot rename a file that is open, even by this process
            sink.close()
        os.replace(path, aside)
    except OSError as exc:
        if aside is not None:
            with suppress(OSError):
                os.unlink(aside)  # only ever the empty name reserved above: the rename did not happen
        sink.close()
        raise RecorderError(f"{path.name} cannot be continued and could not be moved aside ({type(exc).__name__}). "
                            "It is left where it was. If another program has it open, close that and try again"
                            ) from exc
    earlier = sink.recovered
    sink.close()
    FileSink.__init__(sink, path, fsync=sink._fsync)  # the path is free: the caller's sink becomes the new file
    if os.fstat(sink._fh.fileno()).st_size:  # between the rename and this open, another recorder started a file here
        sink.close()
        raise RecorderError(f"{path.name} was moved aside, and another recorder has since started a file at this path")
    told = {"file": aside.name.encode("utf-8", "replace").decode("utf-8"), "sha256": digest,
            "reason": _damage_reason(damage)}
    return {**told, "torn_tail": earlier} if earlier else told


def _renewed(chain_id: str) -> str:
    """How the id of a chain started in place of ``chain_id`` begins. The next restart knows it by this."""
    return f"{chain_id[:119]}-"


def _reserve_aside_name(path: Path) -> Path:
    """An empty new file with a name no other file has. A rename onto it overwrites nothing else."""
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    for n in range(1000):
        aside = path.with_name(f"{path.name}.damaged-{stamp}" + (f"-{n}" if n else ""))
        try:
            os.close(os.open(aside, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600))
        except FileExistsError:
            continue
        return aside
    raise FileExistsError(f"{path.name}: no free .damaged name")


def _file_digest(path: Path) -> str:
    """The SHA-256 of a file, read a piece at a time so that a large one stays out of memory."""
    hasher = hashlib.sha256()
    with open(path, "rb") as fh:
        while chunk := fh.read(1 << 20):
            hasher.update(chunk)
    return "sha256:" + hasher.hexdigest()


def _damage_reason(damage: Exception) -> str:
    """Why a file failed, for the next chain's first note: this code's own words, plain text, short."""
    text = "a line is not valid JSON" if isinstance(damage, SinkError) else str(damage).replace(_REFUSED, "").strip()
    return plain_text(text, _MAX_REASON)


def _refuse_bad_schema(records: list[dict]) -> None:
    """Raise ``RecorderError`` for the first of ``records`` that breaks the schema."""
    for record in records:
        if schema_problem(record, show_value=False):  # by code only: this message goes to the agent's logs
            raise RecorderError(f"record {record.get('seq')!r} failed verification (schema). {_REFUSED}")


def _refuse_damage(checker: ChainVerifier, record: dict) -> None:
    """Raise ``RecorderError`` if ``record`` is not what a recorder would have written next in this chain."""
    seq = record.get("seq")
    keep = _REFUSED
    seen = len(checker.report.errors)
    checker.feed_parsed(record)
    codes = {issue.code for issue in checker.report.errors[seen:]} - {"timestamp"}
    if "canonical" in codes:  # a record with no canonical form can only have been put there by hand
        raise RecorderError(f"record {seq!r} cannot be read as a record of this chain. {keep}")
    if codes & _HASH_CHECKS:
        raise RecorderError(f"record {seq!r} does not match its hash chain, so it was changed after it was written. "
                            f"{keep}")
    if codes:  # by code: a verifier's message can quote the record, and this one goes to the agent's logs
        raise RecorderError(f"record {seq!r} failed verification ({', '.join(sorted(codes))}). {keep}")


def _fail_open(method: Callable[..., Any]) -> Callable[..., Any]:
    """Recording an event never raises into the agent (unless strict): turning the agent's own
    objects into JSON happens before ``emit``, so it is guarded here as well."""
    @functools.wraps(method)
    def guarded(self: Run, /, *args: Any, **kwargs: Any) -> Any:
        try:
            return method(self, *args, **kwargs)
        except Exception as exc:
            if self.recorder.strict:
                raise
            self.recorder._record_failure(exc)
            return None
    return guarded


class Run:
    """One agent run. Every event it emits carries its identity."""

    def __init__(self, recorder: Recorder, *, run_id: str, parent_run_id: str | None,
                 agent_id: str, operator_id: str | None) -> None:
        self.recorder = recorder
        self.run_id = run_id
        self.parent_run_id = parent_run_id
        self.agent_id = agent_id
        self.operator_id = operator_id
        self._step = 0
        self.ended = False

    def bind(self, fn: Callable) -> Callable:
        """Wrap ``fn`` so it runs inside this run, e.g. in a worker thread.

        Threads don't inherit the active run (contextvars), so without this their
        tool calls and network traffic would not be attributed::

            pool.submit(run.bind(fetch_page), url)
        """
        @functools.wraps(fn)
        def bound(*args: Any, **kwargs: Any) -> Any:
            token = _current_run.set(self)
            try:
                return fn(*args, **kwargs)
            finally:
                _current_run.reset(token)

        return bound

    def emit(self, event_type: str, **fields: Any) -> dict | None:
        """Record an event. Returns the record, or None if recording failed (non-strict)."""
        body: dict[str, Any] = {
            "event_type": event_type,
            "run_id": self.run_id,
            "parent_run_id": self.parent_run_id,
            "agent_id": self.agent_id,
            "operator_id": self.operator_id,
            "sandbox_id": self.recorder.sandbox_id,
            "agent_identity": self.recorder.agent_identity,
        }
        body.update(fields)
        try:
            with self.recorder._lock:  # under the chain's lock, so steps run in the order of the records
                body["step_id"] = self._step
                self._step += 1
                if self.ended:  # a thread of this run, still working after it finished
                    extra = body.get("attributes")
                    body["attributes"] = {**(extra if isinstance(extra, dict) else {}), "after_run_end": True}
                elif event_type == "run_end":
                    self.ended = True
                try:
                    return self.recorder.append_event(body)
                except CanonicalizationError:  # text that is not valid Unicode: keep the event, mend the text
                    return self.recorder.append_event(valid_texts(body))
        except Exception as exc:
            if self.recorder.strict:
                raise
            self.recorder._record_failure(exc)
            return None

    @_fail_open
    def llm_call(
        self,
        *,
        provider: str,
        model: str,
        context: list[Segment | dict],
        output: Any = _MISSING,
        response_model: str | None = None,
        stop_reason: str | None = None,
        response_id: str | None = None,
        tool_calls: list[dict] | None = None,
        usage: dict | None = None,
        params: dict | None = None,
        system_prompt: Any = None,
        latency_ms: int | None = None,
        error: str | None = None,
        attributes: dict | None = None,
    ) -> dict | None:
        error = _text(error)
        model_info: dict[str, Any] = {"provider": _text(provider) or _UNKNOWN, "name": _text(model) or _UNKNOWN}
        if response_model is not None:
            model_info["version"] = _text(response_model)
        if params:
            model_info["params"] = to_jsonable(params)
        out = None
        if output is not _MISSING:
            out = {"content": to_jsonable(output), "stop_reason": _text(stop_reason), "response_id": _text(response_id)}
            out = {k: v for k, v in out.items() if v is not None or k == "content"}
        return self.emit(
            "llm_call",
            model=model_info,
            system_prompt_hash=value_digest(to_jsonable(system_prompt)) if system_prompt is not None else None,
            context=[s.to_dict() if isinstance(s, Segment) else Segment(**s).to_dict() for s in context],
            output=out,
            tool_calls=[_tool_call_dict(tc) for tc in tool_calls] if tool_calls else None,
            usage=_counts(usage),
            latency_ms=latency_ms,
            status="error" if error else "ok",
            error=error,
            attributes=to_jsonable(attributes),
        )

    @_fail_open
    def tool_call(
        self,
        name: str,
        arguments: Any,
        result: Any = _MISSING,
        *,
        call_id: str | None = None,
        result_source: str = "tool_output",
        error: str | None = None,
        latency_ms: int | None = None,
        attributes: dict | None = None,
    ) -> dict | None:
        error = _text(error)
        call: dict[str, Any] = {"id": call_id, "name": name, "arguments": arguments,
                                "result_source": result_source, "error": error, "latency_ms": latency_ms}
        if result is not _MISSING:
            call["result"] = result
        return self.emit(
            "tool_call",
            tool_calls=[_tool_call_dict(call)],
            status="error" if error else "ok",
            error=error,
            attributes=to_jsonable(attributes),
        )

    @_fail_open
    def approval(self, action: str, decision: str, approver: str, *,
                 approver_type: str = "human", reason: str | None = None) -> dict | None:
        entry = {"action": action, "decision": decision, "approver": approver, "approver_type": approver_type}
        if reason:
            entry["reason"] = reason
        return self.emit("approval", approvals=[entry])

    @_fail_open
    def egress(self, entry: dict, *, latency_ms: int | None = None, error: str | None = None) -> dict | None:
        """Record one outbound request or connection. Usually called by mnestiq.egress."""
        return self.emit(
            "egress",
            egress=[{k: v for k, v in entry.items() if v is not None}],
            latency_ms=latency_ms,
            status="error" if error else "ok",
            error=error,
        )

    @_fail_open
    def note(self, /, message: str, **attributes: Any) -> dict | None:
        return self.emit("note", attributes=to_jsonable({"message": message, **attributes}))


_UNKNOWN = "<unknown>"  # for a name the schema requires and the caller or the SDK did not give


def _text(value: Any) -> str | None:
    """A value the schema wants as text. SDK responses can hold anything here, and one odd id must not cost
    the record of the call."""
    return value if value is None or isinstance(value, str) else str(to_jsonable(value))


def _counts(usage: Any) -> dict | None:
    """The token counts in ``usage`` that the schema can hold."""
    if not isinstance(usage, dict):
        return None
    return {k: v for k, v in usage.items()
            if isinstance(v, int) and not isinstance(v, bool) and abs(v) <= MAX_SAFE_INTEGER} or None


_TRUNCATED = " <truncated>"


def _capped_error(text: str, limit: int) -> str:
    """``text``, at most ``limit`` bytes, keeping the exception's type name. With no room for a message,
    the type name alone."""
    encoded = text.encode("utf-8", "surrogatepass")
    if len(encoded) <= limit:
        return text
    head, sep, _ = text.partition(": ")
    prefix = head + sep if sep and head.isidentifier() else ""
    room = limit - len(prefix.encode("utf-8", "surrogatepass")) - len(_TRUNCATED)
    if room <= 0:
        return head if prefix else "<omitted>"
    kept = encoded[len(prefix.encode("utf-8", "surrogatepass")):][:room].decode("utf-8", "ignore")
    return prefix + kept + _TRUNCATED


def _tool_call_dict(tc: dict) -> dict:
    out = {k: v for k, v in tc.items() if v is not None and k not in ("arguments", "result")}
    out["name"] = _text(out.get("name")) or _UNKNOWN
    if "id" in out:
        out["id"] = _text(out["id"])
    if "error" in out:
        out["error"] = _text(out["error"])
    if "arguments" in tc:
        out["arguments"] = to_jsonable(tc["arguments"])
    if "result" in tc:
        out["result"] = to_jsonable(tc["result"])
    return out


_IDENTITY_FIELDS = frozenset({"provider", "id", "app_id", "object_id", "blueprint_id", "tenant_id", "name"})


def _check_identity(identity: Any) -> None:
    if not isinstance(identity, dict):
        raise ValueError("agent_identity must be a dict")
    unknown = sorted(set(identity) - _IDENTITY_FIELDS)
    if unknown:
        raise ValueError(f"agent_identity has unknown field(s) {', '.join(unknown)}; "
                         f"expected {', '.join(sorted(_IDENTITY_FIELDS))}")
    if not isinstance(identity.get("provider"), str) or not identity["provider"]:
        raise ValueError("agent_identity needs a provider, such as \"entra\"")
    if not any(isinstance(identity.get(k), str) and identity[k] for k in ("id", "app_id", "object_id")):
        raise ValueError("agent_identity needs at least one of id, app_id or object_id")
    if not all(isinstance(v, str) for v in identity.values()):
        raise ValueError("agent_identity values must be strings")
    empty = sorted(k for k, v in identity.items() if not v and k != "name")
    if empty:  # the schema refuses these, so every event would be lost
        raise ValueError(f"agent_identity has empty field(s) {', '.join(empty)}")


def _writes_v1() -> bool:
    """Whether this recorder writes spec 1.0 records (salted digests, context_base, agent_identity)."""
    return SPEC_VERSION not in ("0.1", "0.2")


_ENTRA_ENV = {"app_id": "MNESTIQ_ENTRA_AGENT_APP_ID", "object_id": "MNESTIQ_ENTRA_AGENT_OBJECT_ID",
              "blueprint_id": "MNESTIQ_ENTRA_BLUEPRINT_ID", "tenant_id": "MNESTIQ_ENTRA_TENANT_ID"}


def _identity_from_env() -> dict | None:
    """The agent's Entra Agent ID from the environment: its app id or object id at least."""
    found = {field: os.environ[name] for field, name in _ENTRA_ENV.items() if os.environ.get(name)}
    if not ({"app_id", "object_id"} & found.keys()):
        return None
    return {"provider": "entra", **found}
