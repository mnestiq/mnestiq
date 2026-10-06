"""The flight recorder: turns agent activity into a hash-chained, signed evidence log."""

from __future__ import annotations

import base64
import contextvars
import functools
import inspect
import logging
import os
import threading
import time
import uuid
import warnings
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from collections.abc import Callable, Iterator

from cryptography.exceptions import InvalidSignature

from .canonical import canonical_json
from .hashing import (
    GENESIS_HASH,
    REDACTABLE_FIELDS,
    digest,
    digest_bytes,
    record_hash,
    signing_payload,
    value_digest,
)
from .identity import detect_sandbox_id
from .jsonable import to_jsonable
from .keys import PrivateKey, key_id, verify_signature
from .merkle import merkle_root
from .signers import Signer, as_signer
from .sinks import Sink
from .verify import schema_problem

SPEC_VERSION = "0.2"
_log = logging.getLogger("mnestiq")

SOURCES = frozenset(
    {"system", "user", "internal", "model", "tool_output", "retrieved_doc", "web", "agent_msg", "memory", "unknown"}
)

_MISSING = object()
_current_run: contextvars.ContextVar[Run | None] = contextvars.ContextVar("mnestiq_run", default=None)


def current_run() -> Run | None:
    """The run active in this thread / async task, if any."""
    return _current_run.get()


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
            out["role"] = self.role
        if self.name is not None:
            out["name"] = self.name
        return out


class RecorderError(Exception):
    pass


class Recorder:
    """Writes evidence records to a sink.

    Thread-safe. If the sink already holds records (e.g. the process restarted),
    the recorder resumes that chain instead of starting a new one.

    Recording never breaks the agent unless you ask it to: by default a failed
    write (disk full, closed sink, unserializable value) is counted in
    ``failures``, logged on the ``mnestiq`` logger and warned about once, and the
    agent carries on. ``strict=True`` raises instead, for deployments where an
    unrecorded action is worse than a failed one.

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
    ) -> None:
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
        self._closed = False
        self._sink = sink
        self.agent_id = agent_id
        self.operator_id = operator_id
        # "auto" detects container / pod / host, None omits it.
        self.sandbox_id = detect_sandbox_id() if sandbox_id == "auto" else sandbox_id
        # The NAT / gateway address the outside world sees. Not auto-detected: that
        # would mean the recorder making its own network calls.
        self.public_ip = public_ip or os.environ.get("MNESTIQ_PUBLIC_IP") or None
        if signing_key is not None and signer is not None:
            raise ValueError("pass signing_key or signer, not both")
        self._signer: Signer | None = as_signer(signing_key) if signing_key is not None else signer
        self._retry_after = retry_after
        self._next_try = 0.0
        self._interval = checkpoint_interval
        self._last_signed = time.monotonic()
        self._stop = threading.Event()
        self._checkpoint_every = checkpoint_every
        self._timestamper = timestamper
        self._on_checkpoint = on_checkpoint
        self._lock = threading.RLock()
        # Maps tool name -> provenance of its output, filled by @recorder.tool.
        self.tool_sources: dict[str, str] = {}

        last: dict | None = None
        pending: list[str] = []
        chain_key: str | None = None  # the key the chain expects next, from its last checkpoint
        for rec in sink.existing():
            if not isinstance(rec, dict) or not {"chain_id", "seq", "record_hash"} <= rec.keys():
                raise RecorderError("the sink already holds data that is not Mnestiq evidence, use a new file")
            last = rec
            if rec.get("kind") == "checkpoint":
                pending = []
                chain_key = (rec.get("next_key") or {}).get("key_id") or rec.get("key_id")
            else:
                pending.append(rec["record_hash"])
        if chain_key and self._signer is not None and key_id(self._signer.public_key) != chain_key:
            raise RecorderError(
                f"this evidence file is signed by {chain_key}, not by the configured key "
                f"{key_id(self._signer.public_key)}. Change keys with Recorder.rotate_signer, or use a new file")
        if last is not None:
            if chain_id is not None and chain_id != last["chain_id"]:
                raise ValueError(
                    f"sink already holds chain {last['chain_id']!r}; cannot write chain {chain_id!r} to it"
                )
            self.chain_id = last["chain_id"]
            self._seq = last["seq"] + 1
            self._prev = last["record_hash"]
        else:
            self.chain_id = chain_id or uuid.uuid4().hex
            self._seq = 0
            self._prev = GENESIS_HASH
        self._pending = pending
        self._pending_from = self._seq - len(pending)

        recovered = getattr(sink, "recovered", None)
        if recovered:
            # Record the recovery in the chain. The torn bytes stay in the sidecar file.
            self.append_event({
                "event_type": "note", "run_id": f"recorder-{self.chain_id[:8]}", "agent_id": self.agent_id,
                "sandbox_id": self.sandbox_id,
                "attributes": {"message": "recovered from an interrupted write", **recovered},
            })
        if self._interval is not None:
            threading.Thread(target=self._heartbeats, name="mnestiq-heartbeat", daemon=True).start()

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
        _log.error("mnestiq: failed to record evidence (%d failure(s) so far): %r", self.failures, exc)
        if not self._warned:
            self._warned = True
            warnings.warn(f"mnestiq: evidence is not being recorded: {exc!r} (further failures are logged "
                          f"on the 'mnestiq' logger; see Recorder.failures)", RuntimeWarning, stacklevel=3)

    def _write(self, record: dict) -> dict:
        record["record_hash"] = record_hash(record)
        problem = schema_problem(record)
        if problem:
            raise RecorderError(f"record would not pass verification, not written: {problem}")
        self._sink.append(record)
        self._seq += 1
        self._prev = record["record_hash"]
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
            if (self._signer is not None and len(self._pending) >= self._checkpoint_every
                    and time.monotonic() >= self._next_try):
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
        record = self._header("event")
        record.update({k: v for k, v in body.items() if v is not None})
        self._hash_and_cap(record)
        self._write(record)
        self._pending.append(record["record_hash"])
        return record

    def _hash_and_cap(self, record: dict) -> None:
        """Set ``<field>_hash`` for redactable values and drop values over the size cap."""
        omitted = []
        for container_key, field in REDACTABLE_FIELDS:
            container = record.get(container_key)
            objects = container if isinstance(container, list) else [container]
            for i, obj in enumerate(objects):
                if not isinstance(obj, dict) or field not in obj:
                    continue
                encoded = canonical_json(obj[field])
                obj[f"{field}_hash"] = digest(encoded)
                if len(encoded) > self.max_content_bytes:
                    del obj[field]
                    where = f"{container_key}[{i}]" if isinstance(container, list) else container_key
                    omitted.append(f"{where}.{field} ({len(encoded)} bytes)")
        if omitted:
            record["x-omitted"] = omitted

    def checkpoint(self) -> dict | None:
        """Sign everything since the last checkpoint. No-op without a signer or new records."""
        with self._lock:
            if self._signer is None or not self._pending or self._closed:
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
            return record

    def _sign_checkpoint(self, signer: Signer, next_key: dict | None, retry: bool = True) -> dict:
        record = self._header("checkpoint")
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
            signature = signer.sign(payload)
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
        if self._timestamper is not None:
            try:
                record["timestamp_token"] = base64.b64encode(self._timestamper(signature)).decode("ascii")
            except Exception as exc:  # write the checkpoint without a token
                _log.warning("mnestiq: timestamping failed, checkpoint written without a token: %r", exc)
        self._write(record)
        self._pending = []
        self._pending_from = self._seq
        if self._on_checkpoint is not None:  # e.g. HeadFile: a copy of the head kept elsewhere
            try:
                self._on_checkpoint(dict(record))
            except Exception as exc:
                if self.strict:
                    raise
                self._record_failure(exc)
        return record

    def close(self) -> None:
        """Write a final checkpoint and close the sink. Safe to call more than once."""
        self._stop.set()
        with self._lock:
            if self._closed:
                return
            try:
                self.checkpoint()
            except Exception as exc:
                if self.strict:
                    raise
                self._record_failure(exc)
            finally:
                self._closed = True
                self._sink.close()

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
            parent_run_id=(parent.run_id if parent else None) if parent_run_id is _MISSING else parent_run_id,
            agent_id=agent_id or self.agent_id,
            operator_id=self.operator_id if operator_id is _MISSING else operator_id,
        )
        run.emit("run_start", effective_permissions=effective_permissions, attributes=attributes)
        token = _current_run.set(run)
        try:
            yield run
        except BaseException as exc:
            run.emit("run_end", status="error", error=f"{type(exc).__name__}: {exc}")
            raise
        else:
            run.emit("run_end", status="ok")
        finally:
            _current_run.reset(token)

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
            tool_name = name or fn.__name__
            self.tool_sources[tool_name] = source
            sig = inspect.signature(fn)

            def arguments(args: tuple, kwargs: dict) -> dict:
                try:
                    return dict(sig.bind(*args, **kwargs).arguments)
                except TypeError:
                    return {"args": list(args), "kwargs": kwargs}

            if inspect.iscoroutinefunction(fn):

                @functools.wraps(fn)
                async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                    with self.ensure_run() as run:
                        start = time.perf_counter()
                        try:
                            result = await fn(*args, **kwargs)
                        except Exception as exc:
                            run.tool_call(tool_name, arguments(args, kwargs), error=f"{type(exc).__name__}: {exc}",
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
                    except Exception as exc:
                        run.tool_call(tool_name, arguments(args, kwargs), error=f"{type(exc).__name__}: {exc}",
                                      result_source=source, latency_ms=_ms_since(start), attributes=marks)
                        raise
                    run.tool_call(tool_name, arguments(args, kwargs), result,
                                  result_source=source, latency_ms=_ms_since(start), attributes=marks)
                    return result

            return wrapper

        return decorate


def _ms_since(start: float) -> int:
    return int((time.perf_counter() - start) * 1000)


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
        self._lock = threading.Lock()

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
        with self._lock:
            step = self._step
            self._step += 1
        body = {
            "event_type": event_type,
            "run_id": self.run_id,
            "parent_run_id": self.parent_run_id,
            "step_id": step,
            "agent_id": self.agent_id,
            "operator_id": self.operator_id,
            "sandbox_id": self.recorder.sandbox_id,
        }
        body.update(fields)
        try:
            return self.recorder.append_event(body)
        except Exception as exc:
            if self.recorder.strict:
                raise
            self.recorder._record_failure(exc)
            return None

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
        model_info: dict[str, Any] = {"provider": provider, "name": model}
        if response_model is not None:
            model_info["version"] = response_model
        if params:
            model_info["params"] = to_jsonable(params)
        out = None
        if output is not _MISSING:
            out = {"content": to_jsonable(output), "stop_reason": stop_reason, "response_id": response_id}
            out = {k: v for k, v in out.items() if v is not None or k == "content"}
        return self.emit(
            "llm_call",
            model=model_info,
            system_prompt_hash=value_digest(to_jsonable(system_prompt)) if system_prompt is not None else None,
            context=[s.to_dict() if isinstance(s, Segment) else Segment(**s).to_dict() for s in context],
            output=out,
            tool_calls=[_tool_call_dict(tc) for tc in tool_calls] if tool_calls else None,
            usage={k: v for k, v in (usage or {}).items() if isinstance(v, int)} or None,
            latency_ms=latency_ms,
            status="error" if error else "ok",
            error=error,
            attributes=attributes,
        )

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
        call: dict[str, Any] = {"id": call_id, "name": name, "arguments": arguments,
                                "result_source": result_source, "error": error, "latency_ms": latency_ms}
        if result is not _MISSING:
            call["result"] = result
        return self.emit(
            "tool_call",
            tool_calls=[_tool_call_dict(call)],
            status="error" if error else "ok",
            error=error,
            attributes=attributes,
        )

    def approval(self, action: str, decision: str, approver: str, *,
                 approver_type: str = "human", reason: str | None = None) -> dict | None:
        entry = {"action": action, "decision": decision, "approver": approver, "approver_type": approver_type}
        if reason:
            entry["reason"] = reason
        return self.emit("approval", approvals=[entry])

    def egress(self, entry: dict, *, latency_ms: int | None = None, error: str | None = None) -> dict | None:
        """Record one outbound request or connection. Usually called by mnestiq.egress."""
        return self.emit(
            "egress",
            egress=[{k: v for k, v in entry.items() if v is not None}],
            latency_ms=latency_ms,
            status="error" if error else "ok",
            error=error,
        )

    def note(self, message: str, **attributes: Any) -> dict | None:
        return self.emit("note", attributes=to_jsonable({"message": message, **attributes}))


def _tool_call_dict(tc: dict) -> dict:
    out = {k: v for k, v in tc.items() if v is not None and k not in ("arguments", "result")}
    if "arguments" in tc:
        out["arguments"] = to_jsonable(tc["arguments"])
    if "result" in tc:
        out["result"] = to_jsonable(tc["result"])
    return out
