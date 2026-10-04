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

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

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
from .keys import key_id, public_key_b64
from .merkle import merkle_root
from .sinks import Sink

SPEC_VERSION = "0.1"
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
    """

    def __init__(
        self,
        sink: Sink,
        *,
        agent_id: str,
        operator_id: str | None = None,
        sandbox_id: str | None = "auto",
        public_ip: str | None = None,
        signing_key: Ed25519PrivateKey | None = None,
        checkpoint_every: int = 100,
        timestamper: Callable[[bytes], bytes] | None = None,
        chain_id: str | None = None,
        strict: bool = False,
        max_content_bytes: int = 1_048_576,
        on_checkpoint: Callable[[dict], None] | None = None,
    ) -> None:
        if checkpoint_every < 1:
            raise ValueError("checkpoint_every must be >= 1")
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
        self._key = signing_key
        self._checkpoint_every = checkpoint_every
        self._timestamper = timestamper
        self._on_checkpoint = on_checkpoint
        self._lock = threading.RLock()
        # Maps tool name -> provenance of its output, filled by @recorder.tool.
        self.tool_sources: dict[str, str] = {}

        last: dict | None = None
        pending: list[str] = []
        for rec in sink.existing():
            last = rec
            if rec.get("kind") == "checkpoint":
                pending = []
            else:
                pending.append(rec["record_hash"])
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

    def _record_failure(self, exc: BaseException) -> None:
        self.failures += 1
        _log.error("mnestiq: failed to record evidence (%d failure(s) so far): %r", self.failures, exc)
        if not self._warned:
            self._warned = True
            warnings.warn(f"mnestiq: evidence is not being recorded: {exc!r} (further failures are logged "
                          f"on the 'mnestiq' logger; see Recorder.failures)", RuntimeWarning, stacklevel=3)

    def _write(self, record: dict) -> dict:
        record["record_hash"] = record_hash(record)
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
            if self._closed:
                raise RecorderError("recorder is closed")
            record = self._header("event")
            record.update({k: v for k, v in body.items() if v is not None})
            self._hash_and_cap(record)
            self._write(record)
            self._pending.append(record["record_hash"])
            if self._key is not None and len(self._pending) >= self._checkpoint_every:
                self.checkpoint()
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
        """Sign everything since the last checkpoint. No-op without a key or new records."""
        with self._lock:
            if self._key is None or not self._pending or self._closed:
                return None
            pub = public_key_b64(self._key)
            record = self._header("checkpoint")
            record.update(
                {
                    "covers": {"from_seq": self._pending_from, "to_seq": self._seq - 1},
                    "merkle_root": "sha256:" + merkle_root([digest_bytes(h) for h in self._pending]).hex(),
                    "sig_alg": "ed25519",
                    "key_id": key_id(pub),
                    "public_key": pub,
                }
            )
            signature = self._key.sign(signing_payload(record))
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
