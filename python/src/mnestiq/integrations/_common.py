"""Shared plumbing for SDK wrappers."""

from __future__ import annotations

import atexit
import contextlib
import contextvars
import functools
import inspect
import json
import threading
import time
import weakref
from collections import deque
from contextlib import contextmanager
from typing import Any
from collections.abc import AsyncIterator, Callable, Iterator

from ..jsonable import exception_text, is_not_given, to_jsonable
from ..recorder import Recorder, _before_close, _current_run, current_run

SAMPLING_PARAMS = ("temperature", "top_p", "top_k", "max_tokens", "max_completion_tokens",
                   "max_output_tokens", "seed", "stop", "stop_sequences", "tool_choice", "reasoning", "thinking",
                   "output_config", "service_tier")
_RECORDED_ARGS = frozenset({"messages", "input", "system", "instructions", *SAMPLING_PARAMS})
_SDK_RESPONSES = ("LegacyAPIResponse", "APIResponse", "AsyncAPIResponse")
_MAX_WATCHED_BODY = 16 * 1024 * 1024

_inside_call: contextvars.ContextVar[bool] = contextvars.ContextVar("mnestiq_inside_call", default=False)


def inside_recorded_call() -> bool:
    """True while a recorded call is in the SDK: a method it reaches from there is the same call."""
    return _inside_call.get()


@contextmanager
def sdk_call() -> Iterator[None]:
    token = _inside_call.set(True)
    try:
        yield
    finally:
        _inside_call.reset(token)


def sampling_params(kwargs: dict) -> dict:
    return {k: kwargs[k] for k in SAMPLING_PARAMS if k in kwargs and not is_not_given(kwargs[k])}


def is_async_client(client: Any, method: Callable) -> bool:
    # SDK decorators can hide coroutine functions from iscoroutinefunction(),
    # so also go by the client class (AsyncAnthropic, AsyncOpenAI, ...), or a class it derives from.
    return inspect.iscoroutinefunction(method) or any(c.__name__.startswith("Async") for c in type(client).__mro__)


def wrap_method(owner: Any, name: str, recorder: Recorder, record: Callable[..., None], client: Any) -> None:
    """Replace ``owner.<name>`` with a recorded version, once."""
    original = getattr(owner, name, None)
    if original is None or getattr(original, "_mnestiq_recorded", False) is True:
        return
    wrapped = wrap_create(recorder, original, record, is_async=is_async_client(client, original))
    wrapped._mnestiq_recorded = True  # type: ignore[attr-defined]
    setattr(owner, name, wrapped)


def follow_copies(client: Any, instrument: Callable[[Any], Any]) -> None:
    """``client.with_options(...)`` and ``client.copy(...)`` return a new client: record it too."""
    for name in ("with_options", "copy"):
        original = getattr(client, name, None)
        if original is None or getattr(original, "_mnestiq_recorded", False) is True:
            continue

        def copied(*args: Any, _original: Callable = original, **kwargs: Any) -> Any:
            return instrument(_original(*args, **kwargs))

        copied._mnestiq_recorded = True  # type: ignore[attr-defined]
        with contextlib.suppress(AttributeError, TypeError):
            setattr(client, name, copied)


def _as_dict(value: Any) -> dict:
    """``value`` if it is a dict, else an empty one: an SDK response can hold anything where a dict belongs."""
    return value if isinstance(value, dict) else {}


def _as_list(value: Any) -> Any:
    """Messages given as a generator would be used up by the SDK before they are recorded."""
    if value is None or isinstance(value, (list, str, dict, bytes)) or is_not_given(value):
        return value
    try:
        iterator = iter(value)
    except TypeError:
        return value
    return list(iterator)  # what a generator raises here is the agent's, as it would be from the SDK


def as_items(value: Any) -> list:
    """History as a list, whatever the agent passed."""
    if value is None or is_not_given(value):
        return []
    return value if isinstance(value, list) else [value]


def remember_tool(names: dict[str, str], tool_id: Any, name: Any) -> None:
    """Note a tool call for the results that follow. An id or name that is not text is no use as a key."""
    if isinstance(tool_id, str) and isinstance(name, str):
        names[tool_id] = name


def tool_name(names: dict[str, str], tool_id: Any) -> str | None:
    return names.get(tool_id) if isinstance(tool_id, str) else None


def snapshot(kwargs: dict) -> tuple[dict, dict]:
    """What the SDK gets, and what is recorded: the arguments as they were sent, even if the
    agent changes them while the call runs."""
    for key in ("messages", "input"):
        if key in kwargs:
            kwargs[key] = _as_list(kwargs[key])
    return kwargs, {k: to_jsonable(v) if k in _RECORDED_ARGS and not is_not_given(v) else v for k, v in kwargs.items()}


def parse_args(raw: Any) -> Any:
    if isinstance(raw, str):
        try:
            return json.loads(raw)
        except (ValueError, RecursionError):  # the model wrote this text: too deep or too long is kept as text
            return raw
    return raw


def _streamed_raw(kwargs: dict) -> bool:
    """``with_streaming_response``: the caller reads the body when it chooses, so it is not read here."""
    headers = kwargs.get("extra_headers")
    return isinstance(headers, dict) and headers.get("X-Stainless-Raw-Response") == "stream"


def _received(exc: BaseException) -> Any:
    """The reply the SDK was holding when its parser failed, from the frames that raised. Model output that
    fails ``parse()`` is evidence: the caller's exception alone would lose it."""
    try:
        tb = exc.__traceback__
        while tb is not None:
            frame_locals = tb.tb_frame.f_locals
            holder: Any = frame_locals.get("self")
            if type(holder).__name__ in _SDK_RESPONSES:
                parsed = frame_locals.get("parsed")
                return parsed if parsed is not None else holder.http_response.json()
            tb = tb.tb_next
    except Exception:
        pass
    return None


def _response_body(response: Any, kwargs: dict) -> tuple[Any, str | None]:
    """``with_raw_response`` hands back the raw HTTP response: the message it holds, and why it could not be read."""
    if _streamed_raw(kwargs):
        return response, None
    if type(response).__name__ in ("LegacyAPIResponse", "APIResponse") and callable(getattr(response, "parse", None)):
        try:
            parsed = response.parse()
        except Exception as exc:
            return _received(exc), exception_text(exc)
        if inspect.isawaitable(parsed):  # an async raw response is read by the caller, not here
            getattr(parsed, "close", lambda: None)()
            return response, None
        return parsed, None
    return response, None


async def _async_response_body(response: Any, kwargs: dict) -> tuple[Any, str | None]:
    """An async raw response gives up its message when awaited. Parsing is cached, so the caller gets the same."""
    if type(response).__name__ != "AsyncAPIResponse" or kwargs.get("stream") is True or _streamed_raw(kwargs):
        return _response_body(response, kwargs)
    try:
        return await response.parse(), None
    except Exception as exc:
        return _received(exc), exception_text(exc)


def _watch_body(response: Any, seen: dict, done: Callable[[Any], None]) -> bool:
    """Call ``done(json)`` when the caller closes a ``with_streaming_response`` reply, or ``done(None)`` if
    the body it read was not whole JSON. Every byte still reaches the caller as it arrives. False if this
    reply cannot be watched."""
    try:
        http = response.http_response
        if seen.get("stream") is True or "json" not in http.headers.get("content-type", ""):
            return False
        is_async = type(response).__name__.startswith("Async")
        kept: list[bytes] = []
        size = [0]

        def keep(chunk: bytes) -> None:
            size[0] += len(chunk)
            if size[0] > _MAX_WATCHED_BODY:
                kept.clear()
            else:
                kept.append(chunk)

        def finished() -> None:
            content = http.__dict__.get("_content")
            try:
                body = json.loads(content if content is not None else b"".join(kept))
            except (ValueError, RecursionError):
                body = None
            done(body if isinstance(body, dict) else None)

        if is_async:
            read_async, close_async = http.aiter_bytes, response.close

            async def aiter_bytes(*args: Any, **kwargs: Any) -> Any:
                async for chunk in read_async(*args, **kwargs):
                    keep(chunk)
                    yield chunk

            async def aclosing() -> Any:
                try:
                    return await close_async()
                finally:
                    finished()

            http.aiter_bytes, response.close = aiter_bytes, aclosing
            return True

        read, close = http.iter_bytes, response.close

        def iter_bytes(*args: Any, **kwargs: Any) -> Any:
            for chunk in read(*args, **kwargs):
                keep(chunk)
                yield chunk

        def closing() -> Any:
            try:
                return close()
            finally:
                finished()

        http.iter_bytes, response.close = iter_bytes, closing
        return True
    except Exception:
        return False


async def _settled(value: Any) -> Any:
    return await value if inspect.isawaitable(value) else value


def wrap_create(
    recorder: Recorder,
    original: Callable,
    record: Callable[..., None],
    *,
    is_async: bool,
    describe: Callable[[tuple, dict], dict] | None = None,
) -> Callable:
    """Wrap an SDK ``create`` method (sync or async).

    ``record(run, kwargs, response, latency_ms, error)`` writes the evidence.
    Recording never breaks the agent: if it fails, the failure is noted and the
    SDK result is returned unchanged. ``describe(args, kwargs)`` gives what the
    call is about when that is not its keyword arguments (a low-level request).
    A record with a ``new_accumulator`` has streams followed to their end.
    """
    new_accumulator = getattr(record, "new_accumulator", None)

    def described(args: tuple, kwargs: dict) -> tuple[dict, dict]:
        return snapshot(kwargs) if describe is None else (kwargs, describe(args, kwargs))

    def streams(seen: dict) -> bool:
        return new_accumulator is not None and seen.get("stream") is True and not _streamed_raw(seen)

    def stream_opened(call: _StreamCall, seen: dict, response: Any) -> Any:
        assert new_accumulator is not None
        capture = StreamCapture(recorder, record, seen, new_accumulator(recorder.max_content_bytes), call)
        if capture.attach(response):
            return response
        try:  # a raw response, or a stream of a shape this version does not know
            body, problem = _response_body(response, seen)
            safe_record(call.run, seen, body, _ms(call.started), problem)
        finally:
            call.end(None)
        return response

    def safe_record(run: Any, kwargs: dict, body: Any, latency: int, error: str | None) -> None:
        try:
            record(run, kwargs, body, latency, error)
        except Exception as exc:  # counted like any recording failure, raised only in strict mode
            if recorder.strict:
                raise
            recorder._record_failure(exc)

    def failed(run: Any, seen: dict, exc: BaseException, start: float) -> None:
        try:
            safe_record(run, seen, _received(exc), _ms(start), exception_text(exc))
        except Exception:
            if isinstance(exc, Exception):  # a cancellation stays a cancellation, even in strict mode
                raise

    def body_done(call: _StreamCall, seen: dict, response: Any) -> Callable[[Any], None]:
        finished = [False]

        def done(body: Any) -> None:
            if finished[0]:
                return
            finished[0] = True
            try:
                if body is None:  # not read, or not whole
                    safe_record(call.run, seen, response, _ms(call.started), None)
                else:
                    safe_record(call.run, {**seen, "extra_headers": None}, body, _ms(call.started), None)
            finally:
                call.end(None)

        return done

    def streamed_body(seen: dict) -> bool:
        return _streamed_raw(seen) and seen.get("stream") is not True

    def held_open(call: _StreamCall, seen: dict, response: Any) -> Any:
        """After the SDK returned something the caller reads later: the record is written when that ends."""
        if not streamed_body(seen):
            return stream_opened(call, seen, response)
        done = body_done(call, seen, response)
        if not _watch_body(response, seen, done):
            done(None)
        return response

    if is_async:

        @functools.wraps(original)
        async def async_create(*args: Any, **kwargs: Any) -> Any:
            if _inside_call.get():
                return await _settled(original(*args, **kwargs))
            _run_deferred()
            kwargs, seen = described(args, kwargs)
            if streams(seen) or streamed_body(seen):
                call = _StreamCall(recorder)
                try:
                    with call.in_run(), sdk_call():
                        response = await _settled(original(*args, **kwargs))
                except BaseException as exc:
                    try:
                        failed(call.run, seen, exc, call.started)
                    finally:
                        call.end(exc)
                    raise
                return held_open(call, seen, response)
            with recorder.ensure_run() as run:
                start = time.perf_counter()
                try:
                    with sdk_call():
                        response = await _settled(original(*args, **kwargs))
                except BaseException as exc:
                    failed(run, seen, exc, start)
                    raise
                latency = _ms(start)
                body, problem = await _async_response_body(response, seen)
                safe_record(run, seen, body, latency, problem)
                return response

        return async_create

    @functools.wraps(original)
    def create(*args: Any, **kwargs: Any) -> Any:
        if _inside_call.get():
            return original(*args, **kwargs)
        _run_deferred()
        kwargs, seen = described(args, kwargs)
        if streams(seen) or streamed_body(seen):
            call = _StreamCall(recorder)
            try:
                with call.in_run(), sdk_call():
                    response = original(*args, **kwargs)
            except BaseException as exc:
                try:
                    failed(call.run, seen, exc, call.started)
                finally:
                    call.end(exc)
                raise
            return held_open(call, seen, response)
        with recorder.ensure_run() as run:
            start = time.perf_counter()
            try:
                with sdk_call():
                    response = original(*args, **kwargs)
            except BaseException as exc:
                failed(run, seen, exc, start)
                raise
            latency = _ms(start)
            body, problem = _response_body(response, seen)
            safe_record(run, seen, body, latency, problem)
            return response

    return create


def _ms(start: float) -> int:
    return int((time.perf_counter() - start) * 1000)


def is_stream(kwargs: dict, response: Any) -> bool:
    # Not hasattr(__iter__): pydantic response models are iterable too.
    return kwargs.get("stream") is True or "Stream" in type(response).__name__ or _streamed_raw(kwargs)


# --- following a stream to its end ----------------------------------------------------------

_CLOSED_EARLY = "stream closed before the message was complete"
_LOCK_WAIT_S = 0.05  # how long a finalizer may hold up the thread it runs on
_SLOT_BYTES = 64  # counted for each block, call or item on top of its text: the objects that hold it are not free
_MAX_PARTS = 4096  # pieces of text kept apart before they are joined
_deferred: deque[Callable[[], None]] = deque()  # writes a finalizer could not do where it ran


def _run_deferred() -> None:
    """Do the writes a finalizer left. Called where the agent is between calls, so waiting for the lock is fine."""
    while True:
        try:
            job = _deferred.popleft()
        except IndexError:
            return
        job()


atexit.register(_run_deferred)
_before_close.append(_run_deferred)  # a recorder closing must not lose what is still waiting to be written to it


class _Bounded:
    """How much of one kind of output is kept, in bytes. What does not fit is dropped, and that is remembered."""

    def __init__(self, limit: int) -> None:
        self.room = limit
        self.truncated = False

    def take(self, text: str) -> str:
        """``text``, or as much of it as still fits."""
        encoded = text.encode("utf-8", "replace")
        if len(encoded) <= self.room:
            self.room -= len(encoded)
            return text
        kept = encoded[:self.room].decode("utf-8", "ignore")
        self.room = 0
        self.truncated = True
        return kept

    def charge(self, size: int) -> bool:
        """Count ``size`` bytes against the room. False if they do not fit, and nothing is then kept."""
        if size > self.room:
            self.truncated = True
            return False
        self.room -= size
        return True

    def fits(self, value: Any) -> bool:
        """Count a whole JSON value, and the slot that holds it, against the room."""
        return self.charge(json_size(value) + _SLOT_BYTES)


def json_size(value: Any) -> int:
    return len(json.dumps(value, ensure_ascii=False).encode("utf-8", "replace"))


def keep_part(parts: list[str], text: str) -> None:
    """Add a piece of text. Past the limit there is nothing to add, so no empty entry is held per chunk.
    Pieces are joined now and then: a million one-byte pieces would cost far more than the limit."""
    if text:
        parts.append(text)
        if len(parts) >= _MAX_PARTS:
            parts[:] = ["".join(parts)]


class StreamAccumulator:
    """Builds the reply the API would have sent whole from the chunks of one stream. Keeps plain data only,
    so a chunk the agent holds can never change the evidence. Text and tool arguments each have their own
    room, ``limit`` bytes (the recorder's ``max_content_bytes``), so a long answer cannot push out a tool call."""

    def __init__(self, limit: int) -> None:
        self.output = _Bounded(limit)
        self.arguments = _Bounded(limit)
        self.complete = False  # the API said this was the end of the reply
        self.damaged = False  # something delivered to the caller could not be kept, or put in its place

    @property
    def truncated(self) -> bool:
        return self.output.truncated or self.arguments.truncated

    def add(self, chunk: Any) -> None:
        raise NotImplementedError

    def result(self) -> dict | None:
        """The reply so far, shaped like a whole one. None if no chunk arrived."""
        raise NotImplementedError


class _StreamCall:
    """The run a stream's record goes into, held until the stream ends. Outside a run it is a one-off run,
    opened and ended in a context of its own: the caller's context never holds it, so a stream that is
    finished on another thread or task, or never finished, cannot leave a dead run behind there."""

    def __init__(self, recorder: Recorder) -> None:
        self.started = time.perf_counter()
        self._context: contextvars.Context | None = None
        self._scope: Any = None
        active = current_run()
        if active is not None and active.recorder is recorder:
            self.run: Any = active
        else:
            self._context = contextvars.copy_context()
            self._scope = recorder.run()
            self.run = self._context.run(self._scope.__enter__)

    @contextmanager
    def in_run(self) -> Iterator[None]:
        """Around the SDK call, so its traffic is attributed to the one-off run too."""
        if self._scope is None:
            yield
            return
        token = _current_run.set(self.run)
        try:
            yield
        finally:
            _current_run.reset(token)

    def end(self, exc: BaseException | None) -> None:
        if self._scope is not None and self._context is not None:
            self._context.run(self._scope.__exit__, type(exc) if exc else None, exc, exc.__traceback__ if exc else None)


class StreamCapture:
    """One streamed model call: sees every chunk on its way to the caller, and writes the record once."""

    def __init__(self, recorder: Recorder, record: Callable[..., None], seen: dict, accumulator: StreamAccumulator,
                 call: _StreamCall) -> None:
        self.recorder, self.record, self.seen, self.accumulator, self.call = recorder, record, seen, accumulator, call
        self.reading = False  # the SDK is being asked for a chunk: its own closing of the response is part of that
        self.damaged = False
        self._written = threading.Lock()  # taken once, never released: the only record of this call
        self._finalizer: weakref.finalize | None = None
        self._inner: weakref.ref | None = None

    def attach(self, stream: Any) -> bool:
        """Follow an SDK stream, in place: the caller keeps the very object the SDK returned. False if this
        is not an SDK stream of a shape this version knows."""
        try:
            inner, http = stream._iterator, stream.response
            if inspect.isasyncgen(inner):
                http.aclose = self._closing_async(http.aclose)
                stream._iterator = _watched_async(inner, self)
            elif inspect.isgenerator(inner):
                self._inner = weakref.ref(inner)
                http.close = self._closing(http.close)
                stream._iterator = _watched(inner, self)
            else:
                return False
        except Exception:
            return False
        with contextlib.suppress(TypeError):  # not a thing weak references can follow: no record if it is dropped
            self._finalizer = weakref.finalize(stream, self.abandoned)
        return True

    def _closing(self, close: Callable) -> Callable:
        """Every way of closing a stream ends in closing its response, the helpers' streams too."""

        def closing(*args: Any, **kwargs: Any) -> Any:
            try:
                return close(*args, **kwargs)
            finally:
                if not self.reading:
                    self._closed()

        return closing

    def _closing_async(self, close: Callable) -> Callable:

        async def closing(*args: Any, **kwargs: Any) -> Any:
            try:
                return await close(*args, **kwargs)
            finally:
                if not self.reading:  # a coroutine is never run by a finalizer: this is an ordinary close
                    self._write_when_safe(-1)

        return closing

    def add(self, chunk: Any) -> None:
        if self._written.locked():
            return
        try:
            self.accumulator.add(chunk)
        except Exception:  # the chunk still reaches the caller. The record says it may be missing something
            self.damaged = True

    def _closed(self) -> None:
        """The response was closed. Its own iterator closing it, while nobody is reading, is that iterator
        being finalized. Anything else is the caller closing the stream, and may wait for the lock."""
        inner = self._inner() if self._inner is not None else None
        if inner is None or inner.gi_running:
            self.abandoned()
        else:
            self._write_when_safe(-1)

    def abandoned(self) -> None:
        """Write from a finalizer. It runs on any thread, at any allocation, so it may not wait long."""
        self._write_when_safe(_LOCK_WAIT_S)

    def _write_when_safe(self, wait_s: float) -> None:
        """Write once the recorder's lock is held. A thread already inside the recorder may only have got
        here through a finalizer: writing through its lock then would break the record being written, so
        the write is left for the next safe point. So is one that cannot get the lock in ``wait_s``."""
        lock: Any = self.recorder._lock
        try:
            free = not lock._is_owned() and lock.acquire(timeout=wait_s)
        except Exception:
            free = False
        if not free:
            _deferred.append(self.finish)
            return
        try:
            self.finish()
        finally:
            lock.release()

    def finish(self, exc: BaseException | None = None, *, may_raise: bool = False) -> None:
        """Write the record, the first time only. Raises only in strict mode and only when ``may_raise``."""
        if not self._written.acquire(blocking=False):
            return
        if self._finalizer is not None:
            self._finalizer.detach()
        try:
            self._write(exc)
        except Exception as record_exc:
            if may_raise and self.recorder.strict:
                raise
            self.recorder._record_failure(record_exc)
        finally:
            try:
                self.call.end(exc)
            except Exception as end_exc:
                self.recorder._record_failure(end_exc)

    def _write(self, exc: BaseException | None) -> None:
        accumulator = self.accumulator
        try:
            body = accumulator.result()
        except Exception:
            body, self.damaged = None, True
        attributes: dict[str, Any] = {"streaming": True}
        damaged = self.damaged or accumulator.damaged
        if not accumulator.complete or accumulator.truncated or damaged:
            attributes["output_captured"] = "partial" if body else False
        if accumulator.truncated:
            attributes["capture_note"] = f"output past {self.recorder.max_content_bytes} bytes was not kept"
        elif damaged:
            attributes["capture_note"] = "a chunk of the stream could not be read or put in its place"
        error: str | None = exception_text(exc) if exc is not None else None
        if error is None and not accumulator.complete:
            error = _CLOSED_EARLY
        kwargs = {k: v for k, v in self.seen.items() if k != "stream"}
        self.record(self.call.run, kwargs, body, _ms(self.call.started), error, attributes=attributes)


def _watched(inner: Iterator, capture: StreamCapture) -> Iterator:
    """Stands in for the SDK's iterator: each chunk is noted and passed on, none is read ahead."""
    try:
        while True:
            capture.reading = True
            try:
                chunk = next(inner)
            finally:
                capture.reading = False
            capture.add(chunk)
            yield chunk
    except StopIteration:
        capture.finish(may_raise=True)
    except GeneratorExit:  # dropped without closing, or the interpreter is stopping
        capture.abandoned()
        raise
    except BaseException as exc:
        capture.finish(exc)
        raise


async def _watched_async(inner: AsyncIterator, capture: StreamCapture) -> AsyncIterator:
    """As ``_watched``. Nothing is awaited on the way out: this can run where nothing can be."""
    try:
        while True:
            capture.reading = True
            try:
                chunk = await inner.__anext__()
            finally:
                capture.reading = False
            capture.add(chunk)
            yield chunk
    except StopAsyncIteration:
        capture.finish(may_raise=True)
    except GeneratorExit:
        capture.abandoned()
        raise
    except BaseException as exc:  # a cancelled task too: what arrived is written and the cancel goes on
        capture.finish(exc)
        raise
