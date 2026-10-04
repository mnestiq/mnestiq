"""Record Anthropic Messages API calls.

    client = instrument_anthropic(anthropic.Anthropic(), recorder)

Works with ``Anthropic`` and ``AsyncAnthropic``. Both ``messages.create`` and the
``messages.stream`` helper are recorded as ``llm_call`` events whose context
segments are tagged by provenance: system prompt and mid-conversation system
messages -> system, user text -> user, earlier assistant turns -> model, tool
results -> the source registered for that tool (default tool_output).
"""

from __future__ import annotations

import time
import warnings
from typing import Any

from ..jsonable import get, is_not_given, to_jsonable
from ..recorder import Recorder, Run, Segment
from ._common import is_async_client, is_stream, sampling_params, wrap_create


def instrument_anthropic(client: Any, recorder: Recorder, *, tool_sources: dict[str, str] | None = None) -> Any:
    extra = tool_sources or {}

    def record(run: Run, kwargs: dict, response: Any, latency: int, error: str | None,
               streamed: bool = False) -> None:
        system = kwargs.get("system")
        system = None if system is None or is_not_given(system) else to_jsonable(system)
        # Read recorder.tool_sources per call: tools may be registered after instrumenting.
        context = context_segments(system, kwargs.get("messages") or [], {**recorder.tool_sources, **extra})
        common: dict[str, Any] = dict(provider="anthropic", model=str(kwargs.get("model")), context=context,
                                      params=sampling_params(kwargs), system_prompt=system, latency_ms=latency,
                                      error=error, attributes={"streaming": True} if streamed else None)
        if response is None:
            run.llm_call(**common)
            return
        if is_stream(kwargs, response):
            common["attributes"] = {"streaming": True, "output_captured": False}
            run.llm_call(**common)
            return
        blocks = to_jsonable(get(response, "content") or [])
        usage = to_jsonable(get(response, "usage")) or {}
        run.llm_call(
            **common,
            output=blocks,
            response_model=get(response, "model"),
            stop_reason=get(response, "stop_reason"),
            response_id=get(response, "id"),
            tool_calls=[{"id": b.get("id"), "name": b.get("name"), "arguments": b.get("input")}
                        for b in blocks if isinstance(b, dict) and b.get("type") == "tool_use"],
            usage={k: v for k, v in usage.items() if k in ("input_tokens", "output_tokens",
                                                            "cache_read_input_tokens",
                                                            "cache_creation_input_tokens")},
        )

    original = client.messages.create
    client.messages.create = wrap_create(recorder, original, record, is_async=is_async_client(client, original))

    # messages.stream() sends its request without going through messages.create.
    original_stream = getattr(client.messages, "stream", None)
    if original_stream is not None:
        def stream(*args: Any, **kwargs: Any) -> _RecordedStream:
            return _RecordedStream(original_stream(*args, **kwargs), recorder, kwargs, record)

        client.messages.stream = stream
    return client


class _RecordedStream:
    """Wraps a (sync or async) MessageStreamManager and records the message when it closes.

    The recorded output is what had arrived by then, so a caller that stops reading
    early is recorded as such rather than forced to download the rest.
    """

    def __init__(self, manager: Any, recorder: Recorder, kwargs: dict, record: Any) -> None:
        self._manager, self._recorder, self._kwargs, self._record = manager, recorder, kwargs, record
        self._stream: Any = None

    def _start(self) -> None:
        self._run_scope = self._recorder.ensure_run()
        self._run = self._run_scope.__enter__()
        self._started = time.perf_counter()

    def _finish(self, exc: BaseException | None) -> None:
        try:
            snapshot = self._stream.current_message_snapshot if self._stream is not None else None
        except Exception:  # no message_start received
            snapshot = None
        error = f"{type(exc).__name__}: {exc}" if exc is not None else None
        try:
            self._record(self._run, self._kwargs, snapshot, int((time.perf_counter() - self._started) * 1000),
                         error, streamed=True)
        except Exception as record_exc:
            warnings.warn(f"mnestiq: failed to record streamed LLM call: {record_exc!r}", RuntimeWarning,
                          stacklevel=3)

    def __enter__(self) -> Any:
        self._start()
        try:
            self._stream = self._manager.__enter__()
        except BaseException as exc:
            self._finish(exc)
            self._run_scope.__exit__(type(exc), exc, exc.__traceback__)
            raise
        return self._stream

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> Any:
        try:
            return self._manager.__exit__(exc_type, exc, tb)
        finally:
            self._finish(exc)
            self._run_scope.__exit__(exc_type, exc, tb)

    async def __aenter__(self) -> Any:
        self._start()
        try:
            self._stream = await self._manager.__aenter__()
        except BaseException as exc:
            self._finish(exc)
            self._run_scope.__exit__(type(exc), exc, exc.__traceback__)
            raise
        return self._stream

    async def __aexit__(self, exc_type: Any, exc: Any, tb: Any) -> Any:
        try:
            return await self._manager.__aexit__(exc_type, exc, tb)
        finally:
            self._finish(exc)
            self._run_scope.__exit__(exc_type, exc, tb)


def context_segments(system: Any, messages: list, sources: dict[str, str]) -> list[Segment]:
    segments: list[Segment] = []
    if system:
        segments.append(Segment(source="system", role="system", content=system))
    tool_names: dict[Any, Any] = {}  # tool_use_id -> tool name
    for message in messages:
        message = to_jsonable(message)
        role = message.get("role")
        content = message.get("content")
        if role == "system":  # mid-conversation operator instruction
            segments.append(Segment(source="system", role=role, content=content))
            continue
        if isinstance(content, str):
            segments.append(Segment(source="model" if role == "assistant" else "user", role=role, content=content))
            continue
        for block in content or []:
            btype = block.get("type") if isinstance(block, dict) else None
            if btype == "tool_use":
                tool_names[block.get("id")] = block.get("name")
            if btype == "tool_result":
                name = tool_names.get(block.get("tool_use_id"))
                segments.append(Segment(source=sources.get(name or "", "tool_output"), role=role, name=name,
                                        content=block))
            elif role == "assistant":
                segments.append(Segment(source="model", role=role, content=block))
            else:
                segments.append(Segment(source="user", role=role, content=block))
    return segments
