"""Record Anthropic Messages API calls.

    client = instrument_anthropic(anthropic.Anthropic(), recorder)

Works with ``Anthropic`` and ``AsyncAnthropic``. Both ``messages.create`` and the
``messages.stream`` helper are recorded as ``llm_call`` events whose context
segments are tagged by provenance: system prompt and mid-conversation system
messages -> system, user text -> user, earlier assistant turns -> model, tool
results -> the source registered for that tool (default tool_output).
"""

from __future__ import annotations

import functools
import time
from typing import Any
from collections.abc import Callable

from ..jsonable import exception_text, get, is_not_given, to_jsonable
from ..recorder import Recorder, Run, Segment
from ._common import (StreamAccumulator, _as_dict, as_items, follow_copies, inside_recorded_call, is_stream, keep_part,
                      model_name, parse_args, remember_tool, sampling_params, sdk_call, snapshot, tool_name,
                      wrap_method)


def make_record(recorder: Recorder, *, tool_sources: dict[str, str] | None = None) -> Callable[..., None]:
    """What writes the evidence for one Messages API call."""
    extra = tool_sources or {}

    def record(run: Run, kwargs: dict, response: Any, latency: int, error: str | None,
               streamed: bool = False, partial: dict[int, Any] | None = None,
               attributes: dict[str, Any] | None = None) -> None:
        system = kwargs.get("system")
        system = None if system is None or is_not_given(system) else to_jsonable(system)
        # Read recorder.tool_sources per call: tools may be registered after instrumenting.
        context = context_segments(system, as_items(kwargs.get("messages")), {**recorder.tool_sources, **extra})
        if attributes is None:
            attributes = {"streaming": True} if streamed else None
            if partial is not None:
                attributes = {"streaming": True, "partial": True}
        common: dict[str, Any] = dict(provider="anthropic", model=model_name(kwargs.get("model")), context=context,
                                      params=sampling_params(kwargs), system_prompt=system, latency_ms=latency,
                                      error=error, attributes=attributes)
        if response is None:
            run.llm_call(**common)
            return
        if is_stream(kwargs, response):
            common["attributes"] = {"streaming": True, "output_captured": False}
            run.llm_call(**common)
            return
        run.llm_call(**common, **message_answer(response, partial))

    record.new_accumulator = _MessageStream  # type: ignore[attr-defined]
    return record


def message_answer(response: Any, partial: dict[int, Any] | None = None) -> dict[str, Any]:
    """What a whole Messages API answer says, as keyword arguments for ``Run.llm_call``. An SDK object
    or the JSON the proxy read: the record is the same for the same answer."""
    blocks = to_jsonable(get(response, "content") or [])
    usage = _as_dict(to_jsonable(get(response, "usage")))
    return {
        "output": blocks,
        "response_model": get(response, "model"),
        "stop_reason": get(response, "stop_reason"),
        "response_id": get(response, "id"),
        "tool_calls": [{"id": b.get("id"), "name": b.get("name"), "arguments": (partial or {}).get(i, b.get("input"))}
                       for i, b in enumerate(blocks if isinstance(blocks, list) else [])
                       if isinstance(b, dict) and b.get("type") == "tool_use"],
        "usage": {k: v for k, v in usage.items() if k in _USAGE_FIELDS},
    }


_TEXT_DELTAS = {"text_delta": "text", "thinking_delta": "thinking", "signature_delta": "signature",
                "compaction_delta": "content"}
_MESSAGE_FIELDS = ("id", "type", "role", "model", "stop_reason", "stop_sequence")
_USAGE_FIELDS = ("input_tokens", "output_tokens", "cache_read_input_tokens", "cache_creation_input_tokens")
# The block a delta belongs to, when the stream never said it started.
_UNSTARTED_BLOCKS: dict[str, dict] = {
    "text_delta": {"type": "text", "text": ""}, "citations_delta": {"type": "text", "text": ""},
    "thinking_delta": {"type": "thinking", "thinking": ""}, "signature_delta": {"type": "thinking", "thinking": ""},
    "compaction_delta": {"type": "compaction"}, "input_json_delta": {"type": "tool_use", "input": {}},
}


class _MessageStream(StreamAccumulator):
    """One ``create(stream=True)`` put back together as the message the API would have sent whole."""

    def __init__(self, limit: int) -> None:
        super().__init__(limit)
        self.message: dict[str, Any] = {}
        self.blocks: dict[int, dict] = {}
        self.fragments: dict[tuple[int, str], list[str]] = {}
        self.started = False

    def add(self, chunk: Any) -> None:
        self.started = True
        kind = get(chunk, "type")
        if kind == "message_start":
            message = _as_dict(to_jsonable(get(chunk, "message")))
            self.message = {k: message[k] for k in _MESSAGE_FIELDS if k in message}
            self._usage(message.get("usage"))
        elif kind == "content_block_start":
            self._start(get(chunk, "index"), to_jsonable(get(chunk, "content_block")))
        elif kind == "content_block_delta":
            self._delta(get(chunk, "index"), get(chunk, "delta"))
        elif kind == "message_delta":
            delta = get(chunk, "delta")
            self.message.update(stop_reason=get(delta, "stop_reason"), stop_sequence=get(delta, "stop_sequence"))
            self._usage(to_jsonable(get(chunk, "usage")))
            self.complete = self.complete or self.message["stop_reason"] is not None
        elif kind == "message_stop":
            self.complete = True

    def _usage(self, usage: Any) -> None:
        """The token counts a record holds, however many other keys a stream sends."""
        counts = _as_dict(usage)
        self.message.setdefault("usage", {}).update({k: counts[k] for k in _USAGE_FIELDS if counts.get(k) is not None})

    def _room(self, block: dict) -> Any:
        return self.arguments if str(block.get("type")).endswith("tool_use") else self.output

    def _start(self, index: Any, block: Any) -> None:
        if not isinstance(index, int) or not isinstance(block, dict):
            self.damaged = True
        elif self._room(block).fits(block):
            self.blocks[index] = block

    def _delta(self, index: Any, delta: Any) -> None:
        kind = get(delta, "type")
        if not isinstance(index, int) or kind not in _UNSTARTED_BLOCKS:  # delivered, and nowhere to keep it
            self.damaged = True
            return
        if index not in self.blocks:
            self.damaged = True
            block = dict(_UNSTARTED_BLOCKS[kind])
            if not self._room(block).fits(block):
                return
            self.blocks[index] = block
        if kind == "input_json_delta":
            self._keep(index, "input", self.arguments.take(get(delta, "partial_json") or ""))
        elif kind in _TEXT_DELTAS:
            field = _TEXT_DELTAS[kind]
            self._keep(index, field, self.output.take(get(delta, field) or ""))
        else:
            citation = to_jsonable(get(delta, "citation"))
            if self.output.fits(citation):
                self.blocks[index].setdefault("citations", []).append(citation)

    def _keep(self, index: int, field: str, text: str) -> None:
        keep_part(self.fragments.setdefault((index, field), []), text)

    def result(self) -> dict | None:
        if not self.started:
            return None
        blocks = {index: dict(block) for index, block in self.blocks.items()}
        for (index, field), parts in self.fragments.items():
            joined = "".join(parts)
            if field == "input":
                blocks[index][field] = parse_args(joined)
                continue
            start = blocks[index].get(field)
            if start is not None and not isinstance(start, str):  # the start held something else: it cannot be joined
                self.damaged = True
            blocks[index][field] = (start if isinstance(start, str) else "") + joined
        return {**self.message, "content": [blocks[index] for index in sorted(blocks)]}


def stream_method(original: Callable, recorder: Recorder, record: Callable[..., None], *,
                  enabled: Callable[[], bool] | None = None) -> Callable:
    """A recorded ``messages.stream``. While ``enabled`` is given and false, nothing is recorded."""

    @functools.wraps(original)
    def stream(*args: Any, **kwargs: Any) -> Any:
        if inside_recorded_call() or (enabled is not None and not enabled()):
            return original(*args, **kwargs)
        kwargs, seen = snapshot(kwargs)
        with sdk_call():
            manager = original(*args, **kwargs)
        return _RecordedStream(manager, recorder, seen, record, enabled)

    return stream


def instrument_anthropic(client: Any, recorder: Recorder, *, tool_sources: dict[str, str] | None = None) -> Any:
    record = make_record(recorder, tool_sources=tool_sources)
    # The beta namespace and the parse() helper send their own requests: each is recorded too.
    for messages in (client.messages, getattr(getattr(client, "beta", None), "messages", None)):
        if messages is None:
            continue
        for name in ("create", "parse"):
            wrap_method(messages, name, recorder, record, client)
        # messages.stream() sends its request without going through messages.create.
        original_stream = getattr(messages, "stream", None)
        if original_stream is not None and getattr(original_stream, "_mnestiq_recorded", False) is not True:
            stream = stream_method(original_stream, recorder, record)
            stream._mnestiq_recorded = True  # type: ignore[attr-defined]
            messages.stream = stream
    follow_copies(client, lambda c: instrument_anthropic(c, recorder, tool_sources=tool_sources))
    return client


class _RecordedStream:
    """Wraps a (sync or async) MessageStreamManager and records the message when it closes.

    The recorded output is what had arrived by then, so a caller that stops reading
    early is recorded as such rather than forced to download the rest.
    """

    def __init__(self, manager: Any, recorder: Recorder, kwargs: dict, record: Any,
                 enabled: Callable[[], bool] | None = None) -> None:
        self._manager, self._recorder, self._kwargs, self._record = manager, recorder, kwargs, record
        self._enabled = enabled
        self._active = False
        self._stream: Any = None

    @property  # type: ignore[misc]
    def __class__(self) -> Any:  # still an instance of the SDK's manager, to a caller that checks
        return type(self._manager)

    def __getattr__(self, name: str) -> Any:
        return getattr(self.__dict__.get("_manager"), name)

    def _start(self) -> None:
        self._active = self._enabled is None or self._enabled()  # built before an undo, entered after: not recorded
        if self._active:
            self._run_scope = self._recorder.ensure_run()
            self._run = self._run_scope.__enter__()
            self._started = time.perf_counter()

    def _finish(self, exc: BaseException | None) -> None:
        try:
            snapshot = self._stream.current_message_snapshot if self._stream is not None else None
        except Exception:  # no message_start received
            snapshot = None
        partial = _partial_inputs(self._stream) if self._stream is not None and get(snapshot, "stop_reason") is None \
            else None
        error = exception_text(exc) if exc is not None else ("stream closed before the message was complete"
                                                             if partial is not None else None)
        try:
            self._record(self._run, self._kwargs, snapshot, int((time.perf_counter() - self._started) * 1000),
                         error, streamed=True, partial=partial)
        except Exception as record_exc:  # counted and warned about like any recording failure
            if self._recorder.strict and (exc is None or isinstance(exc, Exception)):
                raise
            self._recorder._record_failure(record_exc)

    def _end(self, exc_type: Any, exc: Any, tb: Any) -> None:
        if not self._active:
            return
        try:
            self._finish(exc)
        finally:
            self._run_scope.__exit__(exc_type, exc, tb)

    def __enter__(self) -> Any:
        self._start()
        try:
            with sdk_call():
                self._stream = self._manager.__enter__()
        except BaseException as exc:
            self._end(type(exc), exc, exc.__traceback__)
            raise
        return self._stream

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> Any:
        try:
            return self._manager.__exit__(exc_type, exc, tb)
        finally:
            self._end(exc_type, exc, tb)

    async def __aenter__(self) -> Any:
        self._start()
        try:
            with sdk_call():
                self._stream = await self._manager.__aenter__()
        except BaseException as exc:
            self._end(type(exc), exc, exc.__traceback__)
            raise
        return self._stream

    async def __aexit__(self, exc_type: Any, exc: Any, tb: Any) -> Any:
        try:
            return await self._manager.__aexit__(exc_type, exc, tb)
        finally:
            self._end(exc_type, exc, tb)


def _partial_inputs(stream: Any) -> dict[int, Any]:
    """What had arrived of each tool input when a stream stopped: the SDK's snapshot shows ``{}`` until it can
    be read as JSON, which would look like a call with no arguments."""
    try:
        for key, value in vars(stream).items():
            if key.endswith("__json_bufs") and isinstance(value, dict):
                return {index: parse_args(bytes(raw).decode("utf-8", "replace")) for index, raw in value.items()}
    except Exception:
        pass
    return {}


def context_segments(system: Any, messages: list, sources: dict[str, str]) -> list[Segment]:
    segments: list[Segment] = []
    if system:
        segments.append(Segment(source="system", role="system", content=system))
    tool_names: dict[str, str] = {}  # tool_use_id -> tool name
    for message in messages:
        message = to_jsonable(message)
        try:
            segments.extend(_message_segments(message, tool_names, sources))
        except (AttributeError, KeyError, TypeError):  # an odd item costs only its own place
            segments.append(Segment(source="unknown", content=message))
    return segments


def _message_segments(message: Any, tool_names: dict[str, str], sources: dict[str, str]) -> list[Segment]:
    role = message.get("role")
    content = message.get("content")
    if role == "system":  # mid-conversation operator instruction
        return [Segment(source="system", role=role, content=content)]
    if isinstance(content, str):
        source = {"assistant": "model", "user": "user"}.get(role, "unknown") if isinstance(role, str) else "unknown"
        return [Segment(source=source, role=role, content=content)]
    segments: list[Segment] = []
    for block in content or []:
        btype = block.get("type") if isinstance(block, dict) else None
        if btype == "tool_use":
            remember_tool(tool_names, block.get("id"), block.get("name"))
        if btype == "tool_result":
            name = tool_name(tool_names, block.get("tool_use_id"))
            segments.append(Segment(source=sources.get(name or "", "tool_output"), role=role, name=name,
                                    content=block))
        elif isinstance(btype, str) and btype.endswith("_tool_result"):
            # A server tool's result (web search, web fetch, code execution, MCP): content from
            # outside, carried in the assistant turn but never the model's own words.
            source = "web" if btype.startswith("web_") else "tool_output"
            segments.append(Segment(source=source, role=role, name=btype.removesuffix("_tool_result"),
                                    content=block))
        elif role == "assistant" and btype in _MODEL_BLOCKS:
            segments.append(Segment(source="model", role=role, content=block))
        elif role == "user" and btype in _USER_BLOCKS:
            segments.append(Segment(source="user", role=role, content=block))
        else:  # a block or role this version does not know may carry anyone's words: not taken as trusted
            segments.append(Segment(source="unknown", role=role, content=block))
    return segments


# Blocks known to be the model's own words, or the caller's own input, in the turn of that role.
_MODEL_BLOCKS = frozenset({"text", "tool_use", "server_tool_use", "mcp_tool_use", "thinking", "redacted_thinking",
                           "compaction"})
_USER_BLOCKS = frozenset({"text", "image", "document", "search_result", "container_upload"})
