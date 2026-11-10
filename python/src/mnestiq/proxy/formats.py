"""The model APIs the proxy reads: which requests are model calls, what each request and answer
holds, and how to put a streamed answer back together."""

from __future__ import annotations

import json
import re
from typing import Any

from ..integrations._common import StreamAccumulator, model_name, sampling_params
from ..integrations.anthropic import _MessageStream, context_segments, message_answer
from ..integrations.openai import (_ChatStream, _ResponsesStream, chat_answer, chat_segments, responses_answer,
                                   responses_segments)
from ..recorder import _UNKNOWN, Segment

OPENAI, ANTHROPIC = "openai", "anthropic"
CHAT, RESPONSES, MESSAGES = "chat", "responses", "messages"
_DEPLOYMENT = re.compile(r"/deployments/([^/]+)/")  # Azure OpenAI names the model in the path
REPEATED_KEY = "an object repeats a key, so another JSON parser may read it differently from this record"
DEFAULT_CONTENT_BYTES = 1_048_576  # as the recorder's own default for max_content_bytes


def model_api(family: str, method: str, path: str) -> str | None:
    """Which model API a request is, or None for anything else (listing models, files, token counts)."""
    if method != "POST":
        return None
    path = path.split("?", 1)[0].rstrip("/")
    if family == ANTHROPIC:
        return MESSAGES if path.endswith("/messages") else None
    if path.endswith("/chat/completions"):
        return CHAT
    if path.endswith("/responses"):
        return RESPONSES
    return None


def request_fields(api: str, body: dict, path: str, sources: dict[str, str]) -> dict[str, Any]:
    """What a request says, as keyword arguments for ``Run.llm_call`` (without the answer). Raises on a
    request shaped as no SDK sends it, for the caller to keep whole."""
    if set(body) == {"unparsed"}:
        raise ValueError("the body is not a JSON object")
    model = body.get("model")
    if model is None:
        found = _DEPLOYMENT.search(path)
        model = found.group(1) if found else None
    fields: dict[str, Any] = {"model": model_name(model), "params": sampling_params(body)}
    if api == MESSAGES:
        system = body.get("system")
        fields["context"] = context_segments(system, _messages(body), sources)
        fields["system_prompt"] = system
    elif api == CHAT:
        messages = _messages(body)
        system = [m.get("content") for m in messages if m.get("role") in ("system", "developer")]
        fields["context"] = chat_segments(messages, sources)
        fields["system_prompt"] = system or None
    else:
        instructions = body.get("instructions")
        fields["context"] = responses_segments(instructions, body.get("input"), sources)
        fields["system_prompt"] = instructions
    return fields


def unreadable_request(body: Any) -> dict[str, Any]:
    """A request the proxy could not read: kept whole, and not taken as anyone's trusted words."""
    return {"model": model_name(body.get("model")) if isinstance(body, dict) else _UNKNOWN,
            "context": [Segment(source="unknown", content=body)]}


def answer_fields(api: str, answer: dict) -> dict[str, Any]:
    """What an answer says, as keyword arguments for ``Run.llm_call``. The SDK path's own mappers, so the
    same answer gives the same record whichever way it was captured."""
    if api == MESSAGES:
        return message_answer(answer)
    if api == CHAT:
        return chat_answer(answer)
    return responses_answer(answer)


def tool_result_ids(api: str, body: dict) -> list[str]:
    """The ids of the tool calls whose results this request hands back to the model."""
    ids: list[Any] = []
    if api == MESSAGES:
        for message in _dicts(body.get("messages")):
            if isinstance(message.get("content"), list):
                ids += [b.get("tool_use_id") for b in _dicts(message["content"]) if b.get("type") == "tool_result"]
    elif api == CHAT:
        ids = [m.get("tool_call_id") for m in _dicts(body.get("messages")) if m.get("role") == "tool"]
    elif isinstance(body.get("input"), list):
        ids = [i.get("call_id") for i in _dicts(body["input"]) if str(i.get("type", "")).endswith("_output")]
    return [i for i in ids if isinstance(i, str) and i]


def conversation(api: str, body: dict) -> list[Any]:
    """The conversation a request carries, first element the system prompt: used to tell which
    run a call continues."""
    raw = body.get("messages")
    messages: list[Any] = raw if isinstance(raw, list) else []
    if api == MESSAGES:
        return [body.get("system"), *messages]
    if api == CHAT:
        return [None, *messages]
    items = body.get("input")
    return [body.get("instructions"), *(items if isinstance(items, list) else [items])]


def _dicts(value: Any) -> list[dict]:
    return [v for v in value if isinstance(v, dict)] if isinstance(value, list) else []


def _messages(body: dict) -> list[dict]:
    """A request's messages. Any other shape raises: leaving out what is not understood would hide it."""
    messages = body.get("messages")
    if messages is None:
        return []
    if not isinstance(messages, list) or not all(isinstance(m, dict) for m in messages):
        raise ValueError("messages is not a list of objects")
    return messages


def read_json(data: str | bytes) -> tuple[Any, bool]:
    """``json.loads``, and whether an object in it repeats a key. Python keeps the last of two equal keys
    and other parsers the first, so the agent and this record could disagree on what was said."""
    repeated = False

    def build(pairs: list[tuple[str, Any]]) -> dict:
        nonlocal repeated
        built = dict(pairs)
        repeated = repeated or len(built) != len(pairs)
        return built

    return json.loads(data, object_pairs_hook=build), repeated


# Streamed answers


class EventStream:
    """Splits a server-sent event stream into (event, data) pairs, fed bytes as they arrive."""

    MAX_BUFFER = 16 << 20  # an event larger than this is not one a model API sends

    def __init__(self) -> None:
        self._buffer = b""
        self.broken = False

    def feed(self, chunk: bytes) -> list[tuple[str | None, str]]:
        if self.broken:
            return []
        self._buffer = (self._buffer + chunk).replace(b"\r\n", b"\n")
        events = []
        while b"\n\n" in self._buffer:
            raw, self._buffer = self._buffer.split(b"\n\n", 1)
            name, data = None, []
            for line in raw.decode("utf-8", "replace").split("\n"):
                field, _, value = line.partition(":")
                value = value[1:] if value.startswith(" ") else value
                if field == "event":
                    name = value
                elif field == "data":
                    data.append(value)
            if data:
                events.append((name, "\n".join(data)))
        if len(self._buffer) > self.MAX_BUFFER:
            self.broken, self._buffer = True, b""
        return events


class _StreamReader:
    """Reads one event at a time, counts those that could not be read, and hands the rest to the stream
    accumulator the SDK path uses, so a streamed answer is put back together the same way on both paths."""

    def __init__(self, accumulator: StreamAccumulator) -> None:
        self.accumulator = accumulator
        self.error: Any = None
        self.unreadable = 0
        self.repeated = False

    @property
    def finished(self) -> bool:
        return self.accumulator.complete

    @property
    def truncated(self) -> bool:
        return self.accumulator.truncated

    @property
    def damaged(self) -> bool:
        return self.accumulator.damaged

    def _read(self, data: str) -> dict | None:
        try:
            value, repeated = read_json(data)
        except (ValueError, RecursionError):
            value, repeated = None, False
        self.repeated = self.repeated or repeated
        if isinstance(value, dict):
            return value
        self.unreadable += 1
        return None

    def result(self) -> dict | None:
        return self.accumulator.result()


class AnthropicStream(_StreamReader):
    """Rebuilds a Messages API answer from its stream."""

    def __init__(self, limit: int = DEFAULT_CONTENT_BYTES) -> None:
        super().__init__(_MessageStream(limit))

    def feed(self, event: str | None, data: str) -> None:
        item = self._read(data)
        if item is None:
            return
        if item.get("type") == "error":
            self.error = item.get("error") or item
            return
        self.accumulator.add(item)


class ChatStream(_StreamReader):
    """Rebuilds a Chat Completions answer from its stream of chunks."""

    def __init__(self, limit: int = DEFAULT_CONTENT_BYTES) -> None:
        super().__init__(_ChatStream(limit))
        self.done = False

    @property
    def finished(self) -> bool:
        return self.done or self.accumulator.complete

    def feed(self, event: str | None, data: str) -> None:
        if data.strip() == "[DONE]":
            self.done = True
            return
        chunk = self._read(data)
        if chunk is None:
            return
        if "error" in chunk:
            self.error = chunk["error"]
            return
        self.accumulator.add(chunk)


class ResponsesStream(_StreamReader):
    """Rebuilds a Responses API answer: the final event carries the whole response."""

    def __init__(self, limit: int = DEFAULT_CONTENT_BYTES) -> None:
        super().__init__(_ResponsesStream(limit))

    def feed(self, event: str | None, data: str) -> None:
        item = self._read(data)
        if item is None:
            return
        if item.get("type") is None and event:  # named by the event line alone
            item = {**item, "type": event}
        if item.get("type") == "error":
            self.error = item
            return
        self.accumulator.add(item)


def stream_reader(api: str, limit: int = DEFAULT_CONTENT_BYTES) -> AnthropicStream | ChatStream | ResponsesStream:
    if api == MESSAGES:
        return AnthropicStream(limit)
    return ChatStream(limit) if api == CHAT else ResponsesStream(limit)
