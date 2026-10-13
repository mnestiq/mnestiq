"""The model APIs the proxy reads: which requests are model calls, what each request and answer
holds, and how to put a streamed answer back together."""

from __future__ import annotations

import json
import re
from typing import Any

from ..integrations._common import sampling_params
from ..integrations.anthropic import context_segments
from ..integrations.openai import MODEL_CALLS, _chat_tool_call, _parse_args, chat_segments, responses_segments
from ..recorder import Segment

OPENAI, ANTHROPIC = "openai", "anthropic"
CHAT, RESPONSES, MESSAGES = "chat", "responses", "messages"
_DEPLOYMENT = re.compile(r"/deployments/([^/]+)/")  # Azure OpenAI names the model in the path


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
    """What a request says, as keyword arguments for ``Run.llm_call`` (without the answer)."""
    model = body.get("model")
    if model is None:
        found = _DEPLOYMENT.search(path)
        model = found.group(1) if found else "unknown"
    fields: dict[str, Any] = {"model": str(model), "params": sampling_params(body)}
    if api == MESSAGES:
        system = body.get("system")
        fields["context"] = context_segments(system, _dicts(body.get("messages")), sources)
        fields["system_prompt"] = system
    elif api == CHAT:
        messages = _dicts(body.get("messages"))
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
    return {"model": str(body.get("model", "unknown")) if isinstance(body, dict) else "unknown",
            "context": [Segment(source="unknown", content=body)]}


def answer_fields(api: str, answer: dict) -> dict[str, Any]:
    """What an answer says, as keyword arguments for ``Run.llm_call``."""
    if api == MESSAGES:
        blocks = answer.get("content") or []
        usage = answer.get("usage") or {}
        return {
            "output": blocks,
            "response_model": answer.get("model"),
            "stop_reason": answer.get("stop_reason"),
            "response_id": answer.get("id"),
            "tool_calls": [{"id": b.get("id"), "name": b.get("name"), "arguments": b.get("input")}
                           for b in blocks if isinstance(b, dict) and b.get("type") == "tool_use"],
            "usage": {k: v for k, v in usage.items() if k in ("input_tokens", "output_tokens",
                                                              "cache_read_input_tokens",
                                                              "cache_creation_input_tokens")},
        }
    if api == CHAT:
        choices = _dicts(answer.get("choices"))
        message = (choices[0].get("message") or {}) if choices else {}
        usage = answer.get("usage") or {}
        return {
            "output": message,
            "response_model": answer.get("model"),
            "stop_reason": choices[0].get("finish_reason") if choices else None,
            "response_id": answer.get("id"),
            "tool_calls": [_chat_tool_call(tc) for tc in _dicts(message.get("tool_calls"))],
            "usage": {"input_tokens": usage.get("prompt_tokens"), "output_tokens": usage.get("completion_tokens")},
        }
    output = _dicts(answer.get("output"))
    usage = answer.get("usage") or {}
    return {
        "output": output,
        "response_model": answer.get("model"),
        "stop_reason": answer.get("status"),
        "response_id": answer.get("id"),
        "tool_calls": [{"id": item.get("call_id"), "name": item.get("name") or item.get("type"),
                        "arguments": _parse_args(item.get("arguments", item.get("input", item.get("action"))))}
                       for item in output if item.get("type") in MODEL_CALLS],
        "usage": {"input_tokens": usage.get("input_tokens"), "output_tokens": usage.get("output_tokens")},
    }


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


class AnthropicStream:
    """Rebuilds a Messages API answer from its stream."""

    def __init__(self) -> None:
        self.message: dict | None = None
        self.blocks: dict[Any, dict] = {}
        self.partial_json: dict[Any, str] = {}
        self.error: Any = None

    def feed(self, event: str | None, data: str) -> None:
        item = _json(data)
        kind = item.get("type")
        index = item.get("index")
        if kind == "message_start":
            self.message = dict(item.get("message") or {})
        elif kind == "content_block_start":
            self.blocks[index] = dict(item.get("content_block") or {})
        elif kind == "content_block_delta":
            block, delta = self.blocks.setdefault(index, {}), item.get("delta") or {}
            dtype = delta.get("type")
            if dtype == "text_delta":
                block["text"] = block.get("text", "") + str(delta.get("text", ""))
            elif dtype == "input_json_delta":
                self.partial_json[index] = self.partial_json.get(index, "") + str(delta.get("partial_json", ""))
            elif dtype == "thinking_delta":
                block["thinking"] = block.get("thinking", "") + str(delta.get("thinking", ""))
            elif dtype == "signature_delta":
                block["signature"] = delta.get("signature")
            elif dtype == "citations_delta":
                block.setdefault("citations", []).append(delta.get("citation"))
        elif kind == "content_block_stop":
            self._close_block(index)
        elif kind == "message_delta" and self.message is not None:
            self.message.update({k: v for k, v in (item.get("delta") or {}).items() if v is not None})
            usage = self.message.setdefault("usage", {})
            if isinstance(usage, dict):
                usage.update(item.get("usage") or {})
        elif kind == "error":
            self.error = item.get("error") or item

    def _close_block(self, index: Any) -> None:
        if index in self.partial_json:
            raw = self.partial_json.pop(index)
            self.blocks.setdefault(index, {})["input"] = _parse_args(raw) if raw else {}

    def result(self) -> dict | None:
        if self.message is None:
            return None
        for index in list(self.partial_json):
            self._close_block(index)
        return {**self.message, "content": [self.blocks[i] for i in sorted(self.blocks, key=_order)]}


class ChatStream:
    """Rebuilds a Chat Completions answer from its stream of chunks."""

    def __init__(self) -> None:
        self.answer: dict[str, Any] = {}
        self.messages: dict[Any, dict] = {}
        self.finish: dict[Any, Any] = {}
        self.calls: dict[Any, dict[Any, dict]] = {}
        self.error: Any = None
        self.seen = False

    def feed(self, event: str | None, data: str) -> None:
        if data.strip() == "[DONE]":
            return
        chunk = _json(data)
        if "error" in chunk:
            self.error = chunk["error"]
            return
        self.seen = True
        for key in ("id", "model", "created", "system_fingerprint"):
            if chunk.get(key) is not None:
                self.answer[key] = chunk[key]
        if isinstance(chunk.get("usage"), dict):
            self.answer["usage"] = chunk["usage"]
        for choice in _dicts(chunk.get("choices")):
            index = choice.get("index", 0)
            message = self.messages.setdefault(index, {"role": "assistant"})
            delta = choice.get("delta") or {}
            for key in ("content", "refusal"):
                if isinstance(delta.get(key), str):
                    message[key] = (message.get(key) or "") + delta[key]
            for part in _dicts(delta.get("tool_calls")):
                call = self.calls.setdefault(index, {}).setdefault(part.get("index", 0), {})
                for key in ("id", "type"):
                    if part.get(key):
                        call[key] = part[key]
                for kind, text_key in (("function", "arguments"), ("custom", "input")):
                    if isinstance(part.get(kind), dict):
                        target = call.setdefault(kind, {})
                        if part[kind].get("name"):
                            target["name"] = target.get("name", "") + part[kind]["name"]
                        if isinstance(part[kind].get(text_key), str):
                            target[text_key] = target.get(text_key, "") + part[kind][text_key]
            if choice.get("finish_reason") is not None:
                self.finish[index] = choice["finish_reason"]

    def result(self) -> dict | None:
        if not self.seen:
            return None
        choices = []
        for index in sorted(self.messages, key=_order):
            message = dict(self.messages[index])
            calls = self.calls.get(index)
            if calls:
                message["tool_calls"] = [calls[i] for i in sorted(calls, key=_order)]
            choices.append({"index": index, "message": message, "finish_reason": self.finish.get(index)})
        return {**self.answer, "choices": choices}


class ResponsesStream:
    """Rebuilds a Responses API answer: the final event carries the whole response."""

    FINAL = ("response.completed", "response.incomplete", "response.failed")

    def __init__(self) -> None:
        self.response: dict | None = None
        self.started: dict | None = None
        self.items: dict[Any, Any] = {}
        self.error: Any = None

    def feed(self, event: str | None, data: str) -> None:
        item = _json(data)
        kind = item.get("type") or event
        if kind in self.FINAL and isinstance(item.get("response"), dict):
            self.response = item["response"]
        elif kind == "response.created" and isinstance(item.get("response"), dict):
            self.started = item["response"]
        elif kind == "response.output_item.done":
            self.items[item.get("output_index")] = item.get("item")
        elif kind == "error":
            self.error = item

    def result(self) -> dict | None:
        if self.response is not None:
            return self.response
        if self.started is None and not self.items:
            return None
        # Broken off before the end: what was finished so far.
        return {**(self.started or {}), "output": [self.items[i] for i in sorted(self.items, key=_order)]}


def stream_reader(api: str) -> AnthropicStream | ChatStream | ResponsesStream:
    if api == MESSAGES:
        return AnthropicStream()
    return ChatStream() if api == CHAT else ResponsesStream()


def _json(data: str) -> dict:
    try:
        value = json.loads(data)
    except (ValueError, RecursionError):
        return {}
    return value if isinstance(value, dict) else {}


def _order(key: Any) -> tuple[int, str]:
    return (key, "") if isinstance(key, int) else (1 << 30, str(key))
