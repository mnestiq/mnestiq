"""Record OpenAI Chat Completions and Responses API calls.

    client = instrument_openai(openai.OpenAI(), recorder)

Works with ``OpenAI`` and ``AsyncOpenAI``. Tool outputs are tagged with the
source registered for that tool (default tool_output).
"""

from __future__ import annotations

from typing import Any
from collections.abc import Callable

from ..jsonable import get, is_not_given, to_jsonable
from ..recorder import Recorder, Run, Segment
from ._common import (_SLOT_BYTES, StreamAccumulator, _as_dict, as_items, follow_copies, is_stream, json_size,
                      keep_part, parse_args as _parse_args, remember_tool, sampling_params, tool_name, wrap_method)


def make_records(recorder: Recorder, *, tool_sources: dict[str, str] | None = None,
                 ) -> tuple[Callable[..., None], Callable[..., None]]:
    """What writes the evidence for one Chat Completions call, and for one Responses API call."""
    extra = tool_sources or {}

    def sources() -> dict[str, str]:
        return {**recorder.tool_sources, **extra}

    def record_chat(run: Run, kwargs: dict, response: Any, latency: int, error: str | None,
                    attributes: dict[str, Any] | None = None) -> None:
        messages = [to_jsonable(m) for m in as_items(kwargs.get("messages"))]
        system = [m.get("content") for m in messages
                  if isinstance(m, dict) and m.get("role") in ("system", "developer")]
        common: dict[str, Any] = dict(provider="openai", model=str(kwargs.get("model")),
                      context=chat_segments(messages, sources()), params=sampling_params(kwargs),
                      system_prompt=system or None, latency_ms=latency, error=error)
        if response is None:
            run.llm_call(**common, attributes=attributes)
            return
        if is_stream(kwargs, response):
            run.llm_call(**common, attributes={"streaming": True, "output_captured": False})
            return
        choices = to_jsonable(get(response, "choices") or [])
        choice = choices[0] if isinstance(choices, list) and choices and isinstance(choices[0], dict) else {}
        message = choice.get("message", {})
        calls = message.get("tool_calls") if isinstance(message, dict) else None
        legacy = message.get("function_call") if isinstance(message, dict) else None
        calls = [*(calls if isinstance(calls, list) else []),
                 *([{"function": legacy}] if isinstance(legacy, dict) else [])]
        usage = _as_dict(to_jsonable(get(response, "usage")))
        run.llm_call(
            **common,
            output=message,
            response_model=get(response, "model"),
            stop_reason=choice.get("finish_reason"),
            response_id=get(response, "id"),
            tool_calls=[_chat_tool_call(tc) for tc in calls if isinstance(tc, dict)],
            usage={"input_tokens": usage.get("prompt_tokens"), "output_tokens": usage.get("completion_tokens")},
            attributes=attributes,
        )

    def record_responses(run: Run, kwargs: dict, response: Any, latency: int, error: str | None,
                         attributes: dict[str, Any] | None = None) -> None:
        instructions = kwargs.get("instructions")
        instructions = None if instructions is None or is_not_given(instructions) else instructions
        common: dict[str, Any] = dict(provider="openai", model=str(kwargs.get("model")),
                      context=responses_segments(instructions, kwargs.get("input"), sources()),
                      params=sampling_params(kwargs), system_prompt=instructions, latency_ms=latency, error=error)
        if response is None:
            run.llm_call(**common, attributes=attributes)
            return
        if is_stream(kwargs, response):
            run.llm_call(**common, attributes={"streaming": True, "output_captured": False})
            return
        output = to_jsonable(get(response, "output") or [])
        usage = _as_dict(to_jsonable(get(response, "usage")))
        run.llm_call(
            **common,
            output=output,
            response_model=get(response, "model"),
            stop_reason=get(response, "status"),
            response_id=get(response, "id"),
            tool_calls=[{"id": item.get("call_id"), "name": item.get("name") or item.get("type"),
                         "arguments": _parse_args(item.get("arguments", item.get("input", item.get("action"))))}
                        for item in (output if isinstance(output, list) else [])
                        if isinstance(item, dict) and item.get("type") in MODEL_CALLS],
            usage={"input_tokens": usage.get("input_tokens"), "output_tokens": usage.get("output_tokens")},
            attributes=attributes,
        )

    record_chat.new_accumulator = _ChatStream  # type: ignore[attr-defined]
    record_responses.new_accumulator = _ResponsesStream  # type: ignore[attr-defined]
    return record_chat, record_responses


_DELTA_FIELDS = frozenset({"role", "content", "refusal", "tool_calls", "function_call"})


def _extra_fields(delta: Any) -> dict:
    """What a delta carries beyond the fields the API documents, as compatible providers' reasoning text."""
    if isinstance(delta, dict):
        return {k: v for k, v in delta.items() if k not in _DELTA_FIELDS}
    found = getattr(delta, "model_extra", None)
    extra = dict(found) if isinstance(found, dict) else {}
    for name in getattr(type(delta), "model_fields", ()):  # what one SDK version keeps as extra, a later one declares
        if name not in _DELTA_FIELDS and getattr(delta, name, None) is not None:
            extra[name] = getattr(delta, name)
    return extra


class _ChatStream(StreamAccumulator):
    """One streamed chat completion put back together, for the first choice: the one a whole reply records."""

    def __init__(self, limit: int) -> None:
        super().__init__(limit)
        self.reply: dict[str, Any] = {}
        self.role: Any = None
        self.finish_reason: Any = None
        self.content: list[str] = []
        self.refusal: list[str] = []
        self.extras: dict[str, list[str]] = {}
        self.calls: list[dict] = []  # in order of arrival. Providers reuse an index or send none
        self.by_index: dict[int, dict] = {}
        self.last_call: dict | None = None
        self.function_call: dict | None = None
        self.started = False

    def add(self, chunk: Any) -> None:
        self.started = True
        for key in ("id", "model"):
            value = get(chunk, key)
            if value is not None:
                self.reply[key] = value
        usage = get(chunk, "usage")
        if usage is not None:
            self.reply["usage"] = to_jsonable(usage)
        for choice in get(chunk, "choices") or []:
            if get(choice, "index", 0) == 0:
                self._choice(choice)

    def _choice(self, choice: Any) -> None:
        finish_reason = get(choice, "finish_reason")
        if finish_reason is not None:
            self.finish_reason, self.complete = finish_reason, True
        delta = get(choice, "delta")
        self.role = get(delta, "role") or self.role
        self._keep(self.content, get(delta, "content"))
        self._keep(self.refusal, get(delta, "refusal"))
        self._function_call(get(delta, "function_call"))
        for call in get(delta, "tool_calls") or []:
            self._call(call)
        self._extras(delta)

    def _keep(self, parts: list[str], text: Any) -> None:
        if text:
            keep_part(parts, self.output.take(text))

    def _extras(self, delta: Any) -> None:
        for key, value in _extra_fields(delta).items():
            if isinstance(value, str):
                if key in self.extras or self.output.fits(key):
                    self._keep(self.extras.setdefault(key, []), value)
            elif value is not None:  # delivered, and not text that can be put together
                self.damaged = True

    def _function_call(self, delta: Any) -> None:
        """The form of a tool call that came before ``tool_calls``."""
        if delta is None:
            return
        if self.function_call is None:
            if not self.arguments.charge(_SLOT_BYTES):
                return
            self.function_call = {"name": None, "arguments": []}
        self._label(self.function_call, "name", get(delta, "name"), joined=True)
        arguments = get(delta, "arguments")
        if arguments:
            keep_part(self.function_call["arguments"], self.arguments.take(arguments))

    def _label(self, call: dict, field: str, value: Any, *, joined: bool = False) -> None:
        """Set an id, type or name, counted against the room. Providers repeat them on every chunk."""
        if value is None or value == "":
            return
        text = value if isinstance(value, str) else str(value)
        if call[field] != text:
            kept = self.arguments.take(text)
            call[field] = (call[field] or "") + kept if joined else kept

    def _slot(self, delta: Any) -> dict | None:
        """The call this delta belongs to. A new id is always a new call, whatever its index says."""
        index = get(delta, "index")
        index = index if isinstance(index, int) else None
        call_id = get(delta, "id")
        known = self.by_index.get(index) if index is not None else self.last_call
        if known is not None and (not call_id or known["id"] is None or known["id"] == str(call_id)):
            return known
        if not self.arguments.fits(index):  # nothing later for this index may land in an earlier call
            self.by_index.pop(index, None)  # type: ignore[arg-type]
            self.last_call = None
            return None
        slot: dict[str, Any] = {"index": index, "order": len(self.calls), "id": None, "type": None, "name": None,
                                "custom": False, "arguments": []}
        self.calls.append(slot)
        if index is not None:
            self.by_index[index] = slot
        return slot

    def _call(self, delta: Any) -> None:
        slot = self.last_call = self._slot(delta)
        if slot is None:
            return
        self._label(slot, "id", get(delta, "id"))
        self._label(slot, "type", get(delta, "type"))
        function, custom = get(delta, "function"), get(delta, "custom")
        if custom is not None:
            slot["custom"] = True
        self._label(slot, "name", get(custom if custom is not None else function, "name"), joined=True)
        text = get(custom, "input") if custom is not None else get(function, "arguments")
        if text:
            keep_part(slot["arguments"], self.arguments.take(text))

    @staticmethod
    def _tool_call(slot: dict) -> dict:
        text = "".join(slot["arguments"])
        if slot["custom"]:
            return {"id": slot["id"], "type": slot["type"] or "custom", "custom": {"name": slot["name"], "input": text}}
        return {"id": slot["id"], "type": slot["type"] or "function",
                "function": {"name": slot["name"], "arguments": text}}

    def result(self) -> dict | None:
        if not self.started:
            return None
        message: dict[str, Any] = {"role": self.role or "assistant", "content": "".join(self.content) or None}
        if self.refusal:
            message["refusal"] = "".join(self.refusal)
        message.update({key: "".join(parts) for key, parts in self.extras.items() if parts})
        if self.function_call is not None:
            message["function_call"] = {"name": self.function_call["name"],
                                        "arguments": "".join(self.function_call["arguments"])}
        if self.calls:
            ordered = sorted(self.calls, key=lambda c: (c["index"] is None, c["index"] or 0, c["order"]))
            message["tool_calls"] = [self._tool_call(slot) for slot in ordered]
        return {**self.reply, "choices": [{"index": 0, "finish_reason": self.finish_reason, "message": message}]}


_RESPONSE_ENDS = ("response.completed", "response.failed", "response.incomplete")
_RESPONSE_TEXT = ("response.output_text.delta", "response.refusal.delta")
_RESPONSE_ARGUMENTS = {"response.function_call_arguments.delta": "arguments",
                       "response.custom_tool_call_input.delta": "input"}


class _ItemSoFar:
    """One output item of a Responses stream: what arrived of it, and how much of each room that holds."""

    __slots__ = ("argument_bytes", "fields", "item", "output_bytes", "texts")

    def __init__(self) -> None:
        self.item: dict | None = None
        self.texts: dict[int, list[str]] = {}
        self.fields: dict[str, list[str]] = {}
        self.output_bytes = 0
        self.argument_bytes = 0


class _ResponsesStream(StreamAccumulator):
    """One streamed Responses API call put back together. The event that ends the stream carries the whole
    reply. Until it arrives, the items and their deltas are what is known."""

    def __init__(self, limit: int) -> None:
        super().__init__(limit)
        self.meta: dict[str, Any] = {}
        self.slots: dict[int, _ItemSoFar] = {}
        self.whole: dict[str, Any] | None = None
        self.started = False

    def add(self, chunk: Any) -> None:
        self.started = True
        kind = get(chunk, "type")
        index = get(chunk, "output_index")
        if kind in ("response.created", "response.in_progress"):
            response = _as_dict(to_jsonable(get(chunk, "response")))
            self.meta.update({k: response[k] for k in ("id", "model", "status") if k in response})
        elif kind in _RESPONSE_ENDS:
            self._ended(to_jsonable(get(chunk, "response")))
        elif kind in ("response.output_item.added", "response.output_item.done"):
            self._item(index, to_jsonable(get(chunk, "item")), done=kind.endswith("done"))
        elif kind in _RESPONSE_TEXT:
            self._text(index, get(chunk, "content_index"), get(chunk, "delta"))
        elif kind in _RESPONSE_ARGUMENTS:
            self._arguments(index, _RESPONSE_ARGUMENTS[kind], get(chunk, "delta"))

    def _ended(self, response: Any) -> None:
        self.complete = True
        if not isinstance(response, dict) or not isinstance(response.get("output"), list):
            self.damaged = True  # it said it was the end, without the reply: what arrived before is all there is
            return
        self.whole, self.slots, self.damaged = response, {}, False
        self.output.truncated = self.arguments.truncated = False  # nothing cut from it: it is the whole reply

    def _at(self, index: Any) -> _ItemSoFar | None:
        """The item at ``index``. None if a delta cannot be placed, or there is no room for one more item."""
        if not isinstance(index, int):
            self.damaged = True
            return None
        slot = self.slots.get(index)
        if slot is None and self.output.charge(_SLOT_BYTES):
            slot = self.slots[index] = _ItemSoFar()
        return slot

    def _item(self, index: Any, item: Any, *, done: bool) -> None:
        slot = self._at(index)
        if slot is None:
            return
        if not isinstance(item, dict):
            self.damaged = True
            return
        is_call = item.get("type") in MODEL_CALLS
        room = self.arguments if is_call else self.output
        size = json_size(item)
        if done:
            if size > room.room + (slot.argument_bytes if is_call else slot.output_bytes):  # what arrived stays
                room.truncated = True
                return
            self.output.room += slot.output_bytes  # the whole item replaces it, and is counted once
            self.arguments.room += slot.argument_bytes
            slot.output_bytes = slot.argument_bytes = 0
            slot.texts, slot.fields = {}, {}
        if room.charge(size):
            slot.item = item
            if is_call:
                slot.argument_bytes += size
            else:
                slot.output_bytes += size

    def _text(self, index: Any, content_index: Any, delta: Any) -> None:
        slot = self._at(index)
        if slot is None:
            return
        if not isinstance(content_index, int):
            self.damaged = True
            return
        if content_index not in slot.texts:
            if not self.output.charge(_SLOT_BYTES):
                return
            slot.output_bytes += _SLOT_BYTES
            slot.texts[content_index] = []
        before = self.output.room
        keep_part(slot.texts[content_index], self.output.take(delta or ""))
        slot.output_bytes += before - self.output.room

    def _arguments(self, index: Any, field: str, delta: Any) -> None:
        slot = self._at(index)
        if slot is not None:
            before = self.arguments.room
            keep_part(slot.fields.setdefault(field, []), self.arguments.take(delta or ""))
            slot.argument_bytes += before - self.arguments.room

    def result(self) -> dict | None:
        if self.whole is not None:
            return self.whole
        if not self.started:
            return None
        output = []
        for index in sorted(self.slots):
            slot = self.slots[index]
            if slot.item is None and not slot.texts and not slot.fields:
                continue
            item = dict(slot.item) if slot.item is not None else self._unannounced(slot)
            if slot.texts:
                self._fill(item, slot.texts)
            item.update({field: "".join(parts) for field, parts in slot.fields.items()})
            output.append(item)
        return {**self.meta, "output": output}

    def _unannounced(self, slot: _ItemSoFar) -> dict:
        """The item for deltas whose ``output_item.added`` never came."""
        self.damaged = True
        return {"type": "function_call"} if slot.fields else {"type": "message", "role": "assistant", "content": []}

    def _fill(self, item: dict, texts: dict[int, list[str]]) -> None:
        """Put each text in its place. An index from the wire is only trusted within the parts that exist: it
        is never used to size anything. Text that does not belong where it says goes last, and that is said."""
        parts = list(item.get("content") or [])
        for content_index in sorted(texts, key=lambda i: (i < 0, i)):
            text = "".join(texts[content_index])
            if 0 <= content_index < len(parts):
                part = parts[content_index]
                parts[content_index] = {**part, "text": text} if isinstance(part, dict) else {"text": text}
                continue
            if content_index != len(parts):
                self.damaged = True
            parts.append({"type": "output_text", "text": text})
        item["content"] = parts


def instrument_openai(client: Any, recorder: Recorder, *, tool_sources: dict[str, str] | None = None) -> Any:
    record_chat, record_responses = make_records(recorder, tool_sources=tool_sources)
    # parse() and the beta namespace send their own requests: each is recorded too.
    for completions in (client.chat.completions,
                        getattr(getattr(getattr(client, "beta", None), "chat", None), "completions", None)):
        if completions is not None:
            for name in ("create", "parse"):
                wrap_method(completions, name, recorder, record_chat, client)
    for responses in (getattr(client, "responses", None), getattr(getattr(client, "beta", None), "responses", None)):
        if responses is not None:
            for name in ("create", "parse"):
                wrap_method(responses, name, recorder, record_responses, client)
    follow_copies(client, lambda c: instrument_openai(c, recorder, tool_sources=tool_sources))
    return client


# Responses API items: the model asking for something, and items that carry what came back.
MODEL_CALLS = frozenset({"function_call", "custom_tool_call", "computer_call", "local_shell_call", "shell_call",
                         "apply_patch_call"})
CALLS_WITH_RESULTS = {"mcp_call": "tool_output", "mcp_list_tools": "tool_output",
                      "code_interpreter_call": "tool_output", "image_generation_call": "tool_output",
                      "file_search_call": "retrieved_doc", "web_search_call": "web"}


def _chat_tool_call(tc: dict) -> dict:
    """A Chat Completions tool call, function or custom ({"type": "custom", "custom": {"name", "input"}})."""
    if isinstance(tc.get("custom"), dict):
        return {"id": tc.get("id"), "name": tc["custom"].get("name"), "arguments": tc["custom"].get("input")}
    function = _as_dict(tc.get("function"))
    return {"id": tc.get("id"), "name": function.get("name"), "arguments": _parse_args(function.get("arguments"))}


def chat_segments(messages: list[dict], sources: dict[str, str]) -> list[Segment]:
    segments: list[Segment] = []
    tool_names: dict[str, str] = {}
    for m in messages:
        try:
            segments.append(_chat_segment(m, tool_names, sources))
        except (AttributeError, KeyError, TypeError):  # an odd item costs only its own place
            segments.append(Segment(source="unknown", content=m))
    return segments


def _chat_segment(m: dict, tool_names: dict[str, str], sources: dict[str, str]) -> Segment:
    role = m.get("role")
    if role == "assistant":
        for tc in m.get("tool_calls") or []:
            remember_tool(tool_names, tc.get("id"), _chat_tool_call(tc)["name"])
        return Segment(source="model", role=role, content=m)
    if role == "tool":
        name = tool_name(tool_names, m.get("tool_call_id"))
        return Segment(source=sources.get(name or "", "tool_output"), role=role, name=name, content=m.get("content"))
    if role in ("system", "developer"):
        return Segment(source="system", role=role, content=m.get("content"))
    return Segment(source="user", role=role or "user", content=m.get("content"))


def responses_segments(instructions: Any, input_: Any, sources: dict[str, str]) -> list[Segment]:
    segments: list[Segment] = []
    if instructions:
        segments.append(Segment(source="system", role="system", content=instructions))
    if input_ is None or is_not_given(input_):
        return segments
    if isinstance(input_, str):
        segments.append(Segment(source="user", role="user", content=input_))
        return segments
    tool_names: dict[str, str] = {}
    for item in (to_jsonable(i) for i in as_items(input_)):
        try:
            segments.append(_responses_segment(item, tool_names, sources))
        except (AttributeError, KeyError, TypeError):  # an odd item costs only its own place
            segments.append(Segment(source="unknown", content=item))
    return segments


def _responses_segment(item: Any, tool_names: dict[str, str], sources: dict[str, str]) -> Segment:
    if not isinstance(item, dict):
        return Segment(source="unknown", role="user", content=item)
    itype, role = item.get("type"), item.get("role")
    if itype in MODEL_CALLS:
        remember_tool(tool_names, item.get("call_id"), item.get("name") or itype)
        return Segment(source="model", role="assistant", content=item)
    if isinstance(itype, str) and itype.endswith("_output"):
        # What a tool, a computer, a shell or an MCP server sent back: never the user's words.
        name = tool_name(tool_names, item.get("call_id"))
        return Segment(source=sources.get(name or "", "tool_output"), role="tool", name=name,
                       content=item.get("output", item))
    if itype in CALLS_WITH_RESULTS:
        return Segment(source=CALLS_WITH_RESULTS[itype], role="tool", name=item.get("name") or itype, content=item)
    if role in ("system", "developer"):
        return Segment(source="system", role=role, content=item.get("content"))
    if role == "assistant" or itype == "reasoning":
        return Segment(source="model", role="assistant", content=item)
    if role == "user" or (itype in (None, "message") and role is None):
        return Segment(source="user", role="user", content=item.get("content", item))
    return Segment(source="unknown", role=role or "user", content=item)  # a kind of item this version does not know
