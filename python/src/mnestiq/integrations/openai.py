"""Record OpenAI Chat Completions and Responses API calls.

    client = instrument_openai(openai.OpenAI(), recorder)

Works with ``OpenAI`` and ``AsyncOpenAI``. Tool outputs are tagged with the
source registered for that tool (default tool_output).
"""

from __future__ import annotations

import json
from typing import Any

from ..jsonable import get, is_not_given, to_jsonable
from ..recorder import Recorder, Run, Segment
from ._common import follow_copies, is_stream, sampling_params, wrap_method


def instrument_openai(client: Any, recorder: Recorder, *, tool_sources: dict[str, str] | None = None) -> Any:
    extra = tool_sources or {}

    def sources() -> dict[str, str]:
        return {**recorder.tool_sources, **extra}

    def record_chat(run: Run, kwargs: dict, response: Any, latency: int, error: str | None) -> None:
        messages = [to_jsonable(m) for m in kwargs.get("messages") or []]
        system = [m.get("content") for m in messages if m.get("role") in ("system", "developer")]
        common: dict[str, Any] = dict(provider="openai", model=str(kwargs.get("model")),
                      context=chat_segments(messages, sources()), params=sampling_params(kwargs),
                      system_prompt=system or None, latency_ms=latency, error=error)
        if response is None:
            run.llm_call(**common)
            return
        if is_stream(kwargs, response):
            run.llm_call(**common, attributes={"streaming": True, "output_captured": False})
            return
        choices = to_jsonable(get(response, "choices") or [])
        message = choices[0].get("message", {}) if choices else {}
        usage = to_jsonable(get(response, "usage")) or {}
        run.llm_call(
            **common,
            output=message,
            response_model=get(response, "model"),
            stop_reason=choices[0].get("finish_reason") if choices else None,
            response_id=get(response, "id"),
            tool_calls=[_chat_tool_call(tc) for tc in message.get("tool_calls") or [] if isinstance(tc, dict)],
            usage={"input_tokens": usage.get("prompt_tokens"), "output_tokens": usage.get("completion_tokens")},
        )

    def record_responses(run: Run, kwargs: dict, response: Any, latency: int, error: str | None) -> None:
        instructions = kwargs.get("instructions")
        instructions = None if instructions is None or is_not_given(instructions) else instructions
        common: dict[str, Any] = dict(provider="openai", model=str(kwargs.get("model")),
                      context=responses_segments(instructions, kwargs.get("input"), sources()),
                      params=sampling_params(kwargs), system_prompt=instructions, latency_ms=latency, error=error)
        if response is None:
            run.llm_call(**common)
            return
        if is_stream(kwargs, response):
            run.llm_call(**common, attributes={"streaming": True, "output_captured": False})
            return
        output = to_jsonable(get(response, "output") or [])
        usage = to_jsonable(get(response, "usage")) or {}
        run.llm_call(
            **common,
            output=output,
            response_model=get(response, "model"),
            stop_reason=get(response, "status"),
            response_id=get(response, "id"),
            tool_calls=[{"id": item.get("call_id"), "name": item.get("name") or item.get("type"),
                         "arguments": _parse_args(item.get("arguments", item.get("input", item.get("action"))))}
                        for item in output if isinstance(item, dict) and item.get("type") in MODEL_CALLS],
            usage={"input_tokens": usage.get("input_tokens"), "output_tokens": usage.get("output_tokens")},
        )

    # parse() and the beta namespace send their own requests: each is recorded too.
    for completions in (client.chat.completions,
                        getattr(getattr(getattr(client, "beta", None), "chat", None), "completions", None)):
        if completions is not None:
            for name in ("create", "parse"):
                wrap_method(completions, name, recorder, record_chat, client)
    if hasattr(client, "responses"):
        for name in ("create", "parse"):
            wrap_method(client.responses, name, recorder, record_responses, client)
    follow_copies(client, lambda c: instrument_openai(c, recorder, tool_sources=tool_sources))
    return client


def _parse_args(raw: Any) -> Any:
    if isinstance(raw, str):
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return raw
    return raw


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
    function = tc.get("function") or {}
    return {"id": tc.get("id"), "name": function.get("name"), "arguments": _parse_args(function.get("arguments"))}


def chat_segments(messages: list[dict], sources: dict[str, str]) -> list[Segment]:
    segments: list[Segment] = []
    tool_names: dict[Any, Any] = {}
    for m in messages:
        role = m.get("role")
        if role == "assistant":
            for tc in m.get("tool_calls") or []:
                tool_names[tc.get("id")] = _chat_tool_call(tc)["name"]
            segments.append(Segment(source="model", role=role, content=m))
        elif role == "tool":
            name = tool_names.get(m.get("tool_call_id"))
            segments.append(Segment(source=sources.get(name or "", "tool_output"), role=role, name=name,
                                    content=m.get("content")))
        elif role in ("system", "developer"):
            segments.append(Segment(source="system", role=role, content=m.get("content")))
        else:
            segments.append(Segment(source="user", role=role or "user", content=m.get("content")))
    return segments


def responses_segments(instructions: Any, input_: Any, sources: dict[str, str]) -> list[Segment]:
    segments: list[Segment] = []
    if instructions:
        segments.append(Segment(source="system", role="system", content=instructions))
    if input_ is None or is_not_given(input_):
        return segments
    if isinstance(input_, str):
        segments.append(Segment(source="user", role="user", content=input_))
        return segments
    tool_names: dict[Any, Any] = {}
    for item in (to_jsonable(i) for i in input_):
        if not isinstance(item, dict):
            segments.append(Segment(source="unknown", role="user", content=item))
            continue
        itype, role = item.get("type"), item.get("role")
        if itype in MODEL_CALLS:
            tool_names[item.get("call_id")] = item.get("name") or itype
            segments.append(Segment(source="model", role="assistant", content=item))
        elif isinstance(itype, str) and itype.endswith("_output"):
            # What a tool, a computer, a shell or an MCP server sent back: never the user's words.
            name = tool_names.get(item.get("call_id"))
            segments.append(Segment(source=sources.get(name or "", "tool_output"), role="tool", name=name,
                                    content=item.get("output", item)))
        elif itype in CALLS_WITH_RESULTS:
            segments.append(Segment(source=CALLS_WITH_RESULTS[itype], role="tool", name=item.get("name") or itype,
                                    content=item))
        elif role in ("system", "developer"):
            segments.append(Segment(source="system", role=role, content=item.get("content")))
        elif role == "assistant" or itype == "reasoning":
            segments.append(Segment(source="model", role="assistant", content=item))
        elif role == "user" or (itype in (None, "message") and role is None):
            segments.append(Segment(source="user", role="user", content=item.get("content", item)))
        else:  # a kind of item this version does not know: not taken as the user's words
            segments.append(Segment(source="unknown", role=role or "user", content=item))
    return segments
