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
from ._common import is_async_client, is_stream, sampling_params, wrap_create


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
            tool_calls=[{"id": tc.get("id"), "name": (tc.get("function") or {}).get("name"),
                         "arguments": _parse_args((tc.get("function") or {}).get("arguments"))}
                        for tc in message.get("tool_calls") or []],
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
            tool_calls=[{"id": item.get("call_id"), "name": item.get("name"),
                         "arguments": _parse_args(item.get("arguments"))}
                        for item in output if isinstance(item, dict) and item.get("type") == "function_call"],
            usage={"input_tokens": usage.get("input_tokens"), "output_tokens": usage.get("output_tokens")},
        )

    original = client.chat.completions.create
    client.chat.completions.create = wrap_create(recorder, original, record_chat,
                                                 is_async=is_async_client(client, original))
    if hasattr(client, "responses"):
        original = client.responses.create
        client.responses.create = wrap_create(recorder, original, record_responses,
                                              is_async=is_async_client(client, original))
    return client


def _parse_args(raw: Any) -> Any:
    if isinstance(raw, str):
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return raw
    return raw


def chat_segments(messages: list[dict], sources: dict[str, str]) -> list[Segment]:
    segments: list[Segment] = []
    tool_names: dict[Any, Any] = {}
    for m in messages:
        role = m.get("role")
        if role == "assistant":
            for tc in m.get("tool_calls") or []:
                tool_names[tc.get("id")] = (tc.get("function") or {}).get("name")
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
        itype, role = item.get("type"), item.get("role")
        if itype == "function_call":
            tool_names[item.get("call_id")] = item.get("name")
            segments.append(Segment(source="model", role="assistant", content=item))
        elif itype == "function_call_output":
            name = tool_names.get(item.get("call_id"))
            segments.append(Segment(source=sources.get(name or "", "tool_output"), role="tool", name=name,
                                    content=item.get("output")))
        elif role in ("system", "developer"):
            segments.append(Segment(source="system", role=role, content=item.get("content")))
        elif role == "assistant" or itype == "reasoning":
            segments.append(Segment(source="model", role="assistant", content=item))
        else:
            segments.append(Segment(source="user", role=role or "user", content=item.get("content", item)))
    return segments
