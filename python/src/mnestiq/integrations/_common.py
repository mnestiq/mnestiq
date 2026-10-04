"""Shared plumbing for SDK wrappers."""

from __future__ import annotations

import functools
import inspect
import time
from typing import Any
from collections.abc import Callable

from ..jsonable import is_not_given
from ..recorder import Recorder

SAMPLING_PARAMS = ("temperature", "top_p", "top_k", "max_tokens", "max_completion_tokens",
                   "max_output_tokens", "seed", "stop", "stop_sequences", "tool_choice", "reasoning", "thinking",
                   "output_config", "service_tier")


def sampling_params(kwargs: dict) -> dict:
    return {k: kwargs[k] for k in SAMPLING_PARAMS if k in kwargs and not is_not_given(kwargs[k])}


def is_async_client(client: Any, method: Callable) -> bool:
    # SDK decorators can hide coroutine functions from iscoroutinefunction(),
    # so also go by the client class (AsyncAnthropic, AsyncOpenAI, ...).
    return inspect.iscoroutinefunction(method) or type(client).__name__.startswith("Async")


def wrap_create(
    recorder: Recorder,
    original: Callable,
    record: Callable[[Any, dict, Any, int, str | None], None],
    *,
    is_async: bool,
) -> Callable:
    """Wrap an SDK ``create`` method (sync or async).

    ``record(run, kwargs, response, latency_ms, error)`` writes the evidence.
    Recording never breaks the agent: if it fails, the failure is noted and the
    SDK result is returned unchanged.
    """

    def safe_record(run: Any, kwargs: dict, response: Any, latency: int, error: str | None) -> None:
        try:
            record(run, kwargs, response, latency, error)
        except Exception as exc:  # report, don't raise
            import warnings

            warnings.warn(f"mnestiq: failed to record LLM call: {exc!r}", RuntimeWarning, stacklevel=3)

    if is_async:

        @functools.wraps(original)
        async def async_create(*args: Any, **kwargs: Any) -> Any:
            with recorder.ensure_run() as run:
                start = time.perf_counter()
                try:
                    response = await original(*args, **kwargs)
                except Exception as exc:
                    safe_record(run, kwargs, None, _ms(start), f"{type(exc).__name__}: {exc}")
                    raise
                safe_record(run, kwargs, response, _ms(start), None)
                return response

        return async_create

    @functools.wraps(original)
    def create(*args: Any, **kwargs: Any) -> Any:
        with recorder.ensure_run() as run:
            start = time.perf_counter()
            try:
                response = original(*args, **kwargs)
            except Exception as exc:
                safe_record(run, kwargs, None, _ms(start), f"{type(exc).__name__}: {exc}")
                raise
            safe_record(run, kwargs, response, _ms(start), None)
            return response

    return create


def _ms(start: float) -> int:
    return int((time.perf_counter() - start) * 1000)


def is_stream(kwargs: dict, response: Any) -> bool:
    # Not hasattr(__iter__): pydantic response models are iterable too.
    return kwargs.get("stream") is True or "Stream" in type(response).__name__
