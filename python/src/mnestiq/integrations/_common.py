"""Shared plumbing for SDK wrappers."""

from __future__ import annotations

import contextlib
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
    # so also go by the client class (AsyncAnthropic, AsyncOpenAI, ...), or a class it derives from.
    return inspect.iscoroutinefunction(method) or any(c.__name__.startswith("Async") for c in type(client).__mro__)


def wrap_method(owner: Any, name: str, recorder: Recorder, record: Callable[..., None], client: Any) -> None:
    """Replace ``owner.<name>`` with a recorded version, once."""
    original = getattr(owner, name, None)
    if original is None or getattr(original, "_mnestiq_recorded", False):
        return
    wrapped = wrap_create(recorder, original, record, is_async=is_async_client(client, original))
    wrapped._mnestiq_recorded = True  # type: ignore[attr-defined]
    setattr(owner, name, wrapped)


def follow_copies(client: Any, instrument: Callable[[Any], Any]) -> None:
    """``client.with_options(...)`` and ``client.copy(...)`` return a new client: record it too."""
    for name in ("with_options", "copy"):
        original = getattr(client, name, None)
        if original is None or getattr(original, "_mnestiq_recorded", False):
            continue

        def copied(*args: Any, _original: Callable = original, **kwargs: Any) -> Any:
            return instrument(_original(*args, **kwargs))

        copied._mnestiq_recorded = True  # type: ignore[attr-defined]
        with contextlib.suppress(AttributeError, TypeError):
            setattr(client, name, copied)


def _as_list(value: Any) -> Any:
    """Messages given as a generator would be used up by the SDK before they are recorded."""
    if value is None or isinstance(value, (list, str, dict, bytes)) or is_not_given(value):
        return value
    try:
        return list(value)
    except TypeError:
        return value


def _response_body(response: Any) -> Any:
    """``with_raw_response`` hands back the raw HTTP response: record the message it holds."""
    if type(response).__name__ in ("LegacyAPIResponse", "APIResponse") and callable(getattr(response, "parse", None)):
        try:
            parsed = response.parse()
        except Exception:
            return response
        if inspect.isawaitable(parsed):  # an async raw response is read by the caller, not here
            getattr(parsed, "close", lambda: None)()
            return response
        return parsed
    return response


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
            record(run, kwargs, _response_body(response), latency, error)
        except Exception as exc:  # counted like any recording failure, raised only in strict mode
            if recorder.strict:
                raise
            recorder._record_failure(exc)

    def prepared(kwargs: dict) -> tuple[dict, dict]:
        """What the SDK gets, and what is recorded: the messages as they were sent, even if the
        agent changes its list while the call runs."""
        for key in ("messages", "input"):
            if key in kwargs:
                kwargs[key] = _as_list(kwargs[key])
        seen = {k: (list(v) if k in ("messages", "input") and isinstance(v, list) else v) for k, v in kwargs.items()}
        return kwargs, seen

    if is_async:

        @functools.wraps(original)
        async def async_create(*args: Any, **kwargs: Any) -> Any:
            kwargs, seen = prepared(kwargs)
            with recorder.ensure_run() as run:
                start = time.perf_counter()
                try:
                    response = await original(*args, **kwargs)
                except Exception as exc:
                    safe_record(run, seen, None, _ms(start), f"{type(exc).__name__}: {exc}")
                    raise
                safe_record(run, seen, response, _ms(start), None)
                return response

        return async_create

    @functools.wraps(original)
    def create(*args: Any, **kwargs: Any) -> Any:
        kwargs, seen = prepared(kwargs)
        with recorder.ensure_run() as run:
            start = time.perf_counter()
            try:
                response = original(*args, **kwargs)
            except Exception as exc:
                safe_record(run, seen, None, _ms(start), f"{type(exc).__name__}: {exc}")
                raise
            safe_record(run, seen, response, _ms(start), None)
            return response

    return create


def _ms(start: float) -> int:
    return int((time.perf_counter() - start) * 1000)


def is_stream(kwargs: dict, response: Any) -> bool:
    # Not hasattr(__iter__): pydantic response models are iterable too.
    return kwargs.get("stream") is True or "Stream" in type(response).__name__
