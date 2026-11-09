"""Record every Anthropic and OpenAI SDK client in the process, wrapped by hand or not.

    import mnestiq
    mnestiq.instrument_models(recorder)

This hooks the methods that send a model call (``create``, ``parse``, ``stream``) on the
SDK's own classes, so it reaches clients built before or after the call, their copies,
Azure OpenAI, and Bedrock, Vertex and Foundry clients of the Anthropic SDK. Each call is
recorded by the same code as a client passed to ``instrument_anthropic`` or
``instrument_openai``. A client wrapped that way keeps its own recorder and is recorded once.

The SDKs' low-level ``request`` method is hooked as well. Model calls that reach it without
going through those methods are recorded there: a ``client.post()`` to a model endpoint, a
method saved before this was called, a method replaced on one client.

Limits: raw HTTP to a provider, other SDKs, batch, embedding, image, audio and realtime
or websocket calls, a ``client.request`` method object saved before this was called, a
model call made from inside another SDK call on the same thread or task (an HTTP event
hook or a custom transport), and subprocesses are not seen. The API proxy sees HTTP sent
through it, whatever made it.
"""

from __future__ import annotations

import functools
import importlib
import inspect
import json
import logging
import sys
import threading
from dataclasses import dataclass
from typing import Any
from collections.abc import Callable, Mapping
from urllib.parse import urlsplit

from ..recorder import Recorder
from ._common import _run_deferred, _streamed_raw, inside_recorded_call, snapshot, wrap_create
from .anthropic import make_record, stream_method
from .openai import make_records

_log = logging.getLogger("mnestiq")

_ABSENT = object()
_ANTHROPIC = ("Messages", "AsyncMessages")
_CHAT = ("Completions", "AsyncCompletions")
_RESPONSES = ("Responses", "AsyncResponses")
_CLIENTS = ("SyncAPIClient", "AsyncAPIClient")

# Bedrock and Vertex copy the beta methods into classes of their own when imported.
_TARGETS: tuple[tuple[str, tuple[str, str], str], ...] = (
    ("anthropic.resources.messages", _ANTHROPIC, "messages"),
    ("anthropic.resources.beta.messages", _ANTHROPIC, "messages"),
    ("anthropic.lib.bedrock._beta_messages", _ANTHROPIC, "messages"),
    ("anthropic.lib.vertex._beta_messages", _ANTHROPIC, "messages"),
    ("openai.resources.chat.completions", _CHAT, "chat"),
    ("openai.resources.beta.chat.completions", _CHAT, "chat"),  # older SDKs only
    ("openai.resources.responses", _RESPONSES, "responses"),
    ("openai.resources.beta.responses", _RESPONSES, "responses"),
    ("anthropic._base_client", _CLIENTS, "anthropic_http"),
    ("openai._base_client", _CLIENTS, "openai_http"),
)
_METHODS = {"messages": ("create", "parse", "stream"), "chat": ("create", "parse"), "responses": ("create", "parse"),
            "anthropic_http": ("request",), "openai_http": ("request",)}
# The end of a request path, and what is recorded for it. Anything else passes through the hook untouched.
_HTTP_ROUTES = {"anthropic_http": (("/v1/messages", "messages"),),
                "openai_http": (("/chat/completions", "chat"), ("/responses", "responses"))}

_Key = tuple[type, str]


@dataclass(frozen=True)
class _Hook:
    saved: Any  # what the class held, to put back
    hooked: Callable  # what it holds now
    original: Callable  # what the hook calls, taking the resource as its first argument
    kind: str


_hooks: dict[_Key, _Hook] = {}
_recording: dict[Callable, Callable] | None = None  # per hook, the recorded call. None while undone
_install_lock = threading.Lock()


def _enabled() -> bool:
    return _recording is not None


def _callable_with_self(raw: Any) -> Callable:
    """What ``raw``, as found on the class, does for an instance. A Mock or a callable object is no
    descriptor: the instance is not passed to it."""
    if inspect.isfunction(raw):
        return raw
    if hasattr(type(raw), "__get__"):
        def bound(resource: Any, *args: Any, **kwargs: Any) -> Any:
            return raw.__get__(resource, type(resource))(*args, **kwargs)

        return bound

    def unbound(_resource: Any, *args: Any, **kwargs: Any) -> Any:
        return raw(*args, **kwargs)

    return unbound


def _select(hooked: Callable, original: Callable) -> Callable:
    """What a hook runs. Only the hook now in ``_hooks`` records: an older one, still in another tool's chain,
    passes straight through, or it would call the recording of the hook above it and go round for ever."""
    recording = _recording
    return original if recording is None or inside_recorded_call() else recording.get(hooked, original)


def _hooked_method(original: Callable, saved: Any) -> Callable:
    hooked: Any
    if inspect.iscoroutinefunction(original):
        @functools.wraps(original)
        async def hooked_async(*args: Any, **kwargs: Any) -> Any:
            return await _select(hooked, original)(*args, **kwargs)

        hooked = hooked_async
    else:
        @functools.wraps(original)
        def hooked_sync(*args: Any, **kwargs: Any) -> Any:
            return _select(hooked, original)(*args, **kwargs)

        hooked = hooked_sync
    hooked._mnestiq_auto_original = original
    hooked._mnestiq_auto_saved = saved
    hooked._mnestiq_auto_self = hooked  # functools.wraps copies the others onto a third party's wrapper. Not this
    return hooked


def _hook(owner: type, name: str, kind: str) -> None:
    key = (owner, name)
    held: Any = owner.__dict__.get(name, _ABSENT)
    entry = _hooks.get(key)
    if (entry is not None and held is entry.hooked) or not hasattr(owner, name):
        return
    ours: Any = getattr(held, "_mnestiq_auto_self", None)
    if ours is not None and ours is held:  # an old hook of ours, put back by another tool
        original, saved = ours._mnestiq_auto_original, ours._mnestiq_auto_saved
    else:
        original, saved = _callable_with_self(inspect.getattr_static(owner, name)), held
    hooked = _hooked_method(original, saved)
    _hooks[key] = _Hook(saved, hooked, original, kind)
    setattr(owner, name, hooked)


def _install() -> None:
    # All imported before any is hooked: a module imported later would copy a hook as if it were the SDK's method.
    modules: dict[str, Any] = {}
    for path, _, _ in _TARGETS:
        try:
            modules[path] = importlib.import_module(path)
        except Exception as exc:  # the SDK is not installed, or this version has no such module
            _log.debug("mnestiq: %s not available: %r", path, exc)
    for path, classes, kind in _TARGETS:
        for class_name in classes:
            owner = getattr(modules.get(path), class_name, None)
            if not isinstance(owner, type):
                continue
            for name in _METHODS[kind]:
                try:
                    _hook(owner, name, kind)
                except Exception as exc:
                    _log.error("mnestiq: could not hook %s.%s.%s: %r", path, class_name, name, exc)
    for sdk in ("anthropic", "openai"):
        if sys.modules.get(sdk) is not None and not any(owner.__module__.startswith(sdk) for owner, _ in _hooks):
            _log.warning("mnestiq: the %s SDK is installed but none of its model calls could be hooked", sdk)


def _request_options(args: tuple, kwargs: dict) -> Any:
    """The ``options`` of ``request(self, cast_to, options, ...)``, however it was passed."""
    return kwargs.get("options", args[2] if len(args) > 2 else None)


def _route(kind: str, options: Any) -> str | None:
    """Which record a request goes to. None for everything that is not a model call."""
    try:
        if str(getattr(options, "method", "")).lower() != "post":
            return None
        path = urlsplit(str(getattr(options, "url", ""))).path.rstrip("/")
        path = path if path.startswith("/") else f"/{path}"
    except Exception:  # an odd request is the SDK's to deal with
        return None
    return next((name for suffix, name in _HTTP_ROUTES[kind] if path.endswith(suffix)), None)


def _request_body(options: Any) -> dict:
    """What a request sends, as the keyword arguments ``create`` would have been given."""
    body = getattr(options, "json_data", None)
    if not isinstance(body, Mapping):
        body = _parsed(getattr(options, "content", None))
    extra = getattr(options, "extra_json", None)
    return {**body, **(extra if isinstance(extra, Mapping) else {})}


def _parsed(raw: Any) -> dict:
    """JSON text or bytes as a dict. An empty one when it is neither."""
    if isinstance(raw, (str, bytes, bytearray)):
        try:
            value = json.loads(raw)
        except (ValueError, RecursionError):
            return {}
        return value if isinstance(value, dict) else {}
    return {}


def _describe_request(args: tuple, kwargs: dict) -> dict:
    options = _request_options(args, kwargs)
    body = _request_body(options)
    sent = getattr(options, "json_data", None)
    copied = dict(body)
    _, seen = snapshot(copied)
    if isinstance(sent, Mapping):  # a generator is used up by reading it: the SDK gets the list that came of it
        for key in ("messages", "input"):
            if key in sent and key in copied and copied[key] is not sent[key]:
                options.json_data = {**sent, key: copied[key]}
                sent = options.json_data
    seen.setdefault("model", "<unknown>")
    seen["stream"] = kwargs.get("stream") is True or body.get("stream") is True
    headers = getattr(options, "headers", None)
    if isinstance(headers, Mapping):
        seen["extra_headers"] = dict(headers)
    return seen


def _reply_body(response: Any, kwargs: dict) -> tuple[Any, bool]:
    """A reply the caller asked to have as text, bytes or a raw HTTP response, as the message inside it, and
    whether it could be read. A stream is left alone: ``is_stream`` says it was not captured."""
    if (response is None or kwargs.get("stream") is True or _streamed_raw(kwargs) or isinstance(response, dict)
            or hasattr(response, "model_dump")):
        return response, True
    if hasattr(response, "http_response"):  # an SDK wrapper: its json() would read a body the caller has not
        return None, False
    if isinstance(response, (str, bytes, bytearray)):
        value: Any = _parsed(response) or None
        return value, value is not None
    json_method = getattr(response, "json", None)
    if callable(json_method) and hasattr(response, "status_code"):
        try:
            value = json_method()
        except Exception:  # not JSON, or a body nobody has read
            return None, False
        return value if isinstance(value, dict) else None, isinstance(value, dict)
    return None, False


def _http_record(record: Callable[..., None]) -> Callable[..., None]:
    """``record``, for a low-level request: ``cast_to`` lets the caller ask for the reply in any shape."""

    def recording(run: Any, kwargs: dict, response: Any, latency: int, error: str | None, **extra: Any) -> None:
        body, readable = _reply_body(response, kwargs)
        if not readable:
            extra.setdefault("attributes", {"output_captured": False,
                                            "capture_note": "the reply was not read as a message"})
        record(run, kwargs, body, latency, error, **extra)

    recording.new_accumulator = getattr(record, "new_accumulator", None)  # type: ignore[attr-defined]
    return recording


def _http_call(hook: _Hook, records: dict[str, Callable], recorder: Recorder, *, is_async: bool) -> Callable:
    """What the hooked ``request`` does: model endpoints are recorded, everything else goes straight through."""
    original = hook.original
    routes = {name: wrap_create(recorder, original, _http_record(records[name]), is_async=is_async,
                                describe=_describe_request)
              for _, name in _HTTP_ROUTES[hook.kind]}

    def call(*args: Any, **kwargs: Any) -> Any:
        route = _route(hook.kind, _request_options(args, kwargs))
        return original(*args, **kwargs) if route is None else routes[route](*args, **kwargs)

    return call


def _recorded_calls(recorder: Recorder, tool_sources: dict[str, str]) -> dict[Callable, Callable]:
    chat, responses = make_records(recorder, tool_sources=tool_sources)
    records = {"messages": make_record(recorder, tool_sources=tool_sources), "chat": chat, "responses": responses}
    calls: dict[Callable, Callable] = {}
    for (owner, name), hook in _hooks.items():
        if hook.kind in _HTTP_ROUTES:
            calls[hook.hooked] = _http_call(hook, records, recorder, is_async=owner.__name__.startswith("Async"))
        elif name == "stream":
            calls[hook.hooked] = stream_method(hook.original, recorder, records[hook.kind], enabled=_enabled)
        else:
            calls[hook.hooked] = wrap_create(recorder, hook.original, records[hook.kind],
                                             is_async=owner.__name__.startswith("Async"))
    return calls


def _hooked_names() -> list[str]:
    return sorted(f"{owner.__module__}.{owner.__qualname__}.{name}" for (owner, name), hook in _hooks.items()
                  if owner.__dict__.get(name) is hook.hooked)


def instrument_models(recorder: Recorder, *, tool_sources: dict[str, str] | None = None) -> list[str]:
    """Record every call made through the Anthropic and OpenAI SDKs in this process.

    Calling again changes the recorder and ``tool_sources``, for calls that start after it.
    Returns the SDK methods hooked now: empty means nothing will be recorded. Never raises.
    """
    global _recording
    try:
        if not isinstance(recorder, Recorder):
            _log.error("mnestiq: instrument_models needs a Recorder, got %s", type(recorder).__name__)
            return []
        with _install_lock:
            _install()
            _recording = _recorded_calls(recorder, dict(tool_sources or {}))
            return _hooked_names()
    except Exception as exc:
        _log.error("mnestiq: could not instrument the model SDKs: %r", exc)
        return []


def uninstrument_models() -> None:
    """Give the SDKs back their own methods. Safe to call at any time, and more than once."""
    global _recording
    try:
        _run_deferred()
        with _install_lock:
            _recording = None
            for (owner, name), hook in list(_hooks.items()):
                del _hooks[(owner, name)]
                if owner.__dict__.get(name) is not hook.hooked:
                    continue  # another tool has wrapped ours: left in its chain, switched off
                if hook.saved is _ABSENT:
                    delattr(owner, name)
                else:
                    setattr(owner, name, hook.saved)
    except Exception as exc:
        _log.error("mnestiq: could not fully restore the model SDKs: %r", exc)
