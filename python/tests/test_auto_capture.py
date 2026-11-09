"""instrument_models: the real SDKs against a mocked HTTP transport. Nothing leaves this machine."""

import asyncio
import functools
import inspect
import json
import os
import subprocess
import sys
import threading
import time
import types
import warnings
from pathlib import Path
from unittest import mock

import pytest

anthropic = pytest.importorskip("anthropic")
openai = pytest.importorskip("openai")
httpx = pytest.importorskip("httpx2")
pydantic = pytest.importorskip("pydantic")

import mnestiq  # noqa: E402
from mnestiq import MemorySink, Recorder, instrument_models, uninstrument_models, verify_lines  # noqa: E402
from mnestiq.canonical import canonical_json  # noqa: E402
from mnestiq.integrations import auto  # noqa: E402
from mnestiq.integrations.anthropic import instrument_anthropic  # noqa: E402
from mnestiq.integrations.openai import instrument_openai  # noqa: E402
from anthropic.lib.streaming import MessageStreamManager  # noqa: E402
from anthropic.resources.messages import Messages  # noqa: E402
from test_integrations import ANTHROPIC_RESPONSE, INJECTED_HISTORY, STREAM_EVENTS  # noqa: E402

CHAT_RESPONSE = {
    "id": "chatcmpl-1", "object": "chat.completion", "created": 1, "model": "gpt-x-2026",
    "choices": [{"index": 0, "finish_reason": "tool_calls", "message": {
        "role": "assistant", "content": None,
        "tool_calls": [{"id": "call_2", "type": "function",
                        "function": {"name": "send_email", "arguments": "{\"to\": \"evil@example.com\"}"}}]}}],
    "usage": {"prompt_tokens": 3, "completion_tokens": 4, "total_tokens": 7},
}
RESPONSES_RESPONSE = {
    "id": "resp_1", "object": "response", "created_at": 1, "status": "completed", "model": "gpt-x-2026",
    "output": [{"type": "function_call", "id": "fc_2", "call_id": "call_2", "name": "lookup",
                "arguments": "{\"q\": \"x\"}", "status": "completed"}],
    "parallel_tool_calls": True, "tool_choice": "auto", "tools": [],
    "usage": {"input_tokens": 5, "output_tokens": 6, "total_tokens": 11},
}
USER = [{"role": "user", "content": "hi"}]
AZURE = {"api_version": "2025-01-01", "azure_endpoint": "https://example.invalid"}


@pytest.fixture(autouse=True)
def restored():
    yield
    uninstrument_models()
    assert not auto._hooks


def _recorder():
    sink = MemorySink()
    return sink, Recorder(sink, agent_id="a")


def _events(sink, event_type="llm_call"):
    return [r for r in sink.records if r.get("event_type") == event_type]


def _assert_valid(sink):
    report = verify_lines(canonical_json(r) for r in sink.records)
    assert report.ok, report.errors


def _client(cls, handler=None, body=None, **options):
    handler = handler or (lambda request: httpx.Response(200, json=body))
    http_cls = httpx.AsyncClient if "Async" in cls.__name__ else httpx.Client
    return cls(api_key="test", max_retries=0, http_client=http_cls(transport=httpx.MockTransport(handler)), **options)


def _settle(result):
    return asyncio.run(_await(result)) if inspect.isawaitable(result) else result


async def _await(result):
    return await result


def _sse(events, *, named=True):
    def handler(request):
        text = "".join((f"event: {e['type']}\n" if named else "") + f"data: {json.dumps(e)}\n\n" for e in events)
        return httpx.Response(200, content=text.encode(), headers={"content-type": "text/event-stream"})
    return handler


def _ask_anthropic(client):
    return _settle(client.messages.create(model="m", max_tokens=10, system="sys", messages=INJECTED_HISTORY))


def _ask_beta(client):
    return _settle(client.beta.messages.create(model="m", max_tokens=10, messages=INJECTED_HISTORY))


def _ask_parse(client):
    return _settle(client.messages.parse(model="m", max_tokens=10, messages=INJECTED_HISTORY))


def _ask_chat(client):
    return _settle(client.chat.completions.create(model="gpt-x", messages=USER))


def _ask_responses(client):
    return _settle(client.responses.create(model="gpt-x", instructions="sys", input=USER))


def _ask_beta_responses(client):
    return _settle(client.beta.responses.create(model="gpt-x", instructions="sys", input=USER))


def _ask_chat_parse(client):
    return _settle(client.chat.completions.parse(model="gpt-x", messages=USER))


def _ask_responses_parse(client):
    return _settle(client.responses.parse(model="gpt-x", input=USER))


CLIENTS = [(anthropic.Anthropic, ANTHROPIC_RESPONSE, _ask_anthropic, {}),
           (anthropic.AsyncAnthropic, ANTHROPIC_RESPONSE, _ask_anthropic, {}),
           (openai.OpenAI, CHAT_RESPONSE, _ask_chat, {}),
           (openai.AsyncOpenAI, CHAT_RESPONSE, _ask_chat, {}),
           (openai.AzureOpenAI, CHAT_RESPONSE, _ask_chat, AZURE),
           (openai.AsyncAzureOpenAI, CHAT_RESPONSE, _ask_chat, AZURE)]


@pytest.mark.parametrize("built_first", [True, False], ids=["built-before", "built-after"])
@pytest.mark.parametrize(("cls", "body", "ask", "options"), CLIENTS, ids=lambda v: getattr(v, "__name__", None))
def test_every_client_is_recorded_once(cls, body, ask, options, built_first):
    sink, rec = _recorder()
    client = _client(cls, body=body, **options) if built_first else None
    assert instrument_models(rec)
    client = client or _client(cls, body=body, **options)
    with rec.run():
        ask(client)
    assert len(_events(sink)) == 1
    assert rec.failures == 0
    _assert_valid(sink)


def _scrubbed(value):
    if isinstance(value, dict):
        return {k: _scrubbed(v) for k, v in value.items() if not k.endswith(("_salt", "_hash"))}
    if isinstance(value, list):
        return [_scrubbed(v) for v in value]
    return value


def _evidence(call):
    return _scrubbed({k: call.get(k) for k in ("context", "model", "output", "tool_calls", "usage", "attributes",
                                               "status", "error")})


@pytest.mark.parametrize(("cls", "body", "ask", "wrap"), [
    (anthropic.Anthropic, ANTHROPIC_RESPONSE, _ask_anthropic, instrument_anthropic),
    (anthropic.Anthropic, ANTHROPIC_RESPONSE, _ask_beta, instrument_anthropic),
    (anthropic.Anthropic, ANTHROPIC_RESPONSE, _ask_parse, instrument_anthropic),
    (anthropic.AsyncAnthropic, ANTHROPIC_RESPONSE, _ask_anthropic, instrument_anthropic),
    (openai.OpenAI, CHAT_RESPONSE, _ask_chat, instrument_openai),
    (openai.AsyncOpenAI, CHAT_RESPONSE, _ask_chat, instrument_openai),
    (openai.OpenAI, RESPONSES_RESPONSE, _ask_responses, instrument_openai),
    (openai.AsyncOpenAI, RESPONSES_RESPONSE, _ask_responses, instrument_openai),
    (openai.OpenAI, RESPONSES_RESPONSE, _ask_beta_responses, instrument_openai),
    (openai.OpenAI, CHAT_RESPONSE, _ask_chat_parse, instrument_openai),
    (openai.AsyncOpenAI, CHAT_RESPONSE, _ask_chat_parse, instrument_openai),
    (openai.OpenAI, RESPONSES_RESPONSE, _ask_responses_parse, instrument_openai),
])
def test_the_evidence_is_the_same_as_for_a_wrapped_client(cls, body, ask, wrap):
    wrapped_sink, wrapped_rec = _recorder()
    wrapped_rec.tool_sources["fetch_page"] = "web"
    with wrapped_rec.run():
        expected = ask(wrap(_client(cls, body=body), wrapped_rec))

    sink, rec = _recorder()
    rec.tool_sources["fetch_page"] = "web"
    instrument_models(rec)
    with rec.run():
        got = ask(_client(cls, body=body))
    uninstrument_models()

    assert type(got) is type(expected)
    assert got.model_dump() == expected.model_dump()
    (call,) = _events(sink)
    (wrapped_call,) = _events(wrapped_sink)
    assert _evidence(call) == _evidence(wrapped_call)
    _assert_valid(sink)


def test_tool_call_and_provenance_fields_are_filled():
    sink, rec = _recorder()
    instrument_models(rec, tool_sources={"fetch_page": "web"})
    with rec.run():
        response = _ask_anthropic(_client(anthropic.Anthropic, body=ANTHROPIC_RESPONSE))
    assert type(response) is anthropic.types.Message and response.content[1].name == "send_email"
    (call,) = _events(sink)
    assert [s["source"] for s in call["context"]] == ["system", "user", "model", "web"]
    assert call["tool_calls"][0]["name"] == "send_email"
    assert call["usage"] == {"input_tokens": 42, "output_tokens": 7}


def test_foundry_clients_inherit_the_hooks():
    sink, rec = _recorder()
    instrument_models(rec)
    client = _client(anthropic.AnthropicFoundry, body=ANTHROPIC_RESPONSE, resource="example")
    with rec.run():
        _ask_anthropic(client)
    assert len(_events(sink)) == 1


def test_bedrock_beta_classes_are_only_checked_for_a_hook_here():
    """Bedrock's client needs botocore, which is not installed: no call goes through it in these tests."""
    from anthropic.lib.bedrock import _beta_messages as bedrock

    instrument_models(_recorder()[1])
    for owner in (bedrock.Messages, bedrock.AsyncMessages):
        assert hasattr(owner.__dict__["create"], "_mnestiq_auto_original")


@pytest.mark.parametrize("ask", [_ask_anthropic, _ask_beta])
def test_vertex_clients_are_recorded(ask):
    sink, rec = _recorder()
    instrument_models(rec)
    transport = httpx.MockTransport(lambda request: httpx.Response(200, json=ANTHROPIC_RESPONSE))
    client = anthropic.AnthropicVertex(region="us-east5", project_id="p", access_token="dummy", max_retries=0,
                                       http_client=httpx.Client(transport=transport))
    with rec.run():
        ask(client)
    assert len(_events(sink)) == 1


def test_a_copy_of_a_client_is_recorded():
    sink, rec = _recorder()
    instrument_models(rec)
    with rec.run():
        _ask_anthropic(_client(anthropic.Anthropic, body=ANTHROPIC_RESPONSE).with_options(timeout=5))
    assert len(_events(sink)) == 1


def test_the_stream_helper_is_recorded_and_keeps_its_type():
    sink, rec = _recorder()
    instrument_models(rec)
    client = _client(anthropic.Anthropic, _sse(STREAM_EVENTS))
    manager = client.messages.stream(model="claude-opus-5-5", max_tokens=100, messages=USER)
    assert isinstance(manager, MessageStreamManager)
    with rec.run(), manager as stream:
        assert stream.get_final_text() == "Shipping takes 3-5 days."
    (call,) = _events(sink)
    assert call["output"]["content"] == [{"type": "text", "text": "Shipping takes 3-5 days."}]
    assert call["attributes"] == {"streaming": True}
    _assert_valid(sink)


def test_the_async_stream_helper_outside_a_run():
    sink, rec = _recorder()
    instrument_models(rec)
    client = _client(anthropic.AsyncAnthropic, _sse(STREAM_EVENTS))

    async def go():
        async with client.messages.stream(model="m", max_tokens=10, messages=USER) as stream:
            return await stream.get_final_text()

    assert asyncio.run(go()) == "Shipping takes 3-5 days."
    assert [r["event_type"] for r in sink.records] == ["run_start", "llm_call", "run_end"]


def test_create_with_stream_true_leaves_the_stream_alone():
    sink, rec = _recorder()
    instrument_models(rec)
    client = _client(anthropic.Anthropic, _sse(STREAM_EVENTS))
    with rec.run():
        stream = client.messages.create(model="m", max_tokens=10, messages=USER, stream=True)
        assert type(stream) is anthropic.Stream
        assert [e.type for e in stream] == [e["type"] for e in STREAM_EVENTS]
    assert _events(sink)[0]["attributes"] == {"streaming": True}


def test_openai_stream_helper_goes_through_create_once():
    chunk = {"id": "c", "object": "chat.completion.chunk", "created": 1, "model": "g", "choices": [
        {"index": 0, "finish_reason": "stop", "delta": {"role": "assistant", "content": "ok"}}]}

    def handler(request):
        text = f"data: {json.dumps(chunk)}\n\ndata: [DONE]\n\n"
        return httpx.Response(200, content=text.encode(), headers={"content-type": "text/event-stream"})

    sink, rec = _recorder()
    instrument_models(rec)
    client = _client(openai.OpenAI, handler)
    with rec.run(), client.chat.completions.stream(model="g", messages=USER) as stream:
        assert stream.get_final_completion().choices[0].message.content == "ok"
    (call,) = _events(sink)
    assert call["attributes"] == {"streaming": True}


class _WatchedBody(httpx.SyncByteStream):
    def __init__(self, payload):
        self.payload, self.touched = payload, False

    def __iter__(self):
        self.touched = True
        yield self.payload


class _AsyncWatchedBody(httpx.AsyncByteStream):
    def __init__(self, payload):
        self.payload, self.touched = payload, False

    async def __aiter__(self):
        self.touched = True
        yield self.payload


def _watched(body):
    return lambda request: httpx.Response(200, stream=body, headers={"content-type": "application/json"})


@pytest.mark.parametrize("wrapped", [False, True], ids=["hooked", "wrapped"])
def test_with_streaming_response_is_not_read_for_the_caller(wrapped):
    sink, rec = _recorder()
    body = _WatchedBody(json.dumps(ANTHROPIC_RESPONSE).encode())
    client = _client(anthropic.Anthropic, _watched(body))
    if wrapped:
        instrument_anthropic(client, rec)
    else:
        instrument_models(rec)
    with rec.run(), client.messages.with_streaming_response.create(model="m", max_tokens=1, messages=USER) as response:
        assert not body.touched
        assert json.loads(response.read())["id"] == "msg_1"
    (call,) = _events(sink)
    assert call["tool_calls"][0]["name"] == "send_email"
    assert call.get("attributes") is None
    assert call["usage"] == {"input_tokens": 42, "output_tokens": 7}
    assert rec.failures == 0


def test_with_streaming_response_async_is_not_read_for_the_caller():
    sink, rec = _recorder()
    instrument_models(rec)
    body = _AsyncWatchedBody(json.dumps(ANTHROPIC_RESPONSE).encode())
    client = _client(anthropic.AsyncAnthropic, _watched(body))

    async def go():
        async with client.messages.with_streaming_response.create(model="m", max_tokens=1, messages=USER) as response:
            assert not body.touched
            return json.loads(await response.read())

    with rec.run():
        assert asyncio.run(go())["id"] == "msg_1"
    (call,) = _events(sink)
    assert call["tool_calls"][0]["name"] == "send_email"


def test_with_streaming_response_outside_a_run_keeps_one_run_open_until_closed():
    sink, rec = _recorder()
    instrument_models(rec)
    client = _client(anthropic.Anthropic, _watched(_WatchedBody(json.dumps(ANTHROPIC_RESPONSE).encode())))
    with client.messages.with_streaming_response.create(model="m", max_tokens=1, messages=USER) as response:
        assert [r["event_type"] for r in sink.records] == ["run_start"]
        response.read()
    assert [r["event_type"] for r in sink.records] == ["run_start", "llm_call", "run_end"]
    _assert_valid(sink)


def test_a_reply_read_through_iter_lines_is_captured():
    sink, rec = _recorder()
    instrument_models(rec)
    client = _client(anthropic.Anthropic, _watched(_WatchedBody(json.dumps(ANTHROPIC_RESPONSE).encode())))
    with rec.run(), client.messages.with_streaming_response.create(model="m", max_tokens=1, messages=USER) as response:
        assert json.loads("".join(response.iter_lines()))["id"] == "msg_1"
    assert _events(sink)[0]["tool_calls"][0]["name"] == "send_email"


@pytest.mark.parametrize("read", [lambda r: None, lambda r: list(r.http_response.iter_raw()),
                                  lambda r: next(r.iter_bytes(chunk_size=3))],
                         ids=["unread", "iter_raw", "partly-read"])
def test_a_reply_not_read_whole_ends_as_output_not_captured(read):
    sink, rec = _recorder()
    instrument_models(rec)
    client = _client(anthropic.Anthropic, _watched(_WatchedBody(json.dumps(ANTHROPIC_RESPONSE).encode())))
    with rec.run(), client.messages.with_streaming_response.create(model="m", max_tokens=1, messages=USER) as response:
        read(response)
    (call,) = _events(sink)
    assert call["attributes"] == {"streaming": True, "output_captured": False}


def test_with_streaming_response_of_a_stream_is_recorded_as_not_captured():
    sink, rec = _recorder()
    instrument_models(rec)
    client = _client(anthropic.Anthropic, _sse(STREAM_EVENTS))
    with rec.run(), client.messages.with_streaming_response.create(model="m", max_tokens=1, messages=USER,
                                                                   stream=True) as response:
        response.read()
    (call,) = _events(sink)
    assert call["attributes"] == {"streaming": True, "output_captured": False}


@pytest.mark.parametrize("cls", [anthropic.Anthropic, anthropic.AsyncAnthropic], ids=lambda c: c.__name__)
def test_with_raw_response_records_the_message_inside(cls):
    sink, rec = _recorder()
    instrument_models(rec)
    client = _client(cls, body=ANTHROPIC_RESPONSE)
    with rec.run():
        raw = _settle(client.messages.with_raw_response.create(model="m", max_tokens=1, messages=USER))
        message = _settle(raw.parse())
    assert message.id == "msg_1"
    (call,) = _events(sink)
    assert call["tool_calls"][0]["name"] == "send_email"


def test_an_api_error_is_recorded_and_raised():
    sink, rec = _recorder()
    instrument_models(rec)
    error = {"type": "error", "error": {"type": "api_error", "message": "x"}}
    client = _client(anthropic.Anthropic, lambda request: httpx.Response(500, json=error))
    with rec.run(), pytest.raises(anthropic.APIError):
        _ask_anthropic(client)
    (call,) = _events(sink)
    assert call["status"] == "error" and "output" not in call


@pytest.mark.parametrize("cls", [anthropic.Anthropic, anthropic.AsyncAnthropic], ids=lambda c: c.__name__)
def test_outside_a_run_it_opens_a_one_off_run_like_a_wrapped_client(cls):
    sink, rec = _recorder()
    instrument_models(rec)
    _ask_anthropic(_client(cls, body=ANTHROPIC_RESPONSE))
    assert [r["event_type"] for r in sink.records] == ["run_start", "llm_call", "run_end"]
    _assert_valid(sink)


# --- never twice -------------------------------------------------------------------------

def test_a_client_wrapped_before_is_recorded_once_by_its_own_recorder():
    wrapped_sink, wrapped_rec = _recorder()
    auto_sink, auto_rec = _recorder()
    client = instrument_anthropic(_client(anthropic.Anthropic, body=ANTHROPIC_RESPONSE), wrapped_rec)
    instrument_models(auto_rec)
    with wrapped_rec.run():
        _ask_anthropic(client)
    assert len(_events(wrapped_sink)) == 1 and not auto_sink.records


def test_a_client_wrapped_after_is_recorded_once_and_stays_recorded_after_undo():
    wrapped_sink, wrapped_rec = _recorder()
    auto_sink, auto_rec = _recorder()
    instrument_models(auto_rec)
    client = instrument_anthropic(_client(anthropic.Anthropic, body=ANTHROPIC_RESPONSE), wrapped_rec)
    with wrapped_rec.run():
        _ask_anthropic(client)
        client.with_options(timeout=5).messages.create(model="m", max_tokens=1, messages=USER)
    uninstrument_models()
    with wrapped_rec.run():
        _ask_anthropic(client)
    assert len(_events(wrapped_sink)) == 3 and not auto_sink.records


def test_a_wrapped_stream_helper_is_recorded_once():
    sink, rec = _recorder()
    instrument_models(rec)
    client = instrument_anthropic(_client(anthropic.Anthropic, _sse(STREAM_EVENTS)), rec)
    with rec.run(), client.messages.stream(model="m", max_tokens=10, messages=USER) as stream:
        stream.get_final_text()
    assert len(_events(sink)) == 1


def test_a_wrapped_openai_client_is_recorded_once():
    sink, rec = _recorder()
    instrument_models(rec)
    client = instrument_openai(_client(openai.OpenAI, body=CHAT_RESPONSE), rec)
    with rec.run():
        _ask_chat(client)
    assert len(_events(sink)) == 1


def test_instrumenting_twice_records_once_and_a_second_recorder_takes_over():
    first_sink, first = _recorder()
    second_sink, second = _recorder()
    assert instrument_models(first) == instrument_models(first)
    client = _client(anthropic.Anthropic, body=ANTHROPIC_RESPONSE)
    with first.run():
        _ask_anthropic(client)
    assert len(_events(first_sink)) == 1

    instrument_models(second)
    with second.run():
        _ask_anthropic(client)
    assert len(_events(first_sink)) == 1 and len(_events(second_sink)) == 1


# --- undo ---------------------------------------------------------------------------------

def _sdk_attributes():
    import importlib

    snapshot = {}
    for path, classes, kind in auto._TARGETS:
        try:
            module = importlib.import_module(path)
        except ImportError:
            continue
        for class_name in classes:
            owner = getattr(module, class_name, None)
            for name in auto._METHODS[kind] if owner is not None else ():
                snapshot[owner, name] = owner.__dict__.get(name, "absent")
    return snapshot


def test_undo_restores_the_exact_methods_and_can_be_repeated():
    before = _sdk_attributes()
    assert before
    instrument_models(_recorder()[1])
    assert _sdk_attributes() != before
    uninstrument_models()
    assert _sdk_attributes() == before
    uninstrument_models()
    assert _sdk_attributes() == before


def test_undo_before_instrumenting_is_safe():
    uninstrument_models()
    assert not auto._hooks


def test_after_undo_nothing_is_recorded_even_through_a_saved_method():
    sink, rec = _recorder()
    instrument_models(rec)
    client = _client(anthropic.Anthropic, body=ANTHROPIC_RESPONSE)
    saved_raw = client.messages.with_raw_response  # holds the hooked method
    uninstrument_models()
    saved_raw.create(model="m", max_tokens=1, messages=USER)
    _ask_anthropic(client)
    assert sink.records == []


def test_another_tool_patching_over_the_hook_is_left_in_place():
    sink, rec = _recorder()
    original = Messages.__dict__["create"]
    instrument_models(rec)
    hooked = Messages.__dict__["create"]

    def theirs(*args, **kwargs):
        return hooked(*args, **kwargs)

    Messages.create = theirs
    try:
        uninstrument_models()
        assert Messages.__dict__["create"] is theirs
        assert not auto._hooks
        client = _client(anthropic.Anthropic, body=ANTHROPIC_RESPONSE)
        _ask_anthropic(client)
        assert sink.records == []
        instrument_models(rec)
        with rec.run():
            _ask_anthropic(client)
        assert len(_events(sink)) == 1  # the old hook, still in their chain, passes straight through
        uninstrument_models()
        assert Messages.__dict__["create"] is theirs
    finally:
        Messages.create = original


@pytest.mark.parametrize("copy_metadata", [True, False], ids=["functools.wraps", "plain"])
def test_a_tool_over_the_hook_still_runs_and_a_wrapped_client_records_once(copy_metadata):
    wrapped_sink, wrapped_rec = _recorder()
    auto_sink, auto_rec = _recorder()
    original = Messages.__dict__["create"]
    instrument_models(auto_rec)
    hooked = Messages.__dict__["create"]
    ran = []

    def theirs(*args, **kwargs):
        ran.append(True)
        return hooked(*args, **kwargs)

    Messages.create = functools.wraps(hooked)(theirs) if copy_metadata else theirs
    try:
        client = instrument_anthropic(_client(anthropic.Anthropic, body=ANTHROPIC_RESPONSE), wrapped_rec)
        with wrapped_rec.run():
            _ask_anthropic(client)
    finally:
        Messages.create = original
    assert ran == [True]
    assert len(_events(wrapped_sink)) == 1 and not auto_sink.records


def test_a_wrapped_client_with_a_subclass_calling_super_records_once():
    class MyMessages(Messages):
        def create(self, **kwargs):
            return super().create(**kwargs)

    wrapped_sink, wrapped_rec = _recorder()
    auto_sink, auto_rec = _recorder()
    instrument_models(auto_rec)
    client = _client(anthropic.Anthropic, body=ANTHROPIC_RESPONSE)
    client.__dict__["messages"] = MyMessages(client)
    instrument_anthropic(client, wrapped_rec)
    with wrapped_rec.run():
        _ask_anthropic(client)
    assert len(_events(wrapped_sink)) == 1 and not auto_sink.records


def test_a_patch_that_ended_is_hooked_again_and_only_real_hooks_are_reported():
    sink, rec = _recorder()
    name = "anthropic.resources.messages.messages.Messages.create"
    with mock.patch.object(Messages, "create", return_value="fake"):
        assert name in instrument_models(rec)
    assert not hasattr(Messages.__dict__["create"], "_mnestiq_auto_original")
    with rec.run():
        names = instrument_models(rec)
        _ask_anthropic(_client(anthropic.Anthropic, body=ANTHROPIC_RESPONSE))
    assert name in names
    assert len(_events(sink)) == 1


def test_a_name_is_not_reported_when_the_attribute_is_no_longer_ours():
    rec = _recorder()[1]
    original = Messages.__dict__["create"]
    instrument_models(rec)
    Messages.create = original
    assert "anthropic.resources.messages.messages.Messages.create" not in auto._hooked_names()


def test_undo_when_the_method_was_inherited():
    class Inherits(Messages):
        pass

    instrument_models(_recorder()[1])
    with auto._install_lock:
        auto._hook(Inherits, "create", "messages")
    assert "create" in Inherits.__dict__
    uninstrument_models()
    assert "create" not in Inherits.__dict__


def test_install_and_undo_hold_the_lock(monkeypatch):
    held = []
    real_install = auto._install

    class CheckedHooks(dict):
        def items(self):
            held.append(auto._install_lock.locked())
            return super().items()

    def install():
        held.append(auto._install_lock.locked())
        real_install()

    monkeypatch.setattr(auto, "_hooks", CheckedHooks())
    monkeypatch.setattr(auto, "_install", install)
    instrument_models(_recorder()[1])
    uninstrument_models()
    assert held and all(held)


@pytest.mark.filterwarnings("ignore::RuntimeWarning")
def test_many_threads_instrumenting_undoing_and_calling():
    sink, rec = _recorder()
    pristine = _sdk_attributes()
    client = _client(anthropic.Anthropic, body=ANTHROPIC_RESPONSE)
    stream_client = _client(anthropic.Anthropic, _sse(STREAM_EVENTS))
    stop = threading.Event()
    errors = []

    def guarded(work):
        def loop():
            while not stop.is_set():
                try:
                    work()
                except BaseException as exc:
                    errors.append(repr(exc))
        return loop

    def stream_once():
        with stream_client.messages.stream(model="m", max_tokens=1, messages=USER) as stream:
            stream.get_final_text()

    def flip():
        instrument_models(rec)
        time.sleep(0.02)
        uninstrument_models()
        time.sleep(0.01)

    work = [lambda: _ask_anthropic(client)] * 3 + [stream_once, flip, flip]
    threads = [threading.Thread(target=guarded(w)) for w in work]
    for thread in threads:
        thread.start()
    time.sleep(1.0)
    stop.set()
    for thread in threads:
        thread.join(30)
    uninstrument_models()
    assert errors == []
    assert not any(thread.is_alive() for thread in threads)
    assert rec.failures == 0
    assert _events(sink)  # calls did land while it was on
    assert _sdk_attributes() == pristine and not auto._hooks
    _assert_valid(sink)


# --- failing open --------------------------------------------------------------------------

class _BrokenSink(MemorySink):
    def append(self, record):
        raise OSError("disk full")


@pytest.mark.parametrize("cls", [anthropic.Anthropic, anthropic.AsyncAnthropic], ids=lambda c: c.__name__)
@pytest.mark.filterwarnings("ignore::RuntimeWarning")
def test_a_broken_sink_never_reaches_the_agent(cls):
    rec = Recorder(_BrokenSink(), agent_id="a")
    instrument_models(rec)
    response = _ask_anthropic(_client(cls, body=ANTHROPIC_RESPONSE))
    assert response.id == "msg_1"
    assert rec.failures > 0


@pytest.mark.filterwarnings("ignore::RuntimeWarning")
def test_a_failure_while_recording_is_counted_not_raised():
    _, rec = _recorder()
    rec.tool_sources["fetch_page"] = "not-a-source"
    instrument_models(rec)
    with rec.run():
        assert _ask_anthropic(_client(anthropic.Anthropic, body=ANTHROPIC_RESPONSE)).id == "msg_1"
    assert rec.failures == 1


@pytest.mark.filterwarnings("ignore::RuntimeWarning")
def test_a_closed_recorder_never_reaches_the_agent():
    _, rec = _recorder()
    instrument_models(rec)
    rec.close()
    assert _ask_anthropic(_client(anthropic.Anthropic, body=ANTHROPIC_RESPONSE)).id == "msg_1"


def test_a_wrong_argument_is_not_raised_and_hooks_nothing():
    assert instrument_models(None) == []
    assert not auto._hooks


def test_a_missing_sdk_is_skipped(monkeypatch):
    real = auto.importlib.import_module

    def without_anthropic(name, *args):
        if name.startswith("anthropic"):
            raise ImportError(name)
        return real(name, *args)

    monkeypatch.setattr(auto.importlib, "import_module", without_anthropic)
    hooked = instrument_models(_recorder()[1])
    assert hooked and not any(name.startswith("anthropic") for name in hooked)


def _in_a_new_process(code):
    source = str(Path(mnestiq.__file__).parents[1])
    env = {**os.environ, "PYTHONPATH": source, "PYTHONDONTWRITEBYTECODE": "1"}
    return subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, env=env, timeout=120,
                          check=True)


def test_without_the_sdks_import_and_the_call_still_work():
    done = _in_a_new_process(
        "import sys\n"
        "sys.modules['anthropic'] = None\n"
        "sys.modules['openai'] = None\n"
        "import mnestiq\n"
        "print(mnestiq.instrument_models(mnestiq.Recorder(mnestiq.MemorySink(), agent_id='a')))\n"
        "mnestiq.uninstrument_models()\n")
    assert done.stdout.strip() == "[]"


def test_importing_mnestiq_does_not_import_the_sdks_or_hook_anything():
    done = _in_a_new_process(
        "import sys\n"
        "import mnestiq\n"
        "from mnestiq.integrations import auto\n"
        "print('anthropic' in sys.modules, 'openai' in sys.modules, len(auto._hooks))\n")
    assert done.stdout.strip() == "False False 0"


def test_without_the_call_a_client_records_nothing():
    sink, rec = _recorder()
    with rec.run():
        _ask_anthropic(_client(anthropic.Anthropic, body=ANTHROPIC_RESPONSE))
    assert _events(sink) == []
    assert not hasattr(Messages.__dict__["create"], "_mnestiq_auto_original")


# --- from the review -----------------------------------------------------------------------

def test_a_mock_on_the_sdk_class_is_called_as_without_the_hook():
    sink, rec = _recorder()
    with mock.patch.object(Messages, "create", return_value="fake") as patched:
        instrument_models(rec)
        with rec.run():
            assert _client(anthropic.Anthropic).messages.create(model="m", max_tokens=1, messages=USER) == "fake"
        assert patched.call_args.args == ()
        wrapped = instrument_anthropic(_client(anthropic.Anthropic), rec)
        with rec.run():
            assert wrapped.messages.create(model="m", max_tokens=1, messages=USER) == "fake"
    assert len(_events(sink)) == 2


def test_a_callable_object_on_the_sdk_class_is_not_given_the_instance():
    class Replacement:
        def __init__(self):
            self.args = None

        def __call__(self, *args, **kwargs):
            self.args = args
            return "from-replacement"

    original = Messages.__dict__["create"]
    replacement = Replacement()
    Messages.create = replacement
    try:
        instrument_models(_recorder()[1])
        client = _client(anthropic.Anthropic)
        assert client.messages.create(model="m", max_tokens=1, messages=USER) == "from-replacement"
        assert replacement.args == ()
    finally:
        uninstrument_models()
        Messages.create = original


def test_a_static_method_on_the_sdk_class_is_bound_as_without_the_hook():
    original = Messages.__dict__["create"]
    Messages.create = staticmethod(lambda **kwargs: "static")
    try:
        instrument_models(_recorder()[1])
        assert _client(anthropic.Anthropic).messages.create(model="m", max_tokens=1, messages=USER) == "static"
    finally:
        uninstrument_models()
        Messages.create = original


async def _cancel_a_call():
    started = asyncio.Event()

    async def handler(request):
        started.set()
        await asyncio.sleep(30)
        return httpx.Response(200, json=ANTHROPIC_RESPONSE)

    client = _client(anthropic.AsyncAnthropic, handler)
    task = asyncio.create_task(client.messages.create(model="m", max_tokens=1, messages=USER))
    await started.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task


def test_a_cancelled_call_is_recorded_and_the_cancel_goes_on():
    sink, rec = _recorder()
    instrument_models(rec)
    with rec.run():
        asyncio.run(_cancel_a_call())
    (call,) = _events(sink)
    assert call["status"] == "error" and "CancelledError" in call["error"]


def test_an_interrupt_during_a_sync_call_is_recorded():
    sink, rec = _recorder()
    instrument_models(rec)

    def handler(request):
        raise KeyboardInterrupt

    with rec.run(), pytest.raises(KeyboardInterrupt):
        _ask_anthropic(_client(anthropic.Anthropic, handler))
    assert _events(sink)[0]["status"] == "error"


def _body_for(request):
    return CHAT_RESPONSE if "chat" in request.url.path else ANTHROPIC_RESPONSE


@pytest.mark.parametrize(("build", "history"), [
    (anthropic.Anthropic, ["hello", {"role": "user", "content": "kept"}]),
    (anthropic.Anthropic, [{"role": "user", "content": 5}, {"role": "user", "content": "kept"}]),
    (openai.OpenAI, ["hello", {"role": "user", "content": "kept"}]),
    (openai.OpenAI, [{"role": "assistant", "tool_calls": [1]}, {"role": "user", "content": "kept"}]),
], ids=["anthropic-str", "anthropic-int-content", "chat-str", "chat-odd-tool-call"])
def test_one_odd_item_costs_only_its_own_place(build, history):
    sink, rec = _recorder()
    instrument_models(rec)
    client = _client(build, lambda request: httpx.Response(200, json=_body_for(request)))
    with rec.run():
        if build is openai.OpenAI:
            client.chat.completions.create(model="g", messages=history)
        else:
            client.messages.create(model="m", max_tokens=1, messages=history)
    assert rec.failures == 0
    (call,) = _events(sink)
    assert [s["source"] for s in call["context"]] == ["unknown", "user"]
    assert call["tool_calls"][0]["name"] == "send_email"


def test_an_odd_responses_item_and_odd_input_keep_the_reply():
    sink, rec = _recorder()
    instrument_models(rec)
    client = _client(openai.OpenAI, body=RESPONSES_RESPONSE)
    with rec.run():
        client.responses.create(model="g", input=[{"type": ["x"]}, {"role": "user", "content": "kept"}])
        client.responses.create(model="g", input=5)
    assert rec.failures == 0
    first, second = _events(sink)
    assert [s["source"] for s in first["context"]] == ["unknown", "user"]
    assert [s["source"] for s in second["context"]] == ["unknown"]
    assert first["tool_calls"][0]["name"] == "lookup"


@pytest.mark.parametrize("history", [
    [{"role": "assistant", "content": [{"type": "tool_use", "id": ["a"], "name": "x", "input": {}}]},
     {"role": "user", "content": [{"type": "tool_result", "tool_use_id": ["a"], "content": "x"}]}],
    [{"role": "assistant", "content": [{"type": "tool_use", "id": "a", "name": ["x"], "input": {}}]},
     {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "a", "content": "x"}]}],
], ids=["id-list", "name-list"])
def test_an_id_or_name_that_is_not_text_is_not_used_as_a_key_anthropic(history):
    sink, rec = _recorder()
    instrument_models(rec)
    with rec.run():
        _client(anthropic.Anthropic, body=ANTHROPIC_RESPONSE).messages.create(model="m", max_tokens=1, messages=history)
    assert rec.failures == 0
    assert [s["source"] for s in _events(sink)[0]["context"]] == ["model", "tool_output"]


def test_an_id_or_name_that_is_not_text_is_not_used_as_a_key_openai():
    sink, rec = _recorder()
    instrument_models(rec)
    chat = [{"role": "assistant", "tool_calls": [{"id": ["a"], "type": "function",
                                                  "function": {"name": ["n"], "arguments": "{}"}}]},
            {"role": "tool", "tool_call_id": ["a"], "content": "x"}]
    items = [{"type": "function_call", "call_id": ["a"], "name": ["n"], "arguments": "{}"},
             {"type": "function_call_output", "call_id": ["a"], "output": "x"}]
    client = _client(openai.OpenAI, lambda request: httpx.Response(
        200, json=CHAT_RESPONSE if "chat" in request.url.path else RESPONSES_RESPONSE))
    with rec.run():
        client.chat.completions.create(model="g", messages=chat)
        client.responses.create(model="g", input=items)
    assert rec.failures == 0
    first, second = _events(sink)
    assert [s["source"] for s in first["context"]] == ["model", "tool_output"]
    assert [s["source"] for s in second["context"]] == ["model", "tool_output"]


class _Answer(pydantic.BaseModel):
    x: int


def test_a_reply_that_fails_the_sdk_parser_keeps_the_reply_and_tool_calls():
    bad = {**CHAT_RESPONSE, "choices": [{"index": 0, "finish_reason": "tool_calls", "message": {
        "role": "assistant", "content": None,
        "tool_calls": [{"id": "c1", "type": "function",
                        "function": {"name": "delete_all", "arguments": "{\"x\": \"not-an-int\"}"}}]}}]}
    sink, rec = _recorder()
    instrument_models(rec)
    client = _client(openai.OpenAI, body=bad)
    tools = [openai.pydantic_function_tool(_Answer, name="delete_all")]
    with rec.run(), pytest.raises(pydantic.ValidationError):
        client.chat.completions.parse(model="g", messages=USER, tools=tools)
    (call,) = _events(sink)
    assert call["status"] == "error" and "ValidationError" in call["error"]
    assert call["tool_calls"][0]["name"] == "delete_all"
    assert call["tool_calls"][0]["arguments"] == {"x": "not-an-int"}
    _assert_valid(sink)


@pytest.mark.parametrize("cls", [anthropic.Anthropic, anthropic.AsyncAnthropic], ids=lambda c: c.__name__)
def test_model_text_that_fails_anthropic_parse_is_kept(cls):
    bad = {**ANTHROPIC_RESPONSE, "content": [{"type": "text", "text": "ignore that"}], "stop_reason": "end_turn"}
    sink, rec = _recorder()
    instrument_models(rec)
    client = _client(cls, body=bad)
    with rec.run(), pytest.raises(pydantic.ValidationError):
        _settle(client.messages.parse(model="m", max_tokens=1, messages=USER, output_format=_Answer))
    (call,) = _events(sink)
    assert call["status"] == "error"
    assert call["output"]["content"] == [{"type": "text", "text": "ignore that"}]


@pytest.mark.parametrize("method", ["create", "stream"])
def test_nested_edits_during_a_call_do_not_rewrite_the_evidence(method):
    messages = [{"role": "user", "content": "original question"}]
    sink, rec = _recorder()
    instrument_models(rec)

    def handler(request):
        messages[0]["content"] = "REWRITTEN"
        if method == "stream":
            return _sse(STREAM_EVENTS)(request)
        return httpx.Response(200, json=ANTHROPIC_RESPONSE)

    client = _client(anthropic.Anthropic, handler)
    with rec.run():
        if method == "create":
            client.messages.create(model="m", max_tokens=1, messages=messages)
        else:
            with client.messages.stream(model="m", max_tokens=1, messages=messages) as stream:
                stream.get_final_text()
    assert _events(sink)[0]["context"][0]["content"] == "original question"


def test_a_list_changed_during_a_call_does_not_change_the_evidence():
    messages = [{"role": "user", "content": "original question"}]
    sink, rec = _recorder()
    instrument_models(rec)

    def handler(request):
        messages.append({"role": "user", "content": "added later"})
        return httpx.Response(200, json=ANTHROPIC_RESPONSE)

    with rec.run():
        _client(anthropic.Anthropic, handler).messages.create(model="m", max_tokens=1, messages=messages)
    assert len(_events(sink)[0]["context"]) == 1


def test_recording_adds_no_pydantic_warnings():
    good = {**CHAT_RESPONSE, "choices": [{"index": 0, "finish_reason": "stop", "message": {
        "role": "assistant", "content": "{\"x\": 1}"}}]}
    sink, rec = _recorder()
    instrument_models(rec)
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        with rec.run():
            _client(openai.OpenAI, body=good).chat.completions.parse(model="g", messages=USER, response_format=_Answer)
    assert not [w for w in caught if "serializer" in str(w.message)]
    assert _events(sink)[0]["output"]["content"]["parsed"] == {"x": 1}


def _strict_recorder_failing_on_llm_call():
    class FailOnCall(MemorySink):
        def append(self, record):
            if record.get("event_type") == "llm_call":
                raise OSError("disk full")
            super().append(record)

    return Recorder(FailOnCall(), agent_id="a", strict=True)


def test_a_strict_recorder_raises_on_a_stream_as_on_create():
    rec = _strict_recorder_failing_on_llm_call()
    instrument_models(rec)
    client = _client(anthropic.Anthropic, _sse(STREAM_EVENTS))
    with rec.run(), pytest.raises(OSError, match="disk full"):
        with client.messages.stream(model="m", max_tokens=1, messages=USER) as stream:
            stream.get_final_text()


def test_a_strict_recorder_never_turns_a_cancel_into_something_else():
    rec = _strict_recorder_failing_on_llm_call()
    instrument_models(rec)
    with rec.run():
        asyncio.run(_cancel_a_call())


@pytest.mark.filterwarnings("ignore::RuntimeWarning")
def test_a_failure_recording_a_stream_is_counted():
    _, rec = _recorder()
    rec.tool_sources["fetch_page"] = "not-a-source"
    instrument_models(rec)
    client = _client(anthropic.Anthropic, _sse(STREAM_EVENTS))
    with rec.run(), client.messages.stream(model="m", max_tokens=1, messages=INJECTED_HISTORY) as stream:
        stream.get_final_text()
    assert rec.failures == 1


def test_a_stream_that_fails_to_open_is_recorded_and_raised():
    sink, rec = _recorder()
    instrument_models(rec)
    error = {"type": "error", "error": {"type": "api_error", "message": "x"}}
    client = _client(anthropic.Anthropic, lambda request: httpx.Response(500, json=error))
    with rec.run(), pytest.raises(anthropic.APIError):
        with client.messages.stream(model="m", max_tokens=1, messages=USER):
            pass
    (call,) = _events(sink)
    assert call["status"] == "error"


def test_an_async_api_error_is_recorded_and_raised():
    sink, rec = _recorder()
    instrument_models(rec)
    error = {"type": "error", "error": {"type": "api_error", "message": "x"}}
    client = _client(anthropic.AsyncAnthropic, lambda request: httpx.Response(500, json=error))
    with rec.run(), pytest.raises(anthropic.APIError):
        _ask_anthropic(client)
    assert _events(sink)[0]["status"] == "error"


def test_the_stream_manager_forwards_its_own_attributes():
    instrument_models(_recorder()[1])
    manager = _client(anthropic.Anthropic, _sse(STREAM_EVENTS)).messages.stream(model="m", max_tokens=1, messages=USER)
    assert callable(manager._MessageStreamManager__api_request)


def test_a_generator_that_raises_is_not_swallowed():
    def history():
        yield {"role": "user", "content": "first"}
        raise TypeError("bad item")

    sent = []

    def handler(request):
        sent.append(request)
        return httpx.Response(200, json=ANTHROPIC_RESPONSE)

    instrument_models(_recorder()[1])
    with pytest.raises(TypeError, match="bad item"):
        _client(anthropic.Anthropic, handler).messages.create(model="m", max_tokens=1, messages=history())
    assert sent == []


TOOL_STREAM = [
    {"type": "message_start", "message": {
        "id": "msg_s", "type": "message", "role": "assistant", "model": "c", "content": [],
        "stop_reason": None, "stop_sequence": None, "usage": {"input_tokens": 1, "output_tokens": 1}}},
    {"type": "content_block_start", "index": 0,
     "content_block": {"type": "tool_use", "id": "t1", "name": "send", "input": {}}},
    {"type": "content_block_delta", "index": 0,
     "delta": {"type": "input_json_delta", "partial_json": "{\"to\": \"evil"}},
    {"type": "content_block_delta", "index": 0,
     "delta": {"type": "input_json_delta", "partial_json": "@example.com\"}"}},
    {"type": "content_block_stop", "index": 0},
    {"type": "message_delta", "delta": {"stop_reason": "tool_use", "stop_sequence": None},
     "usage": {"output_tokens": 9}},
    {"type": "message_stop"},
]


def test_a_stream_closed_early_with_a_tool_call_is_marked_partial():
    sink, rec = _recorder()
    instrument_models(rec)
    client = _client(anthropic.Anthropic, _sse(TOOL_STREAM))
    with rec.run(), client.messages.stream(model="m", max_tokens=1, messages=USER) as stream:
        for i, _ in enumerate(stream):
            if i == 2:
                break
    (call,) = _events(sink)
    assert call["status"] == "error" and "before the message was complete" in call["error"]
    assert call["attributes"] == {"streaming": True, "partial": True}
    assert call["tool_calls"][0]["arguments"] == "{\"to\": \"evil"
    _assert_valid(sink)


def test_a_stream_read_to_the_end_is_not_partial():
    sink, rec = _recorder()
    instrument_models(rec)
    client = _client(anthropic.Anthropic, _sse(TOOL_STREAM))
    with rec.run(), client.messages.stream(model="m", max_tokens=1, messages=USER) as stream:
        stream.get_final_message()
    (call,) = _events(sink)
    assert call["status"] == "ok" and call["attributes"] == {"streaming": True}
    assert call["tool_calls"][0]["arguments"] == {"to": "evil@example.com"}


@pytest.mark.parametrize("cls", [anthropic.Anthropic, anthropic.AsyncAnthropic], ids=lambda c: c.__name__)
def test_an_unreadable_body_through_with_raw_response_is_not_recorded_as_ok(cls):
    sink, rec = _recorder()
    instrument_models(rec)
    client = _client(cls, lambda request: httpx.Response(200, content=b"<html>oops</html>",
                                                         headers={"content-type": "application/json"}))
    with rec.run():
        raw = _settle(client.messages.with_raw_response.create(model="m", max_tokens=1, messages=USER))
        with pytest.raises(json.JSONDecodeError):
            _settle(raw.parse())
    (call,) = _events(sink)
    assert call["status"] == "error" and "output" not in call


def test_async_with_raw_response_of_a_stream_is_left_unread():
    sink, rec = _recorder()
    instrument_models(rec)
    body = _AsyncWatchedBody(b"")
    client = _client(anthropic.AsyncAnthropic,
                     lambda request: httpx.Response(200, stream=body, headers={"content-type": "text/event-stream"}))

    async def go():
        await client.messages.with_raw_response.create(model="m", max_tokens=1, messages=USER, stream=True)
        return body.touched

    with rec.run():
        assert asyncio.run(go()) is False
    assert _events(sink)[0]["attributes"] == {"streaming": True, "output_captured": False}


def test_a_stream_manager_built_before_undo_and_entered_after_does_not_record():
    sink, rec = _recorder()
    instrument_models(rec)
    manager = _client(anthropic.Anthropic, _sse(STREAM_EVENTS)).messages.stream(model="m", max_tokens=1, messages=USER)
    uninstrument_models()
    with rec.run(), manager as stream:
        assert stream.get_final_text() == "Shipping takes 3-5 days."
    assert _events(sink) == []


def test_a_recorder_swap_during_a_call_does_not_reach_the_call_in_flight():
    old_sink, old = _recorder()
    new_sink, new = _recorder()
    new.tool_sources["fetch_page"] = "web"
    instrument_models(old, tool_sources={"other": "memory"})

    def handler(request):
        instrument_models(new, tool_sources={"fetch_page": "web"})
        return httpx.Response(200, json=ANTHROPIC_RESPONSE)

    with old.run():
        _client(anthropic.Anthropic, handler).messages.create(model="m", max_tokens=1, messages=INJECTED_HISTORY)
    (call,) = _events(old_sink)
    assert [s["source"] for s in call["context"]] == ["user", "model", "tool_output"]
    assert _events(new_sink) == []


def test_tool_sources_given_to_the_call_are_used():
    sink, rec = _recorder()
    instrument_models(rec, tool_sources={"fetch_page": "web"})
    with rec.run():
        _ask_anthropic(_client(anthropic.Anthropic, body=ANTHROPIC_RESPONSE))
    assert [s["source"] for s in _events(sink)[0]["context"]][-1] == "web"


def test_hooks_look_the_same_as_the_sdk_methods():
    before = _sdk_attributes()
    instrument_models(_recorder()[1])
    for (owner, name), held in before.items():
        if held != "absent":
            assert inspect.iscoroutinefunction(owner.__dict__[name]) == inspect.iscoroutinefunction(held), (owner, name)
            assert owner.__dict__[name].__name__ == held.__name__


@pytest.mark.parametrize("is_async", [False, True], ids=["sync", "async"])
def test_a_parse_that_calls_create_records_once(monkeypatch, is_async):
    """Older SDKs: openai 1.40 ``beta.chat.completions.parse`` called ``chat.completions.create`` on the client."""

    class Completions:
        def create(self, **kwargs):
            return CHAT_RESPONSE

        def parse(self, **kwargs):
            return self.create(**kwargs)

    class AsyncCompletions:
        async def create(self, **kwargs):
            return CHAT_RESPONSE

        async def parse(self, **kwargs):
            return await self.create(**kwargs)

    module = types.ModuleType("fake_sdk_module")
    module.Completions, module.AsyncCompletions = Completions, AsyncCompletions
    monkeypatch.setitem(sys.modules, "fake_sdk_module", module)
    monkeypatch.setattr(auto, "_TARGETS", (("fake_sdk_module", ("Completions", "AsyncCompletions"), "chat"),))
    cls = AsyncCompletions if is_async else Completions

    sink, rec = _recorder()
    instrument_models(rec)
    with rec.run():
        _settle(cls().parse(model="g", messages=USER))
    assert len(_events(sink)) == 1
    uninstrument_models()

    wrapped_sink, wrapped_rec = _recorder()
    client = types.SimpleNamespace(chat=types.SimpleNamespace(completions=cls()))
    instrument_openai(client, wrapped_rec)
    with wrapped_rec.run():
        _settle(client.chat.completions.parse(model="g", messages=USER))
    assert len(_events(wrapped_sink)) == 1


def test_a_model_call_in_another_thread_during_a_call_is_its_own_record():
    sink, rec = _recorder()
    instrument_models(rec)
    plain = _client(anthropic.Anthropic, body=ANTHROPIC_RESPONSE)

    def handler(request):
        thread = threading.Thread(target=_ask_anthropic, args=(plain,))
        thread.start()
        thread.join(10)
        return httpx.Response(200, json=ANTHROPIC_RESPONSE)

    with rec.run():
        _ask_anthropic(_client(anthropic.Anthropic, handler))
    assert len(_events(sink)) == 2


def test_a_model_call_inside_an_sdk_call_on_the_same_thread_is_the_outer_call():
    """A documented limit: an HTTP event hook or transport that calls a model is not recorded on its own."""
    sink, rec = _recorder()
    instrument_models(rec)
    plain = _client(anthropic.Anthropic, body=ANTHROPIC_RESPONSE)

    def handler(request):
        _ask_anthropic(plain)
        return httpx.Response(200, json=ANTHROPIC_RESPONSE)

    with rec.run():
        _ask_anthropic(_client(anthropic.Anthropic, handler))
    assert len(_events(sink)) == 1
