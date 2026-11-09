"""The hook on the SDKs' low-level request path: the real SDKs against a mocked HTTP transport."""

import asyncio
import functools
import json

import pytest

anthropic = pytest.importorskip("anthropic")
openai = pytest.importorskip("openai")
httpx = pytest.importorskip("httpx2")

from anthropic._base_client import AsyncAPIClient as AnthropicAsyncClient  # noqa: E402
from anthropic._base_client import SyncAPIClient as AnthropicSyncClient  # noqa: E402
from anthropic.resources.messages import Messages  # noqa: E402
from openai._base_client import AsyncAPIClient as OpenAIAsyncClient  # noqa: E402
from openai._base_client import SyncAPIClient as OpenAISyncClient  # noqa: E402

from mnestiq import MemorySink, Recorder, instrument_models, uninstrument_models, verify_lines  # noqa: E402
from mnestiq.canonical import canonical_json  # noqa: E402
from mnestiq.integrations import auto  # noqa: E402
from mnestiq.integrations.anthropic import instrument_anthropic  # noqa: E402
from test_auto_capture import CHAT_RESPONSE, RESPONSES_RESPONSE  # noqa: E402
from test_integrations import ANTHROPIC_RESPONSE, INJECTED_HISTORY, STREAM_EVENTS  # noqa: E402
from test_stream_capture import CHAT_STREAM  # noqa: E402

USER = [{"role": "user", "content": "hi"}]
ANTHROPIC_BODY = {"model": "m", "max_tokens": 1, "messages": INJECTED_HISTORY}
CHAT_BODY = {"model": "g", "messages": USER}


@pytest.fixture(autouse=True)
def undone():
    yield
    uninstrument_models()
    assert not auto._hooks


def _recorder():
    sink = MemorySink()
    return sink, Recorder(sink, agent_id="a")


def _events(sink):
    return [r for r in sink.records if r.get("event_type") == "llm_call"]


def _replies(body):
    return lambda request: httpx.Response(200, json=body)


def _client(cls, handler):
    http_cls = httpx.AsyncClient if "Async" in cls.__name__ else httpx.Client
    return cls(api_key="test", max_retries=0, http_client=http_cls(transport=httpx.MockTransport(handler)))


def _sse(events, *, named=True, done=False):
    def handler(request):
        text = "".join((f"event: {e['type']}\n" if named else "") + f"data: {json.dumps(e)}\n\n" for e in events)
        text += "data: [DONE]\n\n" if done else ""
        return httpx.Response(200, content=text.encode(), headers={"content-type": "text/event-stream"})
    return handler


def _valid(sink):
    report = verify_lines(canonical_json(r) for r in sink.records)
    assert report.ok, report.errors


@pytest.mark.parametrize(("cls", "path", "body", "reply", "tool"), [
    (anthropic.Anthropic, "/v1/messages", ANTHROPIC_BODY, ANTHROPIC_RESPONSE, "send_email"),
    (openai.OpenAI, "/chat/completions", CHAT_BODY, CHAT_RESPONSE, "send_email"),
    (openai.OpenAI, "/responses", {"model": "g", "input": USER}, RESPONSES_RESPONSE, "lookup"),
], ids=["messages", "chat", "responses"])
def test_a_low_level_post_is_recorded(cls, path, body, reply, tool):
    sink, rec = _recorder()
    instrument_models(rec)
    with rec.run():
        got = _client(cls, _replies(reply)).post(path, body=body, cast_to=object)
    assert isinstance(got, dict) and got["id"] == reply["id"]
    (call,) = _events(sink)
    assert call["tool_calls"][0]["name"] == tool
    assert call["model"]["name"] == body["model"]
    assert rec.failures == 0
    _valid(sink)


def test_the_context_of_a_low_level_post_is_read_with_provenance():
    sink, rec = _recorder()
    instrument_models(rec, tool_sources={"fetch_page": "web"})
    with rec.run():
        _client(anthropic.Anthropic, _replies(ANTHROPIC_RESPONSE)).post(
            "/v1/messages", body={**ANTHROPIC_BODY, "system": "sys"}, cast_to=object)
    assert [s["source"] for s in _events(sink)[0]["context"]] == ["system", "user", "model", "web"]


@pytest.mark.parametrize(("cls", "path", "body", "reply"), [
    (anthropic.AsyncAnthropic, "/v1/messages", ANTHROPIC_BODY, ANTHROPIC_RESPONSE),
    (openai.AsyncOpenAI, "/chat/completions", CHAT_BODY, CHAT_RESPONSE),
    (openai.AsyncOpenAI, "/responses", {"model": "g", "input": USER}, RESPONSES_RESPONSE),
], ids=["messages", "chat", "responses"])
def test_an_async_low_level_post_is_recorded(cls, path, body, reply):
    sink, rec = _recorder()
    instrument_models(rec)
    client = _client(cls, _replies(reply))

    async def go():
        return await client.post(path, body=body, cast_to=object)

    with rec.run():
        assert asyncio.run(go())["id"] == reply["id"]
    assert len(_events(sink)) == 1


def test_a_full_url_and_a_query_are_understood():
    sink, rec = _recorder()
    instrument_models(rec)
    client = _client(anthropic.Anthropic, _replies(ANTHROPIC_RESPONSE))
    with rec.run():
        client.post("https://api.anthropic.com/v1/messages", body=ANTHROPIC_BODY, cast_to=object)
        client.post("/v1/messages?beta=true", body=ANTHROPIC_BODY, cast_to=object)
    assert len(_events(sink)) == 2


def test_azure_deployment_paths_are_model_calls():
    sink, rec = _recorder()
    instrument_models(rec)
    client = openai.AzureOpenAI(api_key="test", max_retries=0, api_version="2025-01-01",
                                azure_endpoint="https://example.invalid",
                                http_client=httpx.Client(transport=httpx.MockTransport(_replies(CHAT_RESPONSE))))
    with rec.run():
        client.post("/deployments/d1/chat/completions", body=CHAT_BODY, cast_to=object)
    assert len(_events(sink)) == 1


@pytest.mark.parametrize(("cls", "method", "path"), [
    (anthropic.Anthropic, "post", "/v1/messages/batches"),
    (anthropic.Anthropic, "post", "/v1/messages/count_tokens"),
    (anthropic.Anthropic, "post", "/v1/complete"),
    (anthropic.Anthropic, "post", "/v1/files"),
    (anthropic.Anthropic, "get", "/v1/models"),
    (anthropic.Anthropic, "get", "/v1/messages"),
    (openai.OpenAI, "post", "/embeddings"),
    (openai.OpenAI, "post", "/completions"),
    (openai.OpenAI, "post", "/threads/t1/messages"),
    (openai.OpenAI, "post", "/responses/compact"),
    (openai.OpenAI, "post", "/responses/resp_1/cancel"),
    (openai.OpenAI, "post", "/chat/completions/c1"),
    (openai.OpenAI, "get", "/responses/resp_1"),
    (openai.OpenAI, "get", "/chat/completions"),
], ids=lambda v: v if isinstance(v, str) else None)
def test_other_endpoints_pass_through_unrecorded(cls, method, path):
    sink, rec = _recorder()
    instrument_models(rec)
    seen = []

    def handler(request):
        seen.append(request.url.path)
        return httpx.Response(200, json={"ok": True})

    with rec.run():
        client = _client(cls, handler)
        got = getattr(client, method)(path, cast_to=object)
    assert got == {"ok": True} and len(seen) == 1
    assert _events(sink) == []


def test_a_bound_method_saved_before_instrumenting_is_recorded():
    sink, rec = _recorder()
    client = _client(anthropic.Anthropic, _replies(ANTHROPIC_RESPONSE))
    saved_create = client.messages.create
    saved_post = client.post
    instrument_models(rec)
    with rec.run():
        saved_create(model="m", max_tokens=1, messages=USER)
        saved_post("/v1/messages", body=ANTHROPIC_BODY, cast_to=object)
    assert len(_events(sink)) == 2


def test_a_saved_with_raw_response_is_recorded():
    sink, rec = _recorder()
    client = _client(anthropic.Anthropic, _replies(ANTHROPIC_RESPONSE))
    raw = client.messages.with_raw_response
    instrument_models(rec)
    with rec.run():
        assert raw.create(model="m", max_tokens=1, messages=USER).parse().id == "msg_1"
    (call,) = _events(sink)
    assert call["tool_calls"][0]["name"] == "send_email"


def test_a_method_replaced_on_one_client_is_recorded():
    sink, rec = _recorder()
    client = _client(anthropic.Anthropic, _replies(ANTHROPIC_RESPONSE))
    original = Messages.create.__get__(client.messages)
    client.messages.create = functools.partial(original, max_tokens=1)
    instrument_models(rec)
    with rec.run():
        client.messages.create(model="m", messages=USER)
    assert len(_events(sink)) == 1


def test_a_method_saved_on_an_openai_client_is_recorded():
    sink, rec = _recorder()
    client = _client(openai.OpenAI, _replies(CHAT_RESPONSE))
    saved = client.chat.completions.create
    instrument_models(rec)
    with rec.run():
        saved(model="g", messages=USER)
    assert len(_events(sink)) == 1


# --- never twice -----------------------------------------------------------------------------

@pytest.mark.parametrize(("cls", "ask"), [
    (anthropic.Anthropic, lambda c: c.messages.create(model="m", max_tokens=1, messages=USER)),
    (openai.OpenAI, lambda c: c.chat.completions.create(model="g", messages=USER)),
], ids=["messages", "chat"])
def test_a_public_method_is_not_recorded_again_by_the_transport_hook(cls, ask):
    body = ANTHROPIC_RESPONSE if cls is anthropic.Anthropic else CHAT_RESPONSE
    sink, rec = _recorder()
    instrument_models(rec)
    with rec.run():
        ask(_client(cls, _replies(body)))
    assert len(_events(sink)) == 1


def test_a_wrapped_client_is_not_recorded_again():
    sink, rec = _recorder()
    auto_sink, auto_rec = _recorder()
    instrument_models(auto_rec)
    client = instrument_anthropic(_client(anthropic.Anthropic, _replies(ANTHROPIC_RESPONSE)), rec)
    with rec.run():
        client.messages.create(model="m", max_tokens=1, messages=USER)
    assert len(_events(sink)) == 1 and not auto_sink.records


# --- streaming through this path -------------------------------------------------------------

def test_a_streamed_post_is_captured_and_passes_unchanged():
    sink, rec = _recorder()
    instrument_models(rec)
    client = _client(anthropic.Anthropic, _sse(STREAM_EVENTS))
    with rec.run():
        stream = client.post("/v1/messages", body={**ANTHROPIC_BODY, "stream": True}, cast_to=object, stream=True,
                             stream_cls=anthropic.Stream[object])
        got = list(stream)
    assert [g["type"] for g in got] == [e["type"] for e in STREAM_EVENTS]
    (call,) = _events(sink)
    assert call["output"]["content"] == [{"type": "text", "text": "Shipping takes 3-5 days."}]
    assert call["attributes"] == {"streaming": True}
    _valid(sink)


def test_an_async_streamed_post_is_captured():
    sink, rec = _recorder()
    instrument_models(rec)
    client = _client(openai.AsyncOpenAI, _sse(CHAT_STREAM, named=False, done=True))

    async def go():
        stream = await client.post("/chat/completions", body={**CHAT_BODY, "stream": True}, cast_to=object, stream=True,
                                   stream_cls=openai.AsyncStream[object])
        return [c async for c in stream]

    with rec.run():
        got = asyncio.run(go())
    assert len(got) == len(CHAT_STREAM)
    (call,) = _events(sink)
    assert call["attributes"] == {"streaming": True}
    assert call["tool_calls"][0]["name"] == "send_email"


def test_a_streamed_post_closed_early_is_partial():
    sink, rec = _recorder()
    instrument_models(rec)
    client = _client(anthropic.Anthropic, _sse(STREAM_EVENTS))
    with rec.run():
        with client.post("/v1/messages", body={**ANTHROPIC_BODY, "stream": True}, cast_to=object, stream=True,
                         stream_cls=anthropic.Stream[object]) as stream:
            next(stream)
    assert _events(sink)[0]["attributes"]["output_captured"] == "partial"


def test_a_saved_stream_helper_is_captured_through_the_transport():
    sink, rec = _recorder()
    client = _client(anthropic.Anthropic, _sse(STREAM_EVENTS))
    saved = client.messages.create
    instrument_models(rec)
    with rec.run():
        events = list(saved(model="m", max_tokens=10, messages=USER, stream=True))
    assert len(events) == len(STREAM_EVENTS)
    assert _events(sink)[0]["output"]["content"][0]["text"] == "Shipping takes 3-5 days."


# --- replies in other shapes -----------------------------------------------------------------

def test_a_raw_http_response_is_read_for_the_record():
    sink, rec = _recorder()
    instrument_models(rec)
    client = _client(anthropic.Anthropic, _replies(ANTHROPIC_RESPONSE))
    with rec.run():
        response = client.post("/v1/messages", body=ANTHROPIC_BODY, cast_to=httpx.Response)
    assert response.status_code == 200
    (call,) = _events(sink)
    assert call["tool_calls"][0]["name"] == "send_email"


def test_a_reply_that_is_not_json_is_said_not_to_be_captured():
    sink, rec = _recorder()
    instrument_models(rec)
    client = _client(anthropic.Anthropic, lambda request: httpx.Response(200, text="not json"))
    with rec.run():
        assert client.post("/v1/messages", body=ANTHROPIC_BODY, cast_to=str) == "not json"
    (call,) = _events(sink)
    assert call["attributes"]["output_captured"] is False and "output" not in call


def test_an_unread_raw_stream_is_left_unread():
    class Body(httpx.SyncByteStream):
        touched = False

        def __iter__(self):
            Body.touched = True
            yield b"event: message_start\ndata: {}\n\n"

    sink, rec = _recorder()
    instrument_models(rec)
    client = _client(anthropic.Anthropic, lambda request: httpx.Response(
        200, stream=Body(), headers={"content-type": "text/event-stream"}))
    with rec.run():
        response = client.post("/v1/messages", body=ANTHROPIC_BODY, cast_to=httpx.Response, stream=True)
        assert not Body.touched
        assert b"message_start" in response.read()
    (call,) = _events(sink)
    assert call["attributes"]["output_captured"] is False


def test_an_api_error_on_a_post_is_recorded_and_raised():
    sink, rec = _recorder()
    instrument_models(rec)
    error = {"type": "error", "error": {"type": "api_error", "message": "x"}}
    client = _client(anthropic.Anthropic, lambda request: httpx.Response(500, json=error))
    with rec.run(), pytest.raises(anthropic.APIStatusError):
        client.post("/v1/messages", body=ANTHROPIC_BODY, cast_to=object)
    (call,) = _events(sink)
    assert call["status"] == "error"


def test_a_generator_in_a_post_body_reaches_the_sdk_as_a_list():
    sent = []

    def handler(request):
        sent.append(json.loads(request.content))
        return httpx.Response(200, json=ANTHROPIC_RESPONSE)

    sink, rec = _recorder()
    instrument_models(rec)
    body = {"model": "m", "max_tokens": 1, "messages": (m for m in USER)}
    with rec.run():
        _client(anthropic.Anthropic, handler).post("/v1/messages", body=body, cast_to=object)
    assert sent[0]["messages"] == USER
    assert _events(sink)[0]["context"][0]["content"] == "hi"


@pytest.mark.parametrize("client_cls", [anthropic.Anthropic, openai.OpenAI], ids=["anthropic", "openai"])
def test_the_request_body_is_left_as_it_was(client_cls):
    reply = ANTHROPIC_RESPONSE if client_cls is anthropic.Anthropic else CHAT_RESPONSE
    path = "/v1/messages" if client_cls is anthropic.Anthropic else "/chat/completions"
    body = {"model": "m", "max_tokens": 1, "messages": [{"role": "user", "content": "kept"}]}
    before = json.dumps(body)
    sent = []

    def handler(request):
        sent.append(json.loads(request.content))
        return httpx.Response(200, json=reply)

    instrument_models(_recorder()[1])
    _client(client_cls, handler).post(path, body=body, cast_to=object)
    assert json.dumps(body) == before and sent == [json.loads(before)]


def test_extra_body_is_recorded_like_the_rest():
    sink, rec = _recorder()
    client = _client(anthropic.Anthropic, _replies(ANTHROPIC_RESPONSE))
    saved = client.messages.create
    instrument_models(rec)
    with rec.run():
        saved(model="m", max_tokens=1, messages=USER, extra_body={"system": "from extra"})
    assert _events(sink)[0]["context"][0]["content"] == "from extra"


# --- undo --------------------------------------------------------------------------------------

_REQUESTS = [(AnthropicSyncClient, "request"), (AnthropicAsyncClient, "request"),
             (OpenAISyncClient, "request"), (OpenAIAsyncClient, "request")]


def test_request_is_hooked_and_restored_exactly():
    before = [owner.__dict__[name] for owner, name in _REQUESTS]
    hooked = instrument_models(_recorder()[1])
    assert "anthropic._base_client.SyncAPIClient.request" in hooked
    assert "openai._base_client.AsyncAPIClient.request" in hooked
    assert [owner.__dict__[name] for owner, name in _REQUESTS] != before
    uninstrument_models()
    assert [owner.__dict__[name] for owner, name in _REQUESTS] == before


def test_nothing_is_recorded_after_undo():
    sink, rec = _recorder()
    instrument_models(rec)
    client = _client(anthropic.Anthropic, _replies(ANTHROPIC_RESPONSE))
    uninstrument_models()
    client.post("/v1/messages", body=ANTHROPIC_BODY, cast_to=object)
    assert sink.records == []


def test_a_third_party_wrapping_request_after_us_is_left_in_place():
    sink, rec = _recorder()
    original = AnthropicSyncClient.__dict__["request"]
    instrument_models(rec)
    hooked = AnthropicSyncClient.__dict__["request"]

    def theirs(*args, **kwargs):
        return hooked(*args, **kwargs)

    AnthropicSyncClient.request = theirs
    try:
        uninstrument_models()
        assert AnthropicSyncClient.__dict__["request"] is theirs
        client = _client(anthropic.Anthropic, _replies(ANTHROPIC_RESPONSE))
        client.post("/v1/messages", body=ANTHROPIC_BODY, cast_to=object)
        assert sink.records == []
    finally:
        AnthropicSyncClient.request = original


# --- fail open ---------------------------------------------------------------------------------

class _BrokenSink(MemorySink):
    def append(self, record):
        raise OSError("disk full")


@pytest.mark.filterwarnings("ignore::RuntimeWarning")
def test_a_broken_sink_never_reaches_a_post():
    rec = Recorder(_BrokenSink(), agent_id="a")
    instrument_models(rec)
    client = _client(anthropic.Anthropic, _replies(ANTHROPIC_RESPONSE))
    assert client.post("/v1/messages", body=ANTHROPIC_BODY, cast_to=object)["id"] == "msg_1"
    assert rec.failures > 0


def test_a_body_that_cannot_be_read_is_recorded_without_it():
    sink, rec = _recorder()
    instrument_models(rec)
    client = _client(anthropic.Anthropic, _replies(ANTHROPIC_RESPONSE))
    with rec.run():
        client.post("/v1/messages", content=b"\x00\x01 not json", cast_to=object)
    (call,) = _events(sink)
    assert call["model"]["name"] == "<unknown>" and call["tool_calls"][0]["name"] == "send_email"
    assert rec.failures == 0


# --- third parties and old hooks -------------------------------------------------------------

def _third_party_over(owner):
    held = owner.__dict__["request"]

    @functools.wraps(held)
    def theirs(*args, **kwargs):
        return held(*args, **kwargs)

    owner.request = theirs
    return held


def _models(request):
    return httpx.Response(200, json=ANTHROPIC_RESPONSE if request.method == "POST" else {"data": []})


def test_a_third_party_between_two_instruments_does_not_loop():
    sink, rec = _recorder()
    original = AnthropicSyncClient.__dict__["request"]
    instrument_models(rec)
    _third_party_over(AnthropicSyncClient)
    instrument_models(rec)
    try:
        client = _client(anthropic.Anthropic, _models)
        assert client.get("/v1/models", cast_to=object) == {"data": []}
        with rec.run():
            client.post("/v1/messages", body=ANTHROPIC_BODY, cast_to=object)
            client.messages.create(model="m", max_tokens=1, messages=USER)
        assert len(_events(sink)) == 2
    finally:
        uninstrument_models()
        AnthropicSyncClient.request = original


def test_an_old_hook_put_back_by_a_third_party_is_replaced_and_undone_exactly():
    sink, rec = _recorder()
    original = AnthropicSyncClient.__dict__["request"]
    instrument_models(rec)
    old_hook = AnthropicSyncClient.__dict__["request"]
    _third_party_over(AnthropicSyncClient)
    uninstrument_models()
    AnthropicSyncClient.request = old_hook  # what the third party saved
    try:
        instrument_models(rec)
        client = _client(anthropic.Anthropic, _models)
        assert client.get("/v1/models", cast_to=object) == {"data": []}
        with rec.run():
            client.post("/v1/messages", body=ANTHROPIC_BODY, cast_to=object)
        assert len(_events(sink)) == 1
        uninstrument_models()
        assert AnthropicSyncClient.__dict__["request"] is original
    finally:
        AnthropicSyncClient.request = original


# --- what is never read for the caller ---------------------------------------------------------

class _NotJson(httpx.SyncByteStream):
    def __init__(self):
        self.pulled = 0

    def __iter__(self):
        for _ in range(3):
            self.pulled += 1
            yield b"chunk"


class _AsyncNotJson(httpx.AsyncByteStream):
    def __init__(self):
        self.pulled = 0

    async def __aiter__(self):
        for _ in range(3):
            self.pulled += 1
            yield b"chunk"


def _plain(body):
    return lambda request: httpx.Response(200, stream=body, headers={"content-type": "text/plain"})


def test_a_saved_streaming_response_is_not_read_for_the_caller():
    body = _NotJson()
    sink, rec = _recorder()
    client = _client(openai.OpenAI, _plain(body))
    saved = client.chat.completions.with_streaming_response.create
    instrument_models(rec)
    with rec.run(), saved(model="g", messages=USER) as response:
        assert body.pulled == 0
        assert response.read() == b"chunkchunkchunk"
    (call,) = _events(sink)
    assert call["attributes"]["output_captured"] is False


@pytest.mark.filterwarnings("error::RuntimeWarning")
def test_a_saved_async_streaming_response_is_not_read_for_the_caller():
    body = _AsyncNotJson()
    sink, rec = _recorder()
    client = _client(openai.AsyncOpenAI, _plain(body))
    saved = client.chat.completions.with_streaming_response.create
    instrument_models(rec)

    async def go():
        async with saved(model="g", messages=USER) as response:
            assert body.pulled == 0
            return await response.read()

    with rec.run():
        assert asyncio.run(go()) == b"chunkchunkchunk"
    (call,) = _events(sink)
    assert call["attributes"]["output_captured"] is False
