"""Streams from create(stream=True) and the OpenAI helpers: the real SDKs against a mocked HTTP transport."""

import asyncio
import contextlib
import contextvars
import gc
import json
import threading
import time
import weakref
from pathlib import Path

import pytest

anthropic = pytest.importorskip("anthropic")
openai = pytest.importorskip("openai")
httpx = pytest.importorskip("httpx2")

from mnestiq import MemorySink, Recorder, instrument_models, uninstrument_models, verify_lines  # noqa: E402
from mnestiq.canonical import canonical_json  # noqa: E402
from mnestiq.findings import findings as all_findings  # noqa: E402
from mnestiq.integrations import _common  # noqa: E402
from mnestiq.integrations.anthropic import instrument_anthropic  # noqa: E402
from mnestiq.integrations.openai import instrument_openai  # noqa: E402
from test_integrations import STREAM_EVENTS  # noqa: E402

USER = [{"role": "user", "content": "hi"}]
SAID = "Shipping takes 3-5 days."

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


def _chat_chunk(delta, finish_reason=None, usage=None):
    return {"id": "c1", "object": "chat.completion.chunk", "created": 1, "model": "g-1", "usage": usage,
            "choices": [{"index": 0, "finish_reason": finish_reason, "delta": delta}]}


CHAT_STREAM = [
    _chat_chunk({"role": "assistant", "content": "Hel"}),
    _chat_chunk({"content": "lo"}),
    _chat_chunk({"tool_calls": [{"index": 0, "id": "call_1", "type": "function",
                                 "function": {"name": "send_email", "arguments": "{\"to\": "}}]}),
    _chat_chunk({"tool_calls": [{"index": 0, "function": {"arguments": "\"evil@example.com\"}"}}]}),
    _chat_chunk({}, finish_reason="tool_calls"),
    {"id": "c1", "object": "chat.completion.chunk", "created": 1, "model": "g-1", "choices": [],
     "usage": {"prompt_tokens": 3, "completion_tokens": 4, "total_tokens": 7}},
]

_FINAL_MESSAGE = {"type": "message", "id": "m1", "role": "assistant", "status": "completed",
                  "content": [{"type": "output_text", "text": "Hello", "annotations": []}]}
_FINAL_CALL = {"type": "function_call", "id": "f1", "call_id": "call_2", "name": "lookup",
               "arguments": "{\"q\": \"x\"}", "status": "completed"}
_RESPONSE_FIELDS = {"created_at": 1, "object": "response", "parallel_tool_calls": True, "tool_choice": "auto",
                    "tools": []}
RESPONSES_STREAM = [
    {"type": "response.created", "sequence_number": 0, "response": {
        "id": "resp_1", "model": "g-1", "status": "in_progress", "output": [], **_RESPONSE_FIELDS}},
    {"type": "response.output_item.added", "sequence_number": 1, "output_index": 0,
     "item": {"type": "message", "id": "m1", "role": "assistant", "status": "in_progress", "content": []}},
    {"type": "response.content_part.added", "sequence_number": 2, "output_index": 0, "content_index": 0,
     "item_id": "m1", "part": {"type": "output_text", "text": "", "annotations": []}},
    {"type": "response.output_text.delta", "sequence_number": 3, "output_index": 0, "content_index": 0,
     "item_id": "m1", "delta": "Hel", "logprobs": []},
    {"type": "response.output_text.delta", "sequence_number": 4, "output_index": 0, "content_index": 0,
     "item_id": "m1", "delta": "lo", "logprobs": []},
    {"type": "response.output_item.done", "sequence_number": 5, "output_index": 0, "item": _FINAL_MESSAGE},
    {"type": "response.output_item.added", "sequence_number": 6, "output_index": 1,
     "item": {**_FINAL_CALL, "arguments": "", "status": "in_progress"}},
    {"type": "response.function_call_arguments.delta", "sequence_number": 7, "output_index": 1,
     "item_id": "f1", "delta": "{\"q\": \"x\"}"},
    {"type": "response.output_item.done", "sequence_number": 8, "output_index": 1, "item": _FINAL_CALL},
    {"type": "response.completed", "sequence_number": 9, "response": {
        "id": "resp_1", "model": "g-1", "status": "completed", "output": [_FINAL_MESSAGE, _FINAL_CALL],
        "usage": {"input_tokens": 5, "output_tokens": 6, "total_tokens": 11}, **_RESPONSE_FIELDS}},
]


@pytest.fixture(autouse=True)
def undone():
    yield
    uninstrument_models()


def _recorder(**options):
    sink = MemorySink()
    return sink, Recorder(sink, agent_id="a", **options)


def _events(sink, kind="llm_call"):
    return [r for r in sink.records if r.get("event_type") == kind]


def _sse(events, *, named=True, done=False):
    def handler(request):
        text = "".join((f"event: {e['type']}\n" if named else "") + f"data: {json.dumps(e)}\n\n" for e in events)
        text += "data: [DONE]\n\n" if done else ""
        return httpx.Response(200, content=text.encode(), headers={"content-type": "text/event-stream"})
    return handler


def _client(cls, handler):
    http_cls = httpx.AsyncClient if "Async" in cls.__name__ else httpx.Client
    return cls(api_key="test", max_retries=0, http_client=http_cls(transport=httpx.MockTransport(handler)))


def _valid(sink):
    report = verify_lines(canonical_json(r) for r in sink.records)
    assert report.ok, report.errors


# Each provider's way of asking for a stream, and what that stream sends.
def _create_messages(client, **kw):
    return client.messages.create(model="m", max_tokens=10, messages=USER, stream=True, **kw)


def _create_beta(client, **kw):
    return client.beta.messages.create(model="m", max_tokens=10, messages=USER, stream=True, **kw)


def _create_chat(client, **kw):
    return client.chat.completions.create(model="g", messages=USER, stream=True, **kw)


def _create_responses(client, **kw):
    return client.responses.create(model="g", input=USER, stream=True, **kw)


FLAVOURS = [
    pytest.param(anthropic.Anthropic, _create_messages, STREAM_EVENTS, True, id="messages"),
    pytest.param(anthropic.Anthropic, _create_beta, STREAM_EVENTS, True, id="beta-messages"),
    pytest.param(openai.OpenAI, _create_chat, CHAT_STREAM, False, id="chat"),
    pytest.param(openai.OpenAI, _create_responses, RESPONSES_STREAM, False, id="responses"),
]
ASYNC_FLAVOURS = [
    pytest.param(anthropic.AsyncAnthropic, _create_messages, STREAM_EVENTS, True, id="messages"),
    pytest.param(anthropic.AsyncAnthropic, _create_beta, STREAM_EVENTS, True, id="beta-messages"),
    pytest.param(openai.AsyncOpenAI, _create_chat, CHAT_STREAM, False, id="chat"),
    pytest.param(openai.AsyncOpenAI, _create_responses, RESPONSES_STREAM, False, id="responses"),
]


def _dumps(chunks):
    return [c.model_dump() for c in chunks]


def _unwatched_chunks(cls, create, events, named):
    """What the SDK alone gives for these events: the reference to compare with."""
    client = _client(cls, _sse(events, named=named, done=not named))
    if "Async" in cls.__name__:
        async def go():
            return [c async for c in await create(client)]
        return _dumps(asyncio.run(go()))
    return _dumps(create(client))


@pytest.mark.parametrize(("cls", "create", "events", "named"), FLAVOURS)
def test_each_chunk_is_identical_and_it_is_recorded_whole(cls, create, events, named):
    expected = _unwatched_chunks(cls, create, events, named)
    sink, rec = _recorder()
    instrument_models(rec)
    client = _client(cls, _sse(events, named=named, done=not named))
    with rec.run():
        stream = create(client)
        assert type(stream).__name__ == "Stream"
        got = list(stream)
    assert _dumps(got) == expected and got
    (call,) = _events(sink)
    assert call["attributes"] == {"streaming": True}
    assert call["status"] == "ok" and "error" not in call
    assert rec.failures == 0
    _valid(sink)


@pytest.mark.parametrize(("cls", "create", "events", "named"), ASYNC_FLAVOURS)
def test_async_each_chunk_is_identical_and_it_is_recorded_whole(cls, create, events, named):
    expected = _unwatched_chunks(cls, create, events, named)
    sink, rec = _recorder()
    instrument_models(rec)
    client = _client(cls, _sse(events, named=named, done=not named))

    async def go():
        stream = await create(client)
        assert type(stream).__name__ == "AsyncStream"
        return [c async for c in stream]

    with rec.run():
        got = asyncio.run(go())
    assert _dumps(got) == expected and got
    (call,) = _events(sink)
    assert call["attributes"] == {"streaming": True}
    assert rec.failures == 0
    _valid(sink)


def test_anthropic_text_and_tool_input_and_usage_are_rebuilt():
    sink, rec = _recorder()
    instrument_models(rec)
    with rec.run():
        list(_create_messages(_client(anthropic.Anthropic, _sse(STREAM_EVENTS))))
        list(_create_messages(_client(anthropic.Anthropic, _sse(TOOL_STREAM))))
    text, tool = _events(sink)
    assert text["output"]["content"] == [{"type": "text", "text": SAID}]
    assert text["output"]["stop_reason"] == "end_turn" and text["output"]["response_id"] == "msg_s"
    assert text["usage"] == {"input_tokens": 12, "output_tokens": 9}
    assert text["model"]["version"] == "claude-opus-5-5"
    assert tool["tool_calls"][0]["name"] == "send"
    assert tool["tool_calls"][0]["arguments"] == {"to": "evil@example.com"}
    assert tool["output"]["content"][0]["input"] == {"to": "evil@example.com"}


def test_chat_text_and_tool_calls_are_rebuilt():
    sink, rec = _recorder()
    instrument_models(rec)
    with rec.run():
        list(_create_chat(_client(openai.OpenAI, _sse(CHAT_STREAM, named=False, done=True))))
    (call,) = _events(sink)
    assert call["output"]["content"]["content"] == "Hello"
    assert call["output"]["stop_reason"] == "tool_calls"
    assert call["tool_calls"][0]["name"] == "send_email"
    assert call["tool_calls"][0]["arguments"] == {"to": "evil@example.com"}
    assert call["usage"] == {"input_tokens": 3, "output_tokens": 4}
    assert call["model"]["version"] == "g-1" and call["output"]["response_id"] == "c1"


def test_responses_output_comes_from_the_final_event():
    sink, rec = _recorder()
    instrument_models(rec)
    with rec.run():
        list(_create_responses(_client(openai.OpenAI, _sse(RESPONSES_STREAM, named=False))))
    (call,) = _events(sink)
    assert call["output"]["content"][0]["content"][0]["text"] == "Hello"
    assert call["tool_calls"][0]["name"] == "lookup" and call["tool_calls"][0]["arguments"] == {"q": "x"}
    assert call["output"]["stop_reason"] == "completed"
    assert call["usage"] == {"input_tokens": 5, "output_tokens": 6}


def test_the_evidence_matches_a_reply_that_was_not_streamed():
    whole = {"id": "c1", "object": "chat.completion", "created": 1, "model": "g-1", "choices": [
        {"index": 0, "finish_reason": "tool_calls", "message": {
            "role": "assistant", "content": "Hello",
            "tool_calls": [{"id": "call_1", "type": "function",
                            "function": {"name": "send_email", "arguments": "{\"to\": \"evil@example.com\"}"}}]}}],
        "usage": {"prompt_tokens": 3, "completion_tokens": 4, "total_tokens": 7}}
    sink, rec = _recorder()
    instrument_models(rec)
    with rec.run():
        list(_create_chat(_client(openai.OpenAI, _sse(CHAT_STREAM, named=False, done=True))))
        _client(openai.OpenAI, lambda request: httpx.Response(200, json=whole)).chat.completions.create(
            model="g", messages=USER)
    streamed, plain = _events(sink)
    for field in ("tool_calls", "usage"):
        assert _no_salt(streamed[field]) == _no_salt(plain[field])
    assert _no_salt(streamed["output"]) == _no_salt(plain["output"])


def _no_salt(value):
    if isinstance(value, dict):
        return {k: _no_salt(v) for k, v in value.items() if not k.endswith(("_salt", "_hash"))}
    if isinstance(value, list):
        return [_no_salt(v) for v in value]
    return value


def test_chunks_are_not_read_ahead():
    """The first chunk reaches the caller before the transport is asked for the second."""
    pulled = []

    class Body(httpx.SyncByteStream):
        def __iter__(self):
            for i, event in enumerate(STREAM_EVENTS):
                pulled.append(i)
                yield f"event: {event['type']}\ndata: {json.dumps(event)}\n\n".encode()

    _, rec = _recorder()
    instrument_models(rec)
    client = _client(anthropic.Anthropic, lambda request: httpx.Response(
        200, stream=Body(), headers={"content-type": "text/event-stream"}))
    with rec.run():
        stream = _create_messages(client)
        assert pulled == []
        assert next(stream).type == "message_start"
        assert pulled == [0]
        stream.close()
    assert pulled == [0]


# --- the stream helpers ----------------------------------------------------------------------

def test_openai_chat_stream_helper_is_recorded_whole():
    sink, rec = _recorder()
    instrument_models(rec)
    client = _client(openai.OpenAI, _sse(CHAT_STREAM, named=False, done=True))
    with rec.run(), client.chat.completions.stream(model="g", messages=USER) as stream:
        completion = stream.get_final_completion()
    assert completion.choices[0].message.content == "Hello"
    (call,) = _events(sink)
    assert call["attributes"] == {"streaming": True}
    assert call["tool_calls"][0]["name"] == "send_email"


def test_openai_chat_stream_helper_closed_early_is_partial():
    sink, rec = _recorder()
    instrument_models(rec)
    client = _client(openai.OpenAI, _sse(CHAT_STREAM, named=False, done=True))
    with rec.run(), client.chat.completions.stream(model="g", messages=USER) as stream:
        next(iter(stream))
    (call,) = _events(sink)
    assert call["attributes"]["output_captured"] == "partial"
    assert call["output"]["content"]["content"] == "Hel"


def test_openai_responses_stream_helper_is_recorded_whole():
    sink, rec = _recorder()
    instrument_models(rec)
    client = _client(openai.OpenAI, _sse(RESPONSES_STREAM, named=False))
    with rec.run(), client.responses.stream(model="g", input=USER) as stream:
        response = stream.get_final_response()
    assert response.status == "completed"
    (call,) = _events(sink)
    assert call["attributes"] == {"streaming": True}
    assert call["tool_calls"][0]["name"] == "lookup"


def test_async_openai_chat_stream_helper_is_recorded_whole():
    sink, rec = _recorder()
    instrument_models(rec)
    client = _client(openai.AsyncOpenAI, _sse(CHAT_STREAM, named=False, done=True))

    async def go():
        async with client.chat.completions.stream(model="g", messages=USER) as stream:
            return await stream.get_final_completion()

    with rec.run():
        assert asyncio.run(go()).choices[0].message.content == "Hello"
    assert _events(sink)[0]["attributes"] == {"streaming": True}


def test_async_openai_responses_stream_helper_closed_early_is_partial():
    sink, rec = _recorder()
    instrument_models(rec)
    client = _client(openai.AsyncOpenAI, _sse(RESPONSES_STREAM, named=False))

    async def go():
        async with client.responses.stream(model="g", input=USER) as stream:
            async for event in stream:
                if event.type == "response.output_text.delta":
                    break

    with rec.run():
        asyncio.run(go())
    (call,) = _events(sink)
    assert call["attributes"]["output_captured"] == "partial"
    assert call["output"]["content"][0]["content"][0]["text"] == "Hel"


# --- ways a stream ends ----------------------------------------------------------------------

def test_a_stream_closed_explicitly_is_recorded_as_partial():
    sink, rec = _recorder()
    instrument_models(rec)
    with rec.run():
        stream = _create_messages(_client(anthropic.Anthropic, _sse(STREAM_EVENTS)))
        for i, _ in enumerate(stream):
            if i == 2:
                break
        stream.close()
        assert len(_events(sink)) == 1  # at close, not at some later collection
    (call,) = _events(sink)
    assert call["attributes"] == {"streaming": True, "output_captured": "partial"}
    assert call["output"]["content"] == [{"type": "text", "text": "Shipping takes "}]
    assert call["status"] == "error" and "before the message was complete" in call["error"]
    _valid(sink)


def test_a_context_manager_that_exits_early_is_recorded_as_partial():
    sink, rec = _recorder()
    instrument_models(rec)
    with rec.run(), _create_messages(_client(anthropic.Anthropic, _sse(STREAM_EVENTS))) as stream:
        next(stream)
    assert _events(sink)[0]["attributes"]["output_captured"] == "partial"


def test_a_context_manager_after_the_stream_is_read_does_not_record_again():
    sink, rec = _recorder()
    instrument_models(rec)
    with rec.run():
        with _create_messages(_client(anthropic.Anthropic, _sse(STREAM_EVENTS))) as stream:
            list(stream)
        stream.close()
        stream.response.close()
    (call,) = _events(sink)
    assert call["attributes"] == {"streaming": True}


def test_async_context_manager_exit_is_recorded_as_partial():
    sink, rec = _recorder()
    instrument_models(rec)
    client = _client(anthropic.AsyncAnthropic, _sse(STREAM_EVENTS))

    async def go():
        async with await _create_messages(client) as stream:
            await stream.__anext__()
            await stream.__anext__()

    with rec.run():
        asyncio.run(go())
    (call,) = _events(sink)
    assert call["attributes"] == {"streaming": True, "output_captured": "partial"}


def test_a_stream_that_ends_without_saying_so_is_partial():
    sink, rec = _recorder()
    instrument_models(rec)
    with rec.run():
        list(_create_messages(_client(anthropic.Anthropic, _sse(STREAM_EVENTS[:4]))))
    (call,) = _events(sink)
    assert call["attributes"]["output_captured"] == "partial"
    assert call["output"]["content"][0]["text"] == SAID


class _Breaks(httpx.SyncByteStream):
    def __init__(self, events):
        self.events = events

    def __iter__(self):
        for event in self.events:
            yield f"event: {event['type']}\ndata: {json.dumps(event)}\n\n".encode()
        raise httpx.ReadError("connection lost")


def test_a_stream_that_breaks_records_what_arrived_and_raises():
    sink, rec = _recorder()
    instrument_models(rec)
    client = _client(anthropic.Anthropic, lambda request: httpx.Response(
        200, stream=_Breaks(STREAM_EVENTS[:3]), headers={"content-type": "text/event-stream"}))
    got = []
    with rec.run():
        with pytest.raises(httpx.ReadError):
            for event in _create_messages(client):
                got.append(event.type)
    assert got == [e["type"] for e in STREAM_EVENTS[:3]]
    (call,) = _events(sink)
    assert call["attributes"]["output_captured"] == "partial" and call["status"] == "error"
    assert "connection lost" in call["error"]
    assert call["output"]["content"][0]["text"] == "Shipping takes "


def test_a_provider_error_inside_the_stream_is_recorded():
    events = [*STREAM_EVENTS[:2], {"type": "error", "error": {"type": "overloaded_error", "message": "busy"}}]
    sink, rec = _recorder()
    instrument_models(rec)
    with rec.run(), pytest.raises(anthropic.APIStatusError):
        list(_create_messages(_client(anthropic.Anthropic, _sse(events))))
    (call,) = _events(sink)
    assert call["attributes"]["output_captured"] == "partial" and call["status"] == "error"
    assert "busy" in call["error"]


class _Hangs(httpx.AsyncByteStream):
    def __init__(self, events, started):
        self.events, self.started = events, started

    async def __aiter__(self):
        for event in self.events:
            yield f"event: {event['type']}\ndata: {json.dumps(event)}\n\n".encode()
        self.started.set()
        await asyncio.sleep(30)


def test_a_cancelled_task_records_what_arrived_and_stays_cancelled():
    sink, rec = _recorder()
    instrument_models(rec)
    got = []

    async def consume(client):
        async for event in await _create_messages(client):
            got.append(event.type)

    async def go():
        started = asyncio.Event()
        client = _client(anthropic.AsyncAnthropic, lambda request: httpx.Response(
            200, stream=_Hangs(STREAM_EVENTS[:3], started), headers={"content-type": "text/event-stream"}))
        task = asyncio.create_task(consume(client))
        await started.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    with rec.run():
        asyncio.run(go())
    assert len(got) == 3
    (call,) = _events(sink)
    assert call["attributes"]["output_captured"] == "partial"
    assert "CancelledError" in call["error"]
    assert call["output"]["content"][0]["text"] == "Shipping takes "


def test_a_stream_never_read_records_that_nothing_arrived():
    sink, rec = _recorder()
    instrument_models(rec)
    with rec.run(), _create_messages(_client(anthropic.Anthropic, _sse(STREAM_EVENTS))):
        pass
    (call,) = _events(sink)
    assert call["attributes"]["output_captured"] is False and "output" not in call


# --- abandoned without closing ---------------------------------------------------------------

def _collect():
    for _ in range(3):
        gc.collect()


def test_a_stream_dropped_midway_is_recorded_when_collected():
    sink, rec = _recorder()
    instrument_models(rec)
    with rec.run():
        stream = _create_messages(_client(anthropic.Anthropic, _sse(STREAM_EVENTS)))
        for i, _ in enumerate(stream):
            if i == 2:
                break
        del stream
        _collect()
    (call,) = _events(sink)
    assert call["attributes"]["output_captured"] == "partial"
    assert call["output"]["content"][0]["text"] == "Shipping takes "
    _valid(sink)


@pytest.mark.parametrize("close_explicitly", [False, True], ids=["dropped", "closed"])
def test_an_async_stream_abandoned_midway_is_recorded(close_explicitly):
    sink, rec = _recorder()
    instrument_models(rec)
    client = _client(anthropic.AsyncAnthropic, _sse(STREAM_EVENTS))

    async def go():
        stream = await _create_messages(client)
        async for event in stream:
            if event.type == "content_block_delta":
                break
        if close_explicitly:
            await stream.close()

    with rec.run():
        asyncio.run(go())
        _collect()
    (call,) = _events(sink)
    assert call["attributes"]["output_captured"] == "partial"
    assert call["output"]["content"][0]["text"] == "Shipping takes "
    _valid(sink)


def test_a_stream_dropped_unread_is_recorded_when_collected():
    sink, rec = _recorder()
    instrument_models(rec)
    with rec.run():
        stream = _create_messages(_client(anthropic.Anthropic, _sse(STREAM_EVENTS)))
        del stream
        _collect()
    (call,) = _events(sink)
    assert call["attributes"]["output_captured"] is False


def test_a_collected_stream_is_recorded_once():
    sink, rec = _recorder()
    instrument_models(rec)
    with rec.run():
        stream = _create_messages(_client(anthropic.Anthropic, _sse(STREAM_EVENTS)))
        list(stream)
        reference = weakref.ref(stream)
        del stream
        _collect()
    assert reference() is None
    assert len(_events(sink)) == 1


@contextlib.contextmanager
def _inside_a_write(rec):
    """This thread part way through writing a record, as a finalizer that runs there finds it."""
    with rec._lock:
        rec._writing += 1
        try:
            yield
        finally:
            rec._writing -= 1


def test_a_finalizer_on_a_thread_in_the_middle_of_a_write_does_not_write_through_it():
    """A collection can start on a thread in the middle of writing a record."""
    sink, rec = _recorder()
    instrument_models(rec)
    with rec.run():
        stream = _create_messages(_client(anthropic.Anthropic, _sse(STREAM_EVENTS)))
        next(stream)
        with _inside_a_write(rec):
            del stream
            _collect()
            assert _events(sink) == []  # not written while this thread is inside a write
        assert _common._deferred
        _common._run_deferred()
    assert not _common._deferred
    assert len(_events(sink)) == 1
    _valid(sink)


def test_a_write_left_by_a_finalizer_is_done_on_the_next_call():
    sink, rec = _recorder()
    instrument_models(rec)
    with rec.run():
        stream = _create_messages(_client(anthropic.Anthropic, _sse(STREAM_EVENTS)))
        next(stream)
        with _inside_a_write(rec):
            del stream
            _collect()
        list(_create_messages(_client(anthropic.Anthropic, _sse(STREAM_EVENTS))))
    assert [c["attributes"].get("output_captured") for c in _events(sink)] == ["partial", None]


# --- outside a run ---------------------------------------------------------------------------

def test_outside_a_run_one_run_holds_the_whole_stream():
    sink, rec = _recorder()
    instrument_models(rec)
    stream = _create_messages(_client(anthropic.Anthropic, _sse(STREAM_EVENTS)))
    assert [r["event_type"] for r in sink.records] == ["run_start"]
    list(stream)
    assert [r["event_type"] for r in sink.records] == ["run_start", "llm_call", "run_end"]
    _valid(sink)


def test_a_stream_outside_a_run_leaves_no_run_behind_it():
    from mnestiq.recorder import current_run

    sink, rec = _recorder()
    instrument_models(rec)
    stream = _create_messages(_client(anthropic.Anthropic, _sse(STREAM_EVENTS)))
    assert current_run() is None
    del stream
    _collect()
    assert current_run() is None
    assert [r["event_type"] for r in sink.records] == ["run_start", "llm_call", "run_end"]


def test_a_stream_finished_in_another_task_does_not_fail():
    sink, rec = _recorder()
    instrument_models(rec)
    client = _client(anthropic.AsyncAnthropic, _sse(STREAM_EVENTS))

    async def read(stream):
        return [c async for c in stream]

    async def go():
        stream = await _create_messages(client)
        return await asyncio.create_task(read(stream))

    assert len(asyncio.run(go())) == len(STREAM_EVENTS)
    assert [r["event_type"] for r in sink.records] == ["run_start", "llm_call", "run_end"]
    assert rec.failures == 0


# --- wrapped clients and the never-twice rule ------------------------------------------------

@pytest.mark.parametrize(("build", "ask", "instrument", "events", "named"), [
    (anthropic.Anthropic, _create_messages, instrument_anthropic, STREAM_EVENTS, True),
    (openai.OpenAI, _create_chat, instrument_openai, CHAT_STREAM, False),
    (openai.OpenAI, _create_responses, instrument_openai, RESPONSES_STREAM, False),
], ids=["messages", "chat", "responses"])
def test_a_client_wrapped_by_hand_is_captured_once(build, ask, instrument, events, named):
    sink, rec = _recorder()
    instrument_models(rec)
    client = instrument(_client(build, _sse(events, named=named, done=not named)), rec)
    with rec.run():
        list(ask(client))
    (call,) = _events(sink)
    assert call["attributes"] == {"streaming": True}


def test_without_instrument_models_a_wrapped_client_is_captured():
    sink, rec = _recorder()
    client = instrument_anthropic(_client(anthropic.Anthropic, _sse(STREAM_EVENTS)), rec)
    with rec.run():
        list(_create_messages(client))
    assert _events(sink)[0]["output"]["content"][0]["text"] == SAID


def test_the_stream_helper_is_recorded_once_with_the_transport_hook_on():
    sink, rec = _recorder()
    instrument_models(rec)
    client = _client(anthropic.Anthropic, _sse(STREAM_EVENTS))
    with rec.run(), client.messages.stream(model="m", max_tokens=10, messages=USER) as stream:
        assert stream.get_final_text() == SAID
    (call,) = _events(sink)
    assert call["attributes"] == {"streaming": True}


# --- fail open ---------------------------------------------------------------------------------

class _BrokenSink(MemorySink):
    def append(self, record):
        raise OSError("disk full")


@pytest.mark.filterwarnings("ignore::RuntimeWarning")
def test_a_broken_sink_never_reaches_the_stream():
    expected = _unwatched_chunks(anthropic.Anthropic, _create_messages, STREAM_EVENTS, True)
    rec = Recorder(_BrokenSink(), agent_id="a")
    instrument_models(rec)
    client = _client(anthropic.Anthropic, _sse(STREAM_EVENTS))
    assert _dumps(list(_create_messages(client))) == expected
    assert rec.failures > 0


@pytest.mark.filterwarnings("ignore::RuntimeWarning")
def test_a_closed_recorder_never_reaches_the_stream():
    _, rec = _recorder()
    instrument_models(rec)
    stream = _create_messages(_client(anthropic.Anthropic, _sse(STREAM_EVENTS)))
    rec.close()
    assert len(list(stream)) == len(STREAM_EVENTS)
    assert rec.failures > 0


def test_a_chunk_that_cannot_be_read_still_passes_and_is_reported(monkeypatch):
    from mnestiq.integrations.anthropic import _MessageStream

    calls = []

    def boom(self, chunk):
        calls.append(chunk)
        raise ValueError("odd chunk")

    monkeypatch.setattr(_MessageStream, "add", boom)
    sink, rec = _recorder()
    instrument_models(rec)
    with rec.run():
        got = list(_create_messages(_client(anthropic.Anthropic, _sse(STREAM_EVENTS))))
    assert len(got) == len(STREAM_EVENTS) and len(calls) == len(STREAM_EVENTS)
    (call,) = _events(sink)
    assert call["attributes"]["output_captured"] is False
    assert "could not be read" in call["attributes"]["capture_note"]


def _strict_failing():
    class FailOnCall(MemorySink):
        def append(self, record):
            if record.get("event_type") == "llm_call":
                raise OSError("disk full")
            super().append(record)

    return Recorder(FailOnCall(), agent_id="a", strict=True)


def test_a_strict_recorder_raises_at_the_end_of_the_stream():
    rec = _strict_failing()
    instrument_models(rec)
    client = _client(anthropic.Anthropic, _sse(STREAM_EVENTS))
    with rec.run(), pytest.raises(OSError, match="disk full"):
        list(_create_messages(client))


def test_a_strict_recorder_never_replaces_the_stream_error():
    rec = _strict_failing()
    instrument_models(rec)
    client = _client(anthropic.Anthropic, lambda request: httpx.Response(
        200, stream=_Breaks(STREAM_EVENTS[:2]), headers={"content-type": "text/event-stream"}))
    with rec.run(), pytest.raises(httpx.ReadError):
        list(_create_messages(client))


def test_a_stream_open_failure_is_recorded_like_a_create():
    sink, rec = _recorder()
    instrument_models(rec)
    error = {"type": "error", "error": {"type": "api_error", "message": "x"}}
    client = _client(anthropic.Anthropic, lambda request: httpx.Response(500, json=error))
    with rec.run(), pytest.raises(anthropic.APIError):
        _create_messages(client)
    (call,) = _events(sink)
    assert call["status"] == "error" and "output" not in call


def test_an_unknown_kind_of_stream_falls_back_to_not_captured():
    from mnestiq.integrations import auto

    sink, rec = _recorder()
    record = auto.make_record(rec)

    class NotAnSdkStream:
        pass

    wrapped = _common.wrap_create(rec, lambda **kw: NotAnSdkStream(), record, is_async=False)
    with rec.run():
        assert type(wrapped(model="m", messages=USER, stream=True)) is NotAnSdkStream
    (call,) = _events(sink)
    assert call["attributes"] == {"streaming": True, "output_captured": False}


# --- memory --------------------------------------------------------------------------------------

def _long_stream(chunks, size):
    head = STREAM_EVENTS[:2]
    body = [{"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": "x" * size}}
            for _ in range(chunks)]
    return [*head, *body, *STREAM_EVENTS[4:]]


def test_a_reply_past_the_limit_is_kept_up_to_it_and_said_to_be_partial():
    events = _long_stream(chunks=30, size=500)
    sink, rec = _recorder(max_content_bytes=4096)
    instrument_models(rec)
    client = _client(anthropic.Anthropic, _sse(events))
    with rec.run():
        got = list(_create_messages(client))
    assert sum(len(e.delta.text) for e in got if e.type == "content_block_delta") == 15000  # the caller got it all
    (call,) = _events(sink)
    assert call["attributes"]["output_captured"] == "partial" and "4096 bytes" in call["attributes"]["capture_note"]
    assert 3000 <= len(call["output"]["content"][0]["text"]) <= 4096
    assert call["status"] == "ok"  # the stream was fine: only the record is cut short
    _valid(sink)


def test_many_small_chunks_stay_within_the_limit():
    from mnestiq.integrations.anthropic import _MessageStream

    accumulator = _MessageStream(1000)
    event = {"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}}
    accumulator.add(event)
    for _ in range(5000):
        accumulator.add({"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": "é"}})
    text = accumulator.result()["content"][0]["text"]
    assert accumulator.truncated and len(text.encode()) <= 1000


def test_a_long_answer_does_not_push_out_a_tool_call():
    events = [*_long_stream(chunks=4, size=2000)[:-3],
              {"type": "content_block_stop", "index": 0}, *TOOL_STREAM[1:4], *TOOL_STREAM[4:]]
    events = [{**e, "index": 1} if "index" in e and e in TOOL_STREAM else e for e in events]
    sink, rec = _recorder(max_content_bytes=1000)
    instrument_models(rec)
    with rec.run():
        list(_create_messages(_client(anthropic.Anthropic, _sse(events))))
    (call,) = _events(sink)
    assert call["tool_calls"][0]["name"] == "send"
    assert call["tool_calls"][0]["arguments"] == {"to": "evil@example.com"}


def test_a_huge_number_of_tool_call_slots_is_bounded():
    from mnestiq.integrations.openai import _ChatStream

    accumulator = _ChatStream(1000)
    for i in range(10_000):
        accumulator.add({"id": "c", "model": "m", "choices": [{"index": 0, "finish_reason": None, "delta": {
            "tool_calls": [{"index": i, "id": "x", "function": {"name": "n", "arguments": "a"}}]}}]})
    assert accumulator.truncated
    assert len(accumulator.result()["choices"][0]["message"]["tool_calls"]) <= 1000


# --- MNQ-000 ------------------------------------------------------------------------------------

def _mnq_000(sink):
    return [f for f in all_findings(sink.records) if f["rule"] == "MNQ-000"]


def test_a_partial_stream_reports_mnq_000():
    sink, rec = _recorder()
    instrument_models(rec)
    with rec.run():
        stream = _create_messages(_client(anthropic.Anthropic, _sse(STREAM_EVENTS)))
        next(stream)
        stream.close()
    (finding,) = _mnq_000(sink)
    assert "only partly captured" in finding["detail"]


def test_the_anthropic_stream_helper_closed_early_reports_mnq_000():
    sink, rec = _recorder()
    instrument_models(rec)
    client = _client(anthropic.Anthropic, _sse(STREAM_EVENTS))
    with rec.run(), client.messages.stream(model="m", max_tokens=10, messages=USER) as stream:
        next(iter(stream))
    assert _events(sink)[0]["attributes"]["partial"] is True
    (finding,) = _mnq_000(sink)
    assert "only partly captured" in finding["detail"]


def test_a_stream_read_to_the_end_reports_no_mnq_000():
    sink, rec = _recorder()
    instrument_models(rec)
    with rec.run():
        list(_create_messages(_client(anthropic.Anthropic, _sse(STREAM_EVENTS))))
    assert _mnq_000(sink) == []


def test_the_dashboard_says_the_same_for_partial_output():
    page = Path(_common.__file__).parents[1].joinpath("dashboard", "index.html").read_text(encoding="utf-8")
    assert 'ev.attributes.output_captured === "partial"' in page
    assert "only partly captured" in page


# --- shapes a provider can send that must not be lost in silence ---------------------------

def _record_of(cls, create, events, *, named=False, **options):
    sink, rec = _recorder(**options)
    instrument_models(rec)
    with rec.run():
        got = list(create(_client(cls, _sse(events, named=named, done=not named))))
    assert got and rec.failures == 0
    uninstrument_models()
    (call,) = _events(sink)
    _valid(sink)
    return call


def _chat_record(events):
    return _record_of(openai.OpenAI, _create_chat, [*events, _chat_chunk({}, finish_reason="tool_calls")])


def _chat_tool(tool_id, name, arguments, **extra):
    return {"id": tool_id, "type": "function", "function": {"name": name, "arguments": arguments}, **extra}


def test_a_tool_call_with_no_index_is_kept():
    call = _chat_record([_chat_chunk({"tool_calls": [_chat_tool("x", "delete_all", "{\"a\"")]}),
                         _chat_chunk({"tool_calls": [{"function": {"arguments": ": 1}"}}]})])
    assert [(c["id"], c["name"], c["arguments"]) for c in call["tool_calls"]] == [("x", "delete_all", {"a": 1})]
    assert call["attributes"] == {"streaming": True}


def test_two_calls_on_one_index_stay_two_calls():
    call = _chat_record([_chat_chunk({"tool_calls": [_chat_tool("a", "read_file", "{\"p\": 1}", index=0)]}),
                         _chat_chunk({"tool_calls": [_chat_tool("b", "send_email", "{\"to\": \"x\"}", index=0)]})])
    assert [(c["id"], c["name"], c["arguments"]) for c in call["tool_calls"]] == [
        ("a", "read_file", {"p": 1}), ("b", "send_email", {"to": "x"})]


def test_an_id_and_name_repeated_on_every_chunk_are_one_call():
    tool = {"index": 0, "id": "a", "type": "function"}
    call = _chat_record([_chat_chunk({"tool_calls": [{**tool, "function": {"name": "f", "arguments": "{\"a\""}}]}),
                         _chat_chunk({"tool_calls": [{**tool, "function": {"name": "f", "arguments": ": 1}"}}]})])
    assert [(c["name"], c["arguments"]) for c in call["tool_calls"]] == [("f", {"a": 1})]


def test_a_legacy_function_call_is_a_tool_call():
    call = _chat_record([_chat_chunk({"function_call": {"name": "wire_money", "arguments": "{\"to\""}}),
                         _chat_chunk({"function_call": {"arguments": ": \"x\"}"}})])
    assert call["tool_calls"][0]["name"] == "wire_money" and call["tool_calls"][0]["arguments"] == {"to": "x"}
    assert call["output"]["content"]["function_call"]["name"] == "wire_money"


def test_a_legacy_function_call_in_a_whole_reply_is_a_tool_call():
    whole = {"id": "c", "object": "chat.completion", "created": 1, "model": "g", "choices": [
        {"index": 0, "finish_reason": "function_call", "message": {
            "role": "assistant", "content": None, "function_call": {"name": "wire_money", "arguments": "{}"}}}]}
    sink, rec = _recorder()
    instrument_models(rec)
    with rec.run():
        _client(openai.OpenAI, lambda request: httpx.Response(200, json=whole)).chat.completions.create(
            model="g", messages=USER)
    assert _events(sink)[0]["tool_calls"][0]["name"] == "wire_money"


def test_a_custom_tool_keeps_its_name_and_input():
    call = _chat_record([_chat_chunk({"tool_calls": [
        {"index": 0, "id": "c", "type": "custom", "custom": {"name": "sh", "input": "rm "}}]}),
        _chat_chunk({"tool_calls": [{"index": 0, "custom": {"input": "-rf /"}}]})])
    assert call["tool_calls"][0]["name"] == "sh" and call["tool_calls"][0]["arguments"] == "rm -rf /"


def test_text_a_provider_adds_to_a_delta_is_kept():
    call = _chat_record([_chat_chunk({"reasoning_content": "let me "}), _chat_chunk({"reasoning_content": "think"})])
    assert call["output"]["content"]["reasoning_content"] == "let me think"


def test_something_else_a_provider_adds_to_a_delta_marks_the_output_partial():
    call = _chat_record([_chat_chunk({"audio": {"data": "AAAA"}})])
    assert call["attributes"]["output_captured"] == "partial"


def _anthropic_record(events):
    return _record_of(anthropic.Anthropic, _create_beta, [STREAM_EVENTS[0], *events, *STREAM_EVENTS[5:]], named=True)


def test_compaction_text_is_kept():
    call = _anthropic_record([{"type": "content_block_start", "index": 0,
                               "content_block": {"type": "compaction", "content": None}},
                              {"type": "content_block_delta", "index": 0,
                               "delta": {"type": "compaction_delta", "content": "summary"}}])
    assert call["output"]["content"] == [{"type": "compaction", "content": "summary"}]
    assert call["attributes"] == {"streaming": True}


def test_a_delta_with_no_block_start_is_kept_and_said_to_be_damaged():
    call = _anthropic_record([{"type": "content_block_delta", "index": 0,
                               "delta": {"type": "text_delta", "text": "visible to the agent"}}])
    assert call["output"]["content"] == [{"type": "text", "text": "visible to the agent"}]
    assert call["attributes"]["output_captured"] == "partial"


def test_a_tool_input_with_no_block_start_is_a_tool_call():
    call = _anthropic_record([{"type": "content_block_delta", "index": 0,
                               "delta": {"type": "input_json_delta", "partial_json": "{\"a\": 1}"}}])
    assert call["tool_calls"][0]["arguments"] == {"a": 1}
    assert call["attributes"]["output_captured"] == "partial"


def test_a_delta_of_an_unknown_kind_marks_the_output_partial():
    call = _anthropic_record([{"type": "content_block_start", "index": 0,
                               "content_block": {"type": "text", "text": ""}},
                              {"type": "content_block_delta", "index": 0, "delta": {"type": "new_delta", "x": "y"}}])
    assert call["attributes"]["output_captured"] == "partial"


def test_a_block_start_of_the_wrong_type_costs_only_that_block():
    call = _anthropic_record([
        {"type": "content_block_start", "index": 0,
         "content_block": {"type": "tool_use", "id": "t", "name": "send", "input": {}}},
        {"type": "content_block_delta", "index": 0, "delta": {"type": "input_json_delta", "partial_json": "{}"}},
        {"type": "content_block_start", "index": 1, "content_block": {"type": "text", "text": 123}},
        {"type": "content_block_delta", "index": 1, "delta": {"type": "text_delta", "text": "a"}}])
    assert call["tool_calls"][0]["name"] == "send"
    assert call["output"]["content"][1]["text"] == "a"
    assert call["attributes"]["output_captured"] == "partial"


_MESSAGE_ITEM = {"type": "message", "id": "m", "role": "assistant", "status": "in_progress", "content": []}
_CALL_ITEM = {"type": "function_call", "id": "f", "call_id": "c", "name": "go", "arguments": "",
              "status": "in_progress"}


def _item_added(item, index=0):
    return {"type": "response.output_item.added", "sequence_number": 1, "output_index": index, "item": item}


def _text_delta(content_index, delta="x"):
    return {"type": "response.output_text.delta", "sequence_number": 2, "output_index": 0,
            "content_index": content_index, "item_id": "m", "delta": delta, "logprobs": []}


def _arguments_delta(delta, index=0):
    return {"type": "response.function_call_arguments.delta", "sequence_number": 2, "output_index": index,
            "item_id": "f", "delta": delta}


def _responses_record(events):
    return _record_of(openai.OpenAI, _create_responses, events)


@pytest.mark.parametrize("content_index", [2_000_000_000, 7], ids=["huge", "gap"])
def test_a_content_index_from_the_wire_never_sizes_anything(content_index):
    call = _responses_record([_item_added(_MESSAGE_ITEM), _text_delta(content_index)])
    assert [p["text"] for p in call["output"]["content"][0]["content"]] == ["x"]
    assert call["attributes"]["output_captured"] == "partial"
    assert "put in its place" in call["attributes"]["capture_note"]


def test_a_negative_content_index_does_not_wipe_the_output():
    call = _responses_record([_item_added(_MESSAGE_ITEM), _text_delta(0, "real text"), _text_delta(-5, "stray")])
    assert [p["text"] for p in call["output"]["content"][0]["content"]] == ["real text", "stray"]
    assert "put in its place" in call["attributes"]["capture_note"]


def test_deltas_with_no_item_are_kept_and_said_to_be_damaged():
    from mnestiq.integrations.openai import _ResponsesStream

    accumulator = _ResponsesStream(1000)
    accumulator.add(_text_delta(0, "orphan"))
    accumulator.add(_arguments_delta("{}", index=1))
    message, call = accumulator.result()["output"]
    assert message["content"][0]["text"] == "orphan" and call["arguments"] == "{}"
    assert accumulator.damaged


def test_an_end_event_without_the_reply_is_not_an_empty_output():
    call = _responses_record([_item_added(_CALL_ITEM), _arguments_delta("{\"a\": 1}"),
                              {"type": "response.completed", "sequence_number": 3}])
    assert call["tool_calls"][0]["arguments"] == {"a": 1}
    assert call["attributes"]["output_captured"] == "partial"
    assert call["status"] == "ok"


# --- what counts against the limit ----------------------------------------------------------

def test_ids_and_names_count_against_the_limit():
    from mnestiq.integrations.openai import _ChatStream

    accumulator = _ChatStream(10_000)
    for i in range(100):
        accumulator.add(_chat_chunk({"tool_calls": [
            {"index": i, "id": f"{i}" + "I" * 5000, "function": {"name": "N" * 5000, "arguments": ""}}]}))
    calls = accumulator.result()["choices"][0]["message"]["tool_calls"]
    assert accumulator.truncated
    assert sum(len(c["id"] or "") + len(c["function"]["name"] or "") for c in calls) <= 10_000


def test_a_call_past_the_limit_does_not_add_to_an_earlier_one():
    from mnestiq.integrations.openai import _ChatStream

    accumulator = _ChatStream(200)
    accumulator.add(_chat_chunk({"tool_calls": [_chat_tool("a", "first", "{}", index=0)]}))
    accumulator.arguments.room = 0
    accumulator.add(_chat_chunk({"tool_calls": [_chat_tool("b", "second", "", index=0)]}))
    accumulator.arguments.room = 200
    accumulator.add(_chat_chunk({"tool_calls": [{"index": 0, "function": {"arguments": "AFTER"}}]}))
    calls = accumulator.result()["choices"][0]["message"]["tool_calls"]
    assert calls[0]["function"]["arguments"] == "{}" and accumulator.truncated


def test_usage_keys_are_only_the_ones_recorded():
    from mnestiq.integrations.anthropic import _MessageStream

    accumulator = _MessageStream(1000)
    accumulator.add(STREAM_EVENTS[0])
    for i in range(1000):
        accumulator.add({"type": "message_delta", "delta": {"stop_reason": None}, "usage": {f"k{i}": 1}})
    accumulator.add(STREAM_EVENTS[5])
    assert accumulator.result()["usage"] == {"input_tokens": 12, "output_tokens": 9}


def test_many_one_byte_pieces_are_joined():
    from mnestiq.integrations.anthropic import _MessageStream

    accumulator = _MessageStream(100_000)
    accumulator.add(STREAM_EVENTS[1])
    for _ in range(10_000):
        accumulator.add({"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": "x"}})
    assert len(accumulator.fragments[0, "text"]) < 4096
    assert accumulator.result()["content"][0]["text"] == "x" * 10_000


def test_items_too_big_when_done_stay_counted_and_are_not_given_back():
    from mnestiq.integrations.openai import _ResponsesStream

    limit = 10_000
    accumulator = _ResponsesStream(limit)
    for i in range(40):
        accumulator.add(_item_added({"type": "message", "content": [], "pad": "S" * 4000}, index=i))
        accumulator.add({"type": "response.output_item.done", "output_index": i,
                         "item": {"type": "message", "content": [], "pad": "B" * (limit + 1)}})
    assert accumulator.truncated
    assert sum(len(json.dumps(s.item)) for s in accumulator.slots.values() if s.item) <= limit


_BIG_ARGUMENTS = json.dumps({"q": "x" * 600_000})
_BIG_CALL = {**_CALL_ITEM, "arguments": _BIG_ARGUMENTS, "status": "completed"}
_ITEM_DONE = {"type": "response.output_item.done", "sequence_number": 3, "output_index": 0, "item": _BIG_CALL}


def test_arguments_over_half_the_limit_are_whole():
    response = {"id": "r", "model": "g", "status": "completed", "output": [_BIG_CALL], **_RESPONSE_FIELDS}
    call = _responses_record([_item_added(_CALL_ITEM), _arguments_delta(_BIG_ARGUMENTS), _ITEM_DONE,
                              {"type": "response.completed", "sequence_number": 4, "response": response}])
    assert call["attributes"] == {"streaming": True}


def test_a_cut_after_done_keeps_the_arguments():
    call = _responses_record([_item_added(_CALL_ITEM), _arguments_delta(_BIG_ARGUMENTS), _ITEM_DONE])
    assert call["output"]["content"][0]["arguments"] == _BIG_ARGUMENTS
    assert call["attributes"]["output_captured"] == "partial"
    assert len(call["tool_calls"][0]["arguments"]["q"]) == 600_000


def test_deltas_stay_when_the_done_item_does_not_fit():
    from mnestiq.integrations.openai import _ResponsesStream

    accumulator = _ResponsesStream(1000)
    accumulator.add(_item_added(_CALL_ITEM))
    accumulator.add(_arguments_delta("{\"a\": 1}"))
    accumulator.add({"type": "response.output_item.done", "output_index": 0,
                     "item": {**_CALL_ITEM, "arguments": "y" * 5000}})
    assert accumulator.result()["output"][0]["arguments"] == "{\"a\": 1}"
    assert accumulator.truncated


# --- closing while the recorder is busy ------------------------------------------------------

def test_closing_a_stream_waits_for_a_busy_recorder_instead_of_deferring():
    sink, rec = _recorder()
    instrument_models(rec)
    stream = _create_messages(_client(anthropic.Anthropic, _sse(STREAM_EVENTS)))
    next(stream)
    held, release = threading.Event(), threading.Event()

    def holder():
        with rec._lock:
            held.set()
            release.wait(10)

    locker = threading.Thread(target=holder)
    locker.start()
    held.wait(10)
    closer = threading.Thread(target=stream.close)
    closer.start()
    time.sleep(0.2)  # longer than a finalizer is allowed to wait
    assert closer.is_alive() and not _common._deferred
    release.set()
    closer.join(10)
    locker.join(10)
    assert len(_events(sink)) == 1 and len(_events(sink, "run_end")) == 1


def test_a_write_left_by_a_finalizer_is_done_by_recorder_close():
    sink, rec = _recorder()
    instrument_models(rec)
    stream = _create_messages(_client(anthropic.Anthropic, _sse(STREAM_EVENTS)))
    next(stream)
    with _inside_a_write(rec):
        del stream
        _collect()
    assert _common._deferred
    rec.close()
    assert not _common._deferred
    assert len(_events(sink)) == 1 and len(_events(sink, "run_end")) == 1
    _valid(sink)


def test_closing_a_stream_on_a_thread_inside_the_recorder_defers():
    sink, rec = _recorder()
    instrument_models(rec)
    stream = _create_messages(_client(anthropic.Anthropic, _sse(STREAM_EVENTS)))
    next(stream)
    with _inside_a_write(rec):
        stream.close()
        assert _events(sink) == []
    _common._run_deferred()
    assert len(_events(sink)) == 1


# --- with_streaming_response -----------------------------------------------------------------

def test_a_streaming_response_closed_on_another_thread_leaves_no_run_behind():
    from mnestiq.recorder import current_run

    body = {"id": "m", "type": "message", "role": "assistant", "model": "c",
            "content": [{"type": "text", "text": "hi"}], "stop_reason": "end_turn", "stop_sequence": None,
            "usage": {"input_tokens": 1, "output_tokens": 1}}

    def go():
        sink, rec = _recorder()
        instrument_models(rec)
        client = _client(anthropic.Anthropic, lambda request: httpx.Response(200, json=body))
        manager = client.messages.with_streaming_response.create(model="m", max_tokens=1, messages=USER)
        response = manager.__enter__()
        response.read()
        assert current_run() is None
        closer = threading.Thread(target=manager.__exit__, args=(None, None, None))
        closer.start()
        closer.join(10)
        assert current_run() is None
        for _ in range(2):
            client.messages.create(model="m", max_tokens=1, messages=USER)
        calls = _events(sink)
        assert len(calls) == 3 and len({c["run_id"] for c in calls}) == 3
        assert not any((c.get("attributes") or {}).get("after_run_end") for c in calls)

    contextvars.copy_context().run(go)
