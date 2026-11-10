"""The same answer, captured by the proxy and by the SDK path, gives the same record: the same output, the same
tool calls, and the same marks on an answer that did not arrive whole. Both paths are fed the very same bytes."""

import http.client
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

anthropic = pytest.importorskip("anthropic")
openai = pytest.importorskip("openai")
httpx = pytest.importorskip("httpx2")

from mnestiq import MemorySink, Recorder  # noqa: E402
from mnestiq.integrations.anthropic import instrument_anthropic, make_record  # noqa: E402
from mnestiq.integrations.openai import instrument_openai, make_records  # noqa: E402
from mnestiq.proxy import ModelProxy  # noqa: E402
from mnestiq.proxy.formats import CHAT, MESSAGES, request_fields, unreadable_request  # noqa: E402
from mnestiq.recorder import _UNKNOWN  # noqa: E402

USER = [{"role": "user", "content": "hi"}]


class _Upstream:
    """Answers every POST with the bytes a test sets, as a provider on this machine."""

    def __init__(self) -> None:
        self.body, self.content_type = b"", "application/json"
        upstream = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args):
                pass

            def do_POST(self):
                self.rfile.read(int(self.headers.get("Content-Length") or 0))
                self.send_response(200)
                self.send_header("Content-Type", upstream.content_type)
                self.send_header("Content-Length", str(len(upstream.body)))
                self.end_headers()
                self.wfile.write(upstream.body)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def upstream():
    up = _Upstream()
    yield up
    up.close()


def _sse(events, *, done=False):
    text = "".join(f"event: {e.get('type', 'x')}\ndata: {json.dumps(e)}\n\n" for e in events)
    return (text + ("data: [DONE]\n\n" if done else "")).encode()


def _via_proxy(upstream, family, path, body, payload, content_type):
    """Record one call through the proxy. Returns its llm_call record."""
    upstream.body, upstream.content_type = payload, content_type
    sink = MemorySink()
    rec = Recorder(sink, agent_id="a")
    proxy = ModelProxy(rec, upstreams=[f"{family}={upstream.url}"], listen="127.0.0.1:0")
    proxy.start()
    try:
        conn = http.client.HTTPConnection("127.0.0.1", proxy.port, timeout=10)
        conn.request("POST", f"/{family}{path}", body=json.dumps(body),
                     headers={"Content-Type": "application/json", "Authorization": "Bearer sk-test-parity-0000"})
        conn.getresponse().read()
        conn.close()
    finally:
        proxy.close()
        rec.close()
    calls = [r for r in sink.records if r.get("event_type") == "llm_call"]
    assert len(calls) == 1
    return calls[0]


def _client(cls, payload, content_type):
    def handler(request):
        return httpx.Response(200, content=payload, headers={"content-type": content_type})
    return cls(api_key="test", max_retries=0, http_client=httpx.Client(transport=httpx.MockTransport(handler)))


def _via_sdk(family, call, payload, content_type):
    """Record one call through the SDK path. Returns its llm_call record."""
    sink = MemorySink()
    rec = Recorder(sink, agent_id="a")
    if family == "openai":
        client = instrument_openai(_client(openai.OpenAI, payload, content_type), rec)
    else:
        client = instrument_anthropic(_client(anthropic.Anthropic, payload, content_type), rec)
    result = call(client)
    if hasattr(result, "__iter__") and not isinstance(result, (dict, list)) and "Stream" in type(result).__name__:
        for _ in result:
            pass
    rec.close()
    calls = [r for r in sink.records if r.get("event_type") == "llm_call"]
    assert len(calls) == 1
    return calls[0]


def _plain(value):
    """A value without the digests and salts the recorder adds, which differ on every record."""
    if isinstance(value, dict):
        return {k: _plain(v) for k, v in value.items() if not k.endswith(("_hash", "_salt"))}
    if isinstance(value, list):
        return [_plain(v) for v in value]
    return value


_MARKS = ("output_captured", "partial", "capture_note")


def _same(proxy_rec, sdk_rec, *, notes_differ=False):
    for key in ("model", "output", "tool_calls", "usage", "error", "status"):
        assert _plain(proxy_rec.get(key)) == _plain(sdk_rec.get(key)), key
    proxy_attrs, sdk_attrs = proxy_rec.get("attributes") or {}, sdk_rec.get("attributes") or {}
    for mark in _MARKS:
        if mark == "capture_note" and notes_differ:  # the proxy says what it saw on the wire, in its own words
            assert (mark in proxy_attrs) or (mark not in sdk_attrs)
            continue
        assert proxy_attrs.get(mark) == sdk_attrs.get(mark), mark


LEGACY_CHAT = {"id": "c1", "object": "chat.completion", "created": 1, "model": "g-1",
               "choices": [{"index": 0, "finish_reason": "function_call", "message": {
                   "role": "assistant", "content": None, "reasoning_content": "thinking it over",
                   "function_call": {"name": "send_email", "arguments": "{\"to\": \"x@y.example\"}"}}}],
               "usage": {"prompt_tokens": 2, "completion_tokens": 3, "total_tokens": 5}}


def _chat_chunk(delta, finish_reason=None):
    return {"id": "c1", "object": "chat.completion.chunk", "created": 1, "model": "g-1",
            "choices": [{"index": 0, "finish_reason": finish_reason, "delta": delta}]}


LEGACY_CHAT_STREAM = [
    _chat_chunk({"role": "assistant", "function_call": {"name": "send_email", "arguments": "{\"to\": "}}),
    _chat_chunk({"function_call": {"arguments": "\"x@y.example\"}"}}),
    _chat_chunk({"reasoning_content": "thinking it over"}),
    _chat_chunk({}, finish_reason="function_call"),
]


def test_a_legacy_function_call_answer_is_a_tool_call_on_both_paths(upstream):
    body = {"model": "g", "messages": USER}
    proxy_rec = _via_proxy(upstream, "openai", "/v1/chat/completions", body,
                           json.dumps(LEGACY_CHAT).encode(), "application/json")
    sdk_rec = _via_sdk("openai", lambda c: c.chat.completions.create(model="g", messages=USER),
                       json.dumps(LEGACY_CHAT).encode(), "application/json")
    assert [t["name"] for t in proxy_rec["tool_calls"]] == ["send_email"]
    assert proxy_rec["tool_calls"][0]["arguments"] == {"to": "x@y.example"}
    _same(proxy_rec, sdk_rec)


def test_a_streamed_legacy_function_call_and_reasoning_text_are_kept_on_both_paths(upstream):
    body = {"model": "g", "messages": USER, "stream": True}
    payload = _sse(LEGACY_CHAT_STREAM, done=True)
    proxy_rec = _via_proxy(upstream, "openai", "/v1/chat/completions", body, payload, "text/event-stream")
    sdk_rec = _via_sdk("openai", lambda c: c.chat.completions.create(model="g", messages=USER, stream=True),
                       payload, "text/event-stream")
    assert [t["name"] for t in proxy_rec["tool_calls"]] == ["send_email"]
    assert proxy_rec["output"]["content"]["reasoning_content"] == "thinking it over"
    _same(proxy_rec, sdk_rec)


def _message_start():
    return {"type": "message_start", "message": {
        "id": "m1", "type": "message", "role": "assistant", "model": "c-1", "content": [],
        "stop_reason": None, "stop_sequence": None, "usage": {"input_tokens": 1, "output_tokens": 1}}}


COMPACTION_STREAM = [
    _message_start(),
    {"type": "content_block_start", "index": 0, "content_block": {"type": "compaction", "content": None}},
    {"type": "content_block_delta", "index": 0, "delta": {"type": "compaction_delta", "content": "SUMMARY TEXT"}},
    {"type": "content_block_stop", "index": 0},
    {"type": "content_block_start", "index": 1,
     "content_block": {"type": "tool_use", "id": "t1", "name": "send", "input": {}}},
    {"type": "content_block_delta", "index": 1, "delta": {"type": "input_json_delta", "partial_json": "{\"a\": 1}"}},
    {"type": "content_block_stop", "index": 1},
    {"type": "message_delta", "delta": {"stop_reason": "tool_use", "stop_sequence": None},
     "usage": {"output_tokens": 7}},
    {"type": "message_stop"},
]


def _messages(client, **kw):
    return client.messages.create(model="c", max_tokens=10, messages=USER, **kw)


def test_a_compaction_block_streamed_is_kept_on_both_paths(upstream):
    body = {"model": "c", "max_tokens": 10, "messages": USER, "stream": True}
    payload = _sse(COMPACTION_STREAM)
    proxy_rec = _via_proxy(upstream, "anthropic", "/v1/messages", body, payload, "text/event-stream")
    sdk_rec = _via_sdk("anthropic", lambda c: _messages(c, stream=True), payload, "text/event-stream")
    assert proxy_rec["output"]["content"][0] == {"type": "compaction", "content": "SUMMARY TEXT"}
    assert [t["arguments"] for t in proxy_rec["tool_calls"]] == [{"a": 1}]
    _same(proxy_rec, sdk_rec)


def test_a_stream_that_stops_before_its_end_is_marked_partial_on_both_paths(upstream):
    body = {"model": "c", "max_tokens": 10, "messages": USER, "stream": True}
    payload = _sse(COMPACTION_STREAM[:4])  # no message_delta, no message_stop
    proxy_rec = _via_proxy(upstream, "anthropic", "/v1/messages", body, payload, "text/event-stream")
    sdk_rec = _via_sdk("anthropic", lambda c: _messages(c, stream=True), payload, "text/event-stream")
    attrs = proxy_rec["attributes"]
    assert attrs["output_captured"] == "partial"
    assert attrs["capture_note"]
    assert proxy_rec["status"] == "error"
    assert proxy_rec["output"]["content"][0]["content"] == "SUMMARY TEXT"
    _same(proxy_rec, sdk_rec, notes_differ=True)


def test_a_whole_messages_answer_and_a_responses_answer_match_on_both_paths(upstream):
    answer = {"id": "m1", "type": "message", "role": "assistant", "model": "c-1", "stop_reason": "tool_use",
              "stop_sequence": None, "usage": {"input_tokens": 1, "output_tokens": 2, "service_tier": "standard"},
              "content": [{"type": "thinking", "thinking": "hm", "signature": "s"},
                          {"type": "tool_use", "id": "t1", "name": "send", "input": {"a": 1}}]}
    payload = json.dumps(answer).encode()
    proxy_rec = _via_proxy(upstream, "anthropic", "/v1/messages", {"model": "c", "max_tokens": 10, "messages": USER},
                           payload, "application/json")
    _same(proxy_rec, _via_sdk("anthropic", _messages, payload, "application/json"))

    response = {"id": "r1", "object": "response", "created_at": 1, "model": "g-1", "status": "completed",
                "parallel_tool_calls": True, "tool_choice": "auto", "tools": [],
                "output": [{"type": "function_call", "id": "f1", "call_id": "call_2", "name": "lookup",
                            "arguments": "{\"q\": \"x\"}", "status": "completed"}],
                "usage": {"input_tokens": 1, "output_tokens": 2, "total_tokens": 3}}
    payload = json.dumps(response).encode()
    proxy_rec = _via_proxy(upstream, "openai", "/v1/responses", {"model": "g", "input": "hi"}, payload,
                           "application/json")
    _same(proxy_rec, _via_sdk("openai", lambda c: c.responses.create(model="g", input="hi"), payload,
                              "application/json"))


def test_a_missing_model_name_is_written_one_way_everywhere():
    sink = MemorySink()
    rec = Recorder(sink, agent_id="a")
    record_messages = make_record(rec)
    record_chat, record_responses = make_records(rec)
    with rec.run() as run:
        record_messages(run, {"messages": USER}, None, 1, "no model")
        record_chat(run, {"messages": USER}, None, 1, "no model")
        record_responses(run, {"input": "hi"}, None, 1, "no model")
    rec.close()
    names = [r["model"]["name"] for r in sink.records if r.get("event_type") == "llm_call"]
    assert names == [_UNKNOWN] * 3
    assert request_fields(MESSAGES, {"messages": USER}, "/v1/messages", {})["model"] == _UNKNOWN
    assert request_fields(CHAT, {"messages": USER}, "/v1/chat/completions", {})["model"] == _UNKNOWN
    assert unreadable_request({"x": 1})["model"] == _UNKNOWN
    assert unreadable_request([1])["model"] == _UNKNOWN


def _choice_chunk(index, delta, finish_reason=None):
    return {"id": "c2", "object": "chat.completion.chunk", "created": 1, "model": "g-1",
            "choices": [{"index": index, "finish_reason": finish_reason, "delta": delta}]}


TWO_CHOICE_STREAM = [
    _choice_chunk(0, {"role": "assistant", "content": "Shipping takes 3 days."}),
    _choice_chunk(1, {"role": "assistant", "tool_calls": [{"index": 0, "id": "call_9", "type": "function",
                                                           "function": {"name": "send_email", "arguments": "{}"}}]}),
    _choice_chunk(0, {}, finish_reason="stop"),
    _choice_chunk(1, {}, finish_reason="tool_calls"),
]

TWO_CHOICE_ANSWER = {"id": "c2", "object": "chat.completion", "created": 1, "model": "g-1",
                     "choices": [{"index": 0, "finish_reason": "stop",
                                  "message": {"role": "assistant", "content": "Shipping takes 3 days."}},
                                 {"index": 1, "finish_reason": "tool_calls", "message": {
                                     "role": "assistant", "content": None, "tool_calls": [{
                                         "id": "call_9", "type": "function",
                                         "function": {"name": "send_email", "arguments": "{}"}}]}}],
                     "usage": {"prompt_tokens": 2, "completion_tokens": 3, "total_tokens": 5}}


def _left_out(record):
    attrs = record.get("attributes") or {}
    assert attrs.get("output_captured") == "partial"
    assert "only the first of several choices" in attrs.get("capture_note", "")


@pytest.mark.parametrize("streamed", [True, False], ids=["streamed", "whole"])
def test_an_answer_with_several_choices_says_only_the_first_is_recorded(upstream, streamed):
    if streamed:
        payload, kind = _sse(TWO_CHOICE_STREAM, done=True), "text/event-stream"
    else:
        payload, kind = json.dumps(TWO_CHOICE_ANSWER).encode(), "application/json"
    body = {"model": "g", "messages": USER, "n": 2, **({"stream": True} if streamed else {})}
    proxy_rec = _via_proxy(upstream, "openai", "/v1/chat/completions", body, payload, kind)
    sdk_rec = _via_sdk("openai", lambda c: c.chat.completions.create(model="g", messages=USER, n=2, stream=streamed),
                       payload, kind)
    for record in (proxy_rec, sdk_rec):
        _left_out(record)
        assert record["output"]["content"]["content"] == "Shipping takes 3 days."
        assert record["status"] == "ok"
    _same(proxy_rec, sdk_rec)


@pytest.mark.parametrize("streamed", [True, False], ids=["streamed", "whole"])
def test_an_answer_with_one_choice_is_not_marked(upstream, streamed):
    stream = [c for c in TWO_CHOICE_STREAM if c["choices"][0]["index"] == 0]
    answer = {**TWO_CHOICE_ANSWER, "choices": TWO_CHOICE_ANSWER["choices"][:1]}
    if streamed:
        payload, kind = _sse(stream, done=True), "text/event-stream"
    else:
        payload, kind = json.dumps(answer).encode(), "application/json"
    body = {"model": "g", "messages": USER, **({"stream": True} if streamed else {})}
    proxy_rec = _via_proxy(upstream, "openai", "/v1/chat/completions", body, payload, kind)
    sdk_rec = _via_sdk("openai", lambda c: c.chat.completions.create(model="g", messages=USER, stream=streamed),
                       payload, kind)
    for record in (proxy_rec, sdk_rec):
        assert "output_captured" not in (record.get("attributes") or {})
    _same(proxy_rec, sdk_rec)
