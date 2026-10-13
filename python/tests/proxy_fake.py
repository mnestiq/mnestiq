"""A model provider on this machine for the proxy tests: answers like OpenAI (Chat Completions and
Responses) and Anthropic (Messages), streamed or not, with the text and tool calls a test scripts."""

from __future__ import annotations

import json
import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any


@dataclass
class Reply:
    text: str = "Done."
    tool: tuple[str, dict] | None = None
    call_id: str = "call_1"
    status: int = 200
    error: str = "something went wrong"
    break_stream: bool = False  # stop halfway and drop the connection
    stream_error: bool = False  # an error event in the middle of a stream
    delay: float = 0.0  # seconds before each streamed event
    short_body: bool = False  # announce a length, send less, hang up
    deep_event: bool = False  # a streamed event nested too deep for a JSON parser


@dataclass
class Seen:
    method: str
    path: str
    headers: dict[str, str]
    body: bytes
    json: Any = field(default=None)


class FakeProvider:
    def __init__(self) -> None:
        self.replies: list[Reply] = []
        self.seen: list[Seen] = []
        self._count = 0
        provider = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args: Any) -> None:
                pass

            def do_GET(self) -> None:
                provider._handle(self)

            do_POST = do_GET

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.server.server_address[1]}"

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()

    def _handle(self, h: BaseHTTPRequestHandler) -> None:
        size = int(h.headers.get("Content-Length") or 0)
        body = h.rfile.read(size) if size else b""
        try:
            parsed = json.loads(body) if body else None
        except (ValueError, RecursionError):
            parsed = None
        self.seen.append(Seen(h.command, h.path, {k.lower(): v for k, v in h.headers.items()}, body, parsed))
        path = h.path.split("?")[0]
        if h.command == "GET":
            return _send_json(h, 200, {"object": "list", "data": [{"id": "fake-model", "object": "model"}]})
        reply = self.replies.pop(0) if self.replies else Reply()
        self._count += 1
        n = self._count
        if reply.status != 200:
            error = {"type": "error", "error": {"type": "api_error", "message": reply.error}}
            return _send_json(h, reply.status, error)
        body = parsed if isinstance(parsed, dict) else {}
        stream = bool(body.get("stream"))
        if path.endswith("/chat/completions"):
            events = _chat_events(body, reply, n) if stream else None
            answer = _chat(body, reply, n)
        elif path.endswith("/responses"):
            events = _responses_events(body, reply, n) if stream else None
            answer = _response(body, reply, n)
        elif path.endswith("/messages"):
            events = _anthropic_events(body, reply, n) if stream else None
            answer = _anthropic(body, reply, n)
        else:
            return _send_json(h, 404, {"error": {"message": "not here"}})
        if events is None and reply.short_body:
            data = json.dumps(answer).encode()
            h.send_response(200)
            h.send_header("Content-Type", "application/json")
            h.send_header("Content-Length", str(len(data) + 100))
            h.end_headers()
            h.wfile.write(data)
            h.wfile.flush()
            h.close_connection = True
            h.connection.shutdown(2)
            return None
        if events is None:
            return _send_json(h, 200, answer)
        h.send_response(200)
        h.send_header("Content-Type", "text/event-stream")
        h.send_header("Transfer-Encoding", "chunked")
        h.send_header("request-id", f"req_{n}")
        h.end_headers()
        if reply.deep_event:
            events.insert(1, (None, "[" * 100_000 + "]" * 100_000))
        if reply.stream_error:
            events.insert(len(events) // 2, ("error", {"type": "error", "error": {"type": "overloaded_error",
                                                                                  "message": "Overloaded"}}))
        for i, (name, data) in enumerate(events):
            if reply.break_stream and i == len(events) // 2:
                h.wfile.flush()
                h.close_connection = True
                h.connection.shutdown(2)
                return
            time.sleep(reply.delay)
            payload = data if isinstance(data, str) else json.dumps(data)
            text = (f"event: {name}\n" if name else "") + "data: " + payload
            piece = (text + "\n\n").encode()
            h.wfile.write(b"%x\r\n%s\r\n" % (len(piece), piece))
            h.wfile.flush()
        h.wfile.write(b"0\r\n\r\n")
        h.wfile.flush()


def _send_json(h: BaseHTTPRequestHandler, status: int, value: Any) -> None:
    data = json.dumps(value).encode()
    h.send_response(status)
    h.send_header("Content-Type", "application/json")
    h.send_header("Content-Length", str(len(data)))
    h.send_header("x-request-id", "req_plain")
    h.end_headers()
    h.wfile.write(data)


def _chat(body: dict, r: Reply, n: int) -> dict:
    message: dict[str, Any] = {"role": "assistant", "content": r.text or None, "refusal": None}
    if r.tool:
        message["tool_calls"] = [{"id": r.call_id, "type": "function",
                                  "function": {"name": r.tool[0], "arguments": json.dumps(r.tool[1])}}]
    return {"id": f"chatcmpl-{n}", "object": "chat.completion", "created": 1, "model": body.get("model"),
            "choices": [{"index": 0, "message": message, "finish_reason": "tool_calls" if r.tool else "stop",
                         "logprobs": None}],
            "usage": {"prompt_tokens": 11, "completion_tokens": 5, "total_tokens": 16}}


def _chat_events(body: dict, r: Reply, n: int) -> list:
    base = {"id": f"chatcmpl-{n}", "object": "chat.completion.chunk", "created": 1, "model": body.get("model")}

    def chunk(delta: dict, finish: str | None = None) -> tuple:
        return (None, {**base, "choices": [{"index": 0, "delta": delta, "finish_reason": finish}]})

    events = [chunk({"role": "assistant", "content": ""})]
    half = len(r.text) // 2
    events += [chunk({"content": r.text[:half]}), chunk({"content": r.text[half:]})]
    if r.tool:
        args = json.dumps(r.tool[1])
        events.append(chunk({"tool_calls": [{"index": 0, "id": r.call_id, "type": "function",
                                             "function": {"name": r.tool[0], "arguments": ""}}]}))
        events.append(chunk({"tool_calls": [{"index": 0, "function": {"arguments": args[:5]}}]}))
        events.append(chunk({"tool_calls": [{"index": 0, "function": {"arguments": args[5:]}}]}))
    events.append(chunk({}, "tool_calls" if r.tool else "stop"))
    events.append((None, {**base, "choices": [], "usage": {"prompt_tokens": 11, "completion_tokens": 5,
                                                           "total_tokens": 16}}))
    events.append((None, "[DONE]"))
    return events


def _response_output(r: Reply) -> list:
    output: list[dict] = [{"type": "message", "id": "msg_1", "status": "completed", "role": "assistant",
                           "content": [{"type": "output_text", "text": r.text, "annotations": []}]}]
    if r.tool:
        output.append({"type": "function_call", "id": "fc_1", "call_id": r.call_id, "name": r.tool[0],
                       "arguments": json.dumps(r.tool[1]), "status": "completed"})
    return output


def _response(body: dict, r: Reply, n: int, status: str = "completed", output: list | None = None) -> dict:
    return {"id": f"resp_{n}", "object": "response", "created_at": 1, "status": status, "model": body.get("model"),
            "output": _response_output(r) if output is None else output, "parallel_tool_calls": True,
            "tool_choice": "auto", "tools": [], "usage": {"input_tokens": 11, "output_tokens": 5, "total_tokens": 16}}


def _responses_events(body: dict, r: Reply, n: int) -> list:
    events: list = [("response.created", {"type": "response.created", "sequence_number": 0,
                                          "response": _response(body, r, n, "in_progress", [])})]
    for i, item in enumerate(_response_output(r)):
        events.append(("response.output_item.added", {"type": "response.output_item.added", "sequence_number": i + 1,
                                                      "output_index": i, "item": {**item, "status": "in_progress"}}))
        events.append(("response.output_item.done", {"type": "response.output_item.done", "sequence_number": i + 1,
                                                     "output_index": i, "item": item}))
    events.append(("response.completed", {"type": "response.completed", "sequence_number": 9,
                                          "response": _response(body, r, n)}))
    return events


def _anthropic(body: dict, r: Reply, n: int) -> dict:
    content: list[dict] = [{"type": "text", "text": r.text}] if r.text else []
    if r.tool:
        content.append({"type": "tool_use", "id": r.call_id, "name": r.tool[0], "input": r.tool[1]})
    return {"id": f"msg_{n}", "type": "message", "role": "assistant", "model": body.get("model"), "content": content,
            "stop_reason": "tool_use" if r.tool else "end_turn", "stop_sequence": None,
            "usage": {"input_tokens": 11, "output_tokens": 5}}


def _anthropic_events(body: dict, r: Reply, n: int) -> list:
    start = {**_anthropic(body, r, n), "content": [], "stop_reason": None, "usage": {"input_tokens": 11,
                                                                                      "output_tokens": 1}}
    events: list = [("message_start", {"type": "message_start", "message": start})]
    index = 0
    if r.text:
        half = len(r.text) // 2
        events += [("content_block_start", {"type": "content_block_start", "index": 0,
                                            "content_block": {"type": "text", "text": ""}}),
                   ("content_block_delta", {"type": "content_block_delta", "index": 0,
                                            "delta": {"type": "text_delta", "text": r.text[:half]}}),
                   ("content_block_delta", {"type": "content_block_delta", "index": 0,
                                            "delta": {"type": "text_delta", "text": r.text[half:]}}),
                   ("content_block_stop", {"type": "content_block_stop", "index": 0})]
        index = 1
    if r.tool:
        args = json.dumps(r.tool[1])
        events += [("content_block_start", {"type": "content_block_start", "index": index,
                                            "content_block": {"type": "tool_use", "id": r.call_id,
                                                              "name": r.tool[0], "input": {}}}),
                   ("content_block_delta", {"type": "content_block_delta", "index": index,
                                            "delta": {"type": "input_json_delta", "partial_json": args[:4]}}),
                   ("content_block_delta", {"type": "content_block_delta", "index": index,
                                            "delta": {"type": "input_json_delta", "partial_json": args[4:]}}),
                   ("content_block_stop", {"type": "content_block_stop", "index": index})]
    events += [("message_delta", {"type": "message_delta", "delta": {"stop_reason": "tool_use" if r.tool
                                                                      else "end_turn", "stop_sequence": None},
                                  "usage": {"output_tokens": 5}}),
               ("message_stop", {"type": "message_stop"})]
    return events
