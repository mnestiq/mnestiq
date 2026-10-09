"""Egress recording, checked against the client address a real local server observed."""

import asyncio
import typing
import http.server
import socket
import threading

import pytest

from mnestiq import MemorySink, Recorder, verify_lines
from mnestiq.canonical import canonical_json
from mnestiq.egress import (
    EGRESS_HEADER,
    RUN_HEADER,
    instrument_egress,
    sanitize_url,
    uninstrument_egress,
)
from mnestiq.identity import detect_sandbox_id

httpx2 = pytest.importorskip("httpx2")
httpx = pytest.importorskip("httpx")
requests = pytest.importorskip("requests")


class _Handler(http.server.BaseHTTPRequestHandler):
    seen: typing.ClassVar[list] = []

    def do_GET(self):
        _Handler.seen.append({"path": self.path, "headers": dict(self.headers), "client": self.client_address})
        if self.path == "/slow":  # reads the request, answers late: the client gives up first
            import time
            time.sleep(1.5)
        if self.path == "/redirect-elsewhere":  # to the same server under another name
            self.send_response(302)
            self.send_header("Location", f"http://localhost:{self.server.server_port}/ok")
            self.end_headers()
            return
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/ok")
            self.end_headers()
            return
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *args):
        pass


@pytest.fixture(scope="module")
def server():
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_port}"
    srv.shutdown()


@pytest.fixture
def tcp_server():
    """Accepts connections and records the peer address, like an SMTP server would see."""
    lsock = socket.socket()
    lsock.bind(("127.0.0.1", 0))
    lsock.listen()
    peers: list = []

    def accept():
        while True:
            try:
                conn, addr = lsock.accept()
            except OSError:
                return
            peers.append(addr)
            conn.close()

    threading.Thread(target=accept, daemon=True).start()
    yield lsock.getsockname()[1], peers
    lsock.close()


@pytest.fixture(autouse=True)
def hooks():
    _Handler.seen.clear()
    instrument_egress(ignore_hosts=set())
    yield
    uninstrument_egress()


@pytest.fixture
def rec():
    return Recorder(MemorySink(), agent_id="agent", sandbox_id="container:abc123", public_ip="203.0.113.7")


def egress_events(rec):
    return [r for r in rec._sink.records if r.get("event_type") == "egress"]


def assert_joinable(entry, seen):
    """Evidence and server agree on headers and the connection 4-tuple."""
    assert seen["headers"][RUN_HEADER] == entry["run_id"]
    assert seen["headers"][EGRESS_HEADER] == entry["egress"][0]["egress_id"]
    eg = entry["egress"][0]
    assert (eg["source_ip"], eg["source_port"]) == tuple(seen["client"])


def assert_valid(rec):
    report = verify_lines(canonical_json(r) for r in rec._sink.records)
    assert report.ok, report.errors


@pytest.mark.parametrize("lib", ["httpx2", "httpx"])
def test_httpx_sync_stamped_and_joinable(server, rec, lib):
    client_cls = {"httpx2": httpx2.Client, "httpx": httpx.Client}[lib]
    with rec.run() as run, client_cls() as client:
        assert client.get(f"{server}/ok?api_key=SECRET&q=shoes").status_code == 200
    (event,) = egress_events(rec)
    eg = event["egress"][0]
    assert event["run_id"] == run.run_id and event["sandbox_id"] == "container:abc123"
    assert eg["protocol"] == "http" and eg["method"] == "GET" and eg["status"] == 200
    assert eg["url"].endswith("/ok?api_key=%2A%2A%2A&q=shoes")
    assert "SECRET" not in canonical_json(rec._sink.records).decode()
    assert eg["run_id_header"] is True and eg["public_ip"] == "203.0.113.7"
    assert eg["dest_port"] == int(server.rsplit(":", 1)[1])
    assert_joinable(event, _Handler.seen[0])
    assert_valid(rec)


def test_httpx_async(server, rec):
    async def go():
        async with httpx2.AsyncClient() as client:
            return await client.get(f"{server}/ok")

    with rec.run():
        assert asyncio.run(go()).status_code == 200
    (event,) = egress_events(rec)
    assert_joinable(event, _Handler.seen[0])


def test_requests_stamped_and_joinable(server, rec):
    with rec.run():
        assert requests.get(f"{server}/ok", timeout=5).status_code == 200
    (event,) = egress_events(rec)  # the socket connect enriches it rather than adding a second event
    assert event["egress"][0]["protocol"] == "http"
    assert_joinable(event, _Handler.seen[0])
    assert_valid(rec)


def test_each_redirect_hop_is_recorded(server, rec):
    with rec.run(), httpx2.Client(follow_redirects=True) as client:
        client.get(f"{server}/redirect")
    events = egress_events(rec)
    assert [e["egress"][0]["status"] for e in events] == [302, 200]
    for event, seen in zip(events, _Handler.seen, strict=True):
        assert_joinable(event, seen)


def test_raw_tcp_connection_is_attributed(tcp_server, rec):
    port, peers = tcp_server
    with rec.run() as run:
        socket.create_connection(("127.0.0.1", port), timeout=5).close()
    (event,) = egress_events(rec)
    eg = event["egress"][0]
    assert event["run_id"] == run.run_id and eg["protocol"] == "tcp"
    assert eg["dest_port"] == port
    for _ in range(50):  # the accept thread may lag slightly
        if peers:
            break
        threading.Event().wait(0.01)
    assert (eg["source_ip"], eg["source_port"]) == tuple(peers[0])
    assert_valid(rec)


def test_refused_connection_recorded_as_error(rec):
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()  # nothing listens here now
    with rec.run(), pytest.raises(OSError):
        socket.create_connection(("127.0.0.1", port), timeout=2)
    events = egress_events(rec)
    assert events and all(e["status"] == "error" and e["egress"][0]["error"] for e in events)
    assert_valid(rec)


def test_nothing_happens_outside_a_run(server, rec):
    with httpx2.Client() as client:
        client.get(f"{server}/ok")
    assert egress_events(rec) == []
    assert RUN_HEADER not in _Handler.seen[0]["headers"]


def test_ignored_hosts_are_neither_stamped_nor_recorded(server, rec):
    instrument_egress(ignore_hosts={"127.0.0.1"})
    with rec.run(), httpx2.Client() as client:
        client.get(f"{server}/ok")
    assert egress_events(rec) == []  # not even the underlying TCP connect
    assert RUN_HEADER not in _Handler.seen[0]["headers"]


def test_stamp_hosts_limits_headers_but_still_records(server, rec):
    instrument_egress(ignore_hosts=set(), stamp_hosts={"internal.example"})
    with rec.run(), httpx2.Client() as client:
        client.get(f"{server}/ok")
    (event,) = egress_events(rec)
    assert event["egress"][0]["run_id_header"] is False
    assert RUN_HEADER not in _Handler.seen[0]["headers"]


def test_uninstrument_restores_originals(server, rec):
    uninstrument_egress()
    with rec.run(), httpx2.Client() as client:
        client.get(f"{server}/ok")
    assert egress_events(rec) == []


@pytest.mark.parametrize("url, expected", [
    ("https://user:pw@host.example/p?token=abc&page=2#frag", "https://host.example/p?token=%2A%2A%2A&page=2"),
    ("https://s3.example/obj?X-Amz-Signature=deadbeef&X-Amz-Credential=me", "https://s3.example/obj?X-Amz-Signature=%2A%2A%2A&X-Amz-Credential=%2A%2A%2A"),
    ("http://[::1]:8080/x?code=123&postcode=SW1", "http://[::1]:8080/x?code=%2A%2A%2A&postcode=SW1"),
])
def test_sanitize_url(url, expected):
    assert sanitize_url(url) == expected


def test_sandbox_id_env_override(monkeypatch):
    monkeypatch.setenv("MNESTIQ_SANDBOX_ID", "ecs:task/abc")
    assert detect_sandbox_id() == "ecs:task/abc"
    monkeypatch.delenv("MNESTIQ_SANDBOX_ID")
    assert detect_sandbox_id().split(":", 1)[0] in ("host", "container", "k8s")


def test_a_timestamp_authority_reached_during_a_checkpoint_does_not_break_the_chain(tcp_server):
    """Found with a real agent: the recorder's own call to the timestamp authority was captured as the
    agent's egress, written in the middle of the checkpoint, and took its place in the chain."""
    from mnestiq.keys import generate_private_key

    port, _ = tcp_server

    def timestamper(signature):
        socket.create_connection(("127.0.0.1", port), timeout=5).close()  # what a real TSA request does
        raise OSError("no answer")  # the checkpoint is then written without a token

    rec = Recorder(MemorySink(), agent_id="agent", sandbox_id="container:abc123", signing_key=generate_private_key(),
                   timestamper=timestamper, checkpoint_every=2)
    with rec.run() as run:
        for i in range(5):
            run.note(str(i))
    rec.close()
    assert_valid(rec)
    assert egress_events(rec) == []  # the recorder's own traffic is not the agent's
    assert sum(r["kind"] == "checkpoint" for r in rec._sink.records) >= 3


def test_an_event_written_while_a_checkpoint_is_signed_comes_after_it():
    """Whatever writes during a checkpoint (a hook, a logging handler), the chain stays whole."""
    from mnestiq.keys import generate_private_key
    from mnestiq.signers import LocalSigner

    class Chatty(LocalSigner):
        def sign(self, payload):
            rec.append_event({"event_type": "note", "run_id": "r", "agent_id": "agent",
                              "attributes": {"message": "written while signing"}})
            return super().sign(payload)

    rec = Recorder(MemorySink(), agent_id="agent", sandbox_id="container:abc123",
                   signer=Chatty(generate_private_key()), checkpoint_every=3)
    with rec.run() as run:
        for i in range(7):
            run.note(str(i))
    rec.close()
    assert_valid(rec)
    kinds = [(r["kind"], (r.get("attributes") or {}).get("message")) for r in rec._sink.records]
    first = kinds.index(("checkpoint", None))
    assert kinds[first + 1] == ("event", "written while signing")


def test_a_request_cancelled_by_a_timeout_is_still_recorded(server, rec):
    """The server already has the request when the agent's framework gives up on it. A cancelled
    request used to leave no trace, so an attacker's slow server made an upload invisible."""
    async def go():
        async with httpx.AsyncClient() as client:
            await asyncio.wait_for(client.get(f"{server}/slow"), 0.3)

    with rec.run():
        with pytest.raises(asyncio.TimeoutError):
            asyncio.run(go())
    (event,) = egress_events(rec)
    assert "CancelledError" in event["egress"][0]["error"]
    assert _Handler.seen and _Handler.seen[0]["path"] == "/slow"


def test_a_cancelled_tool_is_still_recorded(rec):
    @rec.tool()
    async def upload(path):
        await asyncio.sleep(5)

    async def go():
        await asyncio.wait_for(upload("export.csv"), 0.1)

    with rec.run():
        with pytest.raises(asyncio.TimeoutError):
            asyncio.run(go())
    (call,) = [r["tool_calls"][0] for r in rec._sink.records if r.get("event_type") == "tool_call"]
    assert call["name"] == "upload" and "CancelledError" in call["error"]


def test_a_run_id_a_header_cannot_carry_does_not_break_the_request(server, rec):
    """A caller-chosen run id with a line break or non-Latin text made the agent's request fail."""
    for run_id in ("ünïcode-run", "line\r\nbreak"):
        _Handler.seen.clear()
        with rec.run(run_id=run_id):
            assert httpx.get(f"{server}/ok").status_code == 200
        assert RUN_HEADER not in _Handler.seen[0]["headers"] and EGRESS_HEADER in _Handler.seen[0]["headers"]


def test_a_failed_request_does_not_record_the_secret_in_its_error(rec):
    with rec.run():
        with pytest.raises(requests.RequestException):  # requests puts the whole URL in its error
            requests.get("http://127.0.0.1:9/x?api_key=SECRET123&q=1", timeout=2)
    (event,) = egress_events(rec)
    assert "SECRET123" not in canonical_json(event).decode()


def test_a_redirect_does_not_carry_the_headers_to_a_host_left_out(server, rec):
    """requests copies the first request's headers onto the redirect: with stamp_hosts, the run's
    identity used to reach the host it was meant to be kept from."""
    instrument_egress(ignore_hosts=set(), stamp_hosts={"127.0.0.1"})
    with rec.run():
        assert requests.get(f"{server}/redirect-elsewhere", timeout=5).status_code == 200
    first, second = _Handler.seen
    assert RUN_HEADER in first["headers"]
    assert RUN_HEADER not in second["headers"] and EGRESS_HEADER not in second["headers"]
