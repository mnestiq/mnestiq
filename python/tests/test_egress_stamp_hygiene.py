"""The run id headers go only where they are meant to: never to a host left out, never back into the caller's own
request object. Host lists are read as host names. A cancellation stays a cancellation in strict mode, and events
put aside while the chain was busy keep their order."""

import asyncio
import http.server
import threading
import typing
import urllib.request

import pytest

from mnestiq import MemorySink, Recorder
from mnestiq import egress as eg
from mnestiq.egress import EGRESS_HEADER, RUN_HEADER, instrument_egress, uninstrument_egress

httpx = pytest.importorskip("httpx")
requests = pytest.importorskip("requests")
urllib3 = pytest.importorskip("urllib3")

OURS = {RUN_HEADER.lower(), EGRESS_HEADER.lower()}


class _Handler(http.server.BaseHTTPRequestHandler):
    seen: typing.ClassVar[list] = []

    def do_GET(self):
        _Handler.seen.append((self.headers.get("Host", ""), self.path,
                              {k.lower() for k in self.headers if k.lower() in OURS}))
        if self.path == "/hop":  # on to the same server under a name that is left out
            self.send_response(302)
            self.send_header("Location", f"http://localhost:{self.server.server_port}/landed")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *args):
        pass


@pytest.fixture(scope="module")
def server():
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv.server_port
    srv.shutdown()
    srv.server_close()


@pytest.fixture(autouse=True)
def clean():
    _Handler.seen.clear()
    yield
    uninstrument_egress()


def _headers_at(path):
    return [names for _, p, names in _Handler.seen if p == path]


def _httpx_get(url):
    with httpx.Client(follow_redirects=True, trust_env=False) as client:
        return client.get(url).status_code


def _requests_get(url):
    session = requests.Session()
    session.trust_env = False
    return session.get(url).status_code


def _urllib3_get(url):
    return urllib3.PoolManager().request("GET", url, redirect=True).status


@pytest.mark.parametrize("get", [_httpx_get, _requests_get, _urllib3_get], ids=["httpx", "requests", "urllib3"])
def test_a_redirect_to_an_ignored_host_carries_no_run_headers(server, get):
    rec = Recorder(MemorySink(), agent_id="a")
    instrument_egress(ignore_hosts={"localhost"}, stamp_hosts={"127.0.0.1"})
    with rec.run():
        assert get(f"http://127.0.0.1:{server}/hop") == 200
    rec.close()
    assert _headers_at("/hop") == [OURS]
    assert _headers_at("/landed") == [set()]


def test_a_request_object_sent_again_carries_no_old_run_id(server):
    rec = Recorder(MemorySink(), agent_id="a")
    instrument_egress(ignore_hosts=set())
    prepared = requests.Request("GET", f"http://127.0.0.1:{server}/first").prepare()
    built = httpx.Request("GET", f"http://127.0.0.1:{server}/first")
    session = requests.Session()
    session.trust_env = False
    with rec.run(), httpx.Client(trust_env=False) as client:
        session.send(prepared)
        client.send(built)
    assert not OURS & {k.lower() for k in prepared.headers}
    assert not OURS & {k.lower() for k in built.headers}
    uninstrument_egress()
    prepared.url = f"http://127.0.0.1:{server}/again"
    built.url = httpx.URL(f"http://127.0.0.1:{server}/again")
    session.send(prepared)
    with httpx.Client(trust_env=False) as client:
        client.send(built)
    rec.close()
    assert _headers_at("/first") == [OURS, OURS]
    assert _headers_at("/again") == [set(), set()]


def test_a_caller_header_of_ours_is_restored_on_its_own_object(server):
    rec = Recorder(MemorySink(), agent_id="a")
    instrument_egress(ignore_hosts=set())
    built = httpx.Request("GET", f"http://127.0.0.1:{server}/first", headers={RUN_HEADER: "theirs"})
    with rec.run(), httpx.Client(trust_env=False) as client:
        client.send(built)
    rec.close()
    assert built.headers[RUN_HEADER] == "theirs"


def test_urllib_leaves_a_header_of_ours_off_an_ignored_host(server):
    rec = Recorder(MemorySink(), agent_id="a")
    instrument_egress(ignore_hosts={"127.0.0.1"})
    request = urllib.request.Request(f"http://127.0.0.1:{server}/plain", headers={RUN_HEADER: "stale"})
    with rec.run():
        urllib.request.build_opener(urllib.request.ProxyHandler({})).open(request).read()
    rec.close()
    assert _headers_at("/plain") == [set()]
    assert request.get_header(RUN_HEADER.capitalize()) == "stale"  # the caller's own object is unchanged


@pytest.mark.parametrize("given, host, matches", [
    ({"Example.com"}, "example.com", True),
    ({"example.com."}, "api.example.com", True),
    ({"[::1]"}, "::1", True),
    ({"example.com"}, "EXAMPLE.COM.", True),
    ({"example.com"}, "notexample.com", False),
])
def test_host_lists_are_read_as_host_names(given, host, matches):
    instrument_egress(ignore_hosts=given, stamp_hosts=given)
    cfg = eg._config
    assert cfg is not None
    assert eg._host_matches(host, cfg.ignore_hosts) is matches
    assert eg._host_matches(host, cfg.stamp_hosts) is matches
    assert eg._host_matches(host, frozenset(given)) is matches  # a list matched directly is read the same way


@pytest.mark.parametrize("option", ["ignore_hosts", "stamp_hosts"])
@pytest.mark.parametrize("bad", ["example.com", b"example.com", 5, {"example.com", 7}])
def test_a_host_list_that_is_not_a_set_of_names_is_refused(option, bad):
    with pytest.raises(TypeError, match=option):
        instrument_egress(**{option: bad})
    assert eg._config is None


class _Failing(MemorySink):
    def append(self, record):
        if record.get("event_type") == "egress":
            raise OSError("disk full")
        super().append(record)


def test_a_cancellation_stays_a_cancellation_in_strict_mode():
    rec = Recorder(_Failing(), agent_id="a", strict=True)
    instrument_egress(ignore_hosts=set())

    def interrupted(request):
        raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        with rec.run():
            with httpx.Client(transport=httpx.MockTransport(interrupted), trust_env=False) as client:
                client.get("http://127.0.0.1:9/")

    async def cancelled(request):
        raise asyncio.CancelledError

    async def main():
        async with httpx.AsyncClient(transport=httpx.MockTransport(cancelled), trust_env=False) as client:
            await client.get("http://127.0.0.1:9/")

    with pytest.raises(asyncio.CancelledError):
        with rec.run():
            asyncio.run(main())
    failures = rec.failures
    assert failures >= 2  # the records that could not be written are still counted

    def failing(request):
        raise ValueError("refused")

    with pytest.raises(OSError):  # an ordinary error is replaced, as strict asks
        with rec.run():
            with httpx.Client(transport=httpx.MockTransport(failing), trust_env=False) as client:
                client.get("http://127.0.0.1:9/")


def test_events_put_aside_keep_their_order_when_the_chain_is_busy():
    sink = MemorySink()
    rec = Recorder(sink, agent_id="a")
    instrument_egress(ignore_hosts=set())
    try:
        with rec.run() as run:
            eg._deferred_events.clear()
            for name in "ABC":
                eg._deferred_events.append((run, "note", {"attributes": {"message": name}}))
            held, go = threading.Event(), threading.Event()

            def hold():
                with rec._lock:
                    held.set()
                    go.wait()

            holder = threading.Thread(target=hold)
            holder.start()
            held.wait()
            try:
                eg._flush_deferred()
                assert [f["attributes"]["message"] for _, _, f in eg._deferred_events] == ["A", "B", "C"]
            finally:  # never left holding the lock the close needs
                go.set()
                holder.join()
            eg._flush_deferred()
        notes = [r["attributes"].get("message") for r in sink.records if r.get("event_type") == "note"]
        assert [n for n in notes if n in ("A", "B", "C")] == ["A", "B", "C"]
    finally:
        eg._deferred_events.clear()
        rec.close()


def test_events_put_aside_from_a_thread_without_a_run_are_capped(monkeypatch):
    rec = Recorder(MemorySink(), agent_id="a")
    instrument_egress(ignore_hosts=set())
    monkeypatch.setattr(eg, "_MAX_DEFERRED", 2)
    try:
        with rec.run() as run:
            eg._deferred_events.clear()
            held, go = threading.Event(), threading.Event()

            def hold():
                with rec._lock:
                    held.set()
                    go.wait()

            holder = threading.Thread(target=hold)
            holder.start()
            held.wait()
            token = eg._marks.set(eg._INFERRED)
            try:
                before = rec.failures
                for _ in range(5):
                    run.note("from a worker")
                assert len(eg._deferred_events) == 2
                assert rec.failures == before + 3
            finally:  # never left holding the lock the close needs
                eg._marks.reset(token)
                go.set()
                holder.join()
    finally:
        eg._deferred_events.clear()
        rec.close()
