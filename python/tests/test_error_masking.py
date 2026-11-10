"""An egress event's error text must not show what its url field masks. Loopback only."""

import logging
import socket

import pytest

from mnestiq import MemorySink, Recorder
from mnestiq import egress
from mnestiq.egress import instrument_egress, sanitize_url, uninstrument_egress

requests = pytest.importorskip("requests")

SECRET = "hunter2"
# Queries sanitize_url masks that the error text used to show: a key in brackets, encoded brackets, a key
# with a colon, and a value with a bracket and a quote in it.
QUERIES = [
    "user[password]=hunter2",
    "secret%5B%5D=hunter2",
    "my:token=hunter2",
    "token=abc)def'ghi",
]
# Forms that were masked before as well, kept here so the change cannot lose them.
PLAIN = ["access_token=hunter2&a=1", "x=1&api%5Fkey=hunter2", "pass%77ord=hunter2", "q=1;session=hunter2"]


def _leaks(query):
    """What must not be left in the text for this query."""
    return ["abc", ")def", "ghi"] if "abc)" in query else [SECRET]


@pytest.fixture
def closed_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.fixture
def recorder():
    sink = MemorySink()
    rec = Recorder(sink, agent_id="a")
    instrument_egress()
    yield sink, rec
    uninstrument_egress()
    rec.close()


def _egress(sink):
    return [r["egress"][0] for r in sink.records if r.get("event_type") == "egress"]


def _no_proxy():
    return {"http": "", "https": ""}


@pytest.mark.parametrize("query", QUERIES)
def test_a_failed_request_names_no_secret_the_url_masks(recorder, closed_port, query):
    sink, rec = recorder
    with rec.run(), pytest.raises(requests.RequestException):
        requests.get(f"http://127.0.0.1:{closed_port}/p?{query}", timeout=0.3, proxies=_no_proxy())
    (entry,) = _egress(sink)
    assert entry.get("error"), entry
    for leak in _leaks(query):
        assert leak not in entry["url"]
        assert leak not in entry["error"], entry["error"]
    assert "127.0.0.1" in entry["error"] and "/p?" in entry["error"]  # the host and path are still told


def test_a_proxy_error_quoting_the_whole_url_names_no_secret(recorder, closed_port):
    sink, rec = recorder
    with rec.run():
        for query in [*QUERIES, *PLAIN]:
            with pytest.raises(requests.RequestException):
                requests.get(f"http://target.example/p?{query}", timeout=0.3,
                             proxies={"http": f"http://127.0.0.1:{closed_port}"})
    entries = _egress(sink)
    assert len(entries) == len(QUERIES) + len(PLAIN)
    for query, entry in zip([*QUERIES, *PLAIN], entries, strict=True):
        for leak in _leaks(query):
            assert leak not in entry["error"], entry["error"]
        assert "target.example" in entry["error"]


def test_what_was_masked_before_still_is(recorder, closed_port):
    sink, rec = recorder
    with rec.run():
        for query in PLAIN:
            with pytest.raises(requests.RequestException):
                requests.get(f"http://127.0.0.1:{closed_port}/p?{query}", timeout=0.3, proxies=_no_proxy())
    entries = _egress(sink)
    assert len(entries) == len(PLAIN)
    assert all(SECRET not in e["error"] and "/p?" in e["error"] for e in entries)


# The forms the clients' own errors take, each quoting the request it failed on.
TEXTS = {
    "requests": "HTTPConnectionPool(host='h.example', port=80): Max retries exceeded with "
                "url: {pq} (Caused by ConnectTimeoutError(<HTTPConnection(host='h.example', port=80)>, 'x'))",
    "urllib3": "HTTPConnectionPool(host='h.example', port=80): Max retries exceeded with url: {pq} "
               "(Caused by NewConnectionError('Failed to establish a new connection'))",
    "httpx": "Invalid URL 'http://h.example{pq}'",
    "urllib": "<urlopen error unknown url type: 'http://h.example{pq}'>",
}


def _recorded_error(rec, sink, url, text):
    """The error an egress event gets when a request to ``url`` fails with ``text``."""
    with rec.run(), egress._http_scope("GET", url) as ctx:
        assert ctx is not None
        egress._finish_http(ctx, error=OSError(text))
    return _egress(sink)[-1]["error"]


@pytest.mark.parametrize("client", sorted(TEXTS))
@pytest.mark.parametrize("query", QUERIES)
def test_each_client_error_form_is_masked_like_the_url(recorder, client, query):
    sink, rec = recorder
    url = f"http://h.example/p?{query}"
    masked = _recorded_error(rec, sink, url, TEXTS[client].format(pq=f"/p?{query}"))
    for leak in _leaks(query):
        assert leak not in masked, masked
        assert leak not in sanitize_url(url)
    assert "h.example" in masked and "/p?" in masked


@pytest.mark.parametrize("query", QUERIES)
def test_the_pattern_alone_masks_a_url_it_was_not_given(recorder, query):
    """A redirect's error quotes a URL the request did not start with: the pattern has to cover it alone."""
    sink, rec = recorder
    masked = _recorded_error(rec, sink, "http://h.example/start", f"failed: url: /p?{query} (Caused by X)")
    for leak in _leaks(query):
        assert leak not in masked, masked


def test_masking_a_short_value_does_not_eat_the_host_port_or_path(recorder):
    sink, rec = recorder
    url = "http://10.1.1.1:8080/v1/items?pin=1&page=1"
    text = "HTTPConnectionPool(host='10.1.1.1', port=8080): Max retries exceeded with url: /v1/items?pin=1&page=1"
    masked = _recorded_error(rec, sink, url, text)
    assert "host='10.1.1.1', port=8080" in masked
    assert "/v1/items?pin=***&page=1" in masked


def test_names_that_do_not_look_secret_keep_their_values(recorder):
    sink, rec = recorder
    text = "url: /search?q=hunter&page=2 (Caused by X)"
    assert _recorded_error(rec, sink, "http://h.example/search?q=hunter&page=2", text) == f"OSError: {text}"


def test_the_proxy_log_masks_a_bad_request_line(caplog):
    from mnestiq.proxy.server import _Handler

    handler = _Handler.__new__(_Handler)
    with caplog.at_level(logging.DEBUG, logger="mnestiq"):
        for query in [*QUERIES, *PLAIN]:
            handler.log_message("code %d, message %s", 400, f"Bad request syntax ('GET /p?{query} HTTP/1.1')")
    logged = "\n".join(r.getMessage() for r in caplog.records)
    assert SECRET not in logged and "ghi" not in logged and ")def" not in logged
    assert logged.count("/p?") == len(QUERIES) + len(PLAIN)
