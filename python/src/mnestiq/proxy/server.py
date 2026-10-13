"""The proxy: passes an agent's model calls on unchanged and records each one."""

from __future__ import annotations

import contextlib
import http.client
import ipaddress
import json
import logging
import queue
import re
import socket
import ssl
import threading
import time
import zlib
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlsplit

from ..egress import sanitize_url
from ..recorder import Recorder, Run
from .formats import (
    ANTHROPIC,
    OPENAI,
    EventStream,
    answer_fields,
    model_api,
    request_fields,
    stream_reader,
    unreadable_request,
)
from .runs import Runs

_log = logging.getLogger("mnestiq")

DEFAULT_UPSTREAMS = ("openai=https://api.openai.com", "anthropic=https://api.anthropic.com")
_NAME = re.compile(r"^[a-z0-9][a-z0-9-]{0,31}$")
# Hop-by-hop headers, and the ones the proxy sets itself.
_NOT_FORWARDED = frozenset({"connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
                            "proxy-connection", "te", "trailer", "transfer-encoding", "upgrade", "host",
                            "content-length", "accept-encoding", "expect"})
# Request headers worth keeping: they say which client and API version sent the call. Never keys.
_KEPT_HEADERS = ("user-agent", "anthropic-version", "anthropic-beta", "openai-beta", "openai-organization",
                 "openai-project", "x-stainless-lang", "x-stainless-package-version", "x-stainless-runtime")
_PROVIDER_IDS = ("request-id", "x-request-id", "apim-request-id")
_CREDENTIAL_HEADERS = ("authorization", "x-api-key", "api-key", "x-goog-api-key")
# Masks key=, token=... in anything logged: a malformed request line is logged as it came.
_SECRET_IN_TEXT = re.compile(r"(?i)((?:api[_-]?)?key|token|secret|sig|signature|password|auth)=[^&\s'\"]+")
_MiB = 1 << 20
_CHUNK_SIZE = re.compile(rb"[0-9A-Fa-f]{1,8}")  # hex digits only: no sign, no 0x, no 4 GiB chunks
_MAX_TRAILERS = 64


@dataclass(frozen=True)
class Upstream:
    """A model provider the proxy forwards to, reached at ``/<name>/...`` on the proxy."""

    name: str
    family: str
    scheme: str
    host: str
    port: int
    base_path: str

    @classmethod
    def parse(cls, spec: str) -> Upstream:
        """``NAME=URL``, or ``NAME=anthropic:URL`` / ``NAME=openai:URL`` to say which API it speaks
        (by default Anthropic's when the name or host says anthropic, otherwise OpenAI's)."""
        name, sep, url = spec.partition("=")
        name = name.strip().lower()
        if not sep or not _NAME.match(name):
            raise ValueError(f"upstream {spec!r}: expected NAME=URL, the name in a-z, 0-9 and -")
        family = None
        for known in (ANTHROPIC, OPENAI):
            if url.startswith(known + ":") and not url.startswith(known + "://"):
                family, url = known, url[len(known) + 1:]
        parts = urlsplit(url.strip())
        if parts.scheme not in ("https", "http") or not parts.hostname:
            raise ValueError(f"upstream {name}: {url!r} is not an http(s) URL")
        if parts.username or parts.password or parts.query or parts.fragment:
            raise ValueError(f"upstream {name}: no credentials, query or fragment in the URL")
        if parts.scheme == "http" and not _is_loopback(parts.hostname):
            raise ValueError(f"upstream {name}: plain http only to this machine (a local model server), "
                             "otherwise https")
        if family is None:
            family = ANTHROPIC if "anthropic" in name or "anthropic" in parts.hostname else OPENAI
        return cls(name, family, parts.scheme, parts.hostname,
                   parts.port or (443 if parts.scheme == "https" else 80), parts.path.rstrip("/"))

    @property
    def host_header(self) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host
        default = 443 if self.scheme == "https" else 80
        return host if self.port == default else f"{host}:{self.port}"

    def url(self, rest: str) -> str:
        return f"{self.scheme}://{self.host_header}{self.base_path}{rest}"


def _is_loopback(host: str) -> bool:
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        return False


def parse_listen(listen: str) -> tuple[str, int]:
    host, sep, port = listen.rpartition(":")
    if not sep or not port.isdigit():
        raise ValueError(f"--listen {listen!r}: expected host:port")
    return host.strip("[]") or "127.0.0.1", int(port)


class _Pool:
    """Keeps a few open connections to an upstream: a new TLS connection per call costs time."""

    def __init__(self, upstream: Upstream, timeout: float, context: ssl.SSLContext, size: int = 8) -> None:
        self.upstream, self.timeout, self.context = upstream, timeout, context
        self._idle: queue.LifoQueue[http.client.HTTPConnection] = queue.LifoQueue(size)

    def get(self) -> tuple[http.client.HTTPConnection, bool]:
        try:
            return self._idle.get_nowait(), True
        except queue.Empty:
            pass
        if self.upstream.scheme == "https":
            return http.client.HTTPSConnection(self.upstream.host, self.upstream.port, timeout=self.timeout,
                                               context=self.context), False
        return http.client.HTTPConnection(self.upstream.host, self.upstream.port, timeout=self.timeout), False

    def put(self, conn: http.client.HTTPConnection) -> None:
        try:
            self._idle.put_nowait(conn)
        except queue.Full:
            conn.close()

    def close(self) -> None:
        while True:
            try:
                self._idle.get_nowait().close()
            except queue.Empty:
                return


class ModelProxy:
    """Records an agent's model calls from outside the agent. See ``mnestiq.proxy``.

    One proxy writes one evidence chain through ``recorder``. Recording never stops a call: if
    writing evidence fails, the call goes through and the failure is counted
    (``recorder.failures``), as with the recorder inside an agent.
    """

    def __init__(
        self,
        recorder: Recorder,
        *,
        upstreams: Iterable[str | Upstream] = DEFAULT_UPSTREAMS,
        listen: str = "127.0.0.1:8787",
        allow_network: bool = False,
        allow_clients: Iterable[str] = (),
        tool_sources: dict[str, str] | None = None,
        max_request_bytes: int = 64 * _MiB,
        max_capture_bytes: int = 64 * _MiB,
        upstream_timeout: float = 600.0,
        client_timeout: float = 300.0,
        max_connections: int = 256,
        tls_context: ssl.SSLContext | None = None,
    ) -> None:
        self.recorder = recorder
        self.upstreams: dict[str, Upstream] = {}
        for spec in upstreams:
            up = spec if isinstance(spec, Upstream) else Upstream.parse(spec)
            if up.name in self.upstreams:
                raise ValueError(f"upstream {up.name} given twice")
            self.upstreams[up.name] = up
        if not self.upstreams:
            raise ValueError("no upstream to forward to")
        self.host, self.port = parse_listen(listen)
        self.allow_network = allow_network
        self.allow_clients = [ipaddress.ip_network(c.strip(), strict=False) for c in allow_clients]
        if not _is_loopback(self.host):
            if not allow_network:
                raise ValueError(f"listening on {self.host} reaches other machines: pass allow_network "
                                 "(--allow-network) and the addresses allowed to use the proxy (--allow-client)")
            if not self.allow_clients:
                raise ValueError("listening on the network needs at least one allowed client address (--allow-client)")
        self.tool_sources = dict(tool_sources or {})
        self.max_request_bytes = max_request_bytes
        self.max_capture_bytes = max_capture_bytes
        self.client_timeout = client_timeout
        self.max_connections = max_connections
        context = tls_context or ssl.create_default_context()
        self._pools = {name: _Pool(up, upstream_timeout, context) for name, up in self.upstreams.items()}
        self.runs = Runs(recorder, recorder.agent_id, recorder.operator_id)
        self._own = Run(recorder, run_id=f"proxy-{recorder.chain_id[:8]}", parent_run_id=None,
                        agent_id=recorder.agent_id, operator_id=recorder.operator_id)
        self._server: _Server | None = None
        self._thread: threading.Thread | None = None
        self._busy = 0  # calls being passed on or recorded
        self._idle = threading.Condition()

    # Lifecycle

    def start(self) -> tuple[str, int]:
        """Listen and serve in a background thread. Returns the address (the port, if 0 was given)."""
        self._server = _Server((self.host, self.port), self)
        self.port = self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever, name="mnestiq-proxy", daemon=True)
        self._thread.start()
        return self.host, self.port

    def wait(self) -> None:
        while self._thread is not None and self._thread.is_alive():
            self._thread.join(0.5)

    def close(self, wait: float = 30.0) -> None:
        """Stop taking calls, and give the ones under way ``wait`` seconds to finish and be recorded."""
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        with self._idle:
            self._idle.wait_for(lambda: self._busy == 0, timeout=wait)
        for pool in self._pools.values():
            pool.close()

    @contextlib.contextmanager
    def _call(self) -> Iterator[None]:
        with self._idle:
            self._busy += 1
        try:
            yield
        finally:
            with self._idle:
                self._busy -= 1
                self._idle.notify_all()

    def base_url(self, upstream: str) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host
        up = self.upstreams[upstream]
        # OpenAI's SDKs expect the /v1 in the base URL. Other providers' paths follow the name as they are.
        v1 = "/v1" if up.host == "api.openai.com" and not up.base_path else ""
        return f"http://{host}:{self.port}/{up.name}{v1}"

    # Checks

    def client_allowed(self, address: str) -> bool:
        try:
            ip = ipaddress.ip_address(address.split("%")[0])
        except ValueError:
            return False
        mapped = getattr(ip, "ipv4_mapped", None)  # ::ffff:127.0.0.1 on a dual-stack socket
        if ip.is_loopback or (mapped is not None and mapped.is_loopback):
            return True
        return any(ip in net for net in self.allow_clients)

    def host_allowed(self, host: str | None) -> bool:
        """Only names of this machine, unless listening on the network (then the client address
        list decides). Stops a web page from reaching the proxy through a name it controls."""
        if self.allow_network:
            return True
        if not host:
            return False
        name = host.rsplit(":", 1)[0] if not host.endswith("]") else host
        return _is_loopback(name.strip("[]"))

    def route(self, path: str) -> tuple[Upstream, str] | None:
        if not path.startswith("/"):
            return None
        name, _, rest = path[1:].partition("/")
        up = self.upstreams.get(name.lower())
        return (up, "/" + rest) if up is not None else None

    # Upstream

    def send(self, up: Upstream, method: str, path: str, headers: list[tuple[str, str]],
             body: bytes) -> tuple[http.client.HTTPConnection, http.client.HTTPResponse, dict]:
        pool = self._pools[up.name]
        for attempt in (1, 2):
            conn, reused = pool.get()
            try:
                conn.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
                conn.putheader("Host", up.host_header)
                conn.putheader("Accept-Encoding", "identity")  # the proxy reads what it passes on
                for name, value in headers:
                    conn.putheader(name, value)
                if body or method in ("POST", "PUT", "PATCH"):
                    conn.putheader("Content-Length", str(len(body)))
                conn.endheaders(body or None)
                where = _addresses(conn)
                return conn, conn.getresponse(), where
            except (http.client.RemoteDisconnected, http.client.ImproperConnectionState, ConnectionResetError,
                    BrokenPipeError):
                conn.close()
                if not reused or attempt == 2:  # only a kept connection that turned out unusable is retried
                    raise
            except BaseException:
                conn.close()
                raise
        raise AssertionError("unreachable")

    # Recording

    def record_call(self, run: Run, how: str, api: str, up: Upstream, rest: str, body: Any, status: int | None,
                    capture: _Capture | None, error: str | None, latency_ms: int, where: dict,
                    request_headers: Any, response_headers: dict[str, str], client: str) -> None:
        try:
            fields: dict[str, Any] = {"provider": up.name, "latency_ms": latency_ms}
            attributes: dict[str, Any] = {
                "captured_by": "proxy", "upstream": up.name, "api": api, "grouping": how,
                "streaming": bool(capture and capture.streaming), "http_status": status,
                "url": sanitize_url(up.url(rest)), "client": client,
                "request_headers": {k: request_headers[k] for k in _KEPT_HEADERS if request_headers.get(k)},
            }
            provider_id = next((response_headers[k] for k in _PROVIDER_IDS if response_headers.get(k)), None)
            if provider_id:
                attributes["upstream_request_id"] = provider_id
            if where:
                attributes["connection"] = where
            try:
                fields.update(request_fields(api, body, rest, self.tool_sources))
            except Exception:  # shaped as no SDK sends it: kept whole, as untrusted
                fields.update(unreadable_request(body))
                attributes["request_understood"] = False
            answer = capture.answer() if capture is not None else None
            if capture is not None and capture.stream_error is not None:  # the cause, before what followed
                error = "the provider reported an error in the stream: " + _short(capture.stream_error) + (
                    f" ({error})" if error else "")
            if status is not None and status >= 400 and error is None:
                error = f"HTTP {status}" + (f": {_error_message(answer)}" if answer else "")
            if answer is not None and (status or 0) < 400:
                try:
                    fields.update(answer_fields(api, answer))
                except Exception:
                    attributes["output_captured"] = False
            else:
                attributes["output_captured"] = False
            if error:
                fields["error"] = _without(error, _credentials(request_headers))
            fields["attributes"] = attributes
            run.llm_call(**fields)
            if "output" in fields:
                self.runs.learn(run, api, body, fields)
        except Exception as exc:
            self.recorder._record_failure(exc)

    def record_other(self, up: Upstream, method: str, rest: str, status: int | None, error: str | None,
                     client: str) -> None:
        """A request that is not a model call (models list, files, token counts): noted, so nothing
        passes the proxy unseen."""
        self._own.note("forwarded, not a model call", captured_by="proxy", upstream=up.name, method=method,
                       url=sanitize_url(up.url(rest)), http_status=status, error=error, client=client)


def _addresses(conn: http.client.HTTPConnection) -> dict:
    try:
        src, dst = conn.sock.getsockname(), conn.sock.getpeername()
        return {"host": conn.host, "source_ip": src[0], "source_port": src[1], "dest_ip": dst[0],
                "dest_port": dst[1]}
    except (OSError, AttributeError, IndexError):
        return {}


def _credentials(headers: Any) -> list[str]:
    """The keys a request carried, to make sure none is written down, even if a provider echoes one."""
    found = []
    for name in _CREDENTIAL_HEADERS:
        value = (headers.get(name) or "").strip()
        value = value.split(" ", 1)[1].strip() if " " in value else value  # "Bearer sk-..."
        if len(value) >= 8:
            found.append(value)
    return found


def _without(text: str, secrets: list[str]) -> str:
    for secret in secrets:
        text = text.replace(secret, "***")
    return text


def _error_message(answer: dict) -> str:
    err = answer.get("error")
    message = err.get("message") if isinstance(err, dict) else err
    return _short(message if message is not None else answer)


def _short(value: Any, limit: int = 300) -> str:
    text = value if isinstance(value, str) else json.dumps(value, default=str)[:limit]
    return text if len(text) <= limit else text[:limit] + "..."


class _Capture:
    """A copy of the answer as it passes, up to ``limit`` bytes, read back afterwards."""

    def __init__(self, api: str | None, streaming: bool, encoding: str, limit: int) -> None:
        self.api, self.streaming, self.limit = api, streaming and api is not None, limit
        self.raw = bytearray()
        self.complete = True
        self._inflate = zlib.decompressobj(16 + zlib.MAX_WBITS if encoding == "gzip" else zlib.MAX_WBITS) \
            if encoding in ("gzip", "deflate") else None
        self._unreadable = encoding not in ("", "identity", "gzip", "deflate")
        self._events = EventStream() if self.streaming else None
        self._reader = stream_reader(api) if self.streaming and api else None

    def feed(self, piece: bytes) -> None:
        if self._unreadable or self.api is None:
            return
        try:
            data = self._inflate.decompress(piece) if self._inflate is not None else piece
            if self._events is not None and self._reader is not None:
                for event, payload in self._events.feed(data):
                    self._reader.feed(event, payload)
            elif len(self.raw) + len(data) <= self.limit:
                self.raw += data
            else:
                self.complete = False
        except Exception:  # an answer the proxy cannot read is still passed on whole
            self._unreadable = True

    @property
    def stream_error(self) -> Any:
        return getattr(self._reader, "error", None)

    def answer(self) -> dict | None:
        if self._unreadable:
            return None
        if self._reader is not None:
            return self._reader.result()
        if not self.complete or not self.raw:
            return None
        try:
            value = json.loads(bytes(self.raw))
        except (ValueError, RecursionError):
            return None
        return value if isinstance(value, dict) else None


class _TooLarge(Exception):
    pass


class _Server(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address: tuple[str, int], proxy: ModelProxy) -> None:
        self.proxy = proxy
        self.address_family = socket.AF_INET6 if ":" in address[0] else socket.AF_INET
        self._slots = threading.BoundedSemaphore(proxy.max_connections)
        super().__init__(address, _Handler)

    def process_request(self, request: Any, client_address: Any) -> None:
        if not self._slots.acquire(blocking=False):
            with contextlib.suppress(OSError):
                request.sendall(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            self.shutdown_request(request)
            return
        super().process_request(request, client_address)

    def handle_error(self, request: Any, client_address: Any) -> None:
        # Agents hang up mid-answer all the time: not worth a traceback on the console.
        _log.debug("proxy: connection from %s ended with an error", client_address[0], exc_info=True)

    def process_request_thread(self, request: Any, client_address: Any) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "mnestiq-proxy"
    # Errors the HTTP layer answers itself (a malformed request line): JSON, and without echoing
    # the request line back.
    error_content_type = "application/json"
    error_message_format = '{"error": {"type": "mnestiq_proxy", "message": "%(code)d: %(explain)s"}}\n'
    sys_version = ""
    server: _Server

    def setup(self) -> None:
        super().setup()
        self.connection.settimeout(self.server.proxy.client_timeout)  # a client that stalls is let go

    def log_request(self, code: Any = "-", size: Any = "-") -> None:
        # The request line can carry a key in its query (some providers take ?key=): logged masked.
        # A request line that could not be parsed has no command or path yet.
        path = getattr(self, "path", "")
        _log.debug("proxy: %s %s -> %s", getattr(self, "command", "?"),
                   sanitize_url("http://proxy" + path) if path.startswith("/") else "(unparsed request)", code)

    def log_message(self, format: str, *args: Any) -> None:
        _log.debug("proxy: %s", _SECRET_IN_TEXT.sub(r"\1=***", format % args if args else format))

    def do_GET(self) -> None:
        with self.server.proxy._call():
            self._proxy()

    do_POST = do_PUT = do_PATCH = do_DELETE = do_HEAD = do_OPTIONS = do_GET

    def _refuse(self, status: int, message: str) -> None:
        body = json.dumps({"error": {"type": "mnestiq_proxy", "message": message}}).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        if status in (400, 413, 502):
            self.send_header("Connection", "close")
            self.close_connection = True
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _proxy(self) -> None:
        proxy = self.server.proxy
        client = self.client_address[0]
        if not proxy.client_allowed(client):
            return self._refuse(403, "this address may not use the proxy")
        if not proxy.host_allowed(self.headers.get("Host")):
            return self._refuse(421, "the proxy answers only to names of this machine")
        route = proxy.route(self.path)
        if route is None:
            return self._refuse(404, "no upstream at this path: use /<upstream>/..., with one of "
                                     + ", ".join(proxy.upstreams))
        up, rest = route
        try:
            body = self._read_body(proxy.max_request_bytes)
        except _TooLarge:
            return self._refuse(413, f"request body over {proxy.max_request_bytes} bytes")
        except ValueError as exc:
            return self._refuse(400, str(exc))
        method = self.command
        api = model_api(up.family, method, rest)
        parsed: Any = None
        if api is not None:
            try:
                parsed = json.loads(body)
            except (ValueError, RecursionError):  # not JSON, or nested too deep to read: passed on unread
                parsed = None
            if not isinstance(parsed, dict):
                parsed = {"unparsed": body.decode("utf-8", "replace")} if body else {}
        run, how = proxy.runs.assign(api, parsed, self.headers) if api is not None else (None, "")
        headers = _forwarded(self.headers)
        start = time.perf_counter()
        try:
            conn, response, where = proxy.send(up, method, up.base_path + rest, headers, body)
        except ssl.SSLError as exc:  # before ValueError: a failed certificate check is both
            refused = f"the upstream {up.name} failed the TLS check: {type(exc).__name__}"
            self._refuse(502, refused)
            if run is not None:
                proxy.record_call(run, how, api or "", up, rest, parsed, None, None, refused, _ms(start), {},
                                  self.headers, {}, client)
            else:
                proxy.record_other(up, method, rest, None, refused, client)
            return
        except ValueError:  # a header or path http.client will not send (a control character, say)
            self._refuse(400, "the request has a header or path the proxy cannot pass on")
            if run is not None:
                proxy.record_call(run, how, api or "", up, rest, parsed, None, None,
                                  "refused: a header or path the proxy cannot pass on", _ms(start), {},
                                  self.headers, {}, client)
            return
        except (OSError, http.client.HTTPException) as exc:
            unreachable = f"the upstream {up.name} could not be reached: {type(exc).__name__}"
            self._refuse(502, unreachable)
            if run is not None:
                proxy.record_call(run, how, api or "", up, rest, parsed, None, None, unreachable, _ms(start), {},
                                  self.headers, {}, client)
            else:
                proxy.record_other(up, method, rest, None, unreachable, client)
            return
        response_headers = {k.lower(): v for k, v in response.getheaders()}
        streaming = "text/event-stream" in response_headers.get("content-type", "")
        capture = _Capture(api, streaming, response_headers.get("content-encoding", "").lower(),
                           proxy.max_capture_bytes) if api is not None else None
        error = self._relay(conn, response, capture)
        if error is None and not response.will_close:
            response.close()  # read to the end, but Python 3.10 leaves it open and the connection unusable
            proxy._pools[up.name].put(conn)
        else:
            conn.close()
        if run is not None:
            proxy.record_call(run, how, api or "", up, rest, parsed, response.status, capture, error, _ms(start),
                              where, self.headers, response_headers, client)
        else:
            proxy.record_other(up, method, rest, response.status, error, client)

    def _relay(self, conn: http.client.HTTPConnection, response: http.client.HTTPResponse,
               capture: _Capture | None) -> str | None:
        """Pass the answer on as it arrives. Returns what went wrong, if anything."""
        no_body = self.command == "HEAD" or response.status in (204, 304) or 100 <= response.status < 200
        length = None if response.chunked else response.length
        chunked = not no_body and length is None and self.request_version >= "HTTP/1.1"
        self.send_response_only(response.status, response.reason)
        dropped = _NOT_FORWARDED | {h.strip().lower() for h in (response.getheader("Connection") or "").split(",")}
        for name, value in response.getheaders():
            if name.lower() not in dropped:
                self.send_header(name, value)
        if no_body:
            if self.command != "HEAD":
                self.send_header("Content-Length", "0")
        elif length is not None:
            self.send_header("Content-Length", str(length))
        elif chunked:
            self.send_header("Transfer-Encoding", "chunked")
        else:
            self.send_header("Connection", "close")
            self.close_connection = True
        self.end_headers()
        if no_body:
            response.read()
            return None
        while True:
            try:
                piece = response.read1(65536)
            except (OSError, http.client.HTTPException) as exc:
                self.close_connection = True  # the agent sees the answer end early
                return f"the upstream broke off the answer: {type(exc).__name__}"
            if capture is not None:
                capture.feed(piece)  # never raises: what it cannot read is left unrecorded
            try:
                if not piece:
                    if length is not None and response.length:  # fewer bytes than the provider announced
                        self.close_connection = True
                        return "the upstream broke off the answer: it ended early"
                    if chunked:
                        self.wfile.write(b"0\r\n\r\n")
                    self.wfile.flush()
                    return None
                self.wfile.write(b"%x\r\n%s\r\n" % (len(piece), piece) if chunked else piece)
                self.wfile.flush()
            except OSError:
                self.close_connection = True
                return "the agent closed the connection before the answer ended"

    def _read_body(self, limit: int) -> bytes:
        if "chunked" in (self.headers.get("Transfer-Encoding") or "").lower():
            data = bytearray()
            while True:
                line = self.rfile.readline(1024)
                token = line.split(b";", 1)[0].strip()
                if not _CHUNK_SIZE.fullmatch(token):
                    raise ValueError("malformed chunked request body")
                size = int(token, 16)
                if size == 0:
                    for _ in range(_MAX_TRAILERS):
                        if self.rfile.readline(1024) in (b"\r\n", b"\n", b""):
                            return bytes(data)
                    raise ValueError("too many trailer lines")
                if len(data) + size > limit:
                    raise _TooLarge
                data += self.rfile.read(size)
                self.rfile.readline(1024)
        length = self.headers.get("Content-Length")
        if length is None:
            return b""
        if not length.strip().isdigit():
            raise ValueError("bad Content-Length")
        size = int(length)
        if size > limit:
            raise _TooLarge
        body = self.rfile.read(size)
        if len(body) != size:
            raise ValueError("request body shorter than its Content-Length")
        return body


def _forwarded(headers: Any) -> list[tuple[str, str]]:
    named_hop = {h.strip().lower() for h in (headers.get("Connection") or "").split(",")}
    return [(k, v) for k, v in headers.items()
            if k.lower() not in _NOT_FORWARDED and k.lower() not in named_hop
            and not k.lower().startswith("x-mnestiq-")]


def _ms(start: float) -> int:
    return int((time.perf_counter() - start) * 1000)
