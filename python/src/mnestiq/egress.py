"""Egress identity propagation: tie every outbound connection to the agent step that made it.

    from mnestiq.egress import instrument_egress
    instrument_egress()

While a run is active, this:

* stamps ``X-Mnestiq-Run-Id`` and ``X-Mnestiq-Egress-Id`` into outbound HTTP
  requests (httpx, httpx2, requests), so reverse-proxy and API gateway logs carry
  the run id
* records an ``egress`` event per request with method, URL (secrets masked),
  status, and the connection's local/remote IP and port
* records an ``egress`` event for every other outbound TCP connection (SMTP,
  databases, raw sockets), so exfiltration that bypasses HTTP is still attributed.

The local IP and port are the join key to VPC flow logs and firewall logs, which
record (src addr, src port, dst addr, dst port, time) but know nothing about agents.

Limits: threads started with ``threading.Thread`` don't inherit the active run
(contextvars). asyncio's Windows proactor loop bypasses ``socket.connect``. Traffic
from subprocesses is not seen. Pair with infrastructure logs for full coverage.
"""

from __future__ import annotations

import contextvars
import errno
import importlib
import ipaddress
import re
import socket
import threading
import time
import uuid
import warnings
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any
from collections.abc import Iterator
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from .recorder import Run, current_run

RUN_HEADER = "X-Mnestiq-Run-Id"
EGRESS_HEADER = "X-Mnestiq-Egress-Id"

# Model API calls are already recorded as llm_call events.
DEFAULT_IGNORE_HOSTS = frozenset({"api.anthropic.com", "api.openai.com"})

_SECRET_PARAM = re.compile(
    r"(?i)(api[_-]?key|^key$|token|secret|passw|signature|^sig$|credential|auth|^code$|session)"
)
_IN_PROGRESS = {0, errno.EINPROGRESS, errno.EWOULDBLOCK, errno.EALREADY, 10035}  # 10035: WSAEWOULDBLOCK


@dataclass
class _Config:
    stamp_headers: bool
    capture_connections: bool
    ignore_hosts: frozenset[str]
    stamp_hosts: frozenset[str] | None


@dataclass
class _HttpCtx:
    run: Run
    egress_id: str
    method: str
    url: str
    host: str
    stamped: bool
    started: float = field(default_factory=time.perf_counter)
    source: tuple | None = None
    dest: tuple | None = None


_config: _Config | None = None
_patches: list[tuple[Any, str, Any]] = []
_install_lock = threading.Lock()
_active_http: contextvars.ContextVar[_HttpCtx | None] = contextvars.ContextVar("mnestiq_http", default=None)
_suppressed: contextvars.ContextVar[bool] = contextvars.ContextVar("mnestiq_egress_off", default=False)


def instrument_egress(
    *,
    stamp_headers: bool = True,
    capture_connections: bool = True,
    ignore_hosts: frozenset[str] | set[str] = DEFAULT_IGNORE_HOSTS,
    stamp_hosts: set[str] | None = None,
) -> None:
    """Install egress hooks process-wide. Calling again updates the options.

    ``ignore_hosts``: neither stamped nor recorded (subdomains included).
    ``stamp_hosts``: if given, only these hosts get headers. Others are still recorded.
    """
    global _config
    with _install_lock:
        _config = _Config(stamp_headers, capture_connections, frozenset(ignore_hosts),
                          frozenset(stamp_hosts) if stamp_hosts is not None else None)
        if _patches:
            return
        try:
            for name in ("httpx", "httpx2"):
                _patch_httpx(name)
            _patch_requests()
            _patch_socket()
        except Exception:
            _unpatch_all()  # all or nothing
            _config = None
            raise


def uninstrument_egress() -> None:
    global _config
    with _install_lock:
        _unpatch_all()
        _config = None


def _unpatch_all() -> None:
    while _patches:
        owner, name, original = _patches.pop()
        if original is _ABSENT:
            delattr(owner, name)
        else:
            setattr(owner, name, original)


@contextmanager
def suppress_egress() -> Iterator[None]:
    """Don't record or stamp anything inside this block (e.g. a sink's own uploads)."""
    token = _suppressed.set(True)
    try:
        yield
    finally:
        _suppressed.reset(token)


def sanitize_url(url: str) -> str:
    """Drop credentials and fragments, and mask query values whose names look secret."""
    try:
        parts = urlsplit(url)
        host = parts.hostname or ""
        if ":" in host:
            host = f"[{host}]"
        if parts.port:
            host += f":{parts.port}"
        query = urlencode([(k, "***" if _SECRET_PARAM.search(k) else v)
                           for k, v in parse_qsl(parts.query, keep_blank_values=True)])
        return urlunsplit((parts.scheme, host, parts.path, query, ""))
    except ValueError:
        return "<unparseable url>"


_ABSENT = object()


def _patch(owner: Any, name: str, replacement: Any) -> None:
    # Remember whether the class defined the attribute itself or inherited it
    # (socket.socket inherits connect from the C type), so uninstall can undo exactly.
    _patches.append((owner, name, owner.__dict__.get(name, _ABSENT)))
    setattr(owner, name, replacement)


def _host_matches(host: str, hosts: frozenset[str]) -> bool:
    host = host.lower().rstrip(".")
    return any(host == h or host.endswith("." + h) for h in hosts)


@contextmanager
def _http_scope(method: str, url: str) -> Iterator[_HttpCtx | None]:
    """Yield a context for an outbound HTTP request, or None if it shouldn't be recorded."""
    cfg, run = _config, current_run()
    if cfg is None or run is None or _suppressed.get():
        yield None
        return
    host = urlsplit(url).hostname or ""
    if _host_matches(host, cfg.ignore_hosts):
        with suppress_egress():  # also hides the underlying socket connect
            yield None
        return
    stamped = cfg.stamp_headers and (cfg.stamp_hosts is None or _host_matches(host, cfg.stamp_hosts))
    ctx = _HttpCtx(run=run, egress_id=uuid.uuid4().hex, method=(method or "GET").upper(),
                   url=sanitize_url(url), host=host, stamped=stamped)
    token = _active_http.set(ctx)
    try:
        yield ctx
    finally:
        _active_http.reset(token)


def _stamp(ctx: _HttpCtx, headers: Any) -> None:
    if ctx.stamped:
        headers[RUN_HEADER] = ctx.run.run_id
        headers[EGRESS_HEADER] = ctx.egress_id


def _addr(entry: dict, prefix: str, addr: tuple | None) -> None:
    if addr and len(addr) >= 2:
        try:
            ipaddress.ip_address(addr[0])
        except ValueError:
            return
        entry[f"{prefix}_ip"], entry[f"{prefix}_port"] = str(addr[0]), int(addr[1])


def _finish_http(ctx: _HttpCtx, *, status: int | None = None, error: BaseException | None = None,
                 conn: tuple[tuple | None, tuple | None] | None = None) -> None:
    local, remote = conn or (None, None)
    entry: dict[str, Any] = {"egress_id": ctx.egress_id, "protocol": "http", "method": ctx.method,
                             "url": ctx.url, "host": ctx.host, "run_id_header": ctx.stamped}
    if status is not None:
        entry["status"] = status
    _addr(entry, "source", local or ctx.source)
    _addr(entry, "dest", remote or ctx.dest)
    _emit(ctx.run, entry, ctx.started, error)


def _emit(run: Run, entry: dict, started: float, error: BaseException | None) -> None:
    public_ip = getattr(run.recorder, "public_ip", None)
    if public_ip:
        entry["public_ip"] = public_ip
    message = f"{type(error).__name__}: {error}" if error else None
    if message:
        entry["error"] = message
    with suppress_egress():
        try:
            run.egress(entry, latency_ms=int((time.perf_counter() - started) * 1000), error=message)
        except Exception as exc:  # recording must not break the request
            warnings.warn(f"mnestiq: failed to record egress: {exc!r}", RuntimeWarning, stacklevel=2)


def _patch_httpx(module_name: str) -> None:
    try:
        mod = importlib.import_module(module_name)
    except ImportError:
        return
    # _send_single_request runs once per actual request, including each redirect hop.
    if "_send_single_request" not in mod.Client.__dict__:
        return
    sync_orig = mod.Client.__dict__["_send_single_request"]
    async_orig = mod.AsyncClient.__dict__["_send_single_request"]

    def send(self: Any, request: Any) -> Any:
        with _http_scope(request.method, str(request.url)) as ctx:
            if ctx is None:
                return sync_orig(self, request)
            _stamp(ctx, request.headers)
            try:
                response = sync_orig(self, request)
            except Exception as exc:
                _finish_http(ctx, error=exc)
                raise
            _finish_http(ctx, status=response.status_code, conn=_httpx_addrs(response))
            return response

    async def async_send(self: Any, request: Any) -> Any:
        with _http_scope(request.method, str(request.url)) as ctx:
            if ctx is None:
                return await async_orig(self, request)
            _stamp(ctx, request.headers)
            try:
                response = await async_orig(self, request)
            except Exception as exc:
                _finish_http(ctx, error=exc)
                raise
            _finish_http(ctx, status=response.status_code, conn=_httpx_addrs(response))
            return response

    _patch(mod.Client, "_send_single_request", send)
    _patch(mod.AsyncClient, "_send_single_request", async_send)


def _httpx_addrs(response: Any) -> tuple[tuple | None, tuple | None] | None:
    try:
        stream = response.extensions.get("network_stream")
        if stream is None:
            return None
        return stream.get_extra_info("client_addr"), stream.get_extra_info("server_addr")
    except Exception:
        return None


def _patch_requests() -> None:
    try:
        from requests.adapters import HTTPAdapter
    except ImportError:
        return
    original = HTTPAdapter.__dict__["send"]

    def send(self: Any, request: Any, *args: Any, **kwargs: Any) -> Any:
        with _http_scope(request.method, request.url) as ctx:
            if ctx is None:
                return original(self, request, *args, **kwargs)
            _stamp(ctx, request.headers)
            try:
                response = original(self, request, *args, **kwargs)
            except Exception as exc:
                _finish_http(ctx, error=exc)
                raise
            # Addresses come from the socket hook (new connections only).
            _finish_http(ctx, status=response.status_code)
            return response

    _patch(HTTPAdapter, "send", send)


def _patch_socket() -> None:
    connect_orig = socket.socket.connect  # inherited from _socket.socket
    connect_ex_orig = socket.socket.connect_ex

    def connect(self: socket.socket, address: Any) -> None:
        watch = _socket_watch(self)
        if watch is None:
            return connect_orig(self, address)
        started = time.perf_counter()
        try:
            connect_orig(self, address)
        except BlockingIOError:  # non-blocking connect in progress
            _socket_done(watch, self, address, None, started)
            raise
        except OSError as exc:
            _socket_done(watch, self, address, exc, started)
            raise
        _socket_done(watch, self, address, None, started)

    def connect_ex(self: socket.socket, address: Any) -> int:
        watch = _socket_watch(self)
        if watch is None:
            return connect_ex_orig(self, address)
        started = time.perf_counter()
        rc = connect_ex_orig(self, address)
        error = None if rc in _IN_PROGRESS else ConnectionError(rc, f"connect_ex returned {rc}")
        _socket_done(watch, self, address, error, started)
        return rc

    _patch(socket.socket, "connect", connect)
    _patch(socket.socket, "connect_ex", connect_ex)

    # Where the OS lacks socketpair (Windows), Python emulates it with a loopback
    # connect. asyncio does this for its wakeup channel, it isn't egress.
    socketpair_orig = socket.socketpair

    def socketpair(*args: Any, **kwargs: Any) -> Any:
        with suppress_egress():
            return socketpair_orig(*args, **kwargs)

    _patch(socket, "socketpair", socketpair)


def _socket_watch(sock: socket.socket) -> tuple[str, Any] | None:
    cfg = _config
    if cfg is None or not cfg.capture_connections or _suppressed.get():
        return None
    if sock.family not in (socket.AF_INET, socket.AF_INET6) or sock.type != socket.SOCK_STREAM:
        return None
    http = _active_http.get()
    if http is not None:
        return ("http", http)  # enrich the HTTP event instead of emitting a second one
    run = current_run()
    return ("tcp", run) if run is not None else None


def _socket_done(watch: tuple[str, Any], sock: socket.socket, address: Any,
                 error: BaseException | None, started: float) -> None:
    try:
        local = sock.getsockname()
    except OSError:
        local = None
    try:
        remote = sock.getpeername()
    except OSError:
        remote = address if isinstance(address, tuple) else None

    kind, target = watch
    if kind == "http":
        target.source, target.dest = local, remote
        return

    host = str(address[0]) if isinstance(address, tuple) and address else ""
    cfg = _config
    if cfg is not None and _host_matches(host, cfg.ignore_hosts):
        return
    entry: dict[str, Any] = {"egress_id": uuid.uuid4().hex, "protocol": "tcp"}
    try:
        ipaddress.ip_address(host)
    except ValueError:
        if host:
            entry["host"] = host
    _addr(entry, "source", local)
    _addr(entry, "dest", remote)
    if "dest_port" not in entry and isinstance(address, tuple) and len(address) >= 2:
        entry["dest_port"] = int(address[1])
    _emit(target, entry, started, error)
