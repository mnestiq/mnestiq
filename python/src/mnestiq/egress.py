"""Egress identity propagation: tie every outbound connection to the agent step that made it.

    from mnestiq.egress import instrument_egress
    instrument_egress()

While a run is active, this:

* stamps ``X-Mnestiq-Run-Id`` and ``X-Mnestiq-Egress-Id`` into outbound HTTP
  requests, so reverse-proxy and API gateway logs carry the run id. httpx, httpx2 and
  requests are stamped by default. urllib.request and urllib3, which cloud SDKs are
  built on, only for the hosts named in ``stamp_hosts``
* records an ``egress`` event per request with method, URL (secrets masked),
  status, and the connection's local/remote IP and port
* records an ``egress`` event for every other outbound TCP connection (SMTP,
  databases, raw sockets), so exfiltration that bypasses HTTP is still attributed
* carries the run into threads started during it, and into tasks given to a
  ``ThreadPoolExecutor`` or ``multiprocessing.pool.ThreadPool``. A thread that goes on
  after its run ended stays attributed to it, marked ``after_run_end`` in the event's
  attributes
* watches Python audit events, which undoing the patches above does not remove. This
  raises the bar and is not a boundary: code in the same process can reach
  ``suppress_egress``, the own-thread mark and the hook's flag as well as this module
  can. A TCP connect the patches missed is recorded as an ``egress`` event, written
  before the connect happens, so it has no source port and no outcome. UDP sends and
  name lookups do not fit the egress format, so each destination gets one ``note`` event
  per run, with details under ``network`` in its attributes. Written records cannot
  change, so repeats are not counted. Each kind of event has its own limit, loopback
  apart from real destinations, and a closing note gives the count and a digest of what
  the limits dropped. Code that left the run's context (a bare ``Context``, a raw thread)
  is recorded against the run if exactly one is open, marked ``run_inferred``.
* records every process started during a run as a ``note`` event, with the executable
  and arguments under ``process`` in its attributes, secrets masked as well as text
  allows. A secret passed as a bare positional argument cannot be told from any other.

The local IP and port are the join key to VPC flow logs and firewall logs, which
record (src addr, src port, dst addr, dst port, time) but know nothing about agents.

Through a proxy, the URL names the target and the connection goes to the proxy. A
request is left out only when both are in ``ignore_hosts``, as a name in a URL costs
nothing to claim. A custom transport or adapter that may route anywhere counts as not
proven direct, so an ignored name is recorded there too, marked ``route_unverified``.
Only a request's own connection is folded into its event: whatever else connects while
it runs is recorded for itself. The IP and port fields always describe the connection to the proxy,
and a proxy that is not in ``ignore_hosts`` is named under ``via_proxy`` in the
event's attributes.

Limits: traffic from native extensions with their own sockets, and from child processes
that are not Python-instrumented, is not seen. The run is not passed to child processes.
On Windows the proactor loop connects and sends without an audit event, so only its
patches see that. HTTP through plain ``http.client`` is recorded as a TCP connection, unstamped. A
thread started outside any run has no run to inherit. Pair with infrastructure logs for
full coverage.
"""

from __future__ import annotations

import _socket
import atexit
import contextvars
import errno
import copy
import hashlib
import http.client
import importlib
import inspect
import ipaddress
import os
import re
import socket
import sys
import threading
import time
import uuid
import warnings
import weakref
from collections import deque
from contextlib import contextmanager, suppress
from dataclasses import dataclass, field
from pathlib import PosixPath, PurePosixPath, PureWindowsPath, WindowsPath
from typing import Any
from collections.abc import Callable, Iterator
from urllib.parse import parse_qsl, quote, quote_plus, unquote, unquote_plus, urlencode, urlsplit, urlunsplit

from .findings import UNTRUSTED
from .jsonable import exception_text
from .recorder import Run, _before_close, _capped_error, _carried_run, _current_run, current_run

RUN_HEADER = "X-Mnestiq-Run-Id"
EGRESS_HEADER = "X-Mnestiq-Egress-Id"

# Model API calls are already recorded as llm_call events.
DEFAULT_IGNORE_HOSTS = frozenset({"api.anthropic.com", "api.openai.com"})

_SECRET_PARAM = re.compile(
    r"(?i)(api[_-]?key|access[_-]?key|^key$|token|secret|passw|^pass$|pwd|^pin$|signature|^sig$|credential|auth|"
    r"^code$|session|jwt|bearer|private|cookie|^otp$)"
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
    secrets: tuple[str, ...] = ()
    query_secrets: tuple[str, ...] = ()  # the query values the url field masks, as an error may quote them
    via_proxy: str | None = None  # a proxy this went through that is not an ignored host
    route_unverified: bool = False  # an ignored name, on a route that could not be proven direct
    ignored: bool = False  # left out of the evidence: this only marks whose socket is whose
    connected: bool = False


_config: _Config | None = None
_patches: list[tuple[Any, str, Any, Any]] = []
_generation = 0  # one more at every uninstall: a hook of an earlier install only passes through
_install_lock = threading.Lock()
_active_http: contextvars.ContextVar[_HttpCtx | None] = contextvars.ContextVar("mnestiq_http", default=None)
_suppressed: contextvars.ContextVar[bool] = contextvars.ContextVar("mnestiq_egress_off", default=False)
_starting_worker: contextvars.ContextVar[bool] = contextvars.ContextVar("mnestiq_pool_submit", default=False)
_covered_socket: contextvars.ContextVar[Any] = contextvars.ContextVar("mnestiq_covered_socket", default=None)
_hook_installed: bool = globals().get("_hook_installed", False)  # kept across a reload, as a hook cannot be removed
_hook_armed = False  # the installed hook does nothing while this is false
_UNVERIFIED = "<unverified route>"
_unwrapped_emit: Any = Run.__dict__["emit"]


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
    ignored = _host_set("ignore_hosts", ignore_hosts)
    stamped = _host_set("stamp_hosts", stamp_hosts) if stamp_hosts is not None else None
    with _install_lock:
        _config = _Config(stamp_headers, capture_connections, ignored, stamped)
        if _patches:
            return
        try:
            _patch_run()
            _patch_winapi()
            for name in ("httpx", "httpx2"):
                _patch_httpx(name)
            _patch_requests()
            _patch_urllib()
            _patch_urllib3()
            _patch_socket()
            _patch_asyncio()
            _patch_threads()
        except Exception:
            _unpatch_all()  # all or nothing
            _config = None
            raise
        _arm_audit_hook()


def uninstrument_egress() -> None:
    global _config
    with _install_lock:
        _unpatch_all()
        _config = None


def _unpatch_all() -> None:
    global _generation, _hook_armed
    _hook_armed = False
    while _patches:
        owner, name, original, ours = _patches.pop()
        if owner.__dict__.get(name) is not ours:  # patched again since: that is someone else's to undo
            continue
        if original is _ABSENT:
            delattr(owner, name)
        else:
            setattr(owner, name, original)
    _generation += 1


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
        # A semicolon also separates parameters on many servers: a secret after one must not pass as a value.
        query = ";".join(urlencode([(k, "***" if _SECRET_PARAM.search(k) else v)
                                    for k, v in parse_qsl(piece, keep_blank_values=True)])
                         for piece in parts.query.split(";"))
        return urlunsplit((parts.scheme, host, parts.path, query, ""))
    except ValueError:
        return "<unparseable url>"


_ABSENT = object()


def _patch(owner: Any, name: str, replacement: Any) -> None:
    # Remember whether the class defined the attribute itself or inherited it
    # (socket.socket inherits connect from the C type), so uninstall can undo exactly.
    # What is installed is a gate: something else may hold on to it after uninstall.
    original = getattr(owner, name)
    generation = _generation

    def gate(*args: Any, **kwargs: Any) -> Any:
        return (replacement if generation == _generation else original)(*args, **kwargs)

    async def async_gate(*args: Any, **kwargs: Any) -> Any:
        return await (replacement if generation == _generation else original)(*args, **kwargs)

    ours: Any = async_gate if inspect.iscoroutinefunction(replacement) else gate
    _patches.append((owner, name, owner.__dict__.get(name, _ABSENT), ours))
    setattr(owner, name, ours)


def _host_set(option: str, hosts: Any) -> frozenset[str]:
    """Host names as matching compares them. A bare string would be read as a set of its letters."""
    if isinstance(hosts, (str, bytes)):
        raise TypeError(f"{option} takes a set of host names, not one string: use {{{hosts!r}}}")
    try:
        names = list(hosts)
    except TypeError:
        raise TypeError(f"{option} takes a set of host names, got {type(hosts).__name__}") from None
    for name in names:
        if not isinstance(name, str):
            raise TypeError(f"{option} takes host names as strings, got {type(name).__name__}")
    return frozenset(filter(None, map(_bare, names)))


def _host_matches(host: str, hosts: frozenset[str]) -> bool:
    host = _bare(host)
    return any(host == h or host.endswith("." + h) for h in map(_bare, hosts))


def _hostname(netloc: str) -> str | None:
    return urlsplit(f"//{netloc}").hostname


def _bare(host: str) -> str:
    return host.strip("[]").lower().rstrip(".")


def _url_secrets(url: str) -> tuple[str, ...]:
    """The user name and password in a URL, as an error's text may quote them, longest first."""
    userinfo = urlsplit(url).netloc.rpartition("@")[0]
    if not userinfo:
        return ()
    pieces = {userinfo, f"{userinfo}@", *(p for p in userinfo.split(":", 1) if len(p) >= 3)}
    return tuple(sorted(pieces | {unquote(p) for p in pieces}, key=len, reverse=True))


# What clients leave unencoded when they write a URL out again (requests, httpx, urllib3).
_REQUOTE_SAFE = ("!#$%&'()*+,/:;=?@[]~", "!$&'()*+,;=:@/?", "")


def _query_secrets(url: str) -> tuple[str, ...]:
    """The query values ``sanitize_url`` masks, as sent, decoded and encoded again, longest first."""
    found: set[str] = set()
    for piece in urlsplit(url).query.split(";"):
        for pair in piece.split("&"):  # split as parse_qsl splits, so the same values are found
            key, sep, value = pair.partition("=")
            if not sep or not value or not _SECRET_PARAM.search(unquote_plus(key)):
                continue
            decoded = unquote_plus(value)
            found.update({value, unquote(value), decoded, quote_plus(decoded)})
            found.update(quote(decoded, safe=safe) for safe in _REQUOTE_SAFE)
    found.discard("")
    return tuple(sorted(found, key=len, reverse=True))


def _mask_values(text: str, values: tuple[str, ...]) -> str:
    """Mask each value where it stands as a whole value of a key that looks secret. Anchored so a short
    value cannot eat a host, a port, a path or another key's value that happens to hold the same text."""
    if not values:
        return text
    pattern = re.compile(r"""([?&;]([^?&;=\s'"]{1,256})=)(?:""" + "|".join(map(re.escape, values))
                         + r""")(?=[&;\s#'"),\]}>]|$)""")
    return pattern.sub(
        lambda m: m.group(1) + "***" if _SECRET_PARAM.search(unquote_plus(m.group(2))) else m.group(), text)


def _mask_error_text(text: str, secrets: tuple[str, ...] = (), query_secrets: tuple[str, ...] = ()) -> str:
    """Mask in an error's text what ``sanitize_url`` masks in the URL it quotes."""
    text = _mask_values(text, query_secrets)  # first, while the values still stand as the client wrote them
    text = _mask_params_in_text(text)
    text = _URL_IN_TEXT.sub(lambda m: sanitize_url(m.group()), text)
    for secret in secrets:
        text = text.replace(secret, "***")
    return text


def _mask_params_in_text(text: str) -> str:
    """Mask query values with secret looking names in free text, a path and query alone included."""
    return _PARAM_IN_TEXT.sub(
        lambda m: m.group(1) + "***" if _SECRET_PARAM.search(unquote_plus(m.group(2))) else m.group(), text)


@contextmanager
def _http_scope(method: str, url: str, *, via: str | None = None, proxy: str | None = None,
                opt_in: bool = False) -> Iterator[_HttpCtx | None]:
    """Yield a context for an outbound HTTP request, or None if it shouldn't be recorded.

    ``via``: the host the connection really goes to, when the client tells us, recorded as the host.
    ``proxy``: the proxy a client sends this through, with the URL's host still recorded as the host,
    or ``_UNVERIFIED`` when the client's route cannot be read.
    ``opt_in``: stamp only hosts named in ``stamp_hosts``."""
    cfg, run = _config, current_run()
    if cfg is None or run is None or _suppressed.get():
        yield None
        return
    try:
        host = urlsplit(url).hostname or ""
        secrets, query_secrets = _url_secrets(url), _query_secrets(url)
    except ValueError:  # recorded as unparseable, and the request is the client's to refuse
        host, secrets, query_secrets = "", (), ()
    # What a URL names is only a claim when the bytes go elsewhere (a proxy, an absolute-form target).
    named = host
    if via and _bare(via) != _bare(host):
        host = via
    # So an ignored name hides a request only if the connection itself goes to an ignored host too.
    named_ignored = _host_matches(named, cfg.ignore_hosts)
    unverified = proxy == _UNVERIFIED
    if unverified:
        proxy = None
    if named_ignored and not unverified and _host_matches(proxy or host, cfg.ignore_hosts):
        # Marks the request's own socket to be left out. Not suppress_egress: code the request runs, a body
        # generator say, can do anything at all, and that is not the request.
        own = _active_http.set(_HttpCtx(run=run, egress_id="", method="", url="", host=host, stamped=False,
                                        ignored=True))
        try:
            yield None
        finally:
            _active_http.reset(own)
        return
    if cfg.stamp_hosts is None:
        stamped = cfg.stamp_headers and not opt_in and not named_ignored
    else:
        stamped = cfg.stamp_headers and not named_ignored and _host_matches(host, cfg.stamp_hosts)
    # The name in the URL says nothing about who reads the bytes first. The findings rules need to know.
    unlisted = proxy and _bare(proxy) != _bare(named) and not _host_matches(proxy, cfg.ignore_hosts)
    ctx = _HttpCtx(run=run, egress_id=uuid.uuid4().hex, method=(method or "GET").upper(),
                   url=sanitize_url(url), host=host, stamped=stamped, secrets=secrets, query_secrets=query_secrets,
                   via_proxy=proxy if unlisted else None, route_unverified=unverified and named_ignored)
    token = _active_http.set(ctx)
    try:
        yield ctx
    finally:
        _active_http.reset(token)


_HEADER_SAFE = re.compile(r"[!-~]{1,200}")
_URL_IN_TEXT = re.compile(r"https?://[^\s'\"<>]+", re.IGNORECASE)
# A key may be percent encoded or hold brackets and colons. A value runs to the next separator, and to a
# quote only where that quote closes the URL, as a bracket or quote inside a value is still the value.
_PARAM_IN_TEXT = re.compile(r"""([?&;]([\w.%\[\]:+-]{1,256})=)((?:(?!['"](?:[\s),.;\]}>]|$))[^&;\s#])+)""")


_STAMP_NAMES = (RUN_HEADER.lower(), EGRESS_HEADER.lower())


@contextmanager
def _stamped_for_send(ctx: _HttpCtx | None, request: Any) -> Iterator[None]:
    """Stamp a request's headers for one send, or strip ours when it is not stamped, as a redirect copies
    the first hop's headers. Once the send returns or raises, the caller's object is as it was."""
    try:
        headers = request.headers
        saved = [(name, value) for name, value in headers.items() if name.lower() in _STAMP_NAMES]
    except Exception:  # headers of a shape this version does not know: sent as they are
        if ctx is not None:
            ctx.stamped = False
        yield
        return
    try:
        if ctx is None:
            _strip(headers)
        else:
            _stamp(ctx, headers)
    except Exception:
        if ctx is not None:
            ctx.stamped = False
    try:
        yield
    finally:
        with suppress(Exception):
            _strip(headers)
            for name, value in saved:
                headers[name] = value


def _strip(headers: Any) -> None:
    for name in [n for n in headers if n.lower() in _STAMP_NAMES]:
        del headers[name]


def _stamp(ctx: _HttpCtx, headers: Any) -> None:
    if ctx.stamped:
        # A run id the caller chose may hold characters a header cannot carry: sending it would
        # make the agent's own request fail, so then only the egress id goes.
        if isinstance(ctx.run.run_id, str) and _HEADER_SAFE.fullmatch(ctx.run.run_id):
            headers[RUN_HEADER] = ctx.run.run_id
        headers[EGRESS_HEADER] = ctx.egress_id
    else:  # a redirect copies the first request's headers: they must not reach a host left out
        for name in (RUN_HEADER, EGRESS_HEADER):
            headers.pop(name, None)


def _finish_failed(ctx: _HttpCtx, exc: BaseException, conn: tuple[tuple | None, tuple | None] | None = None) -> None:
    """Record a request that raised. In strict mode a recording failure is raised in its place,
    but a cancellation stays a cancellation."""
    try:
        _finish_http(ctx, error=exc, conn=conn)
    except Exception as failure:
        if isinstance(exc, Exception):
            raise
        with suppress(Exception):
            ctx.run.recorder._record_failure(failure)


def _addr(entry: dict, prefix: str, addr: tuple | None) -> None:
    # What a transport reports can be anything: a bad address is left out, the request goes on.
    try:
        host, port = str(ipaddress.ip_address(addr[0])), int(addr[1])  # type: ignore[index]
    except (TypeError, ValueError, IndexError, KeyError):
        return
    if 0 <= port <= 65535:
        entry[f"{prefix}_ip"], entry[f"{prefix}_port"] = host, port


def _finish_http(ctx: _HttpCtx, *, status: int | None = None, error: BaseException | None = None,
                 conn: tuple[tuple | None, tuple | None] | None = None) -> None:
    local, remote = conn or (None, None)
    entry: dict[str, Any] = {"egress_id": ctx.egress_id, "protocol": "http", "method": ctx.method,
                             "url": ctx.url, "host": ctx.host, "run_id_header": ctx.stamped}
    if status is not None:
        entry["status"] = status
    _addr(entry, "source", local or ctx.source)
    _addr(entry, "dest", remote or ctx.dest)
    attributes: dict[str, Any] = {}
    if ctx.via_proxy:
        attributes["via_proxy"] = ctx.via_proxy
    if ctx.route_unverified:
        attributes["route_unverified"] = True
    _emit(ctx.run, entry, ctx.started, error, ctx.secrets, attributes, ctx.query_secrets)


def _outlived(run: Run) -> bool:
    return run is _carried_run.get() and run.recorder._closed


def _emit(run: Run, entry: dict, started: float, error: BaseException | None, secrets: tuple[str, ...] = (),
          attributes: dict[str, Any] | None = None, query_secrets: tuple[str, ...] = ()) -> None:
    public_ip = getattr(run.recorder, "public_ip", None)
    if public_ip:
        entry["public_ip"] = public_ip
    # Libraries put the full URL in their errors, query secrets included: mask it like the url field.
    message = None
    if error:
        message = _mask_error_text(exception_text(error), secrets, query_secrets)
    if message:
        entry["error"] = message
    with suppress_egress():
        try:
            latency = int((time.perf_counter() - started) * 1000)
            if attributes:
                run.emit("egress", egress=[entry], latency_ms=latency, status="error" if message else "ok",
                         error=message, attributes=attributes)
            else:
                run.egress(entry, latency_ms=latency, error=message)
        except Exception as exc:  # recording must not break the request, unless strict says it must
            if _outlived(run):  # its recorder closed while this request ran: not the agent's problem
                return
            if run.recorder.strict:
                raise
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
        with _http_scope(request.method, str(request.url), proxy=_httpx_proxy(self, request)) as ctx:
            if ctx is None:
                with _stamped_for_send(None, request):
                    return sync_orig(self, request)
            try:
                with _stamped_for_send(ctx, request):
                    response = sync_orig(self, request)
            except BaseException as exc:  # a cancelled request may still have sent its data
                _finish_failed(ctx, exc)
                raise
            _finish_http(ctx, status=response.status_code, conn=_httpx_addrs(response))
            return response

    async def async_send(self: Any, request: Any) -> Any:
        with _http_scope(request.method, str(request.url), proxy=_httpx_proxy(self, request)) as ctx:
            if ctx is None:
                with _stamped_for_send(None, request):
                    return await async_orig(self, request)
            try:
                with _stamped_for_send(ctx, request):
                    response = await async_orig(self, request)
            except BaseException as exc:  # a cancelled request may still have sent its data
                _finish_failed(ctx, exc)
                raise
            _finish_http(ctx, status=response.status_code, conn=_httpx_addrs(response))
            return response

    _patch(mod.Client, "_send_single_request", send)
    _patch(mod.AsyncClient, "_send_single_request", async_send)


def _httpx_proxy(client: Any, request: Any) -> str | None:
    """The proxy host this client sends the request through. None only if it is proven direct."""
    try:
        transport = client._transport_for_url(request.url)
        if type(transport).__name__ not in ("HTTPTransport", "AsyncHTTPTransport"):  # it can send anywhere
            return _UNVERIFIED
        pool = transport._pool
        if type(pool).__name__ in ("ConnectionPool", "AsyncConnectionPool"):
            return None
        host = pool._proxy_url.host
        return host.decode("ascii") if isinstance(host, bytes) else host
    except Exception:  # a version with other internals
        return _UNVERIFIED


def _requests_proxy(adapter: Any, url: str, args: tuple, kwargs: dict) -> str | None:
    """The proxy host ``HTTPAdapter.send`` was told to use. None only if it is proven direct."""
    try:
        from requests.adapters import HTTPAdapter
        from requests.utils import select_proxy
        from urllib3.poolmanager import PoolManager

        rerouted = any(getattr(type(adapter), name, None) is not getattr(HTTPAdapter, name, None)
                       for name in ("get_connection_with_tls_context", "get_connection", "proxy_manager_for"))
        if rerouted or type(adapter.poolmanager) is not PoolManager:
            return _UNVERIFIED
        proxy = select_proxy(url, kwargs.get("proxies", args[4] if len(args) > 4 else None))
        return urlsplit(proxy if "://" in proxy else f"http://{proxy}").hostname if proxy else None
    except Exception:
        return _UNVERIFIED


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
        with _http_scope(request.method, request.url, proxy=_requests_proxy(self, request.url, args, kwargs)) as ctx:
            if ctx is None:
                with _stamped_for_send(None, request):
                    return original(self, request, *args, **kwargs)
            try:
                with _stamped_for_send(ctx, request):
                    response = original(self, request, *args, **kwargs)
            except BaseException as exc:  # a cancelled request may still have sent its data
                _finish_failed(ctx, exc)
                raise
            # Addresses come from the socket hook (new connections only).
            _finish_http(ctx, status=response.status_code)
            return response

    _patch(HTTPAdapter, "send", send)


def _patch_urllib() -> None:
    from urllib.request import AbstractHTTPHandler

    # do_open runs once per actual request: a redirect comes back through it as a new one.
    original = AbstractHTTPHandler.__dict__["do_open"]

    def do_open(self: Any, http_class: Any, req: Any, **http_conn_args: Any) -> Any:
        try:
            # Through a proxy, req.host is the proxy and full_url still names the target, tunnelled or not.
            method, url, proxy = req.get_method(), req.full_url, _hostname(req.host)
            if http_class not in (http.client.HTTPConnection, http.client.HTTPSConnection):
                proxy = _UNVERIFIED  # a connection class of its own can go anywhere
        except Exception:
            return original(self, http_class, req, **http_conn_args)
        if _active_http.get() is not None or not isinstance(method, str):
            return original(self, http_class, req, **http_conn_args)
        with _http_scope(method, url, proxy=proxy, opt_in=True) as ctx:
            if ctx is None:
                return original(self, http_class, _stamped_request(None, req), **http_conn_args)
            try:
                response = original(self, http_class, _stamped_request(ctx, req), **http_conn_args)
            except BaseException as exc:  # a cancelled request may still have sent its data
                _finish_failed(ctx, exc)
                raise
            _finish_http(ctx, status=response.status)
            return response

    _patch(AbstractHTTPHandler, "do_open", do_open)


def _stamped_request(ctx: _HttpCtx | None, req: Any) -> Any:
    # A copy, as the caller's request may be shared or sent again. Unredirected headers, as urllib
    # carries a request's normal ones over to a redirect. Not stamped: ours are left off the copy.
    stamping = ctx is not None and ctx.stamped
    try:
        carried = any(n.lower() in _STAMP_NAMES for n in (*req.headers, *req.unredirected_hdrs))
        if not stamping and not carried:
            return req
        stamped = copy.copy(req)
        stamped.headers = {n: v for n, v in req.headers.items() if n.lower() not in _STAMP_NAMES}
        stamped.unredirected_hdrs = {n: v for n, v in req.unredirected_hdrs.items()
                                     if n.lower() not in _STAMP_NAMES}
        if ctx is not None and stamping:
            stamp: dict[str, str] = {}
            _stamp(ctx, stamp)
            for name, value in stamp.items():
                stamped.unredirected_hdrs[name.capitalize()] = value
    except Exception:
        if ctx is not None:
            ctx.stamped = False
        return req
    return stamped


def _patch_urllib3() -> None:
    try:
        mod = importlib.import_module("urllib3.connectionpool")
    except ImportError:
        return
    pool = mod.HTTPConnectionPool
    if "_make_request" not in pool.__dict__:
        return
    make_request_orig = pool.__dict__["_make_request"]

    # Once per attempt on the wire: a retry or a redirect comes back through here as its own request.
    def make_request(self: Any, conn: Any, method: Any, url: Any, *args: Any, **kwargs: Any) -> Any:
        if _active_http.get() is not None or not isinstance(method, str):  # inside requests' own scope
            return make_request_orig(self, conn, method, url, *args, **kwargs)
        try:
            full_url, route = _pool_url(self, url), _pool_route(self)
        except Exception:
            return make_request_orig(self, conn, method, url, *args, **kwargs)
        with _http_scope(method, full_url, opt_in=True, **route) as ctx:
            kwargs = _stamped_kwargs(ctx, kwargs, self.headers)
            if ctx is None:
                return make_request_orig(self, conn, method, url, *args, **kwargs)
            try:
                response = make_request_orig(self, conn, method, url, *args, **kwargs)
            except BaseException as exc:  # a cancelled request may still have sent its data
                _finish_failed(ctx, exc, _conn_addrs(conn))
                raise
            _finish_http(ctx, status=response.status, conn=_conn_addrs(conn))
            return response

    _patch(pool, "_make_request", make_request)
    tunnelling = mod.HTTPSConnectionPool  # the plain pool's own _prepare_proxy does nothing
    if "_prepare_proxy" not in tunnelling.__dict__:
        return
    prepare_proxy_orig = tunnelling.__dict__["_prepare_proxy"]

    # Opens a proxy tunnel before the first attempt. The attempt records that connection, unless this fails.
    def prepare_proxy(self: Any, conn: Any) -> Any:
        if _active_http.get() is not None:
            return prepare_proxy_orig(self, conn)
        try:
            target, route = _pool_url(self, "/"), _pool_route(self)
        except Exception:
            return prepare_proxy_orig(self, conn)
        with _http_scope("CONNECT", target, opt_in=True, **route) as ctx:
            if ctx is None:
                return prepare_proxy_orig(self, conn)
            try:
                return prepare_proxy_orig(self, conn)
            except BaseException as exc:
                _finish_failed(ctx, exc)
                raise

    _patch(tunnelling, "_prepare_proxy", prepare_proxy)


def _pool_route(pool: Any) -> dict[str, str]:
    # With no proxy set, an absolute-form URL is only a claim, and the pool's own host is where the bytes go.
    if pool.ConnectionCls.__module__ != "urllib3.connection":  # a connection class of its own can go anywhere
        return {"proxy": _UNVERIFIED}
    return {"proxy": pool.proxy.host} if getattr(pool, "proxy", None) else {"via": pool.host}


def _pool_url(pool: Any, url: str) -> str:
    if url.startswith(("http://", "https://")):  # absolute-form, as sent to a forward proxy
        return url
    host = pool.host
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    port = f":{pool.port}" if pool.port else ""
    return f"{pool.scheme}://{host}{port}{url}"


def _stamped_kwargs(ctx: _HttpCtx | None, kwargs: dict, default: Any) -> dict:
    # On a copy: the caller's headers, or a pool's shared ones, are what the next attempt starts from.
    # Not stamped: ours are left off the copy, as a redirect or a retry starts from the last headers.
    try:
        given = kwargs.get("headers")
        source = default if given is None else given
        stamping = ctx is not None and ctx.stamped
        if not (stamping or any(n.lower() in _STAMP_NAMES for n in source or ())):
            return kwargs
        stamped = source.copy()
        _strip(stamped)  # a plain dict would send the caller's spelling as well as ours
        if ctx is not None and stamping:
            _stamp(ctx, stamped)
    except Exception:
        if ctx is not None:
            ctx.stamped = False
        return kwargs
    return {**kwargs, "headers": stamped}


def _conn_addrs(conn: Any) -> tuple[tuple | None, tuple | None] | None:
    try:
        return conn.sock.getsockname(), conn.sock.getpeername()
    except Exception:  # not connected, or already closed
        return None


def _patch_socket() -> None:
    connect_orig = socket.socket.connect  # inherited from _socket.socket
    connect_ex_orig = socket.socket.connect_ex

    def connect(self: socket.socket, address: Any) -> None:
        watch = _socket_watch(self, address)
        if watch is None:
            return connect_orig(self, address)
        started = time.perf_counter()
        token = _covered_socket.set(self)  # the audit hook sees this connect too, and this patch records it
        try:
            connect_orig(self, address)
        except BlockingIOError:  # non-blocking connect in progress
            _socket_done(watch, self, address, None, started)
            raise
        except OSError as exc:
            _socket_done(watch, self, address, exc, started)
            raise
        finally:
            _covered_socket.reset(token)
        _socket_done(watch, self, address, None, started)

    def connect_ex(self: socket.socket, address: Any) -> int:
        watch = _socket_watch(self, address)
        if watch is None:
            return connect_ex_orig(self, address)
        started = time.perf_counter()
        token = _covered_socket.set(self)
        try:
            rc = connect_ex_orig(self, address)
        finally:
            _covered_socket.reset(token)
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


def _socket_watch(sock: socket.socket, address: Any) -> tuple[str, Any] | None:
    cfg = _config
    if cfg is None or not cfg.capture_connections or _suppressed.get():
        return None
    if sock.family not in (socket.AF_INET, socket.AF_INET6) or sock.type != socket.SOCK_STREAM:
        return None
    request = _active_http.get()
    if request is not None and _request_owns(request, address):
        return ("http", request)  # enrich the HTTP event instead of emitting a second one
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
        target.connected = target.connected or error is None
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


def _patch_asyncio() -> None:
    # The proactor loop connects with an overlapped call that never reaches the socket hook.
    try:
        import asyncio
        from asyncio.proactor_events import BaseProactorEventLoop
    except ImportError:
        return
    sock_connect_orig = BaseProactorEventLoop.__dict__["sock_connect"]

    async def sock_connect(self: Any, sock: socket.socket, address: Any) -> Any:
        watch = _socket_watch(sock, address)
        if watch is None:
            return await sock_connect_orig(self, sock, address)
        started = time.perf_counter()
        try:
            result = await sock_connect_orig(self, sock, address)
        except (OSError, asyncio.CancelledError) as exc:  # cancelled too: the attempt has already gone out
            _socket_done(watch, sock, address, exc, started)
            raise
        _socket_done(watch, sock, address, None, started)
        return result

    _patch(BaseProactorEventLoop, "sock_connect", sock_connect)
    _patch_proactor_sendto()


def _patch_proactor_sendto() -> None:
    # Like its connect, the proactor's datagram send is an overlapped call that raises no audit event.
    try:
        proactor: Any = importlib.import_module("asyncio.windows_events").IocpProactor
    except ImportError:
        return
    sendto_orig = proactor.__dict__["sendto"]

    def sendto(self: Any, conn: Any, buf: Any, flags: int = 0, addr: Any = None) -> Any:
        with suppress(OSError):  # not connected: the send will fail for the caller on its own
            _audit_hook("socket.sendto", (conn, addr if addr is not None else conn.getpeername()))
        return sendto_orig(self, conn, buf, flags, addr)

    _patch(proactor, "sendto", sendto)


@contextmanager
def _carrying(run: Run, suppressed: bool) -> Iterator[None]:
    # Only the recorder's own variables: the agent's context stays as Python would leave it in a new thread.
    run_token, carried_token = _current_run.set(run), _carried_run.set(run)
    off_token, http_token = _suppressed.set(suppressed), _active_http.set(None)
    try:
        yield
    finally:
        _active_http.reset(http_token)
        _suppressed.reset(off_token)
        _carried_run.reset(carried_token)
        _current_run.reset(run_token)


def _carry_into_thread(thread: threading.Thread) -> Any:
    """Make ``thread`` start inside the active run. Returns how to take that back, or None if it won't."""
    try:
        run, suppressed = current_run(), _suppressed.get()
        # A pool's workers outlive the task that started them, and the recorder's own threads are not the agent's.
        if (_config is None or run is None or _starting_worker.get() or thread.ident is not None
                or thread.__dict__.get("_mnestiq_own")):
            return None
        own = thread.__dict__.get("run", _ABSENT)
        target = thread.run

        def undo() -> None:
            if own is _ABSENT:
                thread.__dict__.pop("run", None)
            else:
                thread.__dict__["run"] = own

        def carried() -> None:
            undo()
            with _carrying(run, suppressed):
                target()

        # On the instance, so a subclass's own run() is covered, and only until the thread begins.
        thread.__dict__["run"] = carried
        if thread.run is not carried:  # a run property wins over the instance: leave that thread alone
            undo()
            return None
        return undo
    except Exception:
        return None


def _for_worker(fn: Any) -> Any:
    run, suppressed = current_run(), _suppressed.get()
    if _config is None or run is None or not callable(fn):
        return fn

    def carried(*args: Any, **kwargs: Any) -> Any:
        with _carrying(run, suppressed):
            return fn(*args, **kwargs)

    return carried


@contextmanager
def _starting_workers() -> Iterator[None]:
    token = _starting_worker.set(True)  # each task carries its submitter's run, not the worker
    try:
        yield
    finally:
        _starting_worker.reset(token)


def _with_initializer(args: tuple, kwargs: dict, position: int) -> tuple[tuple, dict]:
    """A pool's constructor arguments with its initializer running in the run the pool was made in."""
    if len(args) > position:
        return (*args[:position], _for_worker(args[position]), *args[position + 1:]), kwargs
    if "initializer" in kwargs:
        return args, {**kwargs, "initializer": _for_worker(kwargs["initializer"])}
    return args, kwargs


def _patch_threads() -> None:
    from concurrent.futures import ThreadPoolExecutor

    start_orig = threading.Thread.__dict__["start"]
    submit_orig = ThreadPoolExecutor.__dict__["submit"]
    executor_init_orig = ThreadPoolExecutor.__dict__["__init__"]

    def start(self: threading.Thread) -> None:
        undo = _carry_into_thread(self)
        if undo is None:
            return start_orig(self)
        try:
            return start_orig(self)
        except BaseException:
            undo()
            raise

    def submit(self: Any, fn: Any, /, *args: Any, **kwargs: Any) -> Any:
        with _starting_workers():
            return submit_orig(self, _for_worker(fn), *args, **kwargs)

    def executor_init(self: Any, *args: Any, **kwargs: Any) -> None:
        args, kwargs = _with_initializer(args, kwargs, 2)
        executor_init_orig(self, *args, **kwargs)

    _patch(threading.Thread, "start", start)
    _patch(ThreadPoolExecutor, "submit", submit)
    _patch(ThreadPoolExecutor, "__init__", executor_init)
    _patch_multiprocessing_pool()


def _patch_multiprocessing_pool() -> None:
    try:
        from multiprocessing.pool import Pool, ThreadPool
    except ImportError:  # a platform without multiprocessing
        return
    init_orig = ThreadPool.__dict__["__init__"]

    def init(self: Any, *args: Any, **kwargs: Any) -> None:
        args, kwargs = _with_initializer(args, kwargs, 1)
        with _starting_workers():
            init_orig(self, *args, **kwargs)

    def per_task(original: Any) -> Any:
        def hook(self: Any, func: Any, *args: Any, **kwargs: Any) -> Any:
            return original(self, _for_worker(func), *args, **kwargs)

        return hook

    _patch(ThreadPool, "__init__", init)
    # map, starmap and their _async forms all go through _map_async. apply goes through apply_async.
    for name in ("apply_async", "_map_async", "imap", "imap_unordered"):
        if name in Pool.__dict__:
            _patch(ThreadPool, name, per_task(Pool.__dict__[name]))


# Audit hooks. Python calls these for every audited operation in the process, and they cannot be removed,
# so the code here has to be cheap, do nothing while not armed, and never raise into the program.

_MAX_NETWORK_NOTES = 256  # per kind of event in a run, for real destinations and for loopback apart
_MAX_PER_LOOPBACK_ADDRESS = 16  # so that sweeping the ports of one loopback address leaves the others seen
_MAX_HOST_CHARS = 255
_MAX_ARGS = 64  # arguments kept from one command
_MAX_ARG_BYTES = 1024  # of one argument
_MASK_WINDOW = 16 * _MAX_ARG_BYTES  # masked over more than is kept, so a secret that the limit cuts is still found
_MAX_MASKED_CHARS = 8 * _MASK_WINDOW  # of one command, so a spawn stays cheap however hostile its arguments are
_MAX_DEFERRED = 4096  # events waiting for the chain's lock to be let go
_MAX_STARVED = 64  # audit events waiting for a stack with room to record them
_RECORDING_DEPTH = 64  # frames that writing an event may need

_RAW_SOCKET: Any = _socket.socket  # the C type: a subclass's own properties are the agent's code, and stay unrun
_THREADING: Any = threading
_INET_FAMILIES = frozenset({int(socket.AF_INET), int(socket.AF_INET6)})
_STREAM, _DATAGRAM = int(socket.SOCK_STREAM), int(socket.SOCK_DGRAM)
_PATH_TYPES = (PurePosixPath, PureWindowsPath, PosixPath, WindowsPath)
_INFERRED: dict[str, bool] = {"run_inferred": True}
_LATE: dict[str, bool] = {"recorded_late": True}
_HTTP_CLIENT_ROOTS = frozenset({"urllib3", "httpcore", "httpcore2", "httpx", "httpx2", "requests", "socks"})
_PLUMBING_ROOTS = frozenset({"socket", "ssl", "asyncio", "anyio", "sniffio", "selectors"})

_thread_state = threading.local()
_marks: contextvars.ContextVar[dict[str, bool] | None] = contextvars.ContextVar("mnestiq_marks", default=None)
_starved: deque[tuple[Run, str, tuple]] = deque()
_deferred_events: deque[tuple[Run, str, dict]] = deque()
_open_runs: dict[int, Run] = {}

_CREDS_IN_URL = re.compile(r"(?i)\b([a-z][a-z0-9+.-]{0,30}://)[^\s/?#'\"]*@")
_CREDS_WITH_SLASH = re.compile(r"(?i)\b([a-z][a-z0-9+.-]{0,30}://)[^\s/?#'\":@]{0,128}:(?!\d+[/\s])[^\s'\"@]{0,256}@")
_ENCODED_PARAM = re.compile(r"(?i)([?&;]([\w.-]{1,64})%3d)[^&;\s'\"#)]+")
_BOT_TOKEN_IN_PATH = re.compile(r"(?i)(/bot\d+:)[^/?#]+")
_SECRET_IN_PATH = re.compile(r"(?i)(/(?:services|webhooks|keys?|tokens?|secrets?|api[_-]?keys?)/)[^?#]+")
_FLAG_IN_ARG = re.compile(r"""(?<![\w-])(--?[A-Za-z][\w.-]{0,64})(=|\s+)((?!-)(?:"[^"]*"|'[^']*'|[^\s"']+))""")
_FLAG_ALONE = re.compile(r"--?[A-Za-z][\w.-]*")
_SLASH_OPTION = re.compile(r"""(?<![\w/:.-])/([A-Za-z][\w-]{0,40})[:=]("[^"]*"|[^\s"']+)""")
_QUOTED_PAIR = re.compile(r'''"([A-Za-z_][\w.-]{0,64})=[^"]*"''')
_PAIR_IN_ARG = re.compile(r"""(?<![\w.-])([A-Za-z_][\w.-]{0,64})\s*=\s*("[^"]*"|'[^']*'|[^\s"'&;]+)""")
_JSON_PAIR_IN_ARG = re.compile(r"""(\\?["']([\w.-]{1,64})\\?["']\s*:\s*)(\\?["'][^"']*|[^\s"',}]+)""")
_USER_IN_ARG = re.compile(r"""(?<![\w-])(-u|--user)(=|\s+)("[^"]*"|'[^']*'|[^\s"']+)""")
_USER_ATTACHED = re.compile(r"""(?<![\w-])-u[^\s:"'-][^\s:"']*:[^\s"']+""")
_PASS_PHRASE = re.compile(r"""(?i)(?<![\w.-])pass:[^\s"']+""")
_HEADER_IN_ARG = re.compile(
    r"""(?i)\b((?:proxy-)?authorization|x-api-key|api-key|x-auth-token|(?:set-)?cookie)\s*:\s*[^"'\r\n]+""")
_SCHEME_IN_ARG = re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}")
# Known token forms, and any long unbroken run of token characters. A digest is masked with them: losing one
# is cheap, and nothing written here can be taken back or redacted.
_TOKEN_IN_ARG = re.compile(
    r"\b(?:sk-[\w-]{16,}|gh[pousr]_\w{20,}|github_pat_\w{20,}|xox[abprs]-[\w-]{10,}|AKIA[0-9A-Z]{16}"
    r"|eyJ[\w-]{10,2048}\.[\w-]{10,2048}\.[\w-]*)|(?<![\w/\\.-])[A-Za-z0-9_+=-]{40,}(?![\w/\\.-])")
_FIRST_WORD = re.compile(r"""\s*(?:"([^"]+)"|(\S+))""")
# Programs that take a password in a short flag, which other programs use for other things.
_TOOL_NAME = re.compile(r"(?i)(?<![\w-])(mysql\w*|mariadb\w*|sshpass|sqlcmd|osql|bcp|redis-cli|openssl)(?![\w-])")
_TOOL_FLAGS = {"sshpass": "-p", "sqlcmd": "-P", "osql": "-P", "bcp": "-P", "redis-cli": "-a", "openssl": "-k"}
_NEXT_FLAG = {flag: re.compile(rf"""(?<![\w-]){flag}(\s+)("[^"]*"|'[^']*'|[^\s"']+)""")
              for flag in set(_TOOL_FLAGS.values())}
_ATTACHED_FLAG = {flag: re.compile(rf"""(?<![\w-]){flag}[^\s"'-][^\s"']*""") for flag in {"-p", *_TOOL_FLAGS.values()}}


def _arm_audit_hook() -> None:
    global _hook_installed, _hook_armed
    if not _hook_installed:
        try:
            sys.addaudithook(_audit_hook)
        except Exception:  # another hook refused it: the patches still work
            return
        _hook_installed = True
        if sys.platform != "win32":
            os.register_at_fork(after_in_child=_disarm_in_forked_child)
    _hook_armed = True


def _disarm_in_forked_child() -> None:
    # A forked child holds a copy of the recorder: anything it wrote would fork the chain. The patches
    # all stop at a missing config, as the hook stops at the flag. A child that wants evidence instruments again.
    global _hook_armed, _config
    _hook_armed = False
    _config = None
    _open_runs.clear()
    _starved.clear()
    _deferred_events.clear()


def _audit_hook(event: str, args: tuple) -> None:
    try:
        if _hook_armed:
            handler = _AUDIT_HANDLERS.get(event)
            if handler is not None:
                _audited(handler, event, args)
    except RecursionError:
        # The agent is at the bottom of its stack. Only what takes no frame of ours can be done here.
        run = None
        try:
            run = _current_run.get()
            if run is not None and not _suppressed.get() and _covered_socket.get() is None:
                if len(_starved) < _MAX_STARVED:
                    _starved.append((run, event, args))
                else:
                    run.recorder.failures += 1
        except RecursionError:
            # Before Python 3.12 looking up a variable that is not set can take one more level than is left.
            # Counting takes none, so the event is counted as missing and not lost without a word.
            if run is not None:
                run.recorder.failures += 1
        except Exception:
            pass
    except Exception:  # not BaseException: a Ctrl-C that lands in here is still the program's
        pass


def _audited(handler: Callable[[Run, _Config, str, tuple], None], event: str, args: tuple) -> None:
    if _suppressed.get():  # a sink's writes and uploads, and the recorder's own traffic
        return
    if _starved:
        _replay_starved()
    cfg, run = _config, current_run()
    if cfg is None:
        return
    marks = None
    if run is None:
        run = _only_open_run()
        if run is None:
            return
        marks = _INFERRED
    if _on_own_thread():
        return
    token, marks_token = _suppressed.set(True), _marks.set(marks)  # the flag also guards against re-entry
    try:
        handler(run, cfg, event, args)
    finally:
        _marks.reset(marks_token)
        _suppressed.reset(token)


def _only_open_run() -> Run | None:
    """Code that left the run's context (a bare Context, a raw thread) still belongs to it, if it can only be this."""
    try:
        for key, stale in list(_open_runs.items()):  # a run whose end or recorder is gone is not open
            if stale.ended or stale.recorder._closed:
                _open_runs.pop(key, None)
        if len(_open_runs) != 1:
            return None
        run = next(iter(_open_runs.values()))
    except (StopIteration, RuntimeError):
        return None
    return None if run.ended or run.recorder._closed else run


def _on_own_thread() -> bool:
    # Not current_thread(), which would register a thread Python did not start.
    thread = _THREADING._active.get(threading.get_ident())
    return thread is not None and bool(thread.__dict__.get("_mnestiq_own"))


def _room(depth: int = _RECORDING_DEPTH) -> None:
    """Raises RecursionError if writing an event would run out of stack halfway through."""
    if depth:
        _room(depth - 1)


def _replay_starved() -> None:
    """Record what the hook could only put aside. The stack here has to have room for it."""
    _room()
    cfg = _config
    while cfg is not None:
        try:
            run, event, args = _starved.popleft()
        except IndexError:
            return
        token, marks_token = _suppressed.set(True), _marks.set(_LATE)
        try:
            _AUDIT_HANDLERS[event](run, cfg, event, args)
        except Exception:
            run.recorder.failures += 1
        finally:
            _marks.reset(marks_token)
            _suppressed.reset(token)


def _holds_chain_lock(recorder: Any) -> bool:
    """This thread is in the middle of writing to the chain: a finalizer has run inside that write.
    A thread that took the lock on purpose to write, as a stream being closed does, is not."""
    return bool(recorder._inside_write()) and not recorder._checkpointing  # that case has its own queue


def _flush_deferred() -> None:
    for _ in range(_MAX_DEFERRED):
        try:
            run, event_type, fields = _deferred_events.popleft()
        except IndexError:
            return
        lock = run.recorder._lock
        if _holds_chain_lock(run.recorder) or not lock.acquire(False):  # never wait here: see _patch_run
            _deferred_events.appendleft((run, event_type, fields))  # back at the front, so the order holds
            return
        try:
            _unwrapped_emit(run, event_type, **fields)
        except Exception as exc:  # raised only when strict, and nobody is waiting for this one
            run.recorder._record_failure(exc)
        finally:
            lock.release()


_before_close.append(_flush_deferred)


def _flush_at_exit() -> None:
    """The last safe point: what is still waiting is written before the process ends."""
    with suppress(BaseException):  # nothing at exit may stop the interpreter from stopping
        _flush_deferred()


atexit.register(_flush_at_exit)


def _before_run_end(run: Run) -> None:
    """What belongs to a run and is still waiting goes in before its last record."""
    try:
        _open_runs.pop(id(run), None)
        if not _suppressed.get():
            if _starved:
                _replay_starved()
            if _deferred_events:
                _flush_deferred()
        _write_dropped_summary(run)
    except Exception:
        pass


def _write_dropped_summary(run: Run) -> None:
    ledger = run.__dict__.get("_mnestiq_network")
    if ledger is not None and ledger.dropped:
        total = sum(ledger.dropped.values())
        _unwrapped_emit(run, "note", attributes={
            "message": f"network: {total} sends or lookups past the limits were not noted",
            "network": {"kind": "dropped_summary", "dropped": total, "by_kind": dict(ledger.dropped),
                        "sha256": ledger.digest.hexdigest()}})
        ledger.forget_dropped()


def _first_taint(run: Run, event_type: str, fields: dict) -> bool:
    """Whether this model call is the first of its run with untrusted content in its context."""
    if event_type != "llm_call" or "_mnestiq_tainted" in run.__dict__:
        return False
    context = fields.get("context")
    if not isinstance(context, list):
        return False
    return any(isinstance(s, dict) and isinstance(s.get("source"), str) and s["source"] in UNTRUSTED for s in context)


def _patch_run() -> None:
    global _unwrapped_emit
    original = Run.__dict__["emit"]

    def written(self: Run, event_type: str, **fields: Any) -> dict | None:
        if event_type == "run_end":  # every path that writes an end comes through here
            _open_runs.pop(id(self), None)
        if not _first_taint(self, event_type, fields):
            return original(self, event_type, **fields)
        # What was noted before taint must not hide what is sent after it: MNQ-003 only counts notes after it. What
        # the limits cut so far is said here, ahead of this call, so that it does not read as cut after taint.
        with suppress(Exception):
            _write_dropped_summary(self)
        result = original(self, event_type, **fields)
        if result is not None:  # not sooner: until the call is on file, a send is not after taint
            self.__dict__["_mnestiq_tainted"] = True
            self.__dict__["_mnestiq_network"] = _NetworkLedger()
        return result

    _unwrapped_emit = written

    def emit(self: Run, event_type: str, **fields: Any) -> dict | None:
        if _holds_chain_lock(self.recorder):
            if len(_deferred_events) < _MAX_DEFERRED:
                _deferred_events.append((self, event_type, fields))
            else:
                self.recorder.failures += 1
            return None
        if _marks.get() is _INFERRED:
            # This thread has no run of its own, so the thread holding the chain's lock may be waiting for it.
            lock = self.recorder._lock
            if not lock.acquire(False):
                if len(_deferred_events) < _MAX_DEFERRED:
                    _deferred_events.append((self, event_type, fields))
                else:
                    self.recorder.failures += 1
                return None
            try:
                return written(self, event_type, **fields)
            finally:
                lock.release()
        if event_type == "run_end":
            _before_run_end(self)
        result = written(self, event_type, **fields)
        if event_type == "run_start":  # not sooner: until it is written, a worker of the sink is not the agent
            _open_runs[id(self)] = self
        if _deferred_events:
            _flush_deferred()
        if _starved and not _suppressed.get():
            with suppress(Exception):  # still too deep: the next event tries again
                _replay_starved()
        return result

    _patch(Run, "emit", emit)


def _patch_winapi() -> None:
    # Its audit event garbles the command line, so the program's arguments are taken from the call itself.
    try:
        winapi: Any = importlib.import_module("_winapi")
    except ImportError:
        return
    original = winapi.CreateProcess

    def create_process(*args: Any, **kwargs: Any) -> Any:
        _thread_state.create_process_command = args[1] if len(args) > 1 else None
        try:
            return original(*args, **kwargs)
        finally:
            _thread_state.create_process_command = None

    _patch(winapi, "CreateProcess", create_process)


def _plain_text(value: Any) -> str | None:
    """``value`` as text, by the C methods only: an odd object's own ``__str__`` is not ours to run."""
    kind = type(value)  # unlike isinstance, this cannot be talked round by a __class__ property
    if issubclass(kind, str):
        return str.__str__(value)
    if issubclass(kind, bytes):
        return bytes.decode(value, "utf-8", "replace")
    if issubclass(kind, bytearray):
        return bytearray.decode(value, "utf-8", "replace")
    return None


def _destination(address: Any) -> tuple[str, int | None] | None:
    """The host and port of an inet socket address as given. None for anything else."""
    if not issubclass(type(address), tuple) or not tuple.__len__(address):
        return None
    host = _plain_text(tuple.__getitem__(address, 0))
    if not host:
        return None
    port = tuple.__getitem__(address, 1) if tuple.__len__(address) >= 2 else None
    return host[:_MAX_HOST_CHARS], port if type(port) is int and 0 <= port <= 65535 else None


def _record_note(run: Run, message: str, **attributes: Any) -> None:
    marks = _marks.get()
    if marks:
        attributes.update(marks)
    try:
        run.note(message, **attributes)
    except Exception as exc:  # raised only when strict, and a hook has no one to raise it to
        run.recorder._record_failure(exc)


def _loopback_name(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return host == "localhost" or host.endswith(".localhost")


class _NetworkLedger:
    """What a run has noted, and what the limits left out. Written records cannot change, so repeats are not counted."""

    def __init__(self) -> None:
        self.seen: dict[tuple, tuple] = {}
        self.noted: dict[tuple, int] = {}
        self.dropped: dict[str, int] = {}
        self.digest = hashlib.sha256()

    def admit(self, kind: str, host: str, loopback: bool) -> bool:
        whole = (kind, loopback)
        if self.noted.get(whole, 0) >= _MAX_NETWORK_NOTES:
            return False
        if loopback:
            one = (kind, host)
            if self.noted.get(one, 0) >= _MAX_PER_LOOPBACK_ADDRESS:
                return False
            self.noted[one] = self.noted.get(one, 0) + 1
        self.noted[whole] = self.noted.get(whole, 0) + 1
        return True

    def drop(self, kind: str, host: str, port: int | None) -> None:
        self.dropped[kind] = self.dropped.get(kind, 0) + 1
        self.digest.update(f"{kind}|{host}|{port}\n".encode("utf-8", "backslashreplace"))

    def forget_dropped(self) -> None:
        self.dropped = {}
        self.digest = hashlib.sha256()


def _note_network(run: Run, cfg: _Config, kind: str, host: str, port: int | None) -> None:
    ledger = run.__dict__.get("_mnestiq_network") or run.__dict__.setdefault("_mnestiq_network", _NetworkLedger())
    key = (kind, host, port)
    if key in ledger.seen or _host_matches(host, cfg.ignore_hosts):
        return
    _room()
    loopback = _loopback_name(host)
    if not ledger.admit(kind, host, loopback):
        ledger.drop(kind, host, port)
        limit = ("limit_reached", kind, loopback)
        if ledger.seen.setdefault(limit, key) is key:  # setdefault is atomic: only one thread writes this
            _record_note(run, f"network: further {kind} destinations not noted", network={
                "kind": "limit_reached", "of": kind, "loopback": loopback, "limit": _MAX_NETWORK_NOTES})
        return
    if ledger.seen.setdefault(key, key) is not key:
        return
    detail: dict[str, Any] = {"kind": kind}
    try:
        detail["dest_ip"] = str(ipaddress.ip_address(host))
    except ValueError:
        detail["host"] = host
    if port is not None:
        detail["dest_port"] = port
    _record_note(run, f"network: {kind} {host}" + (f":{port}" if port is not None else ""), network=detail)


def _socket_kind(sock: Any) -> tuple[int, int]:
    return _RAW_SOCKET.family.__get__(sock), _RAW_SOCKET.type.__get__(sock)


def _called_by_http_client() -> bool:
    """Whether the socket call under way comes from an HTTP library, and not from code it was given to run."""
    frame: Any = sys._getframe(1)
    through_anyio = False
    for _ in range(128):
        if frame is None:  # anyio connects in a task of its own, which has no caller to look at
            return through_anyio
        name = frame.f_globals.get("__name__")
        if name == "http.client":
            return True
        if name == "asyncio.events" and frame.f_code.co_name == "_run":  # the bottom of a task
            return through_anyio
        if name != __name__:
            root = name.partition(".")[0] if type(name) is str else ""
            if root in _HTTP_CLIENT_ROOTS:
                return True
            if root not in _PLUMBING_ROOTS:
                return False
            through_anyio = through_anyio or root == "anyio"
        frame = frame.f_back
    return False


def _request_owns(http: _HttpCtx, address: Any) -> bool:
    """A request has one connection. Anything else that connects during it is recorded for itself."""
    if http.connected:
        try:
            if _bare(str(http.dest[0])) != _bare(str(address[0])) or http.dest[1] != address[1]:  # type: ignore[index]
                return False
        except (TypeError, IndexError):
            return False
    return _called_by_http_client()


def _on_connect(run: Run, cfg: _Config, event: str, args: tuple) -> None:
    sock, address = args
    if _covered_socket.get() is sock or not cfg.capture_connections:
        return
    family, kind = _socket_kind(sock)
    dest = _destination(address)
    if family not in _INET_FAMILIES or dest is None:
        return
    if kind != _STREAM:  # a connected datagram socket: its later send() raises no audit event at all
        _note_network(run, cfg, "udp_connect" if kind == _DATAGRAM else "raw_connect", *dest)
        return
    http = _active_http.get()
    if http is not None and _request_owns(http, dest):  # the patch that would have filled this in is gone
        http.dest = http.dest or dest
        return
    _record_raw_connect(run, cfg, sock, dest)


def _record_raw_connect(run: Run, cfg: _Config, sock: Any, dest: tuple[str, int | None]) -> None:
    host, port = dest
    if _host_matches(host, cfg.ignore_hosts):
        return
    _room()
    last = getattr(_thread_state, "last_connect", None)
    if last is not None and last[0]() is sock and last[1] == dest:  # a non-blocking connect being polled
        return
    try:
        _thread_state.last_connect = (weakref.ref(sock), dest)
    except TypeError:  # a bare _socket.socket takes no weak reference
        _thread_state.last_connect = None
    entry: dict[str, Any] = {"egress_id": uuid.uuid4().hex, "protocol": "tcp"}
    try:
        entry["dest_ip"] = str(ipaddress.ip_address(host))
    except ValueError:
        entry["host"] = host
    if port is not None:
        entry["dest_port"] = port
    public_ip = getattr(run.recorder, "public_ip", None)
    if public_ip:
        entry["public_ip"] = public_ip
    attributes = {"captured_by": "audit_hook", "outcome": "unknown", **(_marks.get() or {})}
    try:  # no status: this runs before the connect, whose outcome nothing here will see
        run.emit("egress", egress=[entry], attributes=attributes)
    except Exception as exc:
        run.recorder._record_failure(exc)


def _is_connected(sock: Any) -> bool:
    try:
        _RAW_SOCKET.getpeername(sock)
    except OSError:
        return False
    return True


def _on_send(run: Run, cfg: _Config, event: str, args: tuple) -> None:
    sock, address = args
    dest = _destination(address)  # None on a connected socket, whose connect was noted
    if dest is None or not cfg.capture_connections:
        return
    family, kind = _socket_kind(sock)
    if family not in _INET_FAMILIES:
        return
    if kind == _STREAM:  # on a socket not yet connected this is TCP Fast Open, which connects
        if not _is_connected(sock):
            _record_raw_connect(run, cfg, sock, dest)
        return
    _note_network(run, cfg, "udp_send" if kind == _DATAGRAM else "raw_send", *dest)


def _note_lookup(run: Run, cfg: _Config, kind: str, name: str | None) -> None:
    if not name or not cfg.capture_connections:
        return
    # A request's own lookup is part of it, and the event for the request names the host.
    if _active_http.get() is not None and _called_by_http_client():
        return
    host = _bare(name)[:_MAX_HOST_CHARS]
    if not host or host == "localhost":
        return
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    if address is None or (kind == "reverse_lookup" and not address.is_loopback):
        _note_network(run, cfg, kind, host, None)


def _on_lookup(run: Run, cfg: _Config, event: str, args: tuple) -> None:
    _note_lookup(run, cfg, "dns_lookup", _plain_text(args[0]))


def _on_reverse_lookup(run: Run, cfg: _Config, event: str, args: tuple) -> None:
    _note_lookup(run, cfg, "reverse_lookup", _plain_text(args[0]))


def _on_nameinfo(run: Run, cfg: _Config, event: str, args: tuple) -> None:
    dest = _destination(args[0])
    _note_lookup(run, cfg, "reverse_lookup", dest[0] if dest else None)


def _secret_flag(flag: str) -> bool:
    return _SECRET_PARAM.search(flag.lstrip("-")) is not None


def _masked_url(match: re.Match[str]) -> str:
    url = sanitize_url(match.group())
    url = _BOT_TOKEN_IN_PATH.sub(r"\1***", url)
    return _SECRET_IN_PATH.sub(r"\1***", url)


def _masked_arg(text: str, next_flags: frozenset[str] = frozenset(), attached: frozenset[str] = frozenset()) -> str:
    def param(match: re.Match[str]) -> str:
        return match.group(1) + "***" if _SECRET_PARAM.search(match.group(2)) else match.group()

    def flag(match: re.Match[str]) -> str:
        return f"{match.group(1)}{match.group(2)}***" if _secret_flag(match.group(1)) else match.group()

    def slash(match: re.Match[str]) -> str:
        return f"/{match.group(1)}:***" if _secret_flag(match.group(1)) else match.group()

    def quoted(match: re.Match[str]) -> str:
        return f'"{match.group(1)}=***"' if _SECRET_PARAM.search(match.group(1)) else match.group()

    def pair(match: re.Match[str]) -> str:
        return f"{match.group(1)}=***" if _SECRET_PARAM.search(match.group(1)) else match.group()

    def user(match: re.Match[str]) -> str:
        return f"{match.group(1)}{match.group(2)}***" if ":" in match.group(3) else match.group()

    def json_pair(match: re.Match[str]) -> str:
        return match.group(1) + "***" if _SECRET_PARAM.search(match.group(2)) else match.group()

    text = text[:_MASK_WINDOW]
    text = _URL_IN_TEXT.sub(_masked_url, text)
    text = _CREDS_IN_URL.sub(r"\1***@", text)
    if "@" in text:
        text = _CREDS_WITH_SLASH.sub(r"\1***@", text)
    text = _PARAM_IN_TEXT.sub(param, text)
    text = _ENCODED_PARAM.sub(param, text)
    text = _HEADER_IN_ARG.sub(r"\1: ***", text)
    text = _SCHEME_IN_ARG.sub(r"\1 ***", text)
    text = _FLAG_IN_ARG.sub(flag, text)
    text = _SLASH_OPTION.sub(slash, text)
    text = _USER_IN_ARG.sub(user, text)
    text = _USER_ATTACHED.sub("-u***", text)
    text = _PASS_PHRASE.sub("pass:***", text)
    for name in next_flags:
        text = _NEXT_FLAG[name].sub(lambda m, name=name: f"{name}{m.group(1)}***", text)  # type: ignore[misc]
    for name in attached:
        text = _ATTACHED_FLAG[name].sub(f"{name}***", text)
    text = _QUOTED_PAIR.sub(quoted, text)
    text = _PAIR_IN_ARG.sub(pair, text)
    text = _JSON_PAIR_IN_ARG.sub(json_pair, text)
    return _TOKEN_IN_ARG.sub("***", text)


def _arg_text(value: Any) -> str:
    """One argument as text. Whatever an odd object does, it costs only its own place in the list."""
    try:
        text = _plain_text(value)
        if text is not None:
            return text
        if type(value) in _PATH_TYPES:
            return str(value)
        return f"<{type.__dict__['__name__'].__get__(type(value))}>"
    except Exception:
        return "<unreadable>"


def _argument_list(raw: Any) -> list:
    kind = type(raw)
    if issubclass(kind, list):  # by the C method: a subclass's own iterator is the agent's code
        return list.__getitem__(raw, slice(None))
    if issubclass(kind, tuple):
        return list(tuple.__getitem__(raw, slice(None)))
    return [raw]  # one command line, or an iterator that is the agent's to consume


def _tool_flags(items: list) -> tuple[frozenset[str], frozenset[str]]:
    """The short flags that hold a password, given the programs named anywhere in the command."""
    following: set[str] = set()
    attached: set[str] = set()
    for item in items[:_MAX_ARGS]:
        for tool in _TOOL_NAME.findall(_arg_text(item)[:_MASK_WINDOW]):
            name = _TOOL_FLAGS.get(tool.lower())
            if name is None:  # mysql alone: -p with a space after it asks at the prompt
                attached.add("-p")
            else:
                following.add(name)
                attached.add(name)
    return frozenset(following), frozenset(attached)


def _shown_args(run: Run, raw: Any) -> tuple[list[str], int]:
    """The arguments as they may be recorded, and how many were left out."""
    items = _argument_list(raw)
    following, attached = _tool_flags(items)
    shown: list[str] = []
    room = run.recorder.max_content_bytes
    limit = min(_MAX_ARG_BYTES, room)
    work = _MAX_MASKED_CHARS
    hide_next = user_flag = False
    for item in items[:_MAX_ARGS]:
        text = _arg_text(item)
        work -= min(len(text), _MASK_WINDOW)
        if work < 0:
            break
        hidden = hide_next or (user_flag and ":" in text)
        value = "***" if hidden else _capped_error(_masked_arg(text, following, attached), limit)
        alone = not hide_next and _FLAG_ALONE.fullmatch(text) is not None
        hide_next = alone and (_secret_flag(text) or text in following)
        user_flag = text in ("-u", "--user")
        room -= len(value.encode("utf-8", "surrogatepass"))
        if room < 0:
            break
        shown.append(value)
    return shown, len(items) - len(shown)


def _follows_popen(event: str, args: tuple) -> bool:
    """Whether this is the call ``subprocess.Popen`` makes right after its own audit event, on this thread."""
    if event == "subprocess.Popen":
        _thread_state.popen = (args[0], args[1])
        return False
    earlier = getattr(_thread_state, "popen", None)
    if earlier is None:
        return False
    if event == "_winapi.CreateProcess":  # only the program can be compared: its command line is garbled
        _thread_state.popen = None
        return _plain_text(earlier[0]) == _plain_text(args[0])
    if event == "os.posix_spawn" and earlier[1] is args[1]:
        _thread_state.popen = None
        return True
    return False


def _on_spawn(run: Run, cfg: _Config, event: str, args: tuple) -> None:
    if _follows_popen(event, args):
        return
    _room()
    executable_at, arguments_at = _SPAWN_FIELDS[event]
    limit = min(_MAX_ARG_BYTES, run.recorder.max_content_bytes)
    detail: dict[str, Any] = {"kind": "fork" if event in ("os.fork", "os.forkpty") else "spawn", "via": event}
    shown: list[str] = []
    raw_arguments = args[arguments_at] if arguments_at is not None else None
    if event == "_winapi.CreateProcess":
        raw_arguments = getattr(_thread_state, "create_process_command", None)
    if raw_arguments is not None:
        shown, omitted = _shown_args(run, raw_arguments)
        if shown:
            detail["args"] = shown
        if omitted:
            detail["args_omitted"] = omitted
    raw_executable = args[executable_at] if executable_at is not None else None
    executable = "" if raw_executable is None else _capped_error(_masked_arg(_arg_text(raw_executable)), limit)
    if not executable and shown:  # Windows gives one command line, and a shell string has only that
        first = _FIRST_WORD.match(shown[0])
        executable = (first.group(1) or first.group(2)) if first else ""
    if executable:
        detail["executable"] = executable
    name = executable.replace("\\", "/").rsplit("/", 1)[-1] if executable else event
    _record_note(run, f"process started: {name}", process=detail)


# Which arguments of each event hold the executable and the arguments.
_SPAWN_FIELDS: dict[str, tuple[int | None, int | None]] = {
    "subprocess.Popen": (0, 1), "os.system": (None, 0), "os.exec": (0, 1), "os.posix_spawn": (0, 1),
    "os.spawn": (1, 2), "os.startfile/2": (0, 2), "pty.spawn": (None, 0), "_winapi.CreateProcess": (0, None),
    "os.fork": (None, None), "os.forkpty": (None, None),
}
_AUDIT_HANDLERS: dict[str, Callable[[Run, _Config, str, tuple], None]] = {
    "socket.connect": _on_connect, "socket.sendto": _on_send, "socket.sendmsg": _on_send,
    "socket.getaddrinfo": _on_lookup, "socket.gethostbyname": _on_lookup,
    "socket.gethostbyaddr": _on_reverse_lookup, "socket.getnameinfo": _on_nameinfo,
    **dict.fromkeys(_SPAWN_FIELDS, _on_spawn),
}
