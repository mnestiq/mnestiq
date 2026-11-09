"""Test-suite guard: nothing may reach the network beyond this machine.

Installed from conftest.py at pytest_configure, before any test module is imported.
Blocks socket connects to non-loopback addresses and DNS lookups of non-local names,
so a test that would talk to the internet fails loudly instead of silently doing it.
"""

from __future__ import annotations

import ipaddress
import socket
import sys

_LOCAL_NAMES = {"localhost", "localhost.localdomain", "ip6-localhost", ""}
_saved: list[tuple[object, str, object]] = []
_ABSENT = object()
_BY_AUDIT_HOOK = object()  # an entry in _saved held by the audit hook below, with nothing to restore
_armed = False
_hook_added = False


class ExternalNetworkBlocked(RuntimeError):
    pass


def is_local(host: object) -> bool:
    if host is None:
        return True
    if isinstance(host, bytes):
        host = host.decode("ascii", "replace")
    if not isinstance(host, str):
        return False
    host = host.strip("[]").split("%")[0].lower()
    if host in _LOCAL_NAMES or host.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _check(address: object) -> None:
    # AF_UNIX addresses are paths (str/bytes), not (host, port): always local.
    if isinstance(address, tuple) and address and not is_local(address[0]):
        raise ExternalNetworkBlocked(f"test attempted a network connection to {address!r}")


def _audit_hook(event: str, args: tuple) -> None:
    # Datagrams are caught here and not by a patch: the suite checks that nothing puts sendto on socket.socket.
    # Connects as well, as the C method can be called with every patch gone round.
    if not _armed or not args:
        return
    if event in ("socket.sendto", "socket.sendmsg", "socket.connect") and len(args) > 1:
        _check(args[1])
    elif event == "socket.getnameinfo":
        _check(args[0])
    elif event == "socket.gethostbyaddr" and not is_local(args[0]) and args[0] != socket.gethostname():
        raise ExternalNetworkBlocked(f"test attempted a reverse lookup of {args[0]!r}")


def install() -> None:
    global _armed, _hook_added
    if _saved:
        return
    connect, connect_ex, getaddrinfo = socket.socket.connect, socket.socket.connect_ex, socket.getaddrinfo
    gethostbyname, gethostbyname_ex = socket.gethostbyname, socket.gethostbyname_ex

    def guarded_connect(self, address):
        _check(address)
        return connect(self, address)

    def guarded_connect_ex(self, address):
        _check(address)
        return connect_ex(self, address)

    def guarded_getaddrinfo(host, *args, **kwargs):
        if not is_local(host):
            raise ExternalNetworkBlocked(f"test attempted a DNS lookup of {host!r}")
        return getaddrinfo(host, *args, **kwargs)

    def guarded_gethostbyname(host):
        if not is_local(host):
            raise ExternalNetworkBlocked(f"test attempted a DNS lookup of {host!r}")
        return gethostbyname(host)

    def guarded_gethostbyname_ex(host):
        if not is_local(host):
            raise ExternalNetworkBlocked(f"test attempted a DNS lookup of {host!r}")
        return gethostbyname_ex(host)

    for owner, name, value in ((socket.socket, "connect", guarded_connect),
                               (socket.socket, "connect_ex", guarded_connect_ex),
                               (socket, "getaddrinfo", guarded_getaddrinfo),
                               (socket, "gethostbyname", guarded_gethostbyname),
                               (socket, "gethostbyname_ex", guarded_gethostbyname_ex)):
        _saved.append((owner, name, owner.__dict__.get(name, _ABSENT)))
        setattr(owner, name, value)
    _saved.extend((_BY_AUDIT_HOOK, name, None) for name in ("sendto", "sendmsg", "gethostbyaddr", "getnameinfo"))
    if not _hook_added:  # an audit hook cannot be removed, so it stays and goes idle
        sys.addaudithook(_audit_hook)
        _hook_added = True
    _armed = True


def uninstall() -> None:
    global _armed
    _armed = False
    while _saved:
        owner, name, original = _saved.pop()
        if owner is _BY_AUDIT_HOOK:
            continue
        if original is _ABSENT:
            delattr(owner, name)
        else:
            setattr(owner, name, original)
