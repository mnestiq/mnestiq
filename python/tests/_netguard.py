"""Test-suite guard: nothing may reach the network beyond this machine.

Installed from conftest.py at pytest_configure, before any test module is imported.
Blocks socket connects to non-loopback addresses and DNS lookups of non-local names,
so a test that would talk to the internet fails loudly instead of silently doing it.
"""

from __future__ import annotations

import ipaddress
import socket

_LOCAL_NAMES = {"localhost", "localhost.localdomain", "ip6-localhost", ""}
_saved: list[tuple[object, str, object]] = []
_ABSENT = object()


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


def install() -> None:
    if _saved:
        return
    connect, connect_ex, getaddrinfo = socket.socket.connect, socket.socket.connect_ex, socket.getaddrinfo

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

    for owner, name, value in ((socket.socket, "connect", guarded_connect),
                               (socket.socket, "connect_ex", guarded_connect_ex),
                               (socket, "getaddrinfo", guarded_getaddrinfo)):
        _saved.append((owner, name, owner.__dict__.get(name, _ABSENT)))
        setattr(owner, name, value)


def uninstall() -> None:
    while _saved:
        owner, name, original = _saved.pop()
        if original is _ABSENT:
            delattr(owner, name)
        else:
            setattr(owner, name, original)
