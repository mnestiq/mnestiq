"""The guard itself: prove external access fails and loopback still works."""

import socket
import threading

import pytest

from _netguard import ExternalNetworkBlocked, is_local


@pytest.mark.parametrize("addr", [("192.0.2.1", 80), ("8.8.8.8", 53), ("2001:db8::1", 443, 0, 0)])
def test_external_connect_is_blocked(addr):
    family = socket.AF_INET6 if ":" in addr[0] else socket.AF_INET
    with socket.socket(family, socket.SOCK_STREAM) as s, pytest.raises(ExternalNetworkBlocked):
        s.connect(addr)
    with socket.socket(family, socket.SOCK_STREAM) as s, pytest.raises(ExternalNetworkBlocked):
        s.connect_ex(addr)


def test_external_dns_is_blocked():
    with pytest.raises(ExternalNetworkBlocked):
        socket.getaddrinfo("example.com", 443)
    with pytest.raises(ExternalNetworkBlocked):
        socket.create_connection(("example.com", 443), timeout=1)


def test_loopback_still_works():
    server = socket.create_server(("127.0.0.1", 0))
    threading.Thread(target=lambda: server.accept()[0].close(), daemon=True).start()
    socket.create_connection(server.getsockname(), timeout=2).close()
    server.close()
    assert socket.getaddrinfo("localhost", 80)


@pytest.mark.parametrize("host, local", [
    ("127.0.0.1", True), ("127.8.9.10", True), ("::1", True), ("[::1]", True), ("localhost", True),
    ("api.localhost", True), (None, True), ("10.0.0.1", False), ("example.com", False), ("0.0.0.0", False),
])
def test_is_local(host, local):
    assert is_local(host) is local
