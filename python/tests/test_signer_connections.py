"""The signing service bounds how many connections it serves at once and closes one left idle, and SignerClient
carries on over a connection the service closed, sending a request again only when that is safe."""

import base64
import json
import socket
import threading
import time
from types import SimpleNamespace

import pytest

from mnestiq import FileSink, Recorder, verify_file
from mnestiq import signer_service, signers
from mnestiq.signer_service import SignerService, init_signer
from mnestiq.signers import SignerClient, SignerError


def _start(tmp_path, **options):
    signer = init_signer(tmp_path / "signer")
    server = SignerService(tmp_path / "signer").start("127.0.0.1:0", **options)
    token = (tmp_path / "signer" / "signer.token").read_text().strip()
    return SimpleNamespace(server=server, token=token, pub=signer.public_key, dir=tmp_path / "signer")


def _handlers():
    return sum(1 for t in threading.enumerate() if t.name == "mnestiq-signer-client" and t.is_alive())


def _wait_for(predicate, timeout=10.0):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if predicate():
            return True
        time.sleep(0.05)
    return False


def _connect_raw(address):
    host, port = address.rsplit(":", 1)
    return socket.create_connection((host, int(port)))


def test_connections_that_never_prove_the_token_hold_a_bounded_number_of_threads(tmp_path):
    svc = _start(tmp_path)
    socks = []
    try:
        base = _handlers()
        for _ in range(signer_service.MAX_HANDSHAKES * 3):
            socks.append(_connect_raw(svc.server.address))
        time.sleep(0.5)
        assert _handlers() - base <= signer_service.MAX_HANDSHAKES
    finally:
        for s in socks:
            s.close()
    try:
        assert _wait_for(lambda: _handlers() == 0)
        client = SignerClient(svc.server.address, svc.token)  # the service still serves the agent
        assert client.public_key == svc.pub
        client.close()
    finally:
        svc.server.close()


def test_past_the_connection_cap_a_new_connection_is_closed_at_once(tmp_path):
    svc = _start(tmp_path, max_connections=2)
    clients = []
    try:
        clients = [SignerClient(svc.server.address, svc.token) for _ in range(2)]
        assert _handlers() == 2
        with pytest.raises(SignerError, match="not reachable"):
            SignerClient(svc.server.address, svc.token, timeout=2.0)
        clients.pop().close()
        assert _wait_for(lambda: _handlers() == 1)
        clients.append(SignerClient(svc.server.address, svc.token))
    finally:
        for c in clients:
            c.close()
        svc.server.close()


@pytest.mark.parametrize("bad", [0, -1, 1.5, True])
def test_a_connection_cap_that_is_not_a_positive_whole_number_is_refused(tmp_path, bad):
    init_signer(tmp_path / "signer")
    with pytest.raises(SignerError, match="max_connections"):
        SignerService(tmp_path / "signer").start("127.0.0.1:0", max_connections=bad)


@pytest.mark.parametrize("bad", [0, -1.0, float("inf"), float("nan")])
def test_an_idle_deadline_that_is_not_a_positive_time_is_refused(tmp_path, bad):
    init_signer(tmp_path / "signer")
    with pytest.raises(SignerError, match="idle_seconds"):
        SignerService(tmp_path / "signer").start("127.0.0.1:0", idle_seconds=bad)


def _events(rec, n, run="r"):
    with rec.run(run_id=run) as r:
        for i in range(n):
            r.note(f"event {i}")


@pytest.mark.parametrize("reuse", ["closed", "too old"])
def test_a_client_left_idle_past_the_deadline_still_signs(tmp_path, monkeypatch, reuse):
    if reuse == "too old":  # the client drops it first, as it does by default well before the service
        monkeypatch.setattr(signers, "IDLE_REUSE_S", 0.2)
    svc = _start(tmp_path, idle_seconds=0.5)
    client = SignerClient(svc.server.address, svc.token)
    path = tmp_path / "e.jsonl"
    rec = Recorder(FileSink(path), agent_id="a", signer=client, checkpoint_every=2)
    try:
        _events(rec, 3, "first")
        assert _wait_for(lambda: _handlers() == 0)  # the service closed both of the client's connections
        failures = rec.failures
        _events(rec, 3, "second")
        rec.close()
        assert rec.failures == failures
        assert rec.witness_refused == 0
    finally:
        client.close()
        svc.server.close()
    assert verify_file(path, [svc.pub]).ok
    log = [json.loads(line) for line in (svc.dir / "signatures.jsonl").read_text().splitlines()]
    checkpoints = [json.loads(line) for line in path.read_text().splitlines() if '"checkpoint"' in line]
    assert [e["seq"] for e in log] == [c["seq"] for c in checkpoints if c.get("kind") == "checkpoint"]


def test_an_authenticated_connection_that_stalls_is_let_go(tmp_path):
    svc = _start(tmp_path, idle_seconds=0.5)
    client = SignerClient(svc.server.address, svc.token)
    try:
        assert _handlers() == 1
        assert _wait_for(lambda: _handlers() == 0, timeout=5.0)
    finally:
        client.close()
        svc.server.close()


class _Conn:
    """A connection to a service that is not there: what it does on each request is scripted."""

    def __init__(self, log, answers):
        self.log, self.answers, self.answer = log, list(answers), None

    def send_bytes(self, data):
        self.log.append(json.loads(data)["op"])
        self.answer = self.answers.pop(0)

    def poll(self, timeout):
        return self.answer != "silent"

    def recv_bytes(self, limit):
        if self.answer == "closed":
            raise EOFError
        return json.dumps(self.answer).encode()

    def close(self):
        pass


def _scripted_client(monkeypatch, answers):
    log = []
    conns = iter(answers)
    monkeypatch.setattr(signers, "_connect", lambda address, token, timeout: _Conn(log, next(conns)))
    client = object.__new__(SignerClient)
    client.address, client._token, client._timeout = "127.0.0.1:1", b"t", 0.1
    client._line, client._witness_line = signers._Line(), signers._Line()
    return client, log


def test_a_witness_head_that_may_have_been_taken_is_not_sent_twice(monkeypatch):
    client, log = _scripted_client(monkeypatch, [["silent"], [{"witnessed": 1}]])
    with pytest.raises(SignerError, match="not reachable"):
        client.witness("c", 1, "sha256:" + "ab" * 32)
    assert log == ["witness"]


def test_a_witness_head_on_a_kept_connection_the_service_closed_is_sent_again(monkeypatch):
    client, log = _scripted_client(monkeypatch, [[{"witnessed": 1}, "closed"], [{"witnessed": 2}]])
    assert client.witness("c", 1, "sha256:" + "ab" * 32) is True
    assert client.witness("c", 2, "sha256:" + "cd" * 32) is True
    assert log == ["witness", "witness", "witness"]


def test_a_sign_request_is_sent_again_after_a_lost_answer(monkeypatch):
    # Safe: the service answers the identical request with the signature it already gave.
    signature = base64.b64encode(b"s" * 64).decode()
    client, log = _scripted_client(monkeypatch, [["silent"], [{"signature": signature}]])
    assert client.sign(b"{}") == b"s" * 64
    assert log == ["sign", "sign"]
