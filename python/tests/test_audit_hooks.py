"""What the audit hooks see, what they leave alone, and where a proxied request is recorded as going."""

import _socket
import _thread
import asyncio
import contextlib
import contextvars
import gc
import http.server
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import textwrap
import threading
import time
import urllib.parse
import urllib.request

import pytest

import _netguard
from _netguard import ExternalNetworkBlocked
from mnestiq import MemorySink, Recorder, Segment, verify_lines
from mnestiq import egress as egress_module
from mnestiq.canonical import canonical_json
from pathlib import PureWindowsPath

from mnestiq.egress import (
    EGRESS_HEADER,
    RUN_HEADER,
    _audit_hook,
    instrument_egress,
    suppress_egress,
    uninstrument_egress,
)
from mnestiq.findings import findings
from test_findings import DASHBOARD, JS_SETS, llm


class _Proxy(http.server.BaseHTTPRequestHandler):
    """A forward proxy as far as a client can tell: it answers every request itself."""

    def do_GET(self):
        self.server.seen.append({"path": self.path, "headers": dict(self.headers), "client": self.client_address})
        if self.headers.get("Transfer-Encoding") == "chunked":
            while True:
                size = int(self.rfile.readline().strip() or b"0", 16)
                self.rfile.read(size + 2)
                if size == 0:
                    break
        elif self.headers.get("Content-Length"):
            self.rfile.read(int(self.headers["Content-Length"]))
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    do_POST = do_GET

    def do_CONNECT(self):  # the tunnel opens, and the TLS that follows it then fails
        self.server.seen.append({"path": self.path, "headers": dict(self.headers), "client": self.client_address})
        self.send_response(200)
        self.end_headers()
        self.close_connection = True

    def log_message(self, *args):
        pass


@pytest.fixture
def web():
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Proxy)
    server.seen = []
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield server
    server.shutdown()
    server.server_close()


@pytest.fixture
def udp_sink():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    yield sock.getsockname()
    sock.close()


@pytest.fixture(autouse=True)
def hooks():
    instrument_egress(ignore_hosts=set())
    egress_module._thread_state.__dict__.clear()  # what the thread remembers of an earlier test's synthetic events
    yield
    uninstrument_egress()


@pytest.fixture
def rec():
    recorder = Recorder(MemorySink(), agent_id="agent")
    yield recorder
    recorder.close()


def entries(rec):
    return [e for r in rec._sink.records if r.get("event_type") == "egress" for e in r["egress"]]


def egress_records(rec):
    return [r for r in rec._sink.records if r.get("event_type") == "egress"]


def notes(rec, key):
    return [r["attributes"][key] for r in rec._sink.records
            if r.get("event_type") == "note" and key in (r.get("attributes") or {})]


def assert_valid(rec):
    report = verify_lines(canonical_json(r) for r in rec._sink.records)
    assert report.ok, report.errors


def raw_connect(address):
    """A connect that goes around every monkeypatch, as code undoing them would."""
    sock = socket.socket()
    sock.settimeout(5)
    try:
        _socket.socket.connect(sock, address)
    finally:
        sock.close()


# Raw connections


def test_a_connect_the_patches_missed_is_recorded_as_tcp(rec, web):
    with rec.run() as run:
        raw_connect(("127.0.0.1", web.server_port))
    [record] = egress_records(rec)
    entry = record["egress"][0]
    assert record["run_id"] == run.run_id and entry["protocol"] == "tcp"
    assert entry["dest_ip"] == "127.0.0.1" and entry["dest_port"] == web.server_port
    assert record["attributes"] == {"captured_by": "audit_hook", "outcome": "unknown"} and "status" not in record
    assert_valid(rec)


def test_a_connect_the_patches_recorded_is_not_recorded_twice(rec, web):
    with rec.run():
        socket.create_connection(("127.0.0.1", web.server_port), timeout=5).close()
        with socket.socket() as sock:
            assert sock.connect_ex(("127.0.0.1", web.server_port)) == 0
    assert len(entries(rec)) == 2
    assert all("captured_by" not in (r.get("attributes") or {}) for r in egress_records(rec))


def test_undoing_the_patches_does_not_hide_a_connect(rec, web):
    patched = vars(socket.socket)["connect"]
    del socket.socket.connect
    try:
        with rec.run():
            socket.create_connection(("127.0.0.1", web.server_port), timeout=5).close()
    finally:
        socket.socket.connect = patched
    assert [e["dest_port"] for e in entries(rec)] == [web.server_port]


def test_polling_one_non_blocking_connect_is_one_event(rec, web):
    with socket.socket() as sock, rec.run():
        sock.setblocking(False)
        for _ in range(5):
            _socket.socket.connect_ex(sock, ("127.0.0.1", web.server_port))
    assert len(entries(rec)) == 1


def test_an_http_request_with_the_socket_patch_undone_is_still_one_event(rec, web):
    urllib3 = pytest.importorskip("urllib3")
    patched = vars(socket.socket)["connect"]
    del socket.socket.connect
    try:
        with rec.run():
            urllib3.PoolManager().request("GET", f"http://127.0.0.1:{web.server_port}/x")
    finally:
        socket.socket.connect = patched
    [entry] = entries(rec)
    assert entry["protocol"] == "http" and entry["dest_port"] == web.server_port


def test_an_ignored_host_is_left_out_of_the_raw_path(rec, web):
    instrument_egress(ignore_hosts={"127.0.0.1"})
    with rec.run():
        raw_connect(("127.0.0.1", web.server_port))
    assert entries(rec) == []


def test_capture_connections_off_leaves_the_raw_path_quiet(rec, web, udp_sink):
    uninstrument_egress()
    instrument_egress(capture_connections=False, ignore_hosts=set())
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp, rec.run():
        raw_connect(("127.0.0.1", web.server_port))
        udp.sendto(b"x", udp_sink)
    assert entries(rec) == [] and notes(rec, "network") == []


# Datagrams and name lookups


def test_udp_is_one_note_per_destination_and_nothing_else(rec, udp_sink):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock, rec.run() as run:
        for _ in range(500):
            sock.sendto(b"x", udp_sink)
    assert notes(rec, "network") == [{"kind": "udp_send", "dest_ip": "127.0.0.1", "dest_port": udp_sink[1]}]
    assert [r["run_id"] for r in rec._sink.records if r.get("event_type") == "note"] == [run.run_id]
    assert entries(rec) == []
    assert_valid(rec)


def test_a_second_run_gets_its_own_note(rec, udp_sink):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        for _ in range(2):
            with rec.run():
                sock.sendto(b"x", udp_sink)
    assert len(notes(rec, "network")) == 2


def test_notes_per_run_are_bounded_and_the_cut_is_recorded(rec, monkeypatch):
    monkeypatch.setattr(egress_module, "_MAX_NETWORK_NOTES", 3)
    with rec.run():
        for n in range(50):
            sys.audit("socket.getaddrinfo", f"h{n}.example", 53, 0, 0, 0)
    found = notes(rec, "network")
    assert [n["kind"] for n in found] == ["dns_lookup"] * 3 + ["limit_reached", "dropped_summary"]
    assert found[-2]["limit"] == 3 and found[-1]["dropped"] == 47 and len(found[-1]["sha256"]) == 64


def test_a_connected_datagram_socket_is_noted_as_its_send_has_no_event(rec, udp_sink):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock, rec.run():
        sock.connect(udp_sink)
        sock.send(b"x")
    assert notes(rec, "network") == [{"kind": "udp_connect", "dest_ip": "127.0.0.1", "dest_port": udp_sink[1]}]


@pytest.mark.parametrize("event, args, expected", [
    ("socket.getaddrinfo", ("db.example", 5432, 0, 0, 0), {"kind": "dns_lookup", "host": "db.example"}),
    ("socket.getaddrinfo", (b"db.example", 5432, 0, 0, 0), {"kind": "dns_lookup", "host": "db.example"}),
    ("socket.gethostbyname", ("db.example",), {"kind": "dns_lookup", "host": "db.example"}),
    ("socket.gethostbyaddr", ("192.0.2.1",), {"kind": "reverse_lookup", "dest_ip": "192.0.2.1"}),
    ("socket.getnameinfo", (("192.0.2.1", 80),), {"kind": "reverse_lookup", "dest_ip": "192.0.2.1"}),
])
def test_a_name_lookup_is_noted(rec, monkeypatch, event, args, expected):
    monkeypatch.setattr(_netguard, "_armed", False)  # only an audit event: nothing is looked up
    with rec.run():
        sys.audit(event, *args)
        sys.audit(event, *args)
    assert notes(rec, "network") == [expected]


@pytest.mark.parametrize("host", ["127.0.0.1", "::1", "localhost", "LOCALHOST.", None, ""])
def test_a_lookup_that_asks_no_one_is_not_noted(rec, host):
    with rec.run():
        sys.audit("socket.getaddrinfo", host, 80, 0, 0, 0)
    assert notes(rec, "network") == []


def test_the_real_lookup_functions_reach_the_hook(rec, monkeypatch):
    calls = []
    monkeypatch.setattr(egress_module, "_note_lookup", lambda run, cfg, kind, name: calls.append((kind, name)))
    with rec.run():
        socket.gethostbyname("localhost")
        socket.gethostbyname_ex("localhost")
        socket.getaddrinfo("localhost", 80)
    assert calls == [("dns_lookup", "localhost")] * 3


def test_an_ignored_name_is_not_noted(rec):
    instrument_egress(ignore_hosts={"api.example"})
    with rec.run():
        sys.audit("socket.gethostbyname", "eu.api.example")
    assert notes(rec, "network") == []


def test_a_lookup_inside_a_request_belongs_to_the_request(rec, web):
    requests = pytest.importorskip("requests")
    with rec.run():
        requests.get(f"http://localhost:{web.server_port}/", timeout=5, proxies={"http": "", "https": ""})
    assert notes(rec, "network") == [] and len(entries(rec)) == 1


# When the hook must do nothing


def test_nothing_is_recorded_outside_a_run(rec, udp_sink):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.sendto(b"x", udp_sink)
    assert notes(rec, "network") == [] and rec._sink.records == [r for r in rec._sink.records if r["kind"] != "event"]


def test_nothing_is_recorded_once_uninstrumented(rec, udp_sink):
    uninstrument_egress()
    assert not egress_module._hook_armed
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock, rec.run():
        sock.sendto(b"x", udp_sink)
        sys.audit("subprocess.Popen", "x", ["x"], None, None)
    assert notes(rec, "network") == [] and notes(rec, "process") == []


def test_nothing_is_recorded_under_suppress_egress(rec, udp_sink):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock, rec.run(), suppress_egress():
        sock.sendto(b"x", udp_sink)
        sys.audit("subprocess.Popen", "x", ["x"], None, None)
    assert notes(rec, "network") == [] and notes(rec, "process") == []


def test_the_recorders_own_thread_is_left_alone_even_when_handed_a_run(rec, udp_sink):
    def work():
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.sendto(b"x", udp_sink)

    with rec.run() as run:
        own = threading.Thread(target=run.bind(work))
        own.__dict__["_mnestiq_own"] = True
        own.start()
        own.join()
    assert notes(rec, "network") == []


def test_a_sink_that_spawns_and_sends_records_nothing_and_keeps_the_chain(udp_sink):
    class Busy(MemorySink):
        def append(self, record):
            super().append(record)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.sendto(b"x", udp_sink)
            sys.audit("subprocess.Popen", "uploader", ["uploader"], None, None)

    recorder = Recorder(Busy(), agent_id="agent")
    with recorder.run() as run:
        run.note("hello")
    assert notes(recorder, "network") == [] and notes(recorder, "process") == []
    assert_valid(recorder)
    recorder.close()


def test_recording_does_not_see_itself(rec, monkeypatch):
    """A note that sets off another audited call while being written is not recorded again."""
    original = egress_module.Run.note
    depth = []

    def noisy(self, message, **attributes):
        depth.append(message)
        sys.audit("socket.gethostbyname", f"inner{len(depth)}.example")
        return original(self, message, **attributes)

    monkeypatch.setattr(egress_module.Run, "note", noisy)
    with rec.run():
        sys.audit("socket.gethostbyname", "outer.example")
    assert len(depth) == 1


class _Odd:
    def __str__(self):
        raise RuntimeError("agent's __str__ must not run")

    __repr__ = __str__

    def __fspath__(self):
        raise RuntimeError("agent's __fspath__ must not run")

    def __iter__(self):
        raise RuntimeError("agent's iterator must not be consumed")


@pytest.mark.parametrize("event, args", [
    ("socket.connect", (1, 2)),
    ("socket.connect", ()),
    ("socket.connect", (object(), ("127.0.0.1", 1))),
    ("socket.sendto", (object(), _Odd())),
    ("socket.sendmsg", (_Odd(), None)),
    ("socket.getaddrinfo", (_Odd(), 1, 2, 3, 4)),
    ("socket.getaddrinfo", ()),
    ("socket.gethostbyname", (12,)),
    ("socket.getnameinfo", ("not a sockaddr",)),
    ("subprocess.Popen", ()),
    ("subprocess.Popen", (_Odd(), _Odd(), _Odd(), _Odd())),
    ("subprocess.Popen", (None, [_Odd(), b"\xff\xfe", 3, None], None, None)),
    ("os.system", (_Odd(),)),
    ("os.exec", ("x",)),
    ("os.spawn", (0,)),
    ("os.posix_spawn", (b"x", iter([]), None)),
])
def test_odd_arguments_never_raise_and_never_run_the_agents_code(rec, event, args):
    with rec.run():
        sys.audit(event, *args)
    assert rec.failures == 0
    assert_valid(rec)


@pytest.mark.parametrize("strict", [False, True])
def test_a_recording_failure_does_not_reach_the_program(strict, udp_sink, monkeypatch):
    recorder = Recorder(MemorySink(), agent_id="agent", strict=strict)
    run = recorder.run()
    with run as active:
        def broken(*args, **kwargs):
            raise RuntimeError("synthetic recording failure")

        monkeypatch.setattr(active, "emit", broken)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            assert sock.sendto(b"x", udp_sink) == 1
        sys.audit("subprocess.Popen", "x", ["x"], None, None)
        monkeypatch.undo()
    assert recorder.failures >= 2
    recorder.close()


def test_the_hook_is_installed_once_in_a_process(monkeypatch):
    added = []
    monkeypatch.setattr(sys, "addaudithook", added.append)
    for _ in range(3):
        uninstrument_egress()
        instrument_egress(ignore_hosts=set())
    assert added == []  # the first install of this process came earlier, and these are repeats


def test_a_module_reload_does_not_add_a_second_hook(tmp_path):
    script = tmp_path / "child.py"
    script.write_text(textwrap.dedent("""
        import importlib, sys
        added = []
        real = sys.addaudithook
        sys.addaudithook = lambda hook: (added.append(hook), real(hook))[1]
        import mnestiq.egress as egress
        egress.instrument_egress(ignore_hosts=set())
        egress.uninstrument_egress()
        importlib.reload(egress)
        egress.instrument_egress(ignore_hosts=set())
        egress.uninstrument_egress()
        print(len(added))
    """), encoding="utf-8")
    done = subprocess.run([sys.executable, str(script)], capture_output=True, text=True, timeout=60,
                          stdin=subprocess.DEVNULL, env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
    assert done.returncode == 0 and done.stdout.strip() == "1", done.stderr


def test_a_forked_child_goes_quiet(rec, web):
    """Called directly: this platform may have no fork, and the rule is what is checked."""
    with rec.run():
        config = egress_module._config
        assert egress_module._hook_armed
        egress_module._disarm_in_forked_child()
        try:
            assert not egress_module._hook_armed
            socket.create_connection(("127.0.0.1", web.server_port), timeout=5).close()  # through the patches
            sys.audit("socket.gethostbyname", "child.example")
        finally:
            egress_module._hook_armed, egress_module._config = True, config
    assert entries(rec) == [] and notes(rec, "network") == []


def test_a_process_that_exits_with_the_hook_armed_stays_silent(tmp_path):
    script = tmp_path / "child.py"
    script.write_text(textwrap.dedent("""
        import socket
        from mnestiq import MemorySink, Recorder
        from mnestiq.egress import instrument_egress
        from mnestiq.recorder import _current_run
        instrument_egress(ignore_hosts=set())
        rec = Recorder(MemorySink(), agent_id="a")
        with rec.run() as run:
            pass
        _current_run.set(run)  # still the current run when the interpreter comes down
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.sendto(b"x", ("127.0.0.1", 9))
    """), encoding="utf-8")
    done = subprocess.run([sys.executable, str(script)], capture_output=True, text=True, timeout=60,
                          stdin=subprocess.DEVNULL, env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
    assert done.returncode == 0 and done.stderr == ""


# Process spawns


def spawned(rec):
    return notes(rec, "process")


def test_a_spawn_is_one_note_with_the_program_and_its_arguments(rec):
    with rec.run() as run:
        subprocess.run([sys.executable, "-c", "pass"], check=True, timeout=30, stdin=subprocess.DEVNULL)
    [process] = spawned(rec)
    assert process["kind"] == "spawn" and process["via"] == "subprocess.Popen"
    assert os.path.basename(process["executable"]).lower().startswith("python")
    assert "-c" in " ".join(process["args"])
    [record] = [r for r in rec._sink.records if r.get("event_type") == "note"]
    assert record["run_id"] == run.run_id and record["attributes"]["message"].startswith("process started: python")
    assert_valid(rec)


def test_a_shell_and_os_system_are_recorded(rec):
    with rec.run():
        subprocess.run("exit 0", shell=True, check=True, timeout=30, stdin=subprocess.DEVNULL)
        assert os.system("exit 0") == 0
    assert [p["via"] for p in spawned(rec)] == ["subprocess.Popen", "os.system"]
    assert spawned(rec)[1]["args"] == ["exit 0"] and spawned(rec)[1]["executable"] == "exit"


def test_a_thread_of_the_run_is_attributed(rec):
    with rec.run() as run:
        worker = threading.Thread(target=lambda: sys.audit("os.system", "whoami"))
        worker.start()
        worker.join()
    [record] = [r for r in rec._sink.records if r.get("event_type") == "note"]
    assert record["run_id"] == run.run_id


@pytest.mark.parametrize("event, args, executable, shown", [
    ("os.exec", ("/bin/ls", ["ls", "-l"], {"SECRET": "s"}), "/bin/ls", ["ls", "-l"]),
    ("os.posix_spawn", (b"/bin/ls", [b"ls"], None), "/bin/ls", ["ls"]),
    ("os.spawn", (0, "/bin/ls", ("ls", "-a"), None), "/bin/ls", ["ls", "-a"]),
    ("os.startfile/2", ("doc.exe", "open", "--flag", None, 1), "doc.exe", ["--flag"]),
    ("pty.spawn", (["/bin/sh", "-i"],), "/bin/sh", ["/bin/sh", "-i"]),
])
def test_each_way_to_start_a_program_is_recorded(rec, event, args, executable, shown):
    with rec.run():
        sys.audit(event, *args)
    [process] = spawned(rec)
    assert (process["via"], process["executable"], process["args"]) == (event, executable, shown)
    assert "SECRET" not in json.dumps(process)


def test_a_fork_is_recorded(rec):
    with rec.run():
        sys.audit("os.fork")
    assert spawned(rec) == [{"kind": "fork", "via": "os.fork"}]


def test_the_environment_is_never_recorded(rec):
    with rec.run():
        sys.audit("subprocess.Popen", "x", ["x"], "/tmp", {"API": "hunter2value"})
    assert "hunter2value" not in json.dumps(spawned(rec))


def test_popen_is_not_recorded_again_by_the_call_it_makes(rec):
    with rec.run():
        argv = ["ls"]
        sys.audit("subprocess.Popen", "/bin/ls", argv, None, None)
        sys.audit("os.posix_spawn", "/bin/ls", argv, None)
    assert len(spawned(rec)) == 1


def test_a_direct_posix_spawn_after_a_popen_is_still_recorded(rec):
    with rec.run():
        sys.audit("subprocess.Popen", "/bin/ls", ["ls"], None, None)
        sys.audit("os.posix_spawn", "/bin/sh", ["sh"], None)
    assert [p["via"] for p in spawned(rec)] == ["subprocess.Popen", "os.posix_spawn"]


def test_a_direct_create_process_is_recorded_without_its_garbled_command_line(rec):
    with rec.run():
        sys.audit("_winapi.CreateProcess", "C:\\python.exe", "\x02", None)
    assert spawned(rec) == [{"kind": "spawn", "via": "_winapi.CreateProcess", "executable": "C:\\python.exe"}]


def test_a_spawn_outside_a_run_is_not_recorded(rec):
    subprocess.run([sys.executable, "-c", "pass"], check=True, timeout=30, stdin=subprocess.DEVNULL)
    assert spawned(rec) == []


def test_the_childs_environment_is_left_as_given(rec):
    code = "import os, json; print(json.dumps(sorted(k for k in os.environ if 'MNESTIQ' in k.upper())))"
    env = {k: v for k, v in os.environ.items() if "MNESTIQ" not in k.upper()}
    with rec.run():
        out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=30, env=env,
                             stdin=subprocess.DEVNULL, check=True).stdout
    assert json.loads(out) == []


@pytest.mark.parametrize("arg, secret", [
    ("--token=abc123secret", "abc123secret"),
    ("--api-key=abc123secret", "abc123secret"),
    ('--password="abc 123secret"', "123secret"),
    ("API_KEY=abc123secret", "abc123secret"),
    ("MY_DB_PASSWORD=abc123secret", "abc123secret"),
    ("https://svc:abc123secret@db.example/x", "abc123secret"),
    ("https://db.example/x?token=abc123secret&a=1", "abc123secret"),
    ("postgres://svc:abc123secret@db.example:5432/app", "abc123secret"),
    ("redis://:abc123secret@cache.example:6379", "abc123secret"),
    ("Authorization: Bearer abc123secret", "abc123secret"),
    ("X-Api-Key: abc123secret", "abc123secret"),
    ("Cookie: sid=abc123secret", "abc123secret"),
    ("Bearer abc123secret", "abc123secret"),
    ('{"password": "abc123secret", "user": "x"}', "abc123secret"),
    ('{\\"api_key\\": \\"abc123secret\\"}', "abc123secret"),
    ("sk-abcdefghijklmnop1234", "sk-abcdefghijklmnop1234"),
    ("ghp_abcdefghijklmnopqrstuvwxyz", "ghp_abcdefghijklmnopqrstuvwxyz"),
    ("AKIAABCDEFGHIJKLMNOP", "AKIAABCDEFGHIJKLMNOP"),
    ("a" * 48, "a" * 48),
])
def test_secrets_in_arguments_are_masked(rec, arg, secret):
    with rec.run():
        sys.audit("subprocess.Popen", "tool", ["tool", arg], None, None)
        sys.audit("subprocess.Popen", "tool", f"tool {arg}", None, None)
        sys.audit("os.system", f"tool {arg} --verbose")
    assert len(spawned(rec)) == 3 and secret not in json.dumps(spawned(rec))


@pytest.mark.parametrize("argv, hidden", [
    (["tool", "--token", "abc123secret"], "abc123secret"),
    (["tool", "--key", "abc123secret"], "abc123secret"),
    (["tool", "--verbose", "--password", "-abc123secret"], "abc123secret"),
    (["curl", "-u", "svc:abc123secret", "http://x.example"], "abc123secret"),
    (["curl", "--user", "svc:abc123secret"], "abc123secret"),
    (["mysql", "-uroot", "-pabc123secret"], "abc123secret"),
])
def test_a_secret_given_as_the_next_argument_is_masked(rec, argv, hidden):
    with rec.run():
        sys.audit("subprocess.Popen", argv[0], argv, None, None)
    assert hidden not in json.dumps(spawned(rec))


@pytest.mark.parametrize("command, hidden", [
    ("tool --verbose --token abc123secret", "abc123secret"),
    ("tool --mode fast --api-key abc123secret --x y", "abc123secret"),
    ("curl -u svc:abc123secret http://x.example", "abc123secret"),
    ("mysql -uroot -pabc123secret db", "abc123secret"),
    ("set TOKEN=abc123secret && run", "abc123secret"),
    ('curl -H "Authorization: Bearer abc123secret" http://x.example', "abc123secret"),
])
def test_a_secret_in_one_command_line_is_masked(rec, command, hidden):
    with rec.run():
        sys.audit("subprocess.Popen", None, command, None, None)
    assert hidden not in json.dumps(spawned(rec))


def test_ordinary_arguments_stay_readable(rec):
    argv = ["git", "-C", "/repo", "log", "--oneline", "-p", "-n", "3", "https://example.test/a@b", "-u", "origin"]
    with rec.run():
        sys.audit("subprocess.Popen", "git", argv, None, None)
    assert spawned(rec)[0]["args"] == argv


def test_arguments_and_their_number_are_limited(rec):
    with rec.run():
        sys.audit("subprocess.Popen", "tool", ["tool", "x y " * 5000, *[str(n) for n in range(200)]], None, None)
    [process] = spawned(rec)
    assert len(process["args"]) == 64 and process["args_omitted"] == 138
    assert len(process["args"][1].encode()) <= 1024 and process["args"][1].endswith("<truncated>")


def test_a_secret_cut_by_the_limit_is_still_masked(rec):
    arg = "x " * 500 + "https://svc:abc123secret" + "y" * 2000 + "@db.example/"
    with rec.run():
        sys.audit("subprocess.Popen", "tool", ["tool", arg], None, None)
    assert "abc123" not in json.dumps(spawned(rec))


def test_the_recorders_own_size_limit_is_respected():
    recorder = Recorder(MemorySink(), agent_id="agent", max_content_bytes=100)
    with recorder.run():
        sys.audit("subprocess.Popen", "tool", ["tool", *["a b " * 40] * 10], None, None)
    [process] = spawned(recorder)
    assert sum(len(a.encode()) for a in process["args"]) <= 100 and process["args_omitted"] >= 1
    recorder.close()


def test_a_path_and_bytes_argument_are_shown_as_text(rec, tmp_path):
    with rec.run():
        sys.audit("subprocess.Popen", tmp_path, [tmp_path / "x", b"y"], None, None)
    [process] = spawned(rec)
    assert process["executable"] == str(tmp_path) and process["args"] == [str(tmp_path / "x"), "y"]


# The real destination through a proxy


def proxies_for(web):
    return {"http": f"http://127.0.0.1:{web.server_port}", "https": f"http://127.0.0.1:{web.server_port}"}


def via_requests(web, url):
    requests = pytest.importorskip("requests")
    return requests.get(url, timeout=5, proxies=proxies_for(web))


def via_httpx(web, url):
    httpx = pytest.importorskip("httpx")
    with httpx.Client(proxy=f"http://127.0.0.1:{web.server_port}", trust_env=False) as client:
        return client.get(url)


def via_httpx2(web, url):
    httpx2 = pytest.importorskip("httpx2")
    with httpx2.Client(proxy=f"http://127.0.0.1:{web.server_port}", trust_env=False) as client:
        return client.get(url)


def via_urllib(web, url):
    handler = urllib.request.ProxyHandler(proxies_for(web))
    return urllib.request.build_opener(handler).open(url, timeout=5).read()


def via_urllib3(web, url):
    urllib3 = pytest.importorskip("urllib3")
    return urllib3.ProxyManager(f"http://127.0.0.1:{web.server_port}").request("GET", url, retries=False)


clients = pytest.mark.parametrize("send", [via_requests, via_httpx, via_httpx2, via_urllib, via_urllib3])


@clients
def test_an_ignored_name_through_a_proxy_does_not_hide_the_connection(rec, web, send):
    instrument_egress(ignore_hosts={"ignored.example"})
    with rec.run():
        send(web, "http://ignored.example/exfil")
    assert web.seen[0]["path"] == "http://ignored.example/exfil"
    [entry] = entries(rec)
    assert entry["host"] == "ignored.example" and entry["url"] == "http://ignored.example/exfil"
    assert entry["dest_ip"] == "127.0.0.1" and entry["dest_port"] == web.server_port
    assert (entry["source_ip"], entry["source_port"]) == tuple(web.seen[0]["client"])
    assert entry["run_id_header"] is False and RUN_HEADER not in web.seen[0]["headers"]


@clients
def test_an_ignored_proxy_does_not_hide_a_request_for_another_host(rec, web, send):
    instrument_egress(ignore_hosts={"127.0.0.1"})
    with rec.run():
        send(web, "http://target.example/p")
    [entry] = entries(rec)
    assert entry["host"] == "target.example" and entry["dest_port"] == web.server_port


@clients
def test_a_request_is_left_out_when_the_target_and_the_proxy_are_both_ignored(rec, web, send):
    instrument_egress(ignore_hosts={"ignored.example", "127.0.0.1"})
    with rec.run():
        send(web, "http://ignored.example/p")
    assert len(web.seen) == 1 and entries(rec) == []


@clients
def test_the_target_decides_the_stamp_and_the_proxy_does_not(rec, web, send):
    instrument_egress(ignore_hosts=set(), stamp_hosts={"named.example"})
    with rec.run():
        send(web, "http://named.example/a")
        send(web, "http://other.example/b")
    first, second = web.seen
    assert first["headers"][EGRESS_HEADER] == entries(rec)[0]["egress_id"] and EGRESS_HEADER not in second["headers"]
    assert [e["host"] for e in entries(rec)] == ["named.example", "other.example"]


@clients
def test_a_tunnel_is_recorded_under_its_target_with_the_proxys_address(rec, web, send):
    """The local proxy refuses CONNECT, so the request fails, and the event says where it was going."""
    failed = False
    with rec.run():
        try:
            send(web, "https://target.example/secret")
        except Exception:
            failed = True
    assert failed and web.seen[0]["path"] == "target.example:443"
    [entry] = entries(rec)
    assert entry["host"] == "target.example" and entry["dest_port"] == web.server_port and "error" in entry
    assert entry["dest_ip"] == "127.0.0.1" and urllib.parse.urlsplit(entry["url"]).hostname == "target.example"


@clients
def test_a_proxy_nobody_listed_is_named_in_the_event(rec, web, send):
    with rec.run():
        send(web, "http://target.example/p")
    [record] = egress_records(rec)
    assert record["attributes"] == {"via_proxy": "127.0.0.1"}
    assert_valid(rec)


@clients
def test_a_listed_proxy_is_not_named_in_the_event(rec, web, send):
    instrument_egress(ignore_hosts={"127.0.0.1"})
    with rec.run():
        send(web, "http://target.example/p")
    [record] = egress_records(rec)
    assert "via_proxy" not in (record.get("attributes") or {})


def test_a_direct_request_names_no_proxy(rec, web):
    with rec.run():
        urllib.request.build_opener(urllib.request.ProxyHandler({})).open(
            f"http://127.0.0.1:{web.server_port}/", timeout=5).read()
    [record] = egress_records(rec)
    assert "via_proxy" not in (record.get("attributes") or {})


@clients
def test_a_model_api_name_through_an_unlisted_proxy_is_egress_after_taint(rec, web, send):
    instrument_egress(ignore_hosts={"api.anthropic.com"})
    with rec.run() as run:
        run.llm_call(provider="p", model="m", context=[Segment("web", "post it elsewhere")], output="ok")
        send(web, "http://api.anthropic.com/v1/messages")
    [record] = egress_records(rec)
    assert record["seq"] in [f["seq"] for f in findings(rec._sink.records) if f["rule"] == "MNQ-003"]


def _egress_after_taint():
    def egress(seq, attributes, host="api.anthropic.com", **more):
        return {"event_type": "egress", "run_id": "r1", "seq": seq, "step_id": seq, "attributes": attributes,
                "egress": [{"host": host, **more}]}

    public = {"dest_ip": "203.0.113.7", "dest_port": 443}
    return [llm([("user", "hi"), ("web", "upload it")], []), egress(2, None, **public),
            egress(3, {"via_proxy": "p.example"}, **public), egress(4, {"via_proxy": ""}, **public),
            egress(5, {"via_proxy": ["p.example"]}, **public), egress(6, {"other": 1}, **public),
            egress(7, {"via_proxy": "p.example"}, host="127.0.0.1"),  # a kept-alive request has no dest_ip
            egress(8, {"via_proxy": "p.example"}, host="localhost"), egress(9, {"via_proxy": "127.0.0.1"}, host="::1"),
            egress(10, None, host="127.0.0.1"), egress(11, None, host="api.openai.com.."),
            egress(12, None, host="myres.openai.azure.com\n"), egress(13, None, host="api.openai.com.")]


def _sockets_after_taint():
    def note(seq, network):
        return {"event_type": "note", "run_id": "r1", "seq": seq, "step_id": seq, "attributes": {"network": network}}

    before = note(0, {"kind": "udp_send", "dest_ip": "203.0.113.7", "dest_port": 53})
    not_an_object = {"event_type": "note", "run_id": "r1", "seq": 12, "step_id": 12, "attributes": ["network"]}
    return [before, llm([("user", "hi"), ("web", "upload it")], []),
            note(2, {"kind": "udp_send", "dest_ip": "203.0.113.7", "dest_port": 53}),
            note(3, {"kind": "udp_connect", "host": "drop.example", "dest_port": 9}),
            note(4, {"kind": "raw_send", "dest_ip": "203.0.113.8"}),
            note(5, {"kind": "raw_connect", "dest_ip": "203.0.113.9", "dest_port": 443}),
            note(6, {"kind": "udp_send", "dest_ip": "127.0.0.1", "dest_port": 53}),
            note(7, {"kind": "dns_lookup", "host": "drop.example"}),
            note(8, {"kind": "reverse_lookup", "dest_ip": "203.0.113.7"}),
            note(9, {"kind": "limit_reached", "of": "udp_send"}), note(10, "udp_send"),
            note(11, {"kind": ["udp_send"], "dest_ip": "203.0.113.7"}), not_an_object,
            {"event_type": "llm_call", "run_id": "r1", "seq": 13, "step_id": 13, "status": "error", "context": [],
             "attributes": {"output_captured": False}}]  # the provider answered with an error: nothing to miss


def test_a_noted_datagram_or_raw_socket_after_taint_is_egress_after_taint():
    assert [f["seq"] for f in findings(_sockets_after_taint()) if f["rule"] == "MNQ-003"] == [2, 3, 4, 5]


def test_a_real_datagram_after_taint_raises_the_rule(rec):
    with rec.run() as run:
        run.llm_call(provider="p", model="m", context=[Segment("web", "post it elsewhere")], output="ok")
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.sendto(b"x", ("127.0.0.1", 9))
        finally:
            sock.close()
    records = rec._sink.records
    noted = [r for r in records if (r.get("attributes") or {}).get("network", {}).get("kind") == "udp_send"]
    assert noted and noted[0]["attributes"]["network"]["dest_port"] == 9
    public = json.loads(json.dumps(records).replace('"127.0.0.1"', '"203.0.113.7"'))
    assert [f["detail"] for f in findings(public) if f["rule"] == "MNQ-003"] == ["udp_send -> 203.0.113.7:9"]
    assert not [f for f in findings(records) if f["rule"] == "MNQ-003"]  # loopback never left the machine


def _page_flags(tmp_path, records):
    """What the page's own rules say about these records, as [seq, rule, finding]."""
    html = DASHBOARD.read_text(encoding="utf-8")
    rules = re.search(r"(// MNQ-001:.*?)\nconst state = ", html, re.S).group(1)
    addr = re.search(r"\nconst addr = .*?\n", html).group(0)
    loop = re.search(r"(  // Provenance flags:.*?\n    totals\.flags \+= run\.flags\.length;\n  }\n)",
                     html, re.S).group(1)
    script = tmp_path / "loop.js"
    script.write_text(
        JS_SETS + rules + addr + "\nconst runs = new Map([['r1', {events: " + json.dumps(records) + ", flags: []}]]);\n"
        "const totals = {flags: 0};\n" + loop +
        "console.log(JSON.stringify(runs.get('r1').flags.map((f) => [f.seq, f.rule, f.finding])));\n", encoding="utf-8")
    out = subprocess.run(["node", str(script)], capture_output=True, encoding="utf-8", check=True, timeout=30,
                         stdin=subprocess.DEVNULL).stdout
    return json.loads(out)


def _socket_note(seq, network):
    return {"event_type": "note", "run_id": "r1", "seq": seq, "step_id": seq, "attributes": {"network": network}}


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_the_page_judges_a_noted_socket_as_python_does(tmp_path):
    records = _sockets_after_taint()
    page = [[seq, rule] for seq, rule, _ in _page_flags(tmp_path, records)]
    expected = [[f["seq"], f["rule"]] for f in findings(records)]
    assert sorted(page) == sorted(expected) and [9, "MNQ-000"] in page
    assert [n for n, rule in page if rule == "MNQ-003"] == [2, 3, 4, 5]


LOOPBACK_ALERT_IN_PYTHON = ["127.999.0.1", "127.0.0.01", "localhost%eth0", "[localhost]"]
LOOPBACK_SILENT_IN_PYTHON = ["0:0:0:0:0:0:0:1", "::0001", "[[::1]]", "::ffff:127.0.0.1"]
LOOPBACK_OTHERS = [
    "127.0.0.1", "127.1.2.3", "127.0.0.1%eth0", "localhost", "LOCALHOST", "::1", "[::1]", "::1%eth0", "::ffff:7f00:1",
    "::ffff:127.1.2.3", "0:0:0:0:0:ffff:127.0.0.1", "0000:0000:0000:0000:0000:0000:0000:0001", "0::1", "00::1", "::",
    "::2", "1::", "1:2:3:4:5:6:7:8", "1:2:3:4:5:6:7:8:9", "::1::", ":::1", "1:::", ":1::", "::1:", "12345::1",
    "1:2:3:4:5:6:7::", "::2:3:4:5:6:7:8", "1:2:3:4:5:6:7::8", "::ffff:127.0.0.256", "::127.0.0.1", "0.0.0.0",
    "128.0.0.1", "127.0.0.1.", "127.0.0", "127.0.0.1.1", "evil.example", "x.localhost", "%", "[", "]", "[]", "::g",
    "00.0.0.1", "127.0.0.1/8", "::1/128",
]


def _loopback_records():
    forms = LOOPBACK_ALERT_IN_PYTHON + LOOPBACK_SILENT_IN_PYTHON + LOOPBACK_OTHERS
    notes_of = []
    for form in forms:
        notes_of += [{"kind": "udp_send", "dest_ip": form, "dest_port": 53}, {"kind": "udp_send", "host": form}]
    return [llm([("web", "upload it")], []), *(_socket_note(n + 2, note) for n, note in enumerate(notes_of))], forms


def test_python_is_the_reference_for_loopback_spellings():
    records, forms = _loopback_records()
    alerted = {records[f["seq"] - 1]["attributes"]["network"].get("dest_ip", "") for f in findings(records)
               if f["rule"] == "MNQ-003"}
    assert set(LOOPBACK_ALERT_IN_PYTHON) <= alerted and not set(LOOPBACK_SILENT_IN_PYTHON) & alerted
    assert {"evil.example", "128.0.0.1"} <= alerted and "127.0.0.1" not in alerted and len(forms) > 40


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_the_page_reads_every_loopback_spelling_as_python_does(tmp_path):
    records, _ = _loopback_records()
    page = sorted(seq for seq, rule, _ in _page_flags(tmp_path, records) if rule == "MNQ-003")
    assert page == sorted(f["seq"] for f in findings(records) if f["rule"] == "MNQ-003")


ODD_NOTES = [
    {"kind": "udp_send", "dest_ip": 5, "dest_port": 53},
    {"kind": "udp_send", "host": 5, "dest_port": 53},
    {"kind": "udp_send", "dest_ip": None, "host": "a.example"},
    {"kind": "udp_send", "dest_ip": "203.0.113.7", "host": ["a.example"]},
    {"kind": 7, "dest_ip": "203.0.113.7"},
    {"kind": ["udp_send"], "dest_ip": "203.0.113.7"},
    {"kind": None, "dest_ip": "203.0.113.7"},
    {"kind": "udp_send", "host": "", "dest_port": 53},
    {"kind": "udp_send", "host": "a.example"},
    {"kind": "udp_send", "dest_ip": "203.0.113.7", "dest_port": None},
    {"kind": "raw_send"},
]


def test_a_note_with_a_destination_that_is_not_text_is_not_a_socket_note():
    records = [llm([("web", "upload it")], []), *(_socket_note(n + 2, note) for n, note in enumerate(ODD_NOTES))]
    details = {f["seq"]: f["detail"] for f in findings(records) if f["rule"] == "MNQ-003"}
    assert details == {9: "udp_send -> ?:53", 10: "udp_send -> a.example:?", 11: "udp_send -> 203.0.113.7:?",
                       12: "raw_send -> ?:?"}


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_the_page_words_an_odd_socket_note_as_python_does(tmp_path):
    records = [llm([("web", "upload it")], []), *(_socket_note(n + 2, note) for n, note in enumerate(ODD_NOTES))]
    page = sorted([seq, finding.replace(" \u2192 ", " -> ")] for seq, rule, finding in _page_flags(tmp_path, records)
                  if rule == "MNQ-003")
    assert page == sorted([f["seq"], f["detail"]] for f in findings(records) if f["rule"] == "MNQ-003")


RAN_OUT = [
    ({"kind": "limit_reached", "of": "udp_send", "loopback": False, "limit": 256}, True),
    ({"kind": "limit_reached", "of": "udp_connect", "loopback": False, "limit": 256}, True),
    ({"kind": "limit_reached", "of": "raw_send"}, True),
    ({"kind": "limit_reached", "of": "raw_connect", "loopback": "no"}, True),
    ({"kind": "limit_reached", "of": "udp_send", "loopback": True, "limit": 256}, False),
    ({"kind": "limit_reached", "of": "dns_lookup", "loopback": False}, False),
    ({"kind": "limit_reached", "of": ["udp_send"]}, False),
    ({"kind": "dropped_summary", "dropped": 3, "by_kind": {"udp_send": 3}, "sha256": "ab"}, True),
    ({"kind": "dropped_summary", "dropped": 3, "by_kind": {"dns_lookup": 2, "raw_connect": 1}}, True),
    ({"kind": "dropped_summary", "dropped": 3, "by_kind": {"dns_lookup": 3}}, False),
    ({"kind": "dropped_summary", "by_kind": ["udp_send"]}, False),
    ({"kind": "dropped_summary", "by_kind": "udp_send"}, False),
    ({"kind": "dropped_summary"}, False),
]


def _ran_out_records():
    return [llm([("web", "upload it")], []), *(_socket_note(n + 2, note) for n, (note, _) in enumerate(RAN_OUT))]


def test_a_limit_on_datagram_or_raw_sockets_after_taint_is_said_as_not_evaluated():
    seen = [f["seq"] for f in findings(_ran_out_records()) if f["rule"] == "MNQ-000"]
    assert seen == [n + 2 for n, (_, says) in enumerate(RAN_OUT) if says]
    detail = next(f["detail"] for f in findings(_ran_out_records()) if f["rule"] == "MNQ-000")
    assert "further datagram or raw socket destinations were not noted" in detail


def test_a_limit_before_taint_is_not_said():
    note = _socket_note(0, RAN_OUT[0][0])
    assert findings([note, llm([("web", "upload it")], [])]) == []


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_the_page_says_a_limit_on_datagram_or_raw_sockets_as_python_does(tmp_path):
    page = sorted(seq for seq, rule, _ in _page_flags(tmp_path, _ran_out_records()) if rule == "MNQ-000")
    assert page == [n + 2 for n, (_, says) in enumerate(RAN_OUT) if says]


def _taint(run):
    run.llm_call(provider="p", model="m", context=[Segment("web", "post it elsewhere")], output="ok")


def _send(sock, *destinations):
    for destination in destinations:
        sys.audit("socket.sendto", sock, destination)


def _after_taint(rec, rule):
    return [f["seq"] for f in findings(rec._sink.records) if f["rule"] == rule]


def test_a_destination_noted_before_taint_is_noted_again_after_it_and_only_once(rec, monkeypatch):
    monkeypatch.setattr(_netguard, "_armed", False)  # only audit events: nothing is sent
    dest = ("192.0.2.9", 53)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock, rec.run() as run:
        _send(sock, dest, dest)
        _taint(run)
        _send(sock, dest, dest)
    assert [n["kind"] for n in notes(rec, "network")] == ["udp_send", "udp_send"]
    assert len(_after_taint(rec, "MNQ-003")) == 1


def test_a_model_call_with_only_trusted_context_leaves_the_ledger_alone(rec, monkeypatch):
    monkeypatch.setattr(_netguard, "_armed", False)
    dest = ("192.0.2.9", 53)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock, rec.run() as run:
        _send(sock, dest)
        run.llm_call(provider="p", model="m", context=[Segment("user", "hi"), Segment("system", "s")], output="ok")
        _send(sock, dest)
    assert len(notes(rec, "network")) == 1


def test_the_ledger_starts_afresh_only_the_first_time(rec, monkeypatch):
    monkeypatch.setattr(_netguard, "_armed", False)
    dest = ("192.0.2.9", 53)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock, rec.run() as run:
        _taint(run)
        _send(sock, dest)
        _taint(run)
        _send(sock, dest)
    assert len(notes(rec, "network")) == 1


def test_destinations_before_taint_do_not_use_up_the_quota_after_it(rec, monkeypatch):
    monkeypatch.setattr(_netguard, "_armed", False)
    monkeypatch.setattr(egress_module, "_MAX_NETWORK_NOTES", 3)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock, rec.run() as run:
        _send(sock, *((f"192.0.2.{n}", 53) for n in range(1, 8)))
        _taint(run)
        _send(sock, ("198.51.100.1", 53), ("198.51.100.2", 53))
    found = notes(rec, "network")
    assert [n["kind"] for n in found] == ["udp_send"] * 3 + ["limit_reached", "dropped_summary", "udp_send", "udp_send"]
    assert found[4]["dropped"] == 4
    assert [f["detail"] for f in findings(rec._sink.records) if f["rule"] == "MNQ-003"] == [
        "udp_send -> 198.51.100.1:53", "udp_send -> 198.51.100.2:53"]
    assert _after_taint(rec, "MNQ-000") == []  # the summary of what was cut before taint comes before the call
    assert_valid(rec)


def test_destinations_past_the_quota_after_taint_are_said_as_not_evaluated(rec, monkeypatch):
    monkeypatch.setattr(_netguard, "_armed", False)
    monkeypatch.setattr(egress_module, "_MAX_NETWORK_NOTES", 2)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock, rec.run() as run:
        _taint(run)
        _send(sock, *((f"198.51.100.{n}", 53) for n in range(1, 6)))
    found = {n["kind"]: n for n in notes(rec, "network")}
    assert found["dropped_summary"]["dropped"] == 3
    details = [f["detail"] for f in findings(rec._sink.records) if f["rule"] == "MNQ-000"]
    assert len(details) == 2 and all("further datagram or raw socket destinations" in d for d in details)


def test_only_an_unlisted_proxy_takes_a_model_api_name_out_of_the_exclusion():
    assert [f["seq"] for f in findings(_egress_after_taint()) if f["rule"] == "MNQ-003"] == [3, 7, 8, 11, 12]


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_the_page_judges_a_proxied_model_api_name_as_python_does(tmp_path):
    html = DASHBOARD.read_text(encoding="utf-8")
    rules = re.search(r"(// MNQ-001:.*?)\nconst state = ", html, re.S).group(1)
    addr = re.search(r"\nconst addr = .*?\n", html).group(0)
    loop = re.search(r"(  // Provenance flags:.*?\n    totals\.flags \+= run\.flags\.length;\n  }\n)",
                     html, re.S).group(1)
    records = _egress_after_taint()
    script = tmp_path / "loop.js"
    script.write_text(
        JS_SETS + rules + addr + "\nconst runs = new Map([['r1', {events: " + json.dumps(records) + ", flags: []}]]);\n"
        "const totals = {flags: 0};\n" + loop +
        "console.log(JSON.stringify(runs.get('r1').flags.map((f) => [f.seq, f.rule])));\n", encoding="utf-8")
    out = subprocess.run(["node", str(script)], capture_output=True, text=True, check=True, timeout=30,
                         stdin=subprocess.DEVNULL).stdout
    expected = [[f["seq"], f["rule"]] for f in findings(records)]
    assert sorted(json.loads(out)) == sorted(expected) and [3, "MNQ-003"] in expected


def test_async_httpx_reads_its_proxy_the_same_way(rec, web):
    httpx = pytest.importorskip("httpx")
    instrument_egress(ignore_hosts={"ignored.example"})

    async def main():
        async with httpx.AsyncClient(proxy=f"http://127.0.0.1:{web.server_port}", trust_env=False) as client:
            await client.get("http://ignored.example/exfil")

    with rec.run():
        asyncio.run(main())
    [entry] = entries(rec)
    assert entry["host"] == "ignored.example" and entry["dest_port"] == web.server_port


def test_requests_given_the_proxies_positionally_are_read(rec, web):
    requests = pytest.importorskip("requests")
    from requests.adapters import HTTPAdapter

    instrument_egress(ignore_hosts={"ignored.example"})
    prepared = requests.Request("GET", "http://ignored.example/p").prepare()
    with rec.run():
        HTTPAdapter().send(prepared, False, 5, True, None, proxies_for(web))
    assert [e["dest_port"] for e in entries(rec)] == [web.server_port]


def test_an_empty_proxy_setting_is_a_direct_request(rec, web):
    requests = pytest.importorskip("requests")
    instrument_egress(ignore_hosts={"127.0.0.1"})
    with rec.run():
        requests.get(f"http://127.0.0.1:{web.server_port}/", timeout=5, proxies={"http": "", "https": ""})
    assert entries(rec) == []


def test_a_custom_httpx_transport_is_not_taken_for_direct(rec):
    httpx = pytest.importorskip("httpx")
    instrument_egress(ignore_hosts={"ignored.example"})
    transport = httpx.MockTransport(lambda request: httpx.Response(200))
    with rec.run(), httpx.Client(transport=transport) as client:
        assert client.get("http://ignored.example/").status_code == 200
    [record] = egress_records(rec)
    assert record["attributes"] == {"route_unverified": True} and record["egress"][0]["host"] == "ignored.example"


def test_an_ignored_proxy_does_not_hide_a_urllib_request_for_another_host(rec, web):
    instrument_egress(ignore_hosts={"127.0.0.1"})
    req = urllib.request.Request("http://target.example/p")
    req.set_proxy(f"127.0.0.1:{web.server_port}", "http")
    with rec.run():
        urllib.request.build_opener(urllib.request.ProxyHandler({})).open(req, timeout=5).read()
    [entry] = entries(rec)
    assert entry["url"] == "http://target.example/p" and entry["dest_port"] == web.server_port


def test_an_ignored_proxy_does_not_hide_a_urllib3_request_for_another_host(rec, web):
    urllib3 = pytest.importorskip("urllib3")
    instrument_egress(ignore_hosts={"127.0.0.1"})
    with rec.run():
        urllib3.ProxyManager(f"http://127.0.0.1:{web.server_port}").request("GET", "http://target.example/p")
    [entry] = entries(rec)
    assert entry["url"] == "http://target.example/p" and entry["dest_port"] == web.server_port


def test_a_host_named_ignored_is_never_stamped_even_when_recorded(rec, web):
    instrument_egress(ignore_hosts={"ignored.example"}, stamp_hosts={"127.0.0.1", "ignored.example"})
    req = urllib.request.Request("http://ignored.example/p")
    req.set_proxy(f"127.0.0.1:{web.server_port}", "http")
    with rec.run():
        urllib.request.build_opener(urllib.request.ProxyHandler({})).open(req, timeout=5).read()
    assert RUN_HEADER not in web.seen[0]["headers"] and entries(rec)[0]["run_id_header"] is False


# The test suite's own network guard


@pytest.mark.parametrize("lookup", [socket.gethostbyname, socket.gethostbyname_ex])
def test_the_guard_blocks_every_name_lookup(lookup):
    with pytest.raises(ExternalNetworkBlocked):
        lookup("example.com")
    assert lookup("localhost")


def test_the_guard_blocks_external_datagrams_and_passes_loopback(udp_sink):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        with pytest.raises(ExternalNetworkBlocked):
            sock.sendto(b"x", ("192.0.2.1", 9))
        with pytest.raises(ExternalNetworkBlocked):
            sock.sendto(b"x", 0, ("example.com", 9))
        assert sock.sendto(b"x", udp_sink) == 1


# Cost


def test_the_hook_is_cheap_on_every_path_a_program_takes_most():
    """A coarse bound, far above the real cost, to catch real work creeping into the fast path."""
    def per_call(event, args):
        started = time.perf_counter()
        for _ in range(20_000):
            _audit_hook(event, args)
        return (time.perf_counter() - started) / 20_000

    assert per_call("open", ("x", "r", 0)) < 20e-6
    uninstrument_egress()
    assert per_call("socket.connect", (object(), ("127.0.0.1", 1))) < 20e-6


# A finalizer that runs in the middle of a write


def test_a_finalizer_inside_a_write_does_not_break_the_chain(rec, udp_sink):
    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    class Cycle:
        count = 0

        def __del__(self):
            Cycle.count += 1
            sender.sendto(b"", ("127.0.0.1", 20000 + Cycle.count % 200))

    def garbage():
        one = Cycle()
        one.me = one

    threshold = gc.get_threshold()
    gc.set_threshold(23, 1, 1)
    try:
        with rec.run() as run:
            for _ in range(400):
                for _ in range(7):
                    garbage()
                run.note("x", payload="y" * 50)
    finally:
        gc.set_threshold(*threshold)
        gc.collect()
    sender.close()
    seqs = [r["seq"] for r in rec._sink.records]
    assert seqs == list(range(len(seqs))) and Cycle.count > 0
    assert_valid(rec)


@pytest.mark.parametrize("act", ["hook", "patch", "agent"])
def test_every_way_to_write_waits_for_the_write_under_way(web, monkeypatch, act):
    """A write that arrives while this thread is writing goes in after it, at the same place every time."""
    recorder = Recorder(MemorySink(), agent_id="agent")
    original = Recorder._hash_and_cap
    state = {"run": None, "done": False}

    def in_the_middle(self, record):
        if state["run"] is not None and not state["done"] and record.get("event_type") == "note":
            state["done"] = True
            if act == "hook":
                sys.audit("socket.gethostbyname", "nested.example")
            elif act == "patch":
                socket.create_connection(("127.0.0.1", web.server_port), timeout=5).close()
            else:
                state["run"].note("from a finalizer")
        return original(self, record)

    monkeypatch.setattr(Recorder, "_hash_and_cap", in_the_middle)
    with recorder.run() as run:
        state["run"] = run
        run.note("outer")
    monkeypatch.undo()
    records = recorder._sink.records
    assert [r["seq"] for r in records] == list(range(len(records)))
    kinds = [r["event_type"] for r in records if r["kind"] == "event"]
    assert kinds[1] == "note" and len(kinds) == 4 and kinds[-1] == "run_end"
    assert_valid(recorder)
    recorder.close()


def test_what_is_left_waiting_is_written_when_the_recorder_closes():
    recorder = Recorder(MemorySink(), agent_id="agent")
    with recorder.run() as run:
        recorder._lock.acquire()
        recorder._writing += 1  # as a finalizer finds a thread part way through a write
        try:
            run.note("waits")
        finally:
            recorder._writing -= 1
            recorder._lock.release()
        assert notes(recorder, "message") == []
    assert notes(recorder, "message") == ["waits"]
    recorder.close()


# What runs during a request


@pytest.fixture
def listener():
    server = socket.create_server(("127.0.0.1", 0))

    def accept():
        while True:
            try:
                server.accept()[0].close()
            except OSError:
                return

    threading.Thread(target=accept, daemon=True).start()
    yield server.getsockname()
    server.close()


def _post_requests(url, body):
    requests = pytest.importorskip("requests")
    requests.post(url, data=body, timeout=5, proxies={"http": "", "https": ""})


def _post_httpx(url, body):
    httpx = pytest.importorskip("httpx")
    with httpx.Client(trust_env=False) as client:
        client.post(url, content=body)


def _post_urllib(url, body):
    request = urllib.request.Request(url, data=body, headers={"Content-Length": "1"})
    urllib.request.build_opener(urllib.request.ProxyHandler({})).open(request, timeout=5).read()


posting = pytest.mark.parametrize("post", [_post_requests, _post_httpx, _post_urllib])


def _meddling_body(address):
    socket.create_connection(address, timeout=5).close()
    sys.audit("os.system", "hidden-spawn")
    sys.audit("socket.gethostbyname", "looked-up.example")
    yield b"x"


@posting
def test_what_a_body_generator_does_is_not_hidden_by_an_ignored_request(rec, web, listener, post):
    instrument_egress(ignore_hosts={"localhost"})
    with rec.run():
        post(f"http://localhost:{web.server_port}/", _meddling_body(listener))
    assert [e["dest_port"] for e in entries(rec)] == [listener[1]] and entries(rec)[0]["protocol"] == "tcp"
    assert [p["args"] for p in notes(rec, "process")] == [["hidden-spawn"]]
    assert [n["host"] for n in notes(rec, "network")] == ["looked-up.example"]


@posting
def test_what_a_body_generator_does_does_not_join_the_request(rec, web, listener, post):
    with rec.run():
        post(f"http://localhost:{web.server_port}/", _meddling_body(listener))
    by_protocol = {e["protocol"]: e for e in entries(rec)}
    assert len(entries(rec)) == 2 and by_protocol["tcp"]["dest_port"] == listener[1]
    assert by_protocol["http"]["dest_port"] == web.server_port
    assert (by_protocol["http"]["source_ip"], by_protocol["http"]["source_port"]) == tuple(web.seen[0]["client"])
    assert notes(rec, "process")


def test_a_second_connection_by_the_library_in_one_request_is_its_own_event(rec, web, listener):
    """Even called through http.client, a request has one connection."""
    urllib3 = pytest.importorskip("urllib3")

    def body():
        http.client.HTTPConnection(*listener, timeout=5).connect()
        yield b"x"

    with rec.run():
        urllib3.PoolManager().request("POST", f"http://127.0.0.1:{web.server_port}/", body=body())
    assert sorted(e["dest_port"] for e in entries(rec)) == sorted([web.server_port, listener[1]])


# A route that cannot be proven direct


class _Wrapper:
    def __init__(self, inner):
        self.inner = inner

    def handle_request(self, request):
        return self.inner.handle_request(request)

    def close(self):
        self.inner.close()


def test_an_httpx_wrapper_around_a_proxy_is_recorded(rec, web):
    httpx = pytest.importorskip("httpx")
    instrument_egress(ignore_hosts={"ignored.example"})

    class Wrapper(_Wrapper, httpx.BaseTransport):
        pass

    transport = Wrapper(httpx.HTTPTransport(proxy=f"http://127.0.0.1:{web.server_port}"))
    with rec.run(), httpx.Client(transport=transport, trust_env=False) as client:
        client.get("http://ignored.example/steal")
    [record] = egress_records(rec)
    assert record["attributes"] == {"route_unverified": True} and record["egress"][0]["dest_port"] == web.server_port


def test_a_requests_adapter_that_forces_a_proxy_is_recorded(rec, web):
    requests = pytest.importorskip("requests")
    from requests.adapters import HTTPAdapter

    proxy = {"http": f"http://127.0.0.1:{web.server_port}"}

    class Forced(HTTPAdapter):
        def get_connection_with_tls_context(self, request, verify, proxies=None, cert=None):
            return super().get_connection_with_tls_context(request, verify, proxies=proxy, cert=cert)

    instrument_egress(ignore_hosts={"ignored.example"})
    session = requests.Session()
    session.trust_env = False
    session.mount("http://", Forced())
    with rec.run():
        session.get("http://ignored.example/steal", timeout=5)
    assert len(web.seen) == 1  # it went to the proxy, and not to the name in the URL
    [record] = egress_records(rec)
    assert record["attributes"] == {"route_unverified": True} and record["egress"][0]["dest_port"] == web.server_port


def test_a_requests_adapter_that_only_retries_is_still_proven_direct(rec, web):
    requests = pytest.importorskip("requests")
    from requests.adapters import HTTPAdapter

    class Retrying(HTTPAdapter):
        def __init__(self):
            super().__init__(max_retries=2)

    instrument_egress(ignore_hosts={"127.0.0.1"})
    session = requests.Session()
    session.trust_env = False
    session.mount("http://", Retrying())
    with rec.run():
        session.get(f"http://127.0.0.1:{web.server_port}/", timeout=5)
    assert entries(rec) == []


def test_a_urllib3_ipv6_proxy_in_ignore_hosts_is_matched(rec):
    urllib3 = pytest.importorskip("urllib3")
    instrument_egress(ignore_hosts={"ignored.example", "::1"})
    with rec.run(), pytest.raises(urllib3.exceptions.HTTPError):
        urllib3.ProxyManager("http://[::1]:1").request("GET", "http://ignored.example/", retries=False, timeout=1)
    assert entries(rec) == []


# A run left behind by the code that made the call


def _raw_in_empty_context(address):
    contextvars.Context().run(raw_connect, address)


def _raw_in_bare_thread(address):
    done = threading.Event()

    def work():
        raw_connect(address)
        done.set()

    _thread.start_new_thread(work, ())
    assert done.wait(5)


@pytest.mark.parametrize("escape", [_raw_in_empty_context, _raw_in_bare_thread])
def test_code_that_left_the_context_is_inferred_to_the_only_open_run(rec, listener, escape):
    with rec.run() as run:
        escape(listener)
    [record] = egress_records(rec)
    assert record["run_id"] == run.run_id and record["attributes"]["run_inferred"] is True
    assert_valid(rec)


def test_an_inferred_write_never_waits_on_a_thread_that_waits_for_it(listener):
    """A worker with no run, that the sink waits for while it holds the chain's lock."""
    finished = []

    class Waiting(MemorySink):
        def append(self, record):
            super().append(record)
            if record.get("event_type") == "note":
                _thread.start_new_thread(lambda: (contextvars.Context().run(raw_connect, listener),
                                                  finished.append(1)), ())
                deadline = time.monotonic() + 4
                while not finished and time.monotonic() < deadline:
                    time.sleep(0.01)

    recorder = Recorder(Waiting(), agent_id="agent")
    with recorder.run() as run:
        run.note("written while a thread is waited for")
    assert finished == [1]
    assert_valid(recorder)
    recorder.close()


def test_notes_are_marked_as_inferred_too(rec):
    with rec.run():
        contextvars.Context().run(sys.audit, "os.system", "whoami")
    [record] = [r for r in rec._sink.records if r.get("event_type") == "note"]
    assert record["attributes"]["run_inferred"] is True


def test_nothing_is_inferred_when_two_runs_are_open(rec, listener):
    with rec.run(), rec.run():
        _raw_in_empty_context(listener)
    assert entries(rec) == []


def test_nothing_is_inferred_after_the_run_ended(rec, listener):
    with rec.run():
        pass
    _raw_in_empty_context(listener)
    assert entries(rec) == []


def test_a_run_in_context_is_not_marked_inferred(rec, listener):
    with rec.run():
        raw_connect(listener)
    assert "run_inferred" not in egress_records(rec)[0]["attributes"]


# Spawns


def test_a_decoy_popen_does_not_hide_the_real_create_process(rec):
    with rec.run():
        sys.audit("subprocess.Popen", "harmless.exe", ["harmless.exe"], None, None)
        sys.audit("_winapi.CreateProcess", "C:\\real.exe", "\x02", None)
    assert [p["via"] for p in notes(rec, "process")] == ["subprocess.Popen", "_winapi.CreateProcess"]


def test_create_process_for_the_same_program_is_popens_own(rec):
    with rec.run():
        sys.audit("subprocess.Popen", "C:\\real.exe", "real", None, None)
        sys.audit("_winapi.CreateProcess", "C:\\real.exe", "\x02", None)
    assert len(notes(rec, "process")) == 1


@pytest.mark.skipif(sys.platform != "win32", reason="CreateProcess is Windows only")
def test_create_process_with_no_application_name_still_names_the_program(rec):
    import _winapi

    command = f'"{sys.executable}" -c "pass" --token=abc123secret'
    with rec.run():
        handle = _winapi.CreateProcess(None, command, None, None, False, 0, None, None, None)
        _winapi.WaitForSingleObject(handle[0], 30000)
        _winapi.CloseHandle(handle[0])
        _winapi.CloseHandle(handle[1])
    [process] = notes(rec, "process")
    assert process["executable"] == sys.executable and "abc123secret" not in json.dumps(process)


class _RaisingPath(PureWindowsPath):
    _str = property(lambda self: 1 / 0)


class _Spoofed:
    @property
    def __class__(self):
        return str


class _RaisingMeta(type):
    def __getattribute__(cls, name):
        if name == "__name__":
            raise ZeroDivisionError
        return super().__getattribute__(name)


class _MetaRaiser(metaclass=_RaisingMeta):
    pass


class _ListKind(list):
    def __iter__(self):
        raise RuntimeError("agent's iterator must not run")


@pytest.mark.parametrize("odd", [_RaisingPath("a"), _Spoofed(), _MetaRaiser()], ids=["path", "spoofed", "metaclass"])
def test_an_odd_argument_costs_only_its_own_place(rec, odd):
    with rec.run():
        sys.audit("os.spawn", 0, "tool", ["tool", odd, "--after"], None)
    [process] = notes(rec, "process")
    assert process["args"][0] == "tool" and process["args"][2] == "--after" and process["args"][1].startswith("<")
    assert rec.failures == 0


def test_a_list_subclass_is_read_without_running_its_code(rec):
    with rec.run():
        sys.audit("os.spawn", 0, "tool", _ListKind(["tool", "--flag"]), None)
    assert notes(rec, "process")[0]["args"] == ["tool", "--flag"]


# The bottom of the stack


# Before 3.12 calls into C count against the limit, so the test guard's own hook runs out of frames first.
needs_c_calls_apart = pytest.mark.skipif(sys.version_info < (3, 12), reason="the test guard needs the frames")


def _with_free_frames(free, call):
    depth, frame = 0, sys._getframe()
    while frame:
        depth, frame = depth + 1, frame.f_back
    limit = sys.getrecursionlimit()
    sys.setrecursionlimit(depth + free + 1)
    try:
        call()
    finally:
        sys.setrecursionlimit(limit)


def test_a_call_near_the_recursion_limit_goes_on_and_is_recorded_later(tmp_path, listener):
    """In a process of its own: the test guard's hook would use up the very frames this is about."""
    script = tmp_path / "child.py"
    script.write_text(textwrap.dedent(f"""
        import _socket, json, socket, sys
        from mnestiq import MemorySink, Recorder
        from mnestiq.egress import instrument_egress
        instrument_egress(ignore_hosts=set())
        def at(free, call):
            depth, frame = 0, sys._getframe()
            while frame:
                depth, frame = depth + 1, frame.f_back
            limit = sys.getrecursionlimit()
            sys.setrecursionlimit(depth + free + 1)
            try:
                call()
            finally:
                sys.setrecursionlimit(limit)
        results = {{}}
        for free in (1, 2, 3, 5, 10, 20, 28, 40):
            rec = Recorder(MemorySink(), agent_id="a")
            sock, got = socket.socket(), []
            sock.settimeout(5)
            def call():
                try:
                    _socket.socket.connect(sock, {listener!r})
                    got.append("connected")
                except BaseException as exc:
                    got.append(type(exc).__name__)
            with rec.run():
                at(free, call)
            sock.close()
            results[free] = [got, sum(r.get("event_type") == "egress" for r in rec._sink.records), rec.failures]
        print(json.dumps(results))
    """), encoding="utf-8")
    done = subprocess.run([sys.executable, str(script)], capture_output=True, text=True, timeout=60,
                          stdin=subprocess.DEVNULL, env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
    assert done.returncode == 0, done.stderr
    for free, (got, recorded, failures) in json.loads(done.stdout).items():
        if sys.version_info < (3, 12) and int(free) < 3:  # the hook's own frame counts there, and it cannot catch that
            continue
        assert got == ["connected"], free
        assert recorded == 1 or failures >= 1, free


@needs_c_calls_apart
def test_a_call_put_aside_says_it_was_recorded_late(listener):
    recorder = Recorder(MemorySink(), agent_id="agent")
    sock = socket.socket()
    sock.settimeout(5)
    with recorder.run():
        _with_free_frames(10, lambda: _socket.socket.connect(sock, listener))
    sock.close()
    assert egress_records(recorder)[0]["attributes"]["recorded_late"] is True
    recorder.close()


@needs_c_calls_apart
def test_when_the_waiting_room_is_full_the_failure_is_counted(listener, monkeypatch):
    monkeypatch.setattr(egress_module, "_MAX_STARVED", 0)
    recorder = Recorder(MemorySink(), agent_id="agent")
    sock = socket.socket()
    sock.settimeout(5)
    with recorder.run():
        _with_free_frames(10, lambda: _socket.socket.connect(sock, listener))
    sock.close()
    assert recorder.failures == 1 and entries(recorder) == []
    recorder.close()


# Limits that a flood must not be able to use up


def test_a_loopback_flood_does_not_use_up_the_real_quota(rec, monkeypatch):
    monkeypatch.setattr(_netguard, "_armed", False)  # only audit events: nothing is sent
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock, rec.run():
        for port in range(20000, 20600):
            sys.audit("socket.sendto", sock, ("127.0.0.1", port))
        sys.audit("socket.sendto", sock, ("127.0.0.2", 53))
        sys.audit("socket.sendto", sock, ("192.0.2.9", 53))
    found = notes(rec, "network")
    assert {"kind": "udp_send", "dest_ip": "192.0.2.9", "dest_port": 53} in found
    assert {"kind": "udp_send", "dest_ip": "127.0.0.2", "dest_port": 53} in found
    summary = found[-1]
    assert summary["kind"] == "dropped_summary" and summary["by_kind"] == {"udp_send": 584}
    assert [n["kind"] for n in found].count("limit_reached") == 1


def test_one_kind_of_event_does_not_use_up_anothers_quota(rec, monkeypatch):
    monkeypatch.setattr(egress_module, "_MAX_NETWORK_NOTES", 2)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock, rec.run():
        for n in range(10):
            sys.audit("socket.gethostbyname", f"h{n}.example")
        monkeypatch.setattr(_netguard, "_armed", False)
        sys.audit("socket.sendto", sock, ("192.0.2.9", 53))
    assert {"kind": "udp_send", "dest_ip": "192.0.2.9", "dest_port": 53} in notes(rec, "network")


def test_no_summary_when_nothing_was_dropped(rec, udp_sink):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock, rec.run():
        sock.sendto(b"x", udp_sink)
    assert [n["kind"] for n in notes(rec, "network")] == ["udp_send"]


# More ways to write a secret on a command line


@pytest.mark.parametrize("argv", [
    ["/bin/sh", "-c", "mysql -uroot -pabc123secret db"],
    ["sudo", "-u", "x", "mysql", "-pabc123secret"],
    ["sshpass", "-p", "abc123secret", "ssh", "h"],
    ["sqlcmd", "-U", "sa", "-P", "abc123secret"],
    ["redis-cli", "-a", "abc123secret"],
    ["curl", "-uadmin:abc123secret", "http://h"],
    ["net", "use", "\\\\h", "/password:abc123secret"],
    ["openssl", "enc", "-passin", "pass:abc123secret"],
    ["openssl", "enc", "-k", "abc123secret"],
    ["python", "-c", "password = 'abc123secret'; print(1)"],
    ["powershell", "-c", "$password = 'abc123secret'"],
    ["cmd", "/c", 'set "PASSWORD=two abc123secret"'],
    ["curl", "-d", '{"pin":123456789}'],
    ["psql", "postgres://u:p/abc123secret@h/db"],
    ["curl", "http://h/?x=1&Password%3dabc123secret"],
    ["curl", "https://api.telegram.org/bot123456:abc123secret/send"],
    ["curl", "https://hooks.slack.com/services/T0/B0/abc123secret"],
])
def test_these_ways_of_passing_a_secret_are_masked(rec, argv):
    with rec.run():
        sys.audit("subprocess.Popen", argv[0], argv, None, None)
    shown = json.dumps(notes(rec, "process"))
    assert "abc123secret" not in shown and "123456789" not in shown


def test_a_tool_flag_means_something_else_in_other_programs(rec):
    argv = ["grep", "-a", "pattern", "-p", "8080", "-k", "value", "-P", "regex"]
    with rec.run():
        sys.audit("subprocess.Popen", "grep", argv, None, None)
    assert notes(rec, "process")[0]["args"] == argv


def test_a_hostile_command_line_is_cheap_to_mask(rec):
    started = time.perf_counter()
    with rec.run():
        sys.audit("subprocess.Popen", "x", ["a." * 8192] * 64, None, None)
    assert time.perf_counter() - started < 5


# Datagrams on the proactor, and TCP Fast Open


def test_asyncio_udp_on_the_default_loop_is_noted(rec, udp_sink):
    async def main():
        loop = asyncio.get_running_loop()
        connected, _ = await loop.create_datagram_endpoint(asyncio.DatagramProtocol, remote_addr=udp_sink)
        connected.sendto(b"x")
        await asyncio.sleep(0.05)
        connected.close()
        open_ended, _ = await loop.create_datagram_endpoint(asyncio.DatagramProtocol, family=socket.AF_INET)
        open_ended.sendto(b"y", udp_sink)
        await asyncio.sleep(0.05)
        open_ended.close()

    with rec.run():
        asyncio.run(main())
    assert {"kind": "udp_send", "dest_ip": "127.0.0.1", "dest_port": udp_sink[1]} in notes(rec, "network")


def test_sendto_on_a_stream_socket_not_yet_connected_is_a_connection(rec, listener):
    with socket.socket() as sock, rec.run():
        with contextlib.suppress(OSError):  # Windows refuses it. The Linux shape is TCP Fast Open.
            sock.sendto(b"x", listener)
    [entry] = entries(rec)
    assert entry["protocol"] == "tcp" and entry["dest_port"] == listener[1]


def test_sendto_on_a_connected_stream_socket_is_not_a_new_connection(rec, web):
    with socket.create_connection(("127.0.0.1", web.server_port), timeout=5) as sock, rec.run():
        with contextlib.suppress(OSError):
            sock.sendto(b"x", ("127.0.0.1", web.server_port))
    assert entries(rec) == []


# The guard, once more


def test_the_guard_blocks_a_raw_connect_and_reverse_lookups():
    with socket.socket() as sock, pytest.raises(ExternalNetworkBlocked):
        _socket.socket.connect(sock, ("192.0.2.1", 9))
    with pytest.raises(ExternalNetworkBlocked):
        socket.gethostbyaddr("192.0.2.1")
    with pytest.raises(ExternalNetworkBlocked):
        socket.getnameinfo(("192.0.2.1", 80), 0)
    assert socket.gethostbyaddr("127.0.0.1")
