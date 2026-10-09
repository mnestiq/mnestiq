import http.client
import json
import threading

import pytest

from mnestiq.dashboard import create_server

from conftest import record_demo


@pytest.fixture
def dashboard(tmp_path, key, pub):
    good = record_demo(tmp_path / "good.jsonl", key)
    bad = tmp_path / "nested" / "bad.jsonl"
    bad.parent.mkdir()
    bad.write_text(good.read_text("utf-8").replace("auto-approve-email", "human:bob"), "utf-8")
    server = create_server(tmp_path, trusted_keys=[pub], port=0, key=KEY)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield server.server_address[1], good
    server.shutdown()
    server.server_close()


KEY = "test-key"


def get(port, path, host=None, headers=None, key=KEY):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    sent = {"Host": host or f"127.0.0.1:{port}", **(headers or {})}
    if key is not None:
        sent["X-Mnestiq-Key"] = key
    conn.request("GET", path, headers=sent)
    res = conn.getresponse()
    body = res.read()
    conn.close()
    return res, body


def test_page_is_served_with_locked_down_csp(dashboard):
    port, _ = dashboard
    res, body = get(port, "/")
    assert res.status == 200 and b"Mnestiq" in body
    csp = res.getheader("Content-Security-Policy")
    assert "default-src 'none'" in csp and "connect-src 'self'" in csp
    assert b"https://" not in body and b"http://" not in body  # no external resources


def test_file_list_reports_verification(dashboard):
    port, _ = dashboard
    _, body = get(port, "/api/files")
    files = {f["name"]: f for f in json.loads(body)["files"]}
    assert files["good.jsonl"]["ok"] is True
    assert files["nested/bad.jsonl"]["ok"] is False and files["nested/bad.jsonl"]["errors"] >= 1


def test_file_payload_and_etag(dashboard):
    port, good = dashboard
    res, body = get(port, "/api/file?name=good.jsonl")
    data = json.loads(body)
    assert data["report"]["ok"] and data["pinned"] is True
    assert [r["seq"] for r in data["records"]] == list(range(len(data["records"])))
    etag = res.getheader("ETag")
    res, body = get(port, "/api/file?name=good.jsonl", headers={"If-None-Match": etag})
    assert res.status == 304 and body == b""

    with open(good, "ab") as fh:  # file grows -> new content, new etag
        fh.write(b"{not json\n")
    res, body = get(port, "/api/file?name=good.jsonl", headers={"If-None-Match": etag})
    assert res.status == 200 and res.getheader("ETag") != etag
    data = json.loads(body)
    assert data["records"][-1]["_unparseable"] is True and not data["report"]["ok"]


def test_rejects_foreign_host_header(dashboard):
    port, _ = dashboard
    res, _ = get(port, "/api/files", host=f"evil.example:{port}")
    assert res.status == 403


def test_non_evidence_jsonl_is_not_listed(tmp_path, key, pub):
    """A proxy log next to the evidence must not be shown (it would look 'tampered')."""
    from mnestiq.dashboard import EvidenceStore

    record_demo(tmp_path / "evidence.jsonl", key)
    (tmp_path / "proxy.jsonl").write_text(json.dumps({"start_time": "2026-10-03T12:00:00Z", "path": "/"}) + "\n")
    (tmp_path / "empty.jsonl").write_text("")
    (tmp_path / "junk.jsonl").write_text("not json at all\n")
    names = [EvidenceStore(tmp_path, [pub]).name(p) for p in EvidenceStore(tmp_path, [pub]).files()]
    assert names == ["evidence.jsonl"]


def test_large_files_are_windowed_but_fully_verified(tmp_path, key, pub):
    from mnestiq.dashboard import EvidenceStore

    path = record_demo(tmp_path / "big.jsonl", key)
    total = sum(1 for line in path.read_bytes().splitlines() if line.strip())
    store = EvidenceStore(tmp_path, [pub], max_records=4)
    data = json.loads(store.load(path).payload)
    assert data["records_total"] == total and len(data["records"]) == 4
    assert data["records_shown_from"] == total - 4
    assert data["records"][-1]["seq"] == total - 1  # the most recent ones
    assert data["report"]["ok"] and data["report"]["records"] == total


@pytest.mark.parametrize("name", ["../secret.jsonl", "/etc/passwd", "good.jsonl/../../x", ""])
def test_only_listed_files_are_readable(dashboard, name):
    port, _ = dashboard
    res, _ = get(port, f"/api/file?name={name}")
    assert res.status == 404


def test_data_needs_the_key_from_the_printed_link(dashboard):
    """Other accounts on the same machine can reach 127.0.0.1: without the key they get nothing."""
    port, _ = dashboard
    assert get(port, "/api/files", key=None)[0].status == 403
    assert get(port, "/api/files", key="wrong")[0].status == 403
    assert get(port, "/api/files")[0].status == 200
    assert get(port, "/", key=None)[0].status == 200  # the page itself holds no evidence


def test_a_line_nested_too_deep_does_not_break_the_dashboard(dashboard, tmp_path):
    port, _ = dashboard
    good = (tmp_path / "good.jsonl").read_bytes()
    (tmp_path / "deep.jsonl").write_bytes(good + b"[" * 100000 + b"]" * 100000 + b"\n")
    res, body = get(port, "/api/files")
    assert res.status == 200
    entry = next(f for f in json.loads(body)["files"] if f["name"].endswith("deep.jsonl"))
    assert entry["ok"] is False
