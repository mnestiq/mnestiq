import base64
from pathlib import Path

import pytest

from mnestiq import FileSink, MemorySink, Recorder, Segment, verify_file, verify_lines
from mnestiq.canonical import canonical_json
from mnestiq.hashing import digest_bytes, record_hash, redact, signing_payload, value_digest
from mnestiq.keys import generate_private_key, key_id, public_key_b64
from mnestiq.merkle import merkle_root

from conftest import dump, load, record_demo


def codes(report):
    return {i.code for i in report.errors}


def test_valid_signed_chain(tmp_path, key, pub):
    path = record_demo(tmp_path / "e.jsonl", key)
    report = verify_file(path, [pub])
    assert report.ok, report.errors
    assert report.warnings == []
    assert report.checkpoints >= 2
    assert report.unsigned_tail == 0
    assert report.signer_keys == [key_id(pub)]


def test_records_capture_identity_and_provenance(tmp_path, key):
    records = load(record_demo(tmp_path / "e.jsonl", key))
    events = [r for r in records if r["kind"] == "event"]
    assert [e["event_type"] for e in events] == [
        "run_start", "llm_call", "tool_call", "llm_call", "approval", "tool_call", "run_end"]
    assert len({e["run_id"] for e in events}) == 1
    assert [e["step_id"] for e in events] == list(range(7))
    assert all(e["agent_id"] == "support-bot" and e["operator_id"] == "alice" for e in events)
    fetch = events[2]["tool_calls"][0]
    assert fetch["name"] == "fetch_page" and fetch["result_source"] == "web"
    assert fetch["arguments"] == {"url": "https://example.com/faq"}
    assert {s["source"] for s in events[3]["context"]} == {"user", "web"}
    assert events[0]["effective_permissions"] == {"email": "send", "crm": "read"}


def test_unsigned_chain_is_valid_but_warns(tmp_path):
    report = verify_file(record_demo(tmp_path / "e.jsonl", None))
    assert report.ok
    assert {w.code for w in report.warnings} == {"unsigned"}


def test_unsigned_tail_warns(tmp_path, key, pub):
    # 7 events, checkpoint every 4, no final checkpoint on close -> 3 unsigned.
    report = verify_file(record_demo(tmp_path / "e.jsonl", key, checkpoint_every=4, close=False), [pub])
    assert report.ok
    assert report.unsigned_tail == 3
    assert {w.code for w in report.warnings} == {"unsigned_tail"}


def test_untrusted_key_warning_without_pin(tmp_path, key):
    report = verify_file(record_demo(tmp_path / "e.jsonl", key))
    assert report.ok
    assert "untrusted_key" in {w.code for w in report.warnings}


# --- tampering -------------------------------------------------------------

def _find(records, event_type):
    return next(i for i, r in enumerate(records) if r.get("event_type") == event_type)


def test_edit_content_detected(tmp_path, key, pub):
    path = record_demo(tmp_path / "e.jsonl", key)
    records = load(path)
    i = _find(records, "tool_call")
    records[i]["tool_calls"][0]["result"] = "harmless page"
    dump(path, records)
    report = verify_file(path, [pub])
    assert not report.ok
    assert codes(report) == {"content_hash"}


def test_edit_content_and_its_digest_detected(tmp_path, key, pub):
    path = record_demo(tmp_path / "e.jsonl", key)
    records = load(path)
    i = _find(records, "tool_call")
    tc = records[i]["tool_calls"][0]
    tc["result"] = "harmless page"
    tc["result_hash"] = value_digest(tc["result"])
    dump(path, records)
    assert codes(verify_file(path, [pub])) == {"record_hash"}


def test_edit_and_rehash_single_record_breaks_link(tmp_path, key, pub):
    path = record_demo(tmp_path / "e.jsonl", key)
    records = load(path)
    i = _find(records, "approval")
    records[i]["approvals"][0]["approver"] = "human:bob"
    records[i]["record_hash"] = record_hash(records[i])
    dump(path, records)
    assert "link" in codes(verify_file(path, [pub]))


def _rehash_from(records, start):
    for j in range(start, len(records)):
        if j:
            records[j]["prev_hash"] = records[j - 1]["record_hash"]
        records[j]["record_hash"] = record_hash(records[j])


def test_full_rewrite_fails_signatures(tmp_path, key, pub):
    path = record_demo(tmp_path / "e.jsonl", key)
    records = load(path)
    i = _find(records, "approval")
    records[i]["approvals"][0]["approver"] = "human:bob"
    _rehash_from(records, i)
    dump(path, records)
    report = verify_file(path, [pub])
    assert not report.ok
    assert "merkle_root" in codes(report) or "signature" in codes(report)


def test_full_rewrite_resigned_by_attacker_needs_key_pinning(tmp_path, key, pub):
    path = record_demo(tmp_path / "e.jsonl", key)
    records = load(path)
    i = _find(records, "approval")
    records[i]["approvals"][0]["approver"] = "human:bob"

    attacker = generate_private_key()
    apub = public_key_b64(attacker)
    pending = []
    for j, r in enumerate(records):
        if j:
            r["prev_hash"] = records[j - 1]["record_hash"]
        if r["kind"] == "checkpoint":
            r["merkle_root"] = "sha256:" + merkle_root([digest_bytes(h) for h in pending]).hex()
            r["public_key"], r["key_id"] = apub, key_id(apub)
            r["signature"] = base64.b64encode(attacker.sign(signing_payload(r))).decode()
            pending = []
        r["record_hash"] = record_hash(r)
        if r["kind"] == "event":
            pending.append(r["record_hash"])
    dump(path, records)

    assert verify_file(path).ok  # internally consistent...
    report = verify_file(path, [pub])  # ...but not signed by the recorder's key
    assert codes(report) == {"untrusted_key"}


def test_deleted_record_detected(tmp_path, key, pub):
    path = record_demo(tmp_path / "e.jsonl", key)
    records = load(path)
    del records[_find(records, "approval")]
    dump(path, records)
    assert {"seq", "link"} <= codes(verify_file(path, [pub]))


def test_reordered_records_detected(tmp_path, key, pub):
    path = record_demo(tmp_path / "e.jsonl", key)
    records = load(path)
    records[1], records[2] = records[2], records[1]
    dump(path, records)
    assert {"seq", "link"} <= codes(verify_file(path, [pub]))


def test_garbage_line_detected(tmp_path, key, pub):
    path = record_demo(tmp_path / "e.jsonl", key)
    path.write_bytes(path.read_bytes() + b"{not json\n")
    assert "parse" in codes(verify_file(path, [pub]))


# --- redaction, resume, structure ---------------------------------------------

def test_redacted_chain_still_verifies(tmp_path, key, pub):
    path = record_demo(tmp_path / "e.jsonl", key)
    records = [redact(r) for r in load(path)]
    dump(path, records)
    assert verify_file(path, [pub]).ok
    text = path.read_text("utf-8")
    assert "evil@example.com" not in text and "Ignore previous instructions" not in text


def test_resume_continues_chain(tmp_path, key, pub):
    path = tmp_path / "e.jsonl"
    with Recorder(FileSink(path), agent_id="a", signing_key=key) as rec:
        with rec.run() as run:
            run.note("first process")
    with Recorder(FileSink(path), agent_id="a", signing_key=key) as rec2:
        with rec2.run() as run:
            run.note("after restart")
    records = load(path)
    assert len({r["chain_id"] for r in records}) == 1
    assert [r["seq"] for r in records] == list(range(len(records)))
    assert verify_file(path, [pub]).ok


def test_resume_refuses_different_chain(tmp_path):
    path = tmp_path / "e.jsonl"
    with Recorder(FileSink(path), agent_id="a") as rec, rec.run():
        pass
    with pytest.raises(ValueError):
        Recorder(FileSink(path), agent_id="a", chain_id="other")


def test_nested_runs_and_errors():
    sink = MemorySink()
    rec = Recorder(sink, agent_id="planner")
    with pytest.raises(RuntimeError):
        with rec.run("outer"):
            with rec.run("inner", agent_id="worker") as inner:
                assert inner.parent_run_id == "outer"
            raise RuntimeError("boom")
    ends = [r for r in sink.records if r["event_type"] == "run_end"]
    assert ends[0]["run_id"] == "inner" and ends[0]["status"] == "ok"
    assert ends[1]["run_id"] == "outer" and ends[1]["status"] == "error" and "boom" in ends[1]["error"]
    assert verify_lines(canonical_json(r) for r in sink.records).ok


def test_tool_decorator_records_failures_and_odd_values():
    sink = MemorySink()
    rec = Recorder(sink, agent_id="a")

    @rec.tool()
    def risky(n: int, big: int = 2**60):
        raise ValueError("nope")

    with rec.run():
        with pytest.raises(ValueError):
            risky(3)
    call = next(r for r in sink.records if r["event_type"] == "tool_call")
    assert call["status"] == "error"
    assert call["tool_calls"][0]["arguments"] == {"n": 3}
    assert "nope" in call["tool_calls"][0]["error"]
    assert verify_lines(canonical_json(r) for r in sink.records).ok


def test_segment_rejects_unknown_source():
    with pytest.raises(ValueError):
        Segment("internet", "x")


def test_bundled_schema_matches_spec():
    repo = Path(__file__).resolve().parents[2]
    spec = repo / "spec" / "schema" / "record.schema.json"
    bundled = repo / "python" / "src" / "mnestiq" / "schema" / "record.schema.json"
    hint = "run: cp spec/schema/record.schema.json python/src/mnestiq/schema/"
    assert spec.read_bytes() == bundled.read_bytes(), hint
