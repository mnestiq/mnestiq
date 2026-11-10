"""The recorder's own events are all built one way, a MemorySink holds what a file would hold, and a resume
refuses a salt that is not 16 bytes, signed record or not."""

import base64
import copy
import json

import pytest

from mnestiq import FileSink, MemorySink, Recorder, RecorderError, verify_file
from mnestiq.canonical import canonical_json
from mnestiq.hashing import salted_digest
from mnestiq.keys import generate_private_key, public_key_b64
from mnestiq.verify import verify_lines

IDENTITY = {"provider": "entra", "app_id": "app-1"}


def _own(sink):
    return [r for r in sink.records if r.get("kind") == "event" and str(r.get("run_id", "")).startswith("recorder-")]


def test_every_event_the_recorder_writes_about_itself_carries_the_identity():
    sink = MemorySink()
    rec = Recorder(sink, agent_id="a", signing_key=generate_private_key(), checkpoint_interval=1000,
                   agent_identity=IDENTITY, sandbox_id=None)
    with rec.run() as run:
        run.note("hello")
    rec.rotate_signer(generate_private_key())
    rec.close()
    own = _own(sink)
    kinds = [(r["event_type"], (r.get("attributes") or {}).get("message")) for r in own]
    assert ("heartbeat", None) in kinds and ("note", "key rotation") in kinds
    assert all(r.get("agent_identity") == IDENTITY for r in own), kinds


def test_an_empty_agent_id_does_not_stop_the_recorder_writing_its_own_events():
    sink = MemorySink()
    rec = Recorder(sink, agent_id="", signing_key=generate_private_key(), checkpoint_interval=1000, sandbox_id=None)
    assert rec.failures == 0
    with rec.run(agent_id="worker") as run:
        run.note("hello")
    rec.rotate_signer(generate_private_key())
    rec.close()
    assert rec.failures == 0
    assert next(r["event_type"] for r in _own(sink)) == "heartbeat"
    assert verify_lines(canonical_json(r) for r in sink.records).ok


def test_a_recovered_file_note_carries_the_identity(tmp_path):
    path = tmp_path / "e.jsonl"
    rec = Recorder(FileSink(path), agent_id="a", sandbox_id=None)
    with rec.run() as run:
        run.note("one")
    rec.close()
    with open(path, "ab") as fh:
        fh.write(b'{"torn":')  # the process died mid-write
    rec = Recorder(FileSink(path), agent_id="", agent_identity=IDENTITY, sandbox_id=None)
    rec.close()
    records = [json.loads(line) for line in path.read_bytes().splitlines() if line.strip()]
    said = "recovered from an interrupted write"
    recovered = [r for r in records if (r.get("attributes") or {}).get("message") == said]
    assert len(recovered) == 1 and recovered[0]["agent_identity"] == IDENTITY
    assert rec.failures == 0


def test_a_memory_sink_holds_a_large_whole_number_as_a_file_would():
    sink = MemorySink()
    rec = Recorder(sink, agent_id="a", sandbox_id=None)
    with rec.run() as run:
        run.note("big", amount=1e20)
    rec.close()
    assert rec.failures == 0
    again = Recorder(sink, agent_id="a", sandbox_id=None)  # resumes from what it holds
    again.close()
    assert verify_lines(canonical_json(r) for r in sink.records).ok


def _signed_file(tmp_path, key):
    path = tmp_path / "e.jsonl"
    rec = Recorder(FileSink(path), agent_id="bot", signing_key=key, checkpoint_every=2, sandbox_id=None)
    with rec.run() as run:
        run.tool_call("lookup_policy", {"q": "refunds"}, 'Policy 7: never pay "account GR96" without a second approval')
    rec.close()
    return path, [json.loads(line) for line in path.read_bytes().splitlines() if line.strip()]


def _write(path, records):
    path.write_bytes(b"".join(canonical_json(r) + b"\n" for r in records))


def _moved_into_salt(records):
    """Move the first bytes of a result into its salt: its digest stays the same."""
    changed = copy.deepcopy(records)
    slot = next(tc for r in changed for tc in r.get("tool_calls", []) if "result" in tc)
    canon = canonical_json(slot["result"])
    cut = canon.index(b'\\"') + 1
    slot["result_salt"] = base64.b64encode(base64.b64decode(slot["result_salt"]) + canon[:cut]).decode()
    slot["result"] = json.loads(canon[cut:])
    assert salted_digest(slot["result_salt"], slot["result"]) == slot["result_hash"]
    return changed


def test_a_resume_refuses_bytes_moved_from_a_value_into_its_salt(tmp_path):
    key = generate_private_key()
    path, records = _signed_file(tmp_path, key)
    assert records[-1]["kind"] == "checkpoint"  # the changed record is under a signature
    _write(path, _moved_into_salt(records))
    assert not verify_file(path, [public_key_b64(key)]).ok
    with pytest.raises(RecorderError, match="failed verification"):
        Recorder(FileSink(path), agent_id="bot", signing_key=key, checkpoint_every=2, sandbox_id=None)


@pytest.mark.parametrize("salt", ["", "AAAA", "A" * 22 + "B=", "A" * 21 + "B==", "A" * 24, None, 7])
def test_a_resume_refuses_a_salt_that_is_not_16_bytes_of_canonical_base64(tmp_path, salt):
    path = tmp_path / "e.jsonl"
    rec = Recorder(FileSink(path), agent_id="bot", sandbox_id=None)
    with rec.run() as run:
        run.tool_call("t", {"a": 1}, "r")
    rec.close()
    records = [json.loads(line) for line in path.read_bytes().splitlines() if line.strip()]
    slot = next(tc for r in records for tc in r.get("tool_calls", []))
    slot["arguments_salt"] = salt
    _write(path, records)
    with pytest.raises(RecorderError):
        Recorder(FileSink(path), agent_id="bot", sandbox_id=None)


def test_a_file_with_good_salts_resumes(tmp_path):
    key = generate_private_key()
    path, _ = _signed_file(tmp_path, key)
    rec = Recorder(FileSink(path), agent_id="bot", signing_key=key, checkpoint_every=2, sandbox_id=None)
    rec.close()
    assert verify_file(path, [public_key_b64(key)]).ok
