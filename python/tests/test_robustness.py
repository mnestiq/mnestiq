"""Crash recovery, write failures, size limits and threading."""

import concurrent.futures
import threading
import warnings

import pytest

from mnestiq import FileSink, MemorySink, Recorder, RecorderError, Segment, SinkError, current_run, verify_file
from mnestiq.hashing import value_digest

from conftest import load


def _events(path):
    return [r for r in load(path) if r["kind"] == "event"]


# --- crash recovery -------------------------------------------------------------------------

def test_torn_write_is_preserved_and_chain_resumes(tmp_path, key, pub):
    path = tmp_path / "e.jsonl"
    with Recorder(FileSink(path), agent_id="a", signing_key=key, checkpoint_every=3) as rec, rec.run() as run:
        for i in range(5):
            run.note(f"step {i}")
    good = path.read_bytes()
    path.write_bytes(good + b'{"spec_version":"0.1","kind":"event","seq":99,"half a rec')  # power cut mid-write

    with Recorder(FileSink(path), agent_id="a", signing_key=key) as rec2, rec2.run() as run:
        run.note("after restart")

    report = verify_file(path, [pub])
    assert report.ok, report.errors
    sidecars = list(tmp_path.glob("e.jsonl.torn-*"))
    assert len(sidecars) == 1 and sidecars[0].read_bytes().endswith(b"half a rec")
    note = next(r for r in _events(path) if r.get("attributes", {}).get("message", "").startswith("recovered"))
    assert note["attributes"]["sidecar"] == sidecars[0].name and note["attributes"]["bytes"] > 0


def test_complete_last_record_missing_only_newline_is_kept(tmp_path):
    path = tmp_path / "e.jsonl"
    with Recorder(FileSink(path), agent_id="a") as rec, rec.run():
        pass
    path.write_bytes(path.read_bytes().rstrip(b"\n"))
    with Recorder(FileSink(path), agent_id="a") as rec2, rec2.run():
        pass
    assert verify_file(path).ok
    assert not list(tmp_path.glob("*.torn-*"))


def test_corrupt_middle_line_refuses_to_resume(tmp_path):
    path = tmp_path / "e.jsonl"
    with Recorder(FileSink(path), agent_id="a") as rec, rec.run():
        pass
    lines = path.read_bytes().splitlines(keepends=True)
    path.write_bytes(lines[0] + b"garbage\n" + b"".join(lines[1:]))
    with pytest.raises(SinkError, match="cannot be resumed"):
        Recorder(FileSink(path), agent_id="a")


def test_failed_write_leaves_no_partial_record(tmp_path):
    path = tmp_path / "e.jsonl"
    sink = FileSink(path)
    rec = Recorder(sink, agent_id="a", strict=True)
    with rec.run() as run:
        run.note("ok")
        real_write = sink._fh.write

        def failing_write(data):
            real_write(data[: len(data) // 2])  # the disk fills up half way through
            raise OSError(28, "No space left on device")

        sink._fh.write = failing_write
        with pytest.raises(OSError):
            run.note("this one fails")
        sink._fh.write = real_write
        run.note("disk has space again")
    rec.close()
    assert verify_file(path).ok  # no half line, no gap in the chain
    assert [e.get("attributes", {}).get("message") for e in _events(path) if e["event_type"] == "note"] == \
        ["ok", "disk has space again"]


# --- never break the agent ---------------------------------------------------------------------

class BrokenSink(MemorySink):
    def append(self, record):
        raise OSError(28, "No space left on device")


def test_broken_sink_does_not_break_the_agent():
    rec = Recorder(BrokenSink(), agent_id="a")

    @rec.tool()
    def add(a, b):
        return a + b

    with pytest.warns(RuntimeWarning, match="not being recorded"):
        with rec.run() as run:
            assert add(2, 3) == 5          # the tool still works
            assert run.note("x") is None   # recording reports failure, doesn't raise
    assert rec.failures >= 3               # run_start, tool_call, note, run_end
    rec.close()


def test_strict_mode_raises():
    rec = Recorder(BrokenSink(), agent_id="a", strict=True)
    with pytest.raises(OSError):
        with rec.run():
            pass


def test_unserializable_and_closed_are_handled():
    sink = MemorySink()
    rec = Recorder(sink, agent_id="a")
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        with rec.run() as run:
            # Non-finite floats can't be canonicalized. The recorder converts them and the agent is unaffected.
            run.tool_call("t", {"x": float("nan")}, {"big": 2**70})
        rec.close()
        rec.close()  # idempotent
        with rec.run() as run:
            assert run.note("after close") is None
    assert rec.failures >= 1
    with pytest.raises(RecorderError):
        rec.append_event({"event_type": "note", "run_id": "r", "agent_id": "a"})


def test_timestamper_outage_keeps_the_signature(tmp_path, key, pub):
    def tsa(_sig):
        raise ConnectionError("TSA unreachable")

    path = tmp_path / "e.jsonl"
    with Recorder(FileSink(path), agent_id="a", signing_key=key, timestamper=tsa) as rec, rec.run():
        pass
    report = verify_file(path, [pub])
    assert report.ok and report.checkpoints == 1


# --- size cap ---------------------------------------------------------------------------------

def test_oversized_content_is_hashed_not_stored(tmp_path):
    path = tmp_path / "e.jsonl"
    big = "A" * 5000
    with Recorder(FileSink(path), agent_id="a", max_content_bytes=1000) as rec, rec.run() as run:
        run.llm_call(provider="p", model="m", context=[Segment("user", "small"), Segment("web", big)], output="ok")
        run.tool_call("dump", {"q": 1}, big)
    events = _events(path)
    llm = next(e for e in events if e["event_type"] == "llm_call")
    assert "content" not in llm["context"][1] and llm["context"][1]["content_hash"] == value_digest(big)
    assert llm["context"][0]["content"] == "small"
    assert llm["x-omitted"] == ["context[1].content (5002 bytes)"]
    tool = next(e for e in events if e["event_type"] == "tool_call")
    assert "result" not in tool["tool_calls"][0] and tool["x-omitted"] == ["tool_calls[0].result (5002 bytes)"]
    assert verify_file(path).ok
    assert path.stat().st_size < 5000


# --- threads ------------------------------------------------------------------------------------

def test_bind_carries_the_run_into_worker_threads():
    sink = MemorySink()
    rec = Recorder(sink, agent_id="a")

    @rec.tool()
    def work(n):
        return current_run().run_id if current_run() else None

    with rec.run("main-run") as run, concurrent.futures.ThreadPoolExecutor(4) as pool:
        unbound = pool.submit(lambda: current_run()).result()
        results = list(pool.map(run.bind(work), range(8)))
    assert unbound is None
    assert results == ["main-run"] * 8
    calls = [r for r in sink.records if r["event_type"] == "tool_call"]
    assert len(calls) == 8 and {c["run_id"] for c in calls} == {"main-run"}


def test_concurrent_writers_keep_a_valid_chain(tmp_path, key, pub):
    path = tmp_path / "e.jsonl"
    rec = Recorder(FileSink(path), agent_id="a", signing_key=key, checkpoint_every=7)

    def agent(i):
        with rec.run(f"run-{i}") as run:
            for j in range(25):
                run.note(f"{i}:{j}")

    threads = [threading.Thread(target=agent, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    rec.close()
    report = verify_file(path, [pub])
    assert report.ok and report.events == 8 * 27 and report.unsigned_tail == 0
    per_run = {}
    for e in _events(path):
        per_run.setdefault(e["run_id"], []).append(e["step_id"])
    assert all(steps == list(range(27)) for steps in per_run.values())
