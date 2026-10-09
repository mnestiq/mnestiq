"""Heartbeats: a quiet agent and a stopped recorder look different."""

import time

import pytest

import mnestiq.recorder
from mnestiq import FileSink, MemorySink, Recorder, verify_file
from mnestiq.cli import main

from conftest import load
from test_signers import Flaky


def test_an_idle_recorder_signs_on_a_timer(tmp_path, key, pub):
    path = tmp_path / "e.jsonl"
    rec = Recorder(FileSink(path), agent_id="a", signing_key=key, checkpoint_interval=0.2)
    with rec.run() as run:
        run.note("one thing, then quiet")
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline and sum(r["kind"] == "checkpoint" for r in load(path)) < 2:
        time.sleep(0.05)
    rec.close()
    records = load(path)
    beats = [r for r in records if r.get("event_type") == "heartbeat"]
    assert beats and beats[0]["attributes"] == {"interval_s": 0.2}
    assert sum(r["kind"] == "checkpoint" for r in records) >= 2
    report = verify_file(path, [pub])
    assert report.ok and report.unsigned_tail == 0


def test_a_busy_recorder_needs_no_heartbeat(key):
    rec = Recorder(MemorySink(), agent_id="a", signing_key=key, checkpoint_every=1, checkpoint_interval=3600)
    with rec.run() as run:
        run.note("busy")
    rec.close()
    # One beat at the start, which puts the interval in the evidence, and none while busy.
    beats = [r for r in rec._sink.records if r.get("event_type") == "heartbeat"]
    assert len(beats) == 1 and beats[0]["seq"] == 0


def test_heartbeats_continue_while_the_signer_is_down(key, recwarn):
    flaky = Flaky(key)
    rec = Recorder(MemorySink(), agent_id="a", signer=flaky, retry_after=3600)
    assert rec.heartbeat() is None  # the signer is down: the beat is written, unsigned
    assert rec.heartbeat() is None  # and not retried before retry_after
    assert flaky.calls == 1
    beats = [r for r in rec._sink.records if r.get("event_type") == "heartbeat"]
    assert len(beats) == 2 and rec.failures == 1


def test_a_stopped_recorder_shows_as_a_gap(tmp_path, monkeypatch, key, pub):
    """The recorder was killed for two hours, then started again on the same file."""
    path = tmp_path / "e.jsonl"
    rec = Recorder(FileSink(path), agent_id="a", signing_key=key, checkpoint_interval=300)
    rec.heartbeat()
    rec.close()
    real = mnestiq.recorder.now_ts

    def later():
        ts = real()
        return {**ts, "wall": "2099" + ts["wall"][4:]}

    monkeypatch.setattr(mnestiq.recorder, "now_ts", later)
    rec = Recorder(FileSink(path), agent_id="a", signing_key=key, checkpoint_interval=300)
    rec.heartbeat()
    rec.close()
    report = verify_file(path, [pub])
    assert report.ok  # the evidence is intact; the silence is a warning, not tampering
    assert "quiet" in {w.code for w in report.warnings}
    assert report.quiet and report.quiet[0]["seconds"] > 7200


def test_without_heartbeats_a_gap_is_just_a_quiet_agent(tmp_path, monkeypatch, key, pub):
    path = tmp_path / "e.jsonl"
    rec = Recorder(FileSink(path), agent_id="a", signing_key=key)
    with rec.run() as run:
        run.note("x")
    rec.close()
    real = mnestiq.recorder.now_ts
    monkeypatch.setattr(mnestiq.recorder, "now_ts", lambda: {**real(), "wall": "2099" + real()["wall"][4:]})
    rec = Recorder(FileSink(path), agent_id="a", signing_key=key)
    with rec.run() as run:
        run.note("y")
    rec.close()
    report = verify_file(path, [pub])
    assert report.ok and "quiet" not in {w.code for w in report.warnings}


def test_heartbeat_needs_spec_0_2(tmp_path, monkeypatch, key, pub):
    monkeypatch.setattr(mnestiq.recorder, "SPEC_VERSION", "0.1")
    rec = Recorder(FileSink(tmp_path / "e.jsonl"), agent_id="a", signing_key=key)
    rec.heartbeat()
    rec.close()
    assert "spec_version" in {i.code for i in verify_file(tmp_path / "e.jsonl", [pub]).errors}


def test_interval_must_be_positive():
    with pytest.raises(ValueError):
        Recorder(MemorySink(), agent_id="a", checkpoint_interval=0)


def test_inspect_shows_heartbeats(tmp_path, key, capsys):
    rec = Recorder(FileSink(tmp_path / "e.jsonl"), agent_id="a", signing_key=key)
    rec.heartbeat()
    rec.close()
    main(["inspect", str(tmp_path / "e.jsonl")])
    assert "recorder alive" in capsys.readouterr().out


def test_a_recorder_stopped_before_its_first_quiet_spell_shows_as_a_silence(key, pub, tmp_path):
    """The verifier learns the interval from a heartbeat. A recorder killed while busy, before any
    idle beat, used to leave no interval, so its silence afterwards went unnoticed."""
    from mnestiq import FileSink, verify_file
    import json

    path = tmp_path / "e.jsonl"
    rec = Recorder(FileSink(path), agent_id="a", signing_key=key, checkpoint_every=1, checkpoint_interval=60)
    with rec.run() as run:
        run.note("busy")
    rec.close()
    first = json.loads(path.read_text().splitlines()[0])
    assert first["event_type"] == "heartbeat" and first["attributes"]["interval_s"] == 60
    assert verify_file(path, [pub]).ok
