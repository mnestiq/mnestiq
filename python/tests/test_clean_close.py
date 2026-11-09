"""A recorder says in the chain when it stopped as intended. A damaged file can be set aside, and the dashboard
never drops a file that may be evidence."""

import hashlib
import json
import os
import re
import threading
from pathlib import Path

import pytest

import mnestiq.dashboard
import mnestiq.recorder
from conftest import dump, load
from mnestiq import FileSink, LocalSigner, MemorySink, Recorder
from mnestiq.cli import main
from mnestiq.dashboard import EvidenceStore
from mnestiq.findings import findings
from mnestiq.hashing import digest_bytes, record_hash
from mnestiq.keys import generate_private_key
from mnestiq.merkle import merkle_root
from mnestiq.signer_service import SignerService, init_signer
from mnestiq.signers import SignerError
from mnestiq.sinks import RecorderError
from mnestiq.verify import CLEAN_CLOSE_FIELD, RESTART_FIELD, UNCLEAN_RESUME_FIELD, ChainVerifier, verify_file

CODE = "resumed_without_clean_close"


def _closed(path, key, **options):
    with Recorder(FileSink(path), agent_id="a", signing_key=key, **options) as rec, rec.run() as run:
        run.note("signed")
    return load(path)


def _ended_right_after_a_checkpoint(path, key):
    """A recorder gone right after signing. A recorder from before the clean-close note leaves the same file."""
    rec = Recorder(FileSink(path), agent_id="a", signing_key=key, checkpoint_every=1000)
    with rec.run() as run:
        run.note("signed")
    rec.checkpoint()
    rec._sink.close()
    return load(path)


def _resume(path, key, **options):
    return Recorder(FileSink(path), agent_id="a", signing_key=key, **options)


def _notes(records, field):
    return [r for r in records if field in (r.get("attributes") or {})]


def _unclean(report):
    return [w for w in report.warnings if w.code == CODE]


def test_a_close_writes_the_note_as_the_last_signed_record(tmp_path, key, pub):
    path = tmp_path / "e.jsonl"
    records = _closed(path, key)
    assert records[-1]["kind"] == "checkpoint" and records[-2]["attributes"] == {
        "message": "recorder closed normally", CLEAN_CLOSE_FIELD: True}
    assert records[-2]["run_id"] == f"recorder-{records[0]['chain_id'][:8]}"
    assert records[-2]["event_type"] == "heartbeat"
    assert records[-1]["covers"]["to_seq"] == records[-2]["seq"]
    report = verify_file(path, [pub])
    assert report.ok and report.unsigned_tail == 0 and not _unclean(report)


def test_a_clean_close_then_a_restart_is_silent(tmp_path, key, pub):
    path = tmp_path / "e.jsonl"
    _closed(path, key)
    with _resume(path, key) as rec, rec.run() as run:
        run.note("later")
    report = verify_file(path, [pub])
    assert report.ok and not _unclean(report) and not report.unclean_restarts
    assert not _notes(load(path), UNCLEAN_RESUME_FIELD)


def test_a_close_with_nothing_written_writes_no_note(tmp_path, key):
    path = tmp_path / "e.jsonl"
    Recorder(FileSink(path), agent_id="a", signing_key=key).close()
    assert not load(path)


def test_a_close_with_no_signer_writes_no_note(tmp_path):
    path = tmp_path / "e.jsonl"
    with Recorder(FileSink(path), agent_id="a") as rec, rec.run() as run:
        run.note("not signed")
    assert not _notes(load(path), CLEAN_CLOSE_FIELD)


def test_the_marker_is_not_a_finding(tmp_path, key):
    path = tmp_path / "e.jsonl"
    records = _closed(path, key)
    assert not [f for f in findings(records) if str(f.get("run_id", "")).startswith("recorder-")]


def test_a_crash_right_after_a_checkpoint_says_check_this_and_not_tampered(tmp_path, key, pub):
    path = tmp_path / "e.jsonl"
    before = _ended_right_after_a_checkpoint(path, key)
    _resume(path, key).close()
    records = load(path)
    note = records[len(before)]
    assert note["attributes"] == {"message": "resumed without a clean close, check this",
                                  UNCLEAN_RESUME_FIELD: {"after_checkpoint_seq": before[-1]["seq"]}}
    report = verify_file(path, [pub])
    assert report.ok
    [warning] = _unclean(report)
    assert "Check this" in warning.message and "tamper" not in warning.message.lower()
    assert "older recorder" in warning.message


def test_the_attack_is_visible_under_a_pinned_key_and_in_json(tmp_path, key, pub, capsys):
    path = tmp_path / "e.jsonl"
    rec = Recorder(FileSink(path), agent_id="a", signing_key=key, checkpoint_every=1000)
    with rec.run() as run:
        run.note("signed")
        rec.checkpoint()
        run.note("the part someone wants gone")
    rec._sink.close()
    records = load(path)
    dump(path, records[:records.index(next(r for r in records if r["kind"] == "checkpoint")) + 1])
    _resume(path, key).close()
    assert verify_file(path, [pub]).ok
    capsys.readouterr()
    assert main(["verify", str(path), "--trusted-key", pub, "--json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert any(w["code"] == CODE for w in report["warnings"])
    assert report["unclean_restarts"][0]["checkpoint_seq"] == report["unclean_restarts"][0]["note_seq"] - 1


def test_a_chain_that_closes_cleanly_later_is_quiet_again(tmp_path, key, pub):
    path = tmp_path / "e.jsonl"
    _ended_right_after_a_checkpoint(path, key)
    _resume(path, key).close()  # the one warning, for the end nobody can vouch for
    _resume(path, key).close()
    report = verify_file(path, [pub])
    assert report.ok and len(_unclean(report)) == 1


def test_a_run_note_shaped_like_a_clean_close_does_not_count(tmp_path, key, pub):
    path = tmp_path / "e.jsonl"
    rec = Recorder(FileSink(path), agent_id="a", signing_key=key, checkpoint_every=1000)
    with rec.run() as run:
        run.note("signed", **{CLEAN_CLOSE_FIELD: True})
    rec.checkpoint()
    rec._sink.close()
    _resume(path, key).close()
    assert len(_unclean(verify_file(path, [pub]))) == 1


@pytest.mark.parametrize(("event_type", "run_id", "value"), [
    ("note", "own", True), ("heartbeat", "agent", True), ("heartbeat", "own", 1), ("heartbeat", "own", "true"),
    ("heartbeat", "own", False), ("heartbeat", "own", None)],
    ids=["old_shape_note", "another_run", "one", "text", "false", "null"])
def test_only_the_recorders_own_beat_counts_as_a_clean_close(tmp_path, key, pub, event_type, run_id, value):
    path = tmp_path / "e.jsonl"
    rec = Recorder(FileSink(path), agent_id="a", signing_key=key, chain_id="c" * 16, checkpoint_every=1000)
    with rec.run() as run:
        run.note("signed")
    rec.append_event({"event_type": event_type, "run_id": f"recorder-{'c' * 8}" if run_id == "own" else "some-run",
                      "agent_id": "a", "attributes": {CLEAN_CLOSE_FIELD: value}})
    rec.checkpoint()
    rec._sink.close()
    _resume(path, key).close()
    assert len(_unclean(verify_file(path, [pub]))) == 1


def test_the_recorders_own_beat_does_count(tmp_path, key, pub):
    path = tmp_path / "e.jsonl"
    rec = Recorder(FileSink(path), agent_id="a", signing_key=key, chain_id="c" * 16, checkpoint_every=1000)
    with rec.run() as run:
        run.note("signed")
    rec.append_event({"event_type": "heartbeat", "run_id": f"recorder-{'c' * 8}", "agent_id": "a",
                      "attributes": {CLEAN_CLOSE_FIELD: True}})
    rec.checkpoint()
    rec._sink.close()
    before = path.read_bytes()
    _resume(path, key).close()
    assert path.read_bytes() == before and not _unclean(verify_file(path, [pub]))


def test_the_beat_leaves_the_quiet_check_alone(tmp_path, key, pub):
    path = tmp_path / "e.jsonl"
    _closed(path, key)
    verifier = ChainVerifier([pub])
    verifier.feed(path.read_bytes().splitlines())
    assert verifier.heartbeat_s is None
    report = verifier.result()
    assert report.ok and not report.quiet and not report.errors

    beats = tmp_path / "beats.jsonl"
    _closed(beats, key, checkpoint_interval=3600)
    verifier = ChainVerifier([pub])
    verifier.feed(beats.read_bytes().splitlines())
    assert verifier.heartbeat_s == 3600 and not verifier.result().quiet


def test_a_beat_in_the_middle_of_a_heartbeat_chain_is_not_a_clean_close(tmp_path, key, pub):
    path = tmp_path / "e.jsonl"
    rec = Recorder(FileSink(path), agent_id="a", signing_key=key, checkpoint_interval=3600)
    rec.heartbeat()  # an ordinary beat, signed, and then the recorder is gone
    rec._sink.close()
    _resume(path, key, checkpoint_interval=3600).close()
    assert len(_unclean(verify_file(path, [pub]))) == 1


def test_the_beat_is_not_a_run_anywhere(tmp_path, key):
    path = tmp_path / "e.jsonl"
    records = _closed(path, key)
    assert records[-2]["event_type"] == "heartbeat" and "interval_s" not in records[-2]["attributes"]
    assert not findings(records)
    assert 'r.event_type === "heartbeat"' in (Path(mnestiq.dashboard.__file__).parent / "index.html").read_text("utf-8")


def _forged(path, key, claim):
    rec = Recorder(FileSink(path), agent_id="a", signing_key=key, checkpoint_every=1000)
    with rec.run() as run:
        run.note("signed")
        rec.append_event({"event_type": "note", "run_id": f"recorder-{rec.chain_id[:8]}", "agent_id": "a",
                          "attributes": {"message": "?", UNCLEAN_RESUME_FIELD: claim}})
    rec.close()


@pytest.mark.parametrize("claim", [{"after_checkpoint_seq": 0}, {"after_checkpoint_seq": 1},
                                   {"after_checkpoint_seq": "1"}, {"after_checkpoint_seq": True}, {}, [], "x", None])
def test_a_note_of_that_shape_elsewhere_is_only_a_note(tmp_path, key, pub, claim):
    path = tmp_path / "e.jsonl"
    _forged(path, key, claim)
    report = verify_file(path, [pub])
    assert report.ok and not _unclean(report) and not report.unclean_restarts


class _Down(LocalSigner):
    down = True

    def sign(self, payload, *args, **kwargs):
        if self.down:
            raise SignerError("the signer is down")
        return super().sign(payload)


def test_a_close_when_signing_fails_still_closes_and_a_resume_reports_it(tmp_path, key, pub):
    path = tmp_path / "e.jsonl"
    rec = Recorder(FileSink(path), agent_id="a", signer=_Down(key))
    with rec.run() as run:
        run.note("not signed yet")
    with pytest.warns(RuntimeWarning, match="the signer is down"):
        rec.close()
    assert rec.failures == 1
    records = load(path)
    assert records[-1]["attributes"][CLEAN_CLOSE_FIELD] is True and not any(r["kind"] == "checkpoint" for r in records)
    _resume(path, key).close()
    report = verify_file(path, [pub])
    assert report.ok and report.unsigned_tail == 0
    assert not _unclean(report) and [w.code for w in report.warnings].count("signed_after_restart") == 1


class _NoRoomForTheCloseNote(FileSink):
    def append(self, record):
        if CLEAN_CLOSE_FIELD in (record.get("attributes") or {}):
            raise OSError("no room for the note")
        super().append(record)


def test_a_failed_close_note_does_not_stop_the_signature(tmp_path, key, pub):
    path = tmp_path / "e.jsonl"
    rec = Recorder(_NoRoomForTheCloseNote(path), agent_id="a", signing_key=key)
    with rec.run() as run:
        run.note("signed")
    with pytest.warns(RuntimeWarning, match="no room for the note"):
        rec.close()
    assert rec.failures == 1 and load(path)[-1]["kind"] == "checkpoint"
    assert verify_file(path, [pub]).unsigned_tail == 0


def test_strict_raises_when_the_close_note_cannot_be_written(tmp_path, key):
    path = tmp_path / "e.jsonl"
    rec = Recorder(_NoRoomForTheCloseNote(path), agent_id="a", signing_key=key, strict=True)
    with rec.run() as run:
        run.note("signed")
    with pytest.raises(OSError, match="no room for the note"):
        rec.close()
    assert rec._sink._fh.closed  # the file is released either way


def test_the_restart_note_comes_before_the_close_note(tmp_path, key, pub):
    path = tmp_path / "e.jsonl"
    rec = Recorder(FileSink(path), agent_id="a", signing_key=key, checkpoint_every=1000)
    with rec.run() as run:
        run.note("not signed")
    rec._sink.close()
    _resume(path, key).close()
    records = load(path)
    assert RESTART_FIELD in records[-3]["attributes"] and CLEAN_CLOSE_FIELD in records[-2]["attributes"]
    assert verify_file(path, [pub]).restarts


# Damaged files.


def _damaged(path, key):
    records = _closed(path, key)
    records[0]["attributes"] = {"changed": True}  # the chain no longer holds together
    dump(path, records)
    return path.read_bytes()


def _asides(path):
    return sorted(path.parent.glob(f"{path.name}.damaged-*"))


def test_a_damaged_file_is_still_refused_by_default(tmp_path, key):
    path = tmp_path / "e.jsonl"
    damaged = _damaged(path, key)
    with pytest.raises(RecorderError):
        _resume(path, key)
    assert path.read_bytes() == damaged and not _asides(path)


def test_new_file_sets_the_damaged_file_aside_and_starts_a_new_chain(tmp_path, key, pub):
    path = tmp_path / "e.jsonl"
    damaged = _damaged(path, key)
    old_chain = load(_asides(path)[0] if _asides(path) else path)[0]["chain_id"]
    rec = _resume(path, key, on_damaged="new_file")
    with rec.run() as run:
        run.note("after")
    rec.close()
    [aside] = _asides(path)
    assert re.fullmatch(r"e\.jsonl\.damaged-\d{8}T\d{12}Z", aside.name)
    assert aside.read_bytes() == damaged
    records = load(path)
    assert records[0]["seq"] == 0 and records[0]["chain_id"] != old_chain
    note = records[0]["attributes"]
    assert note["message"] == "started a new file because the one at this path could not be continued"
    told = note["continues_from"]
    assert told["file"] == aside.name and told["sha256"] == "sha256:" + hashlib.sha256(damaged).hexdigest()
    assert told["reason"] and str(tmp_path) not in told["reason"]
    report = verify_file(path, [pub])
    assert report.ok and report.unsigned_tail == 0
    assert not rec.failures


def test_a_second_restart_resumes_the_new_chain(tmp_path, key, pub):
    path = tmp_path / "e.jsonl"
    _damaged(path, key)
    _resume(path, key, on_damaged="new_file").close()
    first = load(path)
    rec = _resume(path, key, on_damaged="new_file")
    with rec.run() as run:
        run.note("more")
    rec.close()
    assert len(_asides(path)) == 1 and load(path)[0] == first[0]
    assert verify_file(path, [pub]).ok


def test_the_aside_name_is_never_overwritten(tmp_path, key, monkeypatch):
    path = tmp_path / "e.jsonl"
    damaged = _damaged(path, key)

    class Fixed(mnestiq.recorder.datetime):
        @classmethod
        def now(cls, tz=None):
            return cls(2026, 1, 2, 3, 4, 5, 6, tzinfo=tz)

    monkeypatch.setattr(mnestiq.recorder, "datetime", Fixed)
    taken = tmp_path / "e.jsonl.damaged-20260102T030405000006Z"
    taken.write_bytes(b"someone else's file")
    _resume(path, key, on_damaged="new_file").close()
    assert taken.read_bytes() == b"someone else's file"
    assert (tmp_path / f"{taken.name}-1").read_bytes() == damaged


def test_a_reason_is_plain_and_bounded(tmp_path, key):
    path = tmp_path / "e.jsonl"
    records = _closed(path, key)
    records[1]["seq"] = "secret\n" * 1000
    dump(path, records)
    rec = _resume(path, key, on_damaged="new_file")
    reason = load(path)[0]["attributes"]["continues_from"]["reason"]
    rec.close()
    assert len(reason) <= mnestiq.recorder._MAX_REASON and "\n" not in reason


def test_a_line_that_is_not_json_is_a_damaged_file(tmp_path, key):
    path = tmp_path / "e.jsonl"
    _closed(path, key)
    path.write_bytes(path.read_bytes() + b"not json\n")
    _resume(path, key, on_damaged="new_file").close()
    assert load(path)[0]["attributes"]["continues_from"]["reason"] == "a line is not valid JSON"


def test_a_torn_last_line_is_named_in_the_note(tmp_path, key):
    path = tmp_path / "e.jsonl"
    damaged = _damaged(path, key)
    path.write_bytes(damaged + b'{"torn')
    _resume(path, key, on_damaged="new_file").close()
    told = load(path)[0]["attributes"]["continues_from"]
    assert (tmp_path / told["torn_tail"]["sidecar"]).read_bytes() == b'{"torn'


def test_another_key_is_refused_by_default_and_set_aside_on_request(tmp_path, key):
    path = tmp_path / "e.jsonl"
    _closed(path, key)
    before = path.read_bytes()
    other = generate_private_key()
    with pytest.raises(RecorderError, match="signed by"):
        _resume(path, other)
    assert path.read_bytes() == before and not _asides(path)
    _resume(path, other, on_damaged="new_file").close()
    [aside] = _asides(path)
    assert aside.read_bytes() == before
    assert "signed by" in load(path)[0]["attributes"]["continues_from"]["reason"]


def test_another_chain_id_is_refused_by_default_and_set_aside_on_request(tmp_path, key):
    path = tmp_path / "e.jsonl"
    _closed(path, key)
    before = path.read_bytes()
    with pytest.raises(ValueError, match="cannot write chain"):
        _resume(path, key, chain_id="mine")
    assert path.read_bytes() == before and not _asides(path)
    _resume(path, key, chain_id="mine", on_damaged="new_file").close()
    [aside] = _asides(path)
    assert aside.read_bytes() == before
    assert "cannot write chain" in load(path)[0]["attributes"]["continues_from"]["reason"]


def test_only_a_file_sink_can_start_a_new_file(key):
    sink = MemorySink()
    sink.records.append({"not": "evidence"})
    with pytest.raises(RecorderError, match="FileSink"):
        Recorder(sink, agent_id="a", signing_key=key, on_damaged="new_file")
    with pytest.raises(ValueError, match="on_damaged"):
        Recorder(MemorySink(), agent_id="a", signing_key=key, on_damaged="delete")


def test_a_file_that_cannot_be_moved_is_refused_and_left_alone(tmp_path, key, monkeypatch):
    path = tmp_path / "e.jsonl"
    damaged = _damaged(path, key)

    def locked(*args, **kwargs):
        raise PermissionError("locked")

    monkeypatch.setattr(os, "replace", locked)
    with pytest.raises(RecorderError, match="could not be moved aside"):
        _resume(path, key, on_damaged="new_file")
    assert path.read_bytes() == damaged and not _asides(path)


@pytest.mark.skipif(os.name != "nt", reason="only Windows refuses to rename an open file")
def test_a_file_held_open_on_windows_is_refused_and_left_alone(tmp_path, key):
    path = tmp_path / "e.jsonl"
    damaged = _damaged(path, key)
    with open(path, "rb"):  # another program with the file open
        with pytest.raises(RecorderError, match="could not be moved aside"):
            _resume(path, key, on_damaged="new_file")
    assert path.read_bytes() == damaged and not _asides(path)


def test_two_recorders_never_both_get_the_file(tmp_path, key):
    path = tmp_path / "e.jsonl"
    damaged = _damaged(path, key)
    barrier = threading.Barrier(2)
    won, refused, surprises = [], [], []

    def start():
        barrier.wait()
        try:
            won.append(_resume(path, key, on_damaged="new_file"))
        except RecorderError as exc:
            refused.append(exc)
        except Exception as exc:
            surprises.append(exc)

    threads = [threading.Thread(target=start) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not surprises and len(won) + len(refused) == 2 and len(won) <= 1
    for rec in won:
        rec.close()
    if won:
        [aside] = _asides(path)
        assert aside.read_bytes() == damaged
        assert load(path)[0]["attributes"]["continues_from"]["file"] == aside.name
    else:  # the loser's brief hold on the file made the winner refuse too: the file is where it was
        assert path.read_bytes() == damaged and not _asides(path)


# The dashboard.


def _chain_bytes(path, key):
    _closed(path, key)
    return path.read_bytes()


def test_a_tampered_file_behind_junk_lines_is_listed_and_damaged(tmp_path, key):
    path = tmp_path / "e.jsonl"
    original = _chain_bytes(path, key)
    path.write_bytes(b"{}\n" * 200 + original)
    store = EvidenceStore(tmp_path, [])
    assert store.files() == [path.resolve()]
    summary = store.load(path.resolve()).summary
    assert summary["ok"] is False and summary["errors"] >= 1 and "unrecognised" not in summary


def test_an_unrelated_long_file_is_still_not_listed(tmp_path):
    (tmp_path / "proxy.jsonl").write_bytes(b'{"start_time":"x","path":"/"}\n' * 500)
    (tmp_path / "text.jsonl").write_bytes(b"plain text line\n" * 500)
    assert EvidenceStore(tmp_path, []).files() == []


def test_a_file_too_large_to_rule_out_is_listed_and_unrecognised(tmp_path, monkeypatch):
    monkeypatch.setattr(mnestiq.dashboard, "SNIFF_BYTES", 4096)
    big = tmp_path / "big.jsonl"
    big.write_bytes(b"{}\n" * 5000)
    store = EvidenceStore(tmp_path, [])
    [listed] = store.files()
    monkeypatch.setattr("pathlib.Path.read_bytes", lambda self: pytest.fail("read the whole file"))
    loaded = store.load(listed)
    assert loaded.summary["unrecognised"] is True and loaded.summary["ok"] is False
    body = json.loads(loaded.payload)
    assert body["records"] == [] and body["report"]["errors"][0]["code"] == "unrecognised"
    assert body["file"]["unrecognised"] is True


def test_evidence_past_the_first_lines_of_a_large_file_is_recognised(tmp_path, key, monkeypatch):
    path = tmp_path / "e.jsonl"
    monkeypatch.setattr(mnestiq.dashboard, "SNIFF_LINES", 2)
    original = _chain_bytes(path, key)
    path.write_bytes(b"{}\n" * 10 + original)
    assert EvidenceStore(tmp_path, []).files() == [path.resolve()]


def test_a_file_that_cannot_be_read_is_listed_as_unrecognised(tmp_path, monkeypatch):
    (tmp_path / "e.jsonl").write_bytes(b"{}\n")

    def unreadable(fh):
        raise OSError("no")

    monkeypatch.setattr(mnestiq.dashboard, "_sniff_file", unreadable)
    store = EvidenceStore(tmp_path, [])
    [listed] = store.files()
    assert store.load(listed).summary["unrecognised"] is True


def test_a_set_aside_file_is_still_listed(tmp_path, key):
    path = tmp_path / "e.jsonl"
    damaged = _damaged(path, key)
    _resume(path, key, on_damaged="new_file").close()
    store = EvidenceStore(tmp_path, [])
    names = {p.name for p in store.files()}
    [aside] = _asides(path)
    assert names == {"e.jsonl", aside.name}
    assert store.load(aside.resolve()).summary["ok"] is False and aside.read_bytes() == damaged


def test_the_page_shows_an_unrecognised_file(tmp_path):
    page = (mnestiq.dashboard.resources.files("mnestiq.dashboard").joinpath("index.html")).read_text("utf-8")
    assert "unrecognised" in page and "Unrecognised" in page


# What a review found: one test for each.


def _flip_a_byte(path):
    raw = bytearray(path.read_bytes())
    raw[40] ^= 1
    path.write_bytes(raw)


def test_a_new_chain_says_what_it_replaced_even_when_the_old_file_is_gone(tmp_path, key, pub, capsys):
    path = tmp_path / "e.jsonl"
    _closed(path, key)
    _flip_a_byte(path)
    with _resume(path, key, on_damaged="new_file") as rec, rec.run() as run:
        run.note("after")
    [aside] = _asides(path)
    aside.unlink()
    report = verify_file(path, [pub])
    assert report.ok
    [warning] = [w for w in report.warnings if w.code == "continues_from"]
    assert aside.name in warning.message and warning.seq == 0
    assert report.continues_from[0]["file"] == aside.name and report.continues_from[0]["note_seq"] == 0
    capsys.readouterr()
    assert main(["verify", str(path), "--trusted-key", pub, "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["continues_from"][0]["file"] == aside.name
    page = json.loads(EvidenceStore(path, [pub]).load(path).payload)
    assert page["report"]["continues_from"][0]["file"] == aside.name
    assert "continues_from" in (Path(mnestiq.dashboard.__file__).parent / "index.html").read_text("utf-8")


@pytest.mark.parametrize("claim", [{"file": 1, "sha256": "x", "reason": "y"}, {"file": "a"}, [], "x", None])
def test_a_note_of_the_wrong_shape_does_not_claim_a_replaced_file(tmp_path, key, pub, claim):
    path = tmp_path / "e.jsonl"
    rec = Recorder(FileSink(path), agent_id="a", signing_key=key)
    rec.append_event({"event_type": "note", "run_id": f"recorder-{rec.chain_id[:8]}", "agent_id": "a",
                      "attributes": {"continues_from": claim}})
    rec.close()
    report = verify_file(path, [pub])
    assert report.ok and not report.continues_from


def test_a_replaced_file_note_after_the_first_checkpoint_is_only_a_note(tmp_path, key, pub):
    path = tmp_path / "e.jsonl"
    rec = Recorder(FileSink(path), agent_id="a", signing_key=key, checkpoint_every=1000)
    with rec.run() as run:
        run.note("signed")
    rec.checkpoint()
    rec.append_event({"event_type": "note", "run_id": f"recorder-{rec.chain_id[:8]}", "agent_id": "a",
                      "attributes": {"continues_from": {"file": "f", "sha256": "s", "reason": "r"}}})
    rec.close()
    report = verify_file(path, [pub])
    assert report.ok and not report.continues_from


@pytest.mark.parametrize("damage", [lambda r: r[:-1] + b"\n", lambda r: b"x" + r + b"\n", lambda r: b"[" + r + b"]\n"])
def test_a_short_file_with_every_line_damaged_is_listed(tmp_path, key, damage):
    path = tmp_path / "e.jsonl"
    lines = _chain_bytes(path, key).splitlines()
    path.write_bytes(b"".join(damage(line) for line in lines))
    store = EvidenceStore(tmp_path, [])
    assert store.files() == [path.resolve()]
    assert store.load(path.resolve()).summary["ok"] is False


class _FailsOnce(FileSink):
    """Refuses the first record it is asked to write."""

    failed = False

    def append(self, record):
        if not self.failed:
            self.failed = True
            raise OSError("disk full for a moment")
        super().append(record)


def test_a_lost_unclean_note_is_written_before_anything_is_signed(tmp_path, key, pub):
    path = tmp_path / "e.jsonl"
    before = _ended_right_after_a_checkpoint(path, key)
    with pytest.warns(RuntimeWarning, match="disk full"):
        rec = Recorder(_FailsOnce(path), agent_id="a", signing_key=key, retry_after=0)
    with rec.run() as run:
        run.note("next session")
    rec.close()
    report = verify_file(path, [pub])
    assert report.ok and report.unsigned_tail == 0 and len(_unclean(report)) == 1
    assert report.unclean_restarts[0]["checkpoint_seq"] == before[-1]["seq"]
    new = load(path)[len(before):]
    first_checkpoint = next(i for i, r in enumerate(new) if r["kind"] == "checkpoint")
    assert _notes(new[:first_checkpoint], UNCLEAN_RESUME_FIELD)


def test_no_checkpoint_is_signed_until_the_unclean_note_is_written(tmp_path, key):
    path = tmp_path / "e.jsonl"
    before = _ended_right_after_a_checkpoint(path, key)

    class NoRoom(FileSink):
        def append(self, record):
            if UNCLEAN_RESUME_FIELD in (record.get("attributes") or {}):
                raise OSError("no room for the note")
            super().append(record)

    with pytest.warns(RuntimeWarning, match="no room for the note"):
        rec = Recorder(NoRoom(path), agent_id="a", signing_key=key, retry_after=0)
    with rec.run() as run:
        run.note("waits")
    with pytest.raises(RecorderError, match="no room for the note"):
        rec.checkpoint()
    rec._sink.close()
    assert not [r for r in load(path)[len(before):] if r["kind"] == "checkpoint"]


def test_a_lost_continues_from_note_is_written_before_anything_is_signed(tmp_path, key, pub, monkeypatch):
    path = tmp_path / "e.jsonl"
    _damaged(path, key)
    sink = FileSink(path)
    real, calls = FileSink.append, []

    def once(self, record):
        calls.append(record)
        if len(calls) == 1:
            raise OSError("disk full for a moment")
        real(self, record)

    monkeypatch.setattr(FileSink, "append", once)
    with pytest.warns(RuntimeWarning, match="disk full"):
        rec = Recorder(sink, agent_id="a", signing_key=key, on_damaged="new_file", retry_after=0)
    with rec.run() as run:
        run.note("new chain")
    rec.close()
    report = verify_file(path, [pub])
    assert report.ok and len(report.continues_from) == 1


def test_a_new_chain_under_a_signing_service_gets_a_new_id(tmp_path):
    folder = tmp_path / "service"
    signer = init_signer(folder)
    service = SignerService(folder)

    class Client:
        sig_alg, public_key = signer.sig_alg, signer.public_key

        def sign(self, payload):
            return service.sign(payload)

    path = tmp_path / "e.jsonl"
    with Recorder(FileSink(path), agent_id="a", signer=Client(), chain_id="fixed") as rec, rec.run() as run:
        run.note("x")
    _flip_a_byte(path)
    rec = Recorder(FileSink(path), agent_id="a", signer=Client(), chain_id="fixed", on_damaged="new_file")
    with rec.run() as run:
        run.note("new")
    rec.close()
    records = load(path)
    assert rec.failures == 0 and records[-1]["kind"] == "checkpoint"
    assert records[0]["chain_id"] != "fixed" and records[0]["chain_id"].startswith("fixed-")
    rec = Recorder(FileSink(path), agent_id="a", signer=Client(), chain_id="fixed", on_damaged="new_file")
    rec.close()
    assert len(_asides(path)) == 1 and rec.chain_id == records[0]["chain_id"]


def test_a_file_over_the_size_limit_is_not_read(tmp_path, key, monkeypatch):
    path = tmp_path / "e.jsonl"
    _chain_bytes(path, key)
    monkeypatch.setattr(mnestiq.dashboard, "MAX_LOAD_BYTES", 10)
    monkeypatch.setattr("pathlib.Path.read_bytes", lambda self: pytest.fail("read the whole file"))
    assert EvidenceStore(path, []).load(path).summary["unrecognised"] is True


def test_checking_stops_at_the_cap_and_says_so(tmp_path, monkeypatch):
    monkeypatch.setattr(mnestiq.dashboard, "MAX_ERRORS", 5)
    monkeypatch.setattr(mnestiq.dashboard, "_VERIFY_BATCH", 10)
    path = tmp_path / "e.jsonl"
    path.write_bytes(b'{"spec_version":"1.0","chain_id":"x"}\n' + b"x\n" * 5000)
    body = json.loads(EvidenceStore(tmp_path, []).load(path.resolve()).payload)
    assert body["report"]["errors"][0]["code"] == "too_many_errors" and body["file"]["ok"] is False
    assert body["records_total"] < 100


def test_a_file_with_its_newlines_removed_is_damage_and_not_a_torn_line(tmp_path, key):
    path = tmp_path / "e.jsonl"
    original = _chain_bytes(path, key)
    flat = original.replace(b"\n", b" ").rstrip()
    path.write_bytes(flat)
    with pytest.raises(RecorderError):
        _resume(path, key)
    assert path.read_bytes() == flat and not list(tmp_path.glob("*.torn-*"))
    _resume(path, key, on_damaged="new_file").close()
    [aside] = _asides(path)
    assert aside.read_bytes() == flat and not list(tmp_path.glob("*.torn-*"))


def test_a_recorder_that_lost_the_path_to_another_is_refused(tmp_path, key, pub, monkeypatch):
    path = tmp_path / "e.jsonl"
    _damaged(path, key)
    real = os.replace

    def racing(a, b):
        real(a, b)
        monkeypatch.setattr(os, "replace", real)
        with Recorder(FileSink(path), agent_id="other", signing_key=key) as rec, rec.run() as run:
            run.note("got here first")

    monkeypatch.setattr(os, "replace", racing)
    with pytest.raises(RecorderError, match="another recorder"):
        _resume(path, key, on_damaged="new_file")
    assert load(path)[0]["agent_id"] == "other" and verify_file(path, [pub]).ok


def test_a_line_only_the_recorder_called_blank_is_refused(tmp_path, key):
    path = tmp_path / "e.jsonl"
    _closed(path, key)
    path.write_bytes(path.read_bytes() + b"\x0b\n")
    with pytest.raises(RecorderError):
        _resume(path, key)
    _resume(path, key, on_damaged="new_file").close()
    assert len(_asides(path)) == 1


def _with_forged_newer_checkpoint(path, key):
    """A signed start, then a forged clean close under a checkpoint nobody here can check."""
    rec = Recorder(FileSink(path), agent_id="a", signing_key=key, checkpoint_every=1000)
    with rec.run() as run:
        run.note("before")
    rec.checkpoint()
    rec._sink.close()
    records = load(path)
    last = records[-1]
    note = {"spec_version": "1.0", "kind": "event", "chain_id": last["chain_id"], "seq": last["seq"] + 1,
            "ts": last["ts"], "prev_hash": last["record_hash"], "event_type": "heartbeat",
            "run_id": f"recorder-{last['chain_id'][:8]}", "agent_id": "a",
            "attributes": {"message": "recorder closed normally", CLEAN_CLOSE_FIELD: True}}
    note["record_hash"] = record_hash(note)
    checkpoint = {"spec_version": "1.1", "kind": "checkpoint", "chain_id": last["chain_id"], "seq": note["seq"] + 1,
                  "ts": last["ts"], "prev_hash": note["record_hash"],
                  "covers": {"from_seq": note["seq"], "to_seq": note["seq"]},
                  "merkle_root": "sha256:" + merkle_root([digest_bytes(note["record_hash"])]).hex(),
                  "sig_alg": "future-alg", "key_id": last["key_id"], "public_key": last["public_key"],
                  "signature": "QUJD"}
    checkpoint["record_hash"] = record_hash(checkpoint)
    dump(path, [*records, note, checkpoint])


def test_a_checkpoint_this_version_cannot_check_is_not_resumed_over(tmp_path, key):
    path = tmp_path / "e.jsonl"
    _with_forged_newer_checkpoint(path, key)
    before = path.read_bytes()
    with pytest.raises(RecorderError, match="cannot check"):
        _resume(path, key)
    assert path.read_bytes() == before
    _resume(path, key, on_damaged="new_file").close()
    assert len(_asides(path)) == 1


def test_a_file_that_goes_away_during_a_listing_does_not_end_it(tmp_path, monkeypatch):
    first = tmp_path / "a.jsonl"
    second = tmp_path / "b.jsonl"
    for path in (first, second):
        path.write_bytes(b'{"spec_version":"1.0","chain_id":"x"}\n')
    real = Path.is_file

    def goes_away(self):
        answer = real(self)
        if answer and self.name == "a.jsonl":
            self.unlink()
        return answer

    monkeypatch.setattr(Path, "is_file", goes_away)
    assert [p.name for p in EvidenceStore(tmp_path, []).files()] == ["b.jsonl"]


@pytest.mark.parametrize("late", [b'{"spec_version":1}\n{"chain_id":2}\n', b'"spec_version" "chain_id"\n',
                                  b'{"m":"\\"spec_version\\": \\"chain_id\\":"}\n'])
def test_the_two_marks_must_be_keys_on_one_line(tmp_path, late):
    (tmp_path / "other.jsonl").write_bytes(b'{"a":1}\n' * 300 + late)
    assert EvidenceStore(tmp_path, []).files() == []


def test_the_two_marks_are_found_across_the_pieces_of_a_long_line(tmp_path, monkeypatch):
    monkeypatch.setattr(mnestiq.dashboard, "_SNIFF_PIECE", 64)
    monkeypatch.setattr(mnestiq.dashboard, "SNIFF_LINES", 1)
    path = tmp_path / "e.jsonl"
    path.write_bytes(b'{"a":1}\n' + b'{"chain_id":"x","pad":"' + b"y" * 500 + b'","spec_version":"1.0"\n')
    assert EvidenceStore(tmp_path, []).files() == [path.resolve()]
