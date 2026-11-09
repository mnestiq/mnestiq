"""A recorder cannot tell whether records it takes over unsigned were changed while it was down. It says in the
chain that it took them over, so a later signature over them is never mistaken for one made as they were written."""

import base64
import contextlib
import json
import warnings
from pathlib import Path

import pytest

from conftest import dump, load
from mnestiq import FileSink, Recorder
from mnestiq.canonical import MAX_SAFE_INTEGER, canonical_json, parse_json
from mnestiq.cli import main
from mnestiq.context import expanded
from mnestiq.dashboard import EvidenceStore
from mnestiq.findings import findings
from mnestiq.hashing import digest_bytes, record_hash, signing_payload
from mnestiq.keys import key_id
from mnestiq.merkle import merkle_root
from mnestiq.signers import as_signer
from mnestiq.sinks import RecorderError
from mnestiq.verify import RESTART_FIELD, verify_file, verify_lines

CODE = "signed_after_restart"
REPOSITORY = Path(__file__).resolve().parents[2]
VECTORS = REPOSITORY / "spec" / "vectors"


def _crashed(path, key, tail=4):
    """A run that signed its first records, then died with ``tail`` records not signed. Those start at seq 3."""
    rec = Recorder(FileSink(path), agent_id="a", signing_key=key, checkpoint_every=1000)
    with rec.run() as run:
        run.note("signed")
        rec.checkpoint()
        for number in range(tail - 1):
            run.note(f"unsigned {number}")
    rec._sink.close()
    return load(path)


def _resume(path, key, **options):
    return Recorder(FileSink(path), agent_id="a", signing_key=key, **options)


def _restart_notes(records):
    return [r for r in records if RESTART_FIELD in (r.get("attributes") or {})]


def _warnings(report):
    return [w for w in report.warnings if w.code == CODE]


def _codes(report):
    return {e.code for e in report.errors}


def _redo_hashes(records, start):
    for i in range(start, len(records)):
        records[i]["prev_hash"] = records[i - 1]["record_hash"]
        records[i]["record_hash"] = record_hash(records[i])


def _note(chain_id, claim):
    return {"event_type": "note", "run_id": f"recorder-{chain_id[:8]}", "agent_id": "a",
            "attributes": {"message": "resumed", RESTART_FIELD: claim}}


def test_a_resume_writes_the_note_first_and_the_next_checkpoint_covers_it(tmp_path, key, pub):
    path = tmp_path / "e.jsonl"
    before = _crashed(path, key)
    rec = _resume(path, key)
    note = load(path)[len(before)]
    assert note["seq"] == before[-1]["seq"] + 1 and note["event_type"] == "note"
    assert note["attributes"][RESTART_FIELD] == {"first_seq": 3, "last_seq": 6, "count": 4}
    assert note["run_id"] == f"recorder-{before[0]['chain_id'][:8]}"
    with rec.run() as run:
        run.note("after the restart")
    rec.close()
    records = load(path)
    assert len(_restart_notes(records)) == 1
    assert records[-1]["kind"] == "checkpoint"
    assert records[-1]["covers"] == {"from_seq": 3, "to_seq": records[-2]["seq"]}
    report = verify_file(path, [pub])
    assert report.ok and report.unsigned_tail == 0
    [warning] = _warnings(report)
    assert warning.seq == note["seq"] and "records 3..6 " in warning.message


def test_a_resume_and_nothing_else_is_still_signed_on_close(tmp_path, key, pub):
    path = tmp_path / "e.jsonl"
    _crashed(path, key)
    _resume(path, key).close()
    report = verify_file(path, [pub])
    assert report.ok and report.unsigned_tail == 0 and len(_warnings(report)) == 1


def test_a_clean_restart_writes_nothing(tmp_path, key, pub):
    path = tmp_path / "e.jsonl"
    with Recorder(FileSink(path), agent_id="a", signing_key=key) as rec, rec.run() as run:
        run.note("signed")
    before = path.read_bytes()
    _resume(path, key).close()
    assert path.read_bytes() == before
    assert not _warnings(verify_file(path, [pub]))


def test_a_clean_restart_then_more_records_gets_no_warning(tmp_path, key, pub):
    path = tmp_path / "e.jsonl"
    with Recorder(FileSink(path), agent_id="a", signing_key=key) as rec, rec.run() as run:
        run.note("signed")
    with _resume(path, key) as rec, rec.run() as run:
        run.note("later")
    assert not _restart_notes(load(path))
    assert not _warnings(verify_file(path, [pub]))


def test_a_new_file_writes_no_note(tmp_path, key):
    path = tmp_path / "e.jsonl"
    Recorder(FileSink(path), agent_id="a", signing_key=key).close()
    assert not load(path)


def test_a_recorder_without_a_signer_writes_no_note(tmp_path, key):
    path = tmp_path / "e.jsonl"
    before = _crashed(path, key)
    with Recorder(FileSink(path), agent_id="a") as rec, rec.run() as run:
        run.note("no key here")
    assert len(load(path)) > len(before)
    assert not _restart_notes(load(path))


def test_a_rewritten_unsigned_end_verifies_with_the_warning(tmp_path, key, pub):
    path = tmp_path / "e.jsonl"
    records = _crashed(path, key)
    changed = next(i for i, r in enumerate(records) if r["seq"] == 4)
    records[changed]["attributes"]["message"] = "this is not what happened"
    _redo_hashes(records, changed)
    dump(path, records)
    _resume(path, key).close()
    report = verify_file(path, [pub])
    assert report.ok  # the known limit: the recorder cannot tell, and the rewrite still verifies
    [warning] = _warnings(report)
    assert "records 3..6 " in warning.message and "hash chain alone" in warning.message


def test_a_shortened_unsigned_end_verifies_with_the_warning(tmp_path, key, pub):
    path = tmp_path / "e.jsonl"
    records = _crashed(path, key)
    dump(path, records[:-2])
    _resume(path, key).close()
    report = verify_file(path, [pub])
    assert report.ok
    [warning] = _warnings(report)
    assert "records 3..4 " in warning.message


def test_removing_the_whole_unsigned_end_leaves_a_warning(tmp_path, key, pub):
    # The attack: with nothing left after the last checkpoint, only the missing clean close tells it from a restart.
    path = tmp_path / "e.jsonl"
    records = _crashed(path, key)
    dump(path, records[:3])
    _resume(path, key).close()
    report = verify_file(path, [pub])
    assert report.ok and not _warnings(report)
    [warning] = [w for w in report.warnings if w.code == "resumed_without_clean_close"]
    assert warning.seq == 3 and "checkpoint at seq 2" in warning.message and "Check this" in warning.message
    assert report.unclean_restarts == [{"note_seq": 3, "checkpoint_seq": 2}]


def test_a_note_not_yet_signed_is_no_claim_that_anything_was_signed(tmp_path, key, pub):
    path = tmp_path / "e.jsonl"
    _crashed(path, key)
    rec = _resume(path, key)
    rec._sink.close()
    report = verify_file(path, [pub])
    assert report.ok and not _warnings(report)
    assert "unsigned_tail" in {w.code for w in report.warnings}


def test_crashing_twice_gives_one_warning_for_the_widest_range(tmp_path, key, pub):
    path = tmp_path / "e.jsonl"
    _crashed(path, key)
    first = _resume(path, key)
    with first.run() as run:
        run.note("between the crashes")
    first._sink.close()
    _resume(path, key).close()
    records = load(path)
    assert len(_restart_notes(records)) == 2
    last = _restart_notes(records)[-1]["attributes"][RESTART_FIELD]["last_seq"]
    report = verify_file(path, [pub])
    assert report.ok
    [warning] = _warnings(report)
    assert f"records 3..{last} " in warning.message


def test_the_chain_can_be_fed_in_parts(tmp_path, key, pub):
    from mnestiq.verify import ChainVerifier

    path = tmp_path / "e.jsonl"
    _crashed(path, key)
    _resume(path, key).close()
    lines = path.read_bytes().splitlines()
    verifier = ChainVerifier([pub])
    for line in lines:
        verifier.feed([line])
    assert verifier.result().to_dict() == verify_lines(lines, [pub]).to_dict()


class _NoRoomForTheNote(FileSink):
    """Takes every record except the restart note, which is what must hold back a signature."""

    rejecting = True

    def append(self, record):
        if self.rejecting and RESTART_FIELD in (record.get("attributes") or {}):
            raise OSError("no room for the note")
        super().append(record)


def _checkpoints_after(path, before):
    return [r for r in load(path)[len(before):] if r["kind"] == "checkpoint"]


def test_no_checkpoint_is_written_until_the_note_is(tmp_path, key, pub):
    path = tmp_path / "e.jsonl"
    before = _crashed(path, key)
    sink = _NoRoomForTheNote(path)
    with pytest.warns(RuntimeWarning, match="no room for the note"):
        rec = Recorder(sink, agent_id="a", signing_key=key, checkpoint_every=1, retry_after=0)
    assert rec.failures == 1
    with rec.run() as run:
        run.note("written, and not signed")
    assert len(load(path)) > len(before) and not _checkpoints_after(path, before)
    with pytest.raises(RecorderError, match="no room for the note"):
        rec.checkpoint()
    assert not _checkpoints_after(path, before)
    sink.rejecting = False
    rec.close()
    records = load(path)
    assert records[-1]["kind"] == "checkpoint" and records[-3]["event_type"] == "note"
    assert records[-3]["attributes"][RESTART_FIELD] == {"first_seq": 3, "last_seq": 6, "count": 4}
    report = verify_file(path, [pub])
    assert report.ok
    [warning] = _warnings(report)
    assert "records 3..6 " in warning.message


def test_a_failed_note_backs_off_and_does_not_say_evidence_is_lost(tmp_path, key):
    path = tmp_path / "e.jsonl"
    before = _crashed(path, key)
    with warnings.catch_warnings(record=True) as seen:
        warnings.simplefilter("always")
        rec = Recorder(_NoRoomForTheNote(path), agent_id="a", signing_key=key, checkpoint_every=1, retry_after=3600)
        with rec.run() as run:
            for number in range(5):
                run.note(str(number))
    assert rec.failures == 1  # one failed attempt, not one for each event that wanted a checkpoint
    rec._sink.close()
    assert [str(w.message) for w in seen if "not being recorded" in str(w.message)] == []
    assert len([w for w in seen if "No checkpoint is signed" in str(w.message)]) == 1
    assert len(load(path)) == len(before) + 7 and not _checkpoints_after(path, before)


def test_strict_raises_when_the_note_cannot_be_written(tmp_path, key):
    path = tmp_path / "e.jsonl"
    _crashed(path, key)
    with pytest.raises(RecorderError, match="no room for the note"):
        Recorder(_NoRoomForTheNote(path), agent_id="a", signing_key=key, strict=True)


def test_a_recorder_with_no_name_of_its_own_still_writes_the_note(tmp_path, key, pub):
    path = tmp_path / "e.jsonl"
    _crashed(path, key)
    rec = Recorder(FileSink(path), agent_id="", signing_key=key, checkpoint_every=2)
    with rec.run(agent_id="b") as run:
        run.note("named by the run")
    rec.close()
    assert rec.failures == 0
    report = verify_file(path, [pub])
    assert report.ok and len(_warnings(report)) == 1 and report.unsigned_tail == 0


def test_a_later_checkpoint_does_not_repeat_the_warning(tmp_path, key, pub):
    path = tmp_path / "e.jsonl"
    _crashed(path, key)
    with _resume(path, key) as rec, rec.run() as run:
        rec.checkpoint()
        run.note("signed as it was written")
        rec.checkpoint()
        run.note("and this")
    report = verify_file(path, [pub])
    assert report.ok and report.checkpoints >= 3
    assert len(_warnings(report)) == 1 and len(report.restarts) == 1


def test_a_record_of_another_type_with_the_same_shape_is_not_the_note(tmp_path, key, pub):
    path = tmp_path / "e.jsonl"
    rec = Recorder(FileSink(path), agent_id="a", signing_key=key, checkpoint_every=1000)
    with rec.run() as run:
        run.note("first")
        rec.append_event({**_note(rec.chain_id, GOOD), "event_type": "heartbeat"})
    rec.close()
    report = verify_file(path, [pub])
    assert report.ok and not _warnings(report)


@pytest.mark.parametrize("damage", ["signed_record", "checkpoint", "content"])
def test_resuming_still_refuses_a_signed_part_that_was_changed(tmp_path, key, damage):
    path = tmp_path / "e.jsonl"
    with Recorder(FileSink(path), agent_id="a", signing_key=key, checkpoint_every=1000) as rec, rec.run() as run:
        run.tool_call("t", {"a": 1}, "result")
        rec.checkpoint()
        run.note("later")
    records = load(path)
    target = next(r for r in records if r.get("event_type") == "tool_call")
    if damage == "signed_record":
        target["step_id"] = 777
        _redo_hashes(records, records.index(target))
    elif damage == "checkpoint":
        checkpoint = next(i for i, r in enumerate(records) if r["kind"] == "checkpoint")
        records[checkpoint]["ts"]["wall"] = "2020-01-01T00:00:00.000000Z"
        _redo_hashes(records, checkpoint)
    else:
        target["tool_calls"][0]["result"] = "not what the tool said"
    dump(path, records)
    with pytest.raises(RecorderError):
        _resume(path, key)


def test_resuming_refuses_a_schema_break_after_the_last_checkpoint(tmp_path, key):
    path = tmp_path / "e.jsonl"
    records = _crashed(path, key)
    records[-2]["step_id"] = "not a number"
    _redo_hashes(records, len(records) - 2)
    dump(path, records)
    with pytest.raises(RecorderError, match="schema"):
        _resume(path, key)


def test_a_checkpoint_whose_signature_cannot_be_checked_does_not_excuse_the_schema(tmp_path, key):
    path = tmp_path / "e.jsonl"
    records = _crashed(path, key)
    records[-2]["step_id"] = "not a number"
    _redo_hashes(records, len(records) - 2)
    records.append(_checkpoint_over(records, key, spec_version="1.1", sig_alg="ml-dsa-65"))
    dump(path, records)
    with pytest.raises(RecorderError, match="schema"):
        _resume(path, key)


def test_a_long_unsigned_stretch_is_schema_checked_too(tmp_path, key, monkeypatch):
    monkeypatch.setattr("mnestiq.recorder._SCHEMA_WINDOW", 2)
    path = tmp_path / "e.jsonl"
    records = _crashed(path, key, tail=8)
    records[4]["step_id"] = "not a number"
    _redo_hashes(records, 4)
    dump(path, records)
    with pytest.raises(RecorderError, match="schema"):
        _resume(path, key)


def test_a_checkpoint_that_cannot_be_checked_is_not_said_to_have_signed_anything(tmp_path, key, pub):
    path = tmp_path / "e.jsonl"
    _crashed(path, key)
    _resume(path, key)._sink.close()
    records = load(path)
    records.append(_checkpoint_over(records, key, spec_version="1.1", sig_alg="ml-dsa-65"))
    dump(path, records)
    report = verify_file(path)
    [warning] = _warnings(report)
    assert "were signed" not in warning.message and "cannot check" in warning.message
    assert "records 3..6 " in warning.message and not report.restarts


def test_the_warning_reaches_the_command_line_and_the_dashboard(tmp_path, key, pub, capsys):
    path = tmp_path / "e.jsonl"
    _crashed(path, key)
    _resume(path, key).close()
    capsys.readouterr()
    assert main(["verify", str(path), "--trusted-key", pub]) == 0
    out = capsys.readouterr()
    assert f"warning [line 8, seq 7] {CODE}: records 3..6 " in out.out + out.err
    assert main(["verify", str(path), "--trusted-key", pub, "--json"]) == 0
    assert any(w["code"] == CODE for w in json.loads(capsys.readouterr().out)["warnings"])
    page = json.loads(EvidenceStore(path, [pub]).load(path).payload)
    assert page["file"]["ok"] is True and page["file"]["warnings"] >= 1
    assert [w["seq"] for w in page["report"]["warnings"] if w["code"] == CODE] == [7]
    assert page["report"]["restarts"] == [{"from_seq": 3, "to_seq": 6, "checkpoint_seq": 9}]


def test_evidence_from_before_this_note_does_not_start_warning():
    if not (VECTORS / "valid.jsonl").exists():  # the source package on PyPI has no spec folder
        pytest.skip("needs spec/vectors from the repository")
    assert not _warnings(verify_lines((VECTORS / "valid.jsonl").read_bytes().splitlines()))


def test_a_note_written_through_a_run_is_only_a_note(tmp_path, key, pub):
    path = tmp_path / "e.jsonl"
    with Recorder(FileSink(path), agent_id="a", signing_key=key) as rec, rec.run() as run:
        run.note("x", **{RESTART_FIELD: {"first_seq": 0, "last_seq": 0, "count": 1}})
    report = verify_file(path, [pub])
    assert report.ok and not _warnings(report)


def _signed_with_note(path, key, claim):
    """A signed file with a recorder-shaped note after seq 0 and 1, among the records of its only checkpoint."""
    rec = Recorder(FileSink(path), agent_id="a", signing_key=key, checkpoint_every=1000)
    with rec.run() as run:
        run.note("first")
        rec.append_event(_note(rec.chain_id, claim))
    rec.close()


GOOD = {"first_seq": 0, "last_seq": 1, "count": 2}
WRONG_TYPES = (("text", "0"), ("float", 0.5), ("true", True), ("false", False), ("null", None), ("list", [0]),
               ("object", {}))
HOSTILE = {
    "number": 5, "list": [0, 1, 2], "text": "0..1", "null": None, "true": True, "empty": {},
    **{f"no_{name}": {k: v for k, v in GOOD.items() if k != name} for name in GOOD},
    **{f"{name}_{label}": {**GOOD, name: bad} for name in GOOD for label, bad in WRONG_TYPES},
    "negative_first": {**GOOD, "first_seq": -1},
    "negative_last": {**GOOD, "last_seq": -1},
    "negative_count": {**GOOD, "count": -2},
    "zero_count": {**GOOD, "count": 0},
    "count_too_large": {**GOOD, "count": 3},
    "inverted": {"first_seq": 1, "last_seq": 0, "count": 2},
    "wrong_start": {"first_seq": 1, "last_seq": 1, "count": 1},
    "past_the_end": {"first_seq": 0, "last_seq": 2, "count": 3},
    "huge_range": {"first_seq": 0, "last_seq": MAX_SAFE_INTEGER - 1, "count": MAX_SAFE_INTEGER},
    "huge_count": {**GOOD, "count": MAX_SAFE_INTEGER},
    "count_too_small": {**GOOD, "count": 1},
}


def _parsed(path):
    out = []
    for line in path.read_bytes().splitlines():
        with contextlib.suppress(ValueError, RecursionError):
            out.append(parse_json(line))
    return out


def _every_reader(path, pub, tmp_path):
    report = verify_file(path, [pub])
    json.dumps(report.to_dict())
    expanded(_parsed(path))
    findings(_parsed(path))
    assert main(["verify", str(path), "--trusted-key", pub]) in (0, 1)
    assert main(["inspect", str(path)]) in (0, 1)
    out = tmp_path / "redacted.jsonl"
    out.unlink(missing_ok=True)
    assert main(["redact", str(path), str(out)]) in (0, 2)
    json.loads(EvidenceStore(path, [pub]).load(path).payload)
    return report


@pytest.mark.parametrize("claim", HOSTILE.values(), ids=HOSTILE.keys())
def test_a_hostile_note_is_only_a_note_to_every_reader(tmp_path, key, pub, claim):
    path = tmp_path / "e.jsonl"
    _signed_with_note(path, key, claim)
    report = _every_reader(path, pub, tmp_path)
    assert report.ok and not report.errors
    assert not _warnings(report)


@pytest.mark.parametrize("claim", HOSTILE.values(), ids=HOSTILE.keys())
def test_a_hostile_note_does_not_hide_a_later_restart(tmp_path, key, pub, claim):
    path = tmp_path / "e.jsonl"
    rec = Recorder(FileSink(path), agent_id="a", signing_key=key, checkpoint_every=1000)
    with rec.run() as run:
        run.note("first")
        rec.append_event(_note(rec.chain_id, claim))
    rec._sink.close()
    tail = load(path)
    _resume(path, key).close()
    report = verify_file(path, [pub])
    assert report.ok
    [warning] = _warnings(report)
    assert f"records 0..{tail[-1]['seq']} " in warning.message


@pytest.mark.parametrize("claim", HOSTILE.values(), ids=HOSTILE.keys())
def test_a_hostile_note_does_not_suppress_an_error(tmp_path, key, pub, claim):
    path = tmp_path / "e.jsonl"
    _signed_with_note(path, key, claim)
    records = load(path)
    records[1]["attributes"]["message"] = "changed after signing"
    dump(path, records)
    report = verify_file(path, [pub])
    assert not report.ok and "record_hash" in _codes(report)


def _checkpoint_over(records, key, spec_version="1.0", sig_alg=None):
    """A checkpoint signed with the chain's key over the records after the last one, as a recorder would write it."""
    start = max(i for i, r in enumerate(records) if r["kind"] == "checkpoint") + 1
    covered = records[start:]
    signer = as_signer(key)
    checkpoint = {"spec_version": spec_version, "kind": "checkpoint", "chain_id": records[0]["chain_id"],
                  "seq": records[-1]["seq"] + 1, "ts": records[-1]["ts"], "prev_hash": records[-1]["record_hash"],
                  "covers": {"from_seq": covered[0]["seq"], "to_seq": covered[-1]["seq"]},
                  "merkle_root": "sha256:" + merkle_root([digest_bytes(r["record_hash"]) for r in covered]).hex(),
                  "sig_alg": sig_alg or signer.sig_alg, "key_id": key_id(signer.public_key),
                  "public_key": signer.public_key}
    checkpoint["signature"] = base64.b64encode(signer.sign(signing_payload(checkpoint))).decode("ascii")
    checkpoint["record_hash"] = record_hash(checkpoint)
    return checkpoint


# The attributes as they stand in the file, and the only error codes the file may then have.
RAW_ATTRIBUTES = {
    "a_number": ("5", {"schema"}),
    "a_list": ("[1,2]", {"schema"}),
    "null": ("null", {"schema"}),
    "text": ('"x"', {"schema"}),
    "very_large": (f'{{"{RESTART_FIELD}":{{"first_seq":1e30,"last_seq":1e30,"count":1}}}}', set()),
    "too_many_digits": (f'{{"{RESTART_FIELD}":{{"first_seq":{"9" * 5000},"last_seq":1,"count":1}}}}', {"parse"}),
    "past_a_double": (f'{{"{RESTART_FIELD}":{{"first_seq":0,"last_seq":{"9" * 400},"count":1}}}}', {"parse"}),
    "infinite": (f'{{"{RESTART_FIELD}":{{"first_seq":1e999,"last_seq":1,"count":1}}}}', {"parse"}),
    "duplicate_key": (f'{{"{RESTART_FIELD}":{{"count":1,"count":2}}}}', {"parse"}),
    "nested_too_deep": (f'{{"{RESTART_FIELD}":{"[" * 100_000}{"]" * 100_000}}}', {"parse"}),
}


@pytest.mark.parametrize(("raw", "codes"), RAW_ATTRIBUTES.values(), ids=RAW_ATTRIBUTES.keys())
def test_a_line_no_recorder_could_write_with_a_true_hash_under_a_real_signature(tmp_path, key, pub, raw, codes):
    path = tmp_path / "e.jsonl"
    records = _crashed(path, key)
    last = records[-1]
    note = {"spec_version": "1.0", "kind": "event", "chain_id": last["chain_id"], "seq": last["seq"] + 1,
            "ts": last["ts"], "prev_hash": last["record_hash"], **_note(last["chain_id"], None), "attributes": "@@"}
    text = json.dumps(note).replace('"@@"', raw)
    try:
        parsed = parse_json(text)
    except (ValueError, RecursionError):
        parsed = None
    if parsed is not None:
        parsed["record_hash"] = record_hash(parsed)
        text = f'{text[:-1]},"record_hash":"{parsed["record_hash"]}"}}'
    checkpoint = _checkpoint_over([*records, *([parsed] if parsed else [])], key)
    path.write_bytes(path.read_bytes() + text.encode("utf-8") + b"\n" + canonical_json(checkpoint) + b"\n")
    report = _every_reader(path, pub, tmp_path)
    assert _codes(report) == codes and report.ok is (not codes)
    assert not _warnings(report)
    if "parse" in codes:  # not a record at all, in the middle of the file
        with pytest.raises(RecorderError):
            _resume(path, key)
    else:  # covered by a signature that checks: the schema of signed records is verify's to report, not resume's
        _resume(path, key).close()
        assert _codes(verify_file(path, [pub])) == codes


def test_a_forged_note_can_add_a_false_warning_and_nothing_else(tmp_path, key, pub):
    path = tmp_path / "e.jsonl"
    _signed_with_note(path, key, GOOD)
    report = verify_file(path, [pub])
    assert report.ok and report.signed_through_seq == load(path)[-1]["seq"]
    assert len(_warnings(report)) == 1


def test_a_forged_note_cannot_narrow_the_range_of_the_real_one(tmp_path, key, pub):
    path = tmp_path / "e.jsonl"
    _crashed(path, key)
    rec = _resume(path, key)
    rec.append_event(_note(rec.chain_id, {"first_seq": 3, "last_seq": 3, "count": 1}))
    rec.close()
    [warning] = _warnings(verify_file(path, [pub]))
    assert "records 3..6 " in warning.message
