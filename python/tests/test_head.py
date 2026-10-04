import json
import random

import pytest

from mnestiq import FileSink, HeadFile, Recorder, Segment, verify_file, verify_lines
from mnestiq.cli import main
from mnestiq.keys import generate_private_key

from conftest import record_demo


def codes(report):
    return {i.code for i in report.errors}


def demo_with_head(tmp_path, key):
    head = tmp_path / "elsewhere" / "agent.head.json"
    rec = Recorder(FileSink(tmp_path / "e.jsonl"), agent_id="a", signing_key=key, checkpoint_every=3,
                   on_checkpoint=HeadFile(head))
    with rec.run() as run:
        for i in range(8):
            run.note(f"step {i}")
    rec.close()
    return tmp_path / "e.jsonl", head


def test_head_holds_the_latest_checkpoint(tmp_path, key, pub):
    path, head = demo_with_head(tmp_path, key)
    last = json.loads(path.read_text("utf-8").splitlines()[-1])
    assert json.loads(head.read_text("utf-8")) == last and last["kind"] == "checkpoint"
    report = verify_file(path, [pub], json.loads(head.read_text("utf-8")))
    assert report.ok and report.head_seq == last["seq"]
    assert not (head.parent / "agent.head.json.tmp").exists()


def test_cut_back_to_an_earlier_checkpoint_is_only_caught_with_the_head(tmp_path, key, pub):
    path, head = demo_with_head(tmp_path, key)
    lines = path.read_bytes().splitlines(keepends=True)
    first_checkpoint = next(i for i, line in enumerate(lines) if b'"kind":"checkpoint"' in line)
    cut = lines[: first_checkpoint + 1]
    assert verify_lines(cut, [pub]).ok  # on its own the shorter file is indistinguishable
    report = verify_lines(cut, [pub], json.loads(head.read_text("utf-8")))
    assert not report.ok and "truncated" in codes(report)


def test_rewritten_chain_does_not_match_the_head(tmp_path, key):
    path, head = demo_with_head(tmp_path, key)
    forged = tmp_path / "forged.jsonl"
    chain_id = json.loads(path.read_text("utf-8").splitlines()[0])["chain_id"]
    rec = Recorder(FileSink(forged), agent_id="a", signing_key=generate_private_key(), checkpoint_every=3,
                   chain_id=chain_id)
    with rec.run() as run:
        for i in range(8):
            run.note(f"edited step {i}")
    rec.close()
    report = verify_file(forged, (), json.loads(head.read_text("utf-8")))  # even with no key pinned
    assert not report.ok and "head" in codes(report)


def test_head_from_another_chain_is_rejected(tmp_path, key, pub):
    path, _ = demo_with_head(tmp_path, key)
    _, other_head = demo_with_head(tmp_path / "other", key)
    report = verify_file(path, [pub], json.loads(other_head.read_text("utf-8")))
    assert "head" in codes(report)


def test_failing_head_writer_does_not_break_the_agent(tmp_path, key, pub):
    def broken(_checkpoint):
        raise OSError("disk unplugged")

    rec = Recorder(FileSink(tmp_path / "e.jsonl"), agent_id="a", signing_key=key, checkpoint_every=2,
                   on_checkpoint=broken)
    with pytest.warns(RuntimeWarning), rec.run() as run:
        run.llm_call(provider="p", model="m", context=[Segment("user", "hi")])
    rec.close()
    assert rec.failures >= 1 and verify_file(tmp_path / "e.jsonl", [pub]).ok

    strict = Recorder(FileSink(tmp_path / "s.jsonl"), agent_id="a", signing_key=key, checkpoint_every=1,
                      on_checkpoint=broken, strict=True)
    with pytest.raises(OSError):
        strict.append_event({"event_type": "note", "run_id": "r", "agent_id": "a"})


def test_cli_verify_with_head(tmp_path, key, pub, capsys):
    path, head = demo_with_head(tmp_path, key)
    assert main(["verify", str(path), "--trusted-key", pub, "--head", str(head)]) == 0
    assert "head      matches the checkpoint" in capsys.readouterr().out
    lines = path.read_bytes().splitlines(keepends=True)
    path.write_bytes(b"".join(lines[:4]))
    assert main(["verify", str(path), "--trusted-key", pub, "--head", str(head)]) != 0
    assert "records were removed from the end" in capsys.readouterr().out


def test_single_byte_flips_in_sealed_records_are_rejected(tmp_path, key, pub):
    # A fixed sample keeps CI fast. Flipping every byte of this file was also checked once by hand.
    raw = record_demo(tmp_path / "e.jsonl", key, checkpoint_every=4).read_bytes()
    accepted = []
    for pos in random.Random(0).sample(range(len(raw)), 1500):
        if raw[pos] in b"\r\n":
            continue
        flipped = bytearray(raw)
        flipped[pos] ^= 0x01
        if verify_lines(bytes(flipped).splitlines(keepends=True), [pub]).ok:
            accepted.append(pos)
    assert accepted == []


@pytest.mark.parametrize("head", [[1], "checkpoint", 7, None])
def test_head_that_is_not_an_object_is_reported_not_crashed(tmp_path, key, pub, head):
    path, _ = demo_with_head(tmp_path, key)
    bad = tmp_path / "bad.head.json"
    bad.write_text(json.dumps(head), "utf-8")
    assert main(["verify", str(path), "--trusted-key", pub, "--head", str(bad)]) != 0
