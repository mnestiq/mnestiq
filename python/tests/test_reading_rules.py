"""Reading rules: how a file is split into lines, what a line may hold, salts, keys, gzip, and the commands
that read a file. One regression test, at least, for each change of behaviour."""

import base64
import gzip
import hashlib
import json
import os
import random
from pathlib import Path

import pytest

import mnestiq.recorder
import mnestiq.verify
from conftest import dump, load, record_demo
from mnestiq import FileSink, Recorder, RecorderError, Segment, SinkError
from mnestiq.canonical import MAX_DEPTH, RefusedJSON, canonical_json, parse_json
from mnestiq.cli import main
from mnestiq.dashboard import EvidenceStore
from mnestiq.demo import _records
from mnestiq.hashing import GENESIS_HASH, record_hash, salted_digest, signing_payload
from mnestiq.keys import (
    P256,
    WeakKeyError,
    alg_of_public,
    ed25519_problem,
    generate_private_key,
    key_id,
    load_public_key_b64,
    public_key_b64,
)
from mnestiq.merkle import merkle_root
from mnestiq.signers import LocalSigner
from mnestiq.verify import (
    ChainVerifier,
    EvidenceLines,
    LineError,
    _schema_pattern,
    closed_object,
    parse_line,
    schema_problem,
    verify_file,
    verify_lines,
    verify_stream,
)

DATA = Path(__file__).parent / "data"
CUT = b'{"agent_id":"support-bot","chain_id":"c","event_ty'  # the start of a record, as a cut write leaves it


def errors(report):
    return sorted({i.code for i in report.errors})


def warnings(report):
    return sorted({i.code for i in report.warnings})


def messages(report, code):
    return [i.message for i in [*report.errors, *report.warnings] if i.code == code]


def lines_of(path):
    """The lines of a file the recorder wrote, each with its LF."""
    return path.read_bytes().splitlines(keepends=True)


def reseal(records, *keys):
    """Recompute every link, Merkle root and record hash, and sign each checkpoint whose key is among ``keys``:
    what the holder of those keys can do to a file."""
    by_public = {public_key_b64(k): LocalSigner(k) for k in keys}
    prev, pending = GENESIS_HASH, []
    for r in records:
        r["prev_hash"] = prev
        if r["kind"] == "checkpoint":
            r["merkle_root"] = "sha256:" + merkle_root([bytes.fromhex(h[7:]) for h in pending]).hex()
            signer = by_public.get(r["public_key"])
            if signer is not None:
                signed = signer.sign(signing_payload(r))
                r["signature"] = base64.b64encode(signed).decode("ascii")
            pending = []
        r["record_hash"] = record_hash(r)
        if r["kind"] == "event":
            pending.append(r["record_hash"])
        prev = r["record_hash"]
    return records


def page(path, pub):
    return json.loads(EvidenceStore(path, [pub]).load(path).payload)


def nested(levels):
    """Arrays inside each other, ``levels`` of them."""
    value = []
    for _ in range(levels - 1):
        value = [value]
    return value


@pytest.fixture
def evidence(tmp_path, key):
    return record_demo(tmp_path / "e.jsonl", key)


# --- 1. a record is a line that ends with LF ----------------------------------------------------------------------

def test_bytes_after_the_last_line_end_are_not_a_record(evidence, pub):
    full = verify_file(evidence, [pub])
    assert full.ok and full.incomplete_tail_bytes == 0 and "incomplete_last_line" not in warnings(full)
    evidence.write_bytes(evidence.read_bytes() + CUT)
    report = verify_file(evidence, [pub])
    assert report.ok, report.errors
    assert report.records == full.records and report.incomplete_tail_bytes == len(CUT)
    assert warnings(report) == sorted({*warnings(full), "incomplete_last_line"})
    (said,) = messages(report, "incomplete_last_line")
    assert f"the last {len(CUT)} byte(s) of the file have no line end" in said and "were not read" in said


@pytest.mark.parametrize("tail", [b"\xff\xfe not text", b"   ", b"\r", b"{", b"]]]]", b'{"a":1}{"a":1}'])
def test_the_bytes_after_the_last_line_end_are_not_parsed(evidence, pub, tail):
    evidence.write_bytes(evidence.read_bytes() + tail)
    report = verify_file(evidence, [pub])
    assert report.ok and errors(report) == [] and report.incomplete_tail_bytes == len(tail)


def test_a_whole_last_record_with_no_line_end_is_counted(evidence, pub):
    full = verify_file(evidence, [pub])
    evidence.write_bytes(evidence.read_bytes()[:-1])  # only the final line end is gone
    report = verify_file(evidence, [pub])
    assert report.ok, report.errors
    assert report.records == full.records and report.checkpoints == full.checkpoints  # the last line is a checkpoint
    assert report.signed_through_seq == full.signed_through_seq and report.unsigned_tail == 0
    assert report.incomplete_tail_bytes == 0
    assert warnings(report) == sorted({*warnings(full), "no_final_newline"})
    assert messages(report, "no_final_newline") == [
        "the last line of the file has no line end. It is a whole record and was read like every other line. A "
        "recorder ends every line with a line end, so something took this one away"]


def test_a_file_whose_only_checkpoint_is_a_last_line_with_no_line_end_is_valid(tmp_path, key, pub):
    path = tmp_path / "e.jsonl"
    with Recorder(FileSink(path), agent_id="a", signing_key=key) as rec, rec.run() as run:
        run.note("a short run")
    assert [r["kind"] for r in load(path)].count("checkpoint") == 1 and load(path)[-1]["kind"] == "checkpoint"
    path.write_bytes(path.read_bytes().rstrip(b"\n"))
    report = verify_file(path, [pub])
    assert report.ok and report.checkpoints == 1 and warnings(report) == ["no_final_newline"]


def test_a_cut_in_the_middle_of_a_record_is_still_a_fragment(evidence, pub):
    full = verify_file(evidence, [pub])
    whole = evidence.read_bytes()
    last = whole.split(b"\n")[-2]
    for cut in (1, 2, len(last) // 2, len(last) - 1):  # bytes of the last record that are missing
        evidence.write_bytes(whole[:-1 - cut])
        report = verify_file(evidence, [pub])
        assert report.records == full.records - 1 and report.incomplete_tail_bytes == len(last) - cut
        assert report.checkpoints == full.checkpoints - 1  # the last line was the closing checkpoint
        assert report.ok and {"incomplete_last_line", "unsigned_tail"} <= set(warnings(report))
        assert "no_final_newline" not in warnings(report)


def reference_closed_object(tail: bytes) -> bool:
    """The rule as it was decided, byte by byte. ``closed_object`` must give this answer for every input."""
    if not tail.startswith(b"{") or not tail.endswith(b"}"):
        return False
    depth = 0
    in_string = escaped = False
    for i, b in enumerate(tail):
        if in_string:
            if escaped:
                escaped = False
            elif b == 0x5C:
                escaped = True
            elif b == 0x22:
                in_string = False
        elif b == 0x22:
            in_string = True
        elif b in (0x7B, 0x5B):
            depth += 1
        elif b in (0x7D, 0x5D):
            depth -= 1
            if depth == 0:
                return i == len(tail) - 1
            if depth < 0:
                return False
    return False


# The table of the rule, the same in the Workbench. Kinds of bracket are not matched, so {[}} is closed. {[}] does
# not end with the closing brace, so it is not.
CLOSED = [b"{}", b'{"a":1}', b'{"a":{"b":[1,2]}}', b'{"a":"}"}', b'{"a":"\\\\"}', b"{[}}"]
NOT_CLOSED = [b"", b"{", b'{"a":1', b'{"a":"}', b'{"a":"\\"}', b"{}{}", b"{} ", b"{}\r", b" {}", b"[]", b'{"a":1}}',
              b"{]", b"{[}]"]


@pytest.mark.parametrize("tail", CLOSED)
def test_a_closed_object_is_a_line(tail):
    assert closed_object(tail) is True and reference_closed_object(tail) is True


@pytest.mark.parametrize("tail", NOT_CLOSED)
def test_anything_else_after_the_last_line_end_is_a_fragment(tail):
    assert closed_object(tail) is False and reference_closed_object(tail) is False


def test_the_table_holds_the_bytes_it_is_meant_to():
    assert len(CLOSED) == 6 and len(NOT_CLOSED) == 13
    assert CLOSED[4] == bytes([0x7B, 0x22, 0x61, 0x22, 0x3A, 0x22, 0x5C, 0x5C, 0x22, 0x7D])  # one escaped backslash
    assert NOT_CLOSED[4] == bytes([0x7B, 0x22, 0x61, 0x22, 0x3A, 0x22, 0x5C, 0x22, 0x7D])  # an escaped closing quote


def test_closed_object_gives_the_answer_of_the_rule_for_every_input(evidence):
    rng = random.Random(12)
    pieces = [b"{", b"}", b"[", b"]", b'"', b"\\", b"a", b" ", b",", b":", b"\n", b"\r", b"\x00", b"\xff", b'\\"',
              b"\\\\", b'"}"', b'{"a":1}']
    tried = closed = 0
    for _ in range(40_000):
        tail = b"".join(rng.choice(pieces) for _ in range(rng.randint(0, 12)))
        if rng.random() < 0.7:  # most random bytes fail the first test, so make that one pass
            tail = b"{" + tail + b"}"
        assert closed_object(tail) is reference_closed_object(tail), tail
        tried += 1
        closed += closed_object(tail)
    assert closed > 1000 and tried - closed > 1000  # both answers were tried often
    for line in evidence.read_bytes().split(b"\n")[:-1]:  # and real records, whole and cut at every byte
        assert closed_object(line) and reference_closed_object(line)
        for n in range(0, len(line), 7):
            assert closed_object(line[:n]) is reference_closed_object(line[:n]) is False


def test_a_long_tail_is_judged_quickly():
    for tail in (b"x" * 50_000_000, b"{" + b"x" * 50_000_000, b"x" * 50_000_000 + b"}"):
        assert closed_object(tail) is False  # the first and last byte decide: nothing in between is read
    long_text = b'{"a":"' + b'\\"' * 2_000_000 + b'"}'
    assert closed_object(long_text) is True
    assert closed_object(long_text[:-2] + b"}") is False  # the text never ends


@pytest.mark.parametrize("tail, code", [(b"{[}}", "parse"), (b'{"a":1,"a":2}', "parse"), (b'{"a":1}', "schema"),
                                        (b"{" + b"[" * 200 + b"]" * 200 + b"}", "parse")])
def test_a_closed_last_line_is_read_strictly_like_any_other(evidence, pub, tail, code):
    full = verify_file(evidence, [pub])
    evidence.write_bytes(evidence.read_bytes() + tail)
    report = verify_file(evidence, [pub])
    assert not report.ok and code in errors(report) and report.incomplete_tail_bytes == 0
    assert "no_final_newline" in warnings(report) and "incomplete_last_line" not in warnings(report)
    assert any(e.line == full.records + 1 for e in report.errors)


def test_a_file_of_one_cut_record_is_empty(tmp_path):
    path = tmp_path / "e.jsonl"
    path.write_bytes(b"{")
    report = verify_file(path)
    assert errors(report) == ["empty"] and report.incomplete_tail_bytes == 1 and report.records == 0


def test_feed_still_takes_lines_with_or_without_their_line_end(evidence, pub):
    bare = evidence.read_bytes().split(b"\n")[:-1]
    for lines in (bare, [line + b"\n" for line in bare], [line + b"\r\n" for line in bare],
                  [line + b"\r" for line in bare], [line.decode("utf-8") for line in bare]):
        report = verify_lines(lines, [pub])
        assert report.ok and report.incomplete_tail_bytes == 0 and report.records == len(bare)


def test_evidence_lines_yields_the_complete_lines_and_counts_the_rest():
    lines = EvidenceLines([b"a\n", b"\n", b"b\r\n", b"cut"])
    assert list(lines) == [b"a\n", b"\n", b"b\r\n"] and lines.incomplete_tail_bytes == 3
    assert lines.no_final_newline is False
    whole = EvidenceLines([b"a\n"])
    assert list(whole) == [b"a\n"] and whole.incomplete_tail_bytes == 0 and whole.no_final_newline is False
    closed = EvidenceLines([b"a\n", b'{"b":1}'])
    assert list(closed) == [b"a\n", b'{"b":1}'] and closed.incomplete_tail_bytes == 0
    assert closed.no_final_newline is True


def test_verify_shows_the_incomplete_tail_in_its_headline_and_in_json(evidence, pub, capsys):
    assert main(["verify", str(evidence), "--trusted-key", pub]) == 0
    assert "no line end" not in capsys.readouterr().out
    evidence.write_bytes(evidence.read_bytes() + CUT)
    assert main(["verify", str(evidence), "--trusted-key", pub]) == 0
    out = capsys.readouterr().out
    headline = out.splitlines()[0]
    assert headline.startswith("VALID")
    assert f"(the last {len(CUT)} byte(s) have no line end and were not read)" in headline
    assert "warning incomplete_last_line:" in out
    assert main(["verify", str(evidence), "--trusted-key", pub, "--json"]) == 0
    body = json.loads(capsys.readouterr().out)
    assert body["ok"] is True and body["incomplete_tail_bytes"] == len(CUT)
    assert "incomplete_last_line" in [w["code"] for w in body["warnings"]]


def test_the_dashboard_reads_a_file_as_the_verifier_does(evidence, pub):
    whole = evidence.read_bytes()
    first, rest = whole.split(b"\n", 1)
    for data in (whole, whole + CUT, whole[:-1], first + b"\n\n" + rest, first.replace(b",", b",\r", 1) + b"\n" + rest,
                 whole.replace(b"\n", b"\r\n"), whole + b"\n", b"{"):
        evidence.write_bytes(data)
        report = verify_file(evidence, [pub])
        body = page(evidence, pub)
        shown = body["report"]
        assert shown["ok"] == report.ok and shown["records"] == report.records
        assert shown["incomplete_tail_bytes"] == report.incomplete_tail_bytes
        assert [e["code"] for e in shown["errors"]] == [e.code for e in report.errors]
        assert [w["code"] for w in shown["warnings"]] == [w.code for w in report.warnings]
        # Every line is on the page, a refused one as a line that could not be read. The bytes after the last
        # LF are a line only when they are a whole record.
        *complete, last = data.split(b"\n")
        assert body["records_total"] == len(complete) + closed_object(last)


def test_inspect_and_redact_leave_out_the_bytes_after_the_last_line_end(evidence, tmp_path, pub, capsys):
    clean = tmp_path / "clean.jsonl"
    assert main(["redact", str(evidence), str(clean)]) == 0
    evidence.write_bytes(evidence.read_bytes() + CUT)
    capsys.readouterr()
    assert main(["inspect", str(evidence)]) == 0
    out = capsys.readouterr().out
    assert f"The last {len(CUT)} byte(s) of the file have no line end and are not listed." in out
    assert "could not be read" not in out
    copy = tmp_path / "copy.jsonl"
    assert main(["redact", str(evidence), str(copy)]) == 0
    assert "were not copied" in capsys.readouterr().out
    report = verify_file(copy, [pub])
    assert report.ok and report.incomplete_tail_bytes == 0
    assert len(lines_of(copy)) == len(lines_of(clean))


def test_verify_shows_a_last_line_with_no_line_end_in_its_headline_and_in_json(evidence, pub, capsys):
    evidence.write_bytes(evidence.read_bytes()[:-1])
    assert main(["verify", str(evidence), "--trusted-key", pub]) == 0
    out = capsys.readouterr().out
    assert out.splitlines()[0] == f"VALID  {evidence}  (the last line has no line end and was read)"
    assert "warning no_final_newline: the last line of the file has no line end." in out
    assert main(["verify", str(evidence), "--trusted-key", pub, "--json"]) == 0
    body = json.loads(capsys.readouterr().out)
    assert body["ok"] is True and body["incomplete_tail_bytes"] == 0
    assert "no_final_newline" in [w["code"] for w in body["warnings"]]


def test_every_reader_takes_a_whole_last_record_with_no_line_end(evidence, tmp_path, pub, capsys):
    count = len(lines_of(evidence))
    whole = evidence.read_bytes()
    evidence.write_bytes(whole[:-1])
    body = page(evidence, pub)
    assert body["report"]["ok"] and body["records_total"] == count
    assert "no_final_newline" in [w["code"] for w in body["report"]["warnings"]]
    assert main(["inspect", str(evidence)]) == 0
    out = capsys.readouterr().out.splitlines()
    assert len(out) == count + 1 and out[-1].startswith("This listing is not a check.")
    assert "checkpoint" in out[-2]  # the last record is listed
    copy = tmp_path / "copy.jsonl"
    assert main(["redact", str(evidence), str(copy)]) == 0
    assert f"wrote {count} redacted records" in capsys.readouterr().out
    report = verify_file(copy, [pub])
    assert report.ok and "no_final_newline" not in warnings(report) and copy.read_bytes().endswith(b"}\n")
    assert len(_records(evidence)) == count
    packed = tmp_path / "e.jsonl.gz"
    packed.write_bytes(gzip.compress(whole[:-1]))
    assert verify_file(packed, [pub]).to_dict() == verify_file(evidence, [pub]).to_dict()


def test_a_recorder_keeps_a_whole_last_record_and_starts_the_next_on_a_new_line(evidence, tmp_path, key, pub):
    whole = evidence.read_bytes()
    count = len(lines_of(evidence))
    evidence.write_bytes(whole[:-1])
    with Recorder(FileSink(evidence), agent_id="support-bot", signing_key=key) as rec, rec.run() as run:
        run.note("back")
    after = evidence.read_bytes()
    assert after.startswith(whole) and after.endswith(b"}\n")  # the record is kept, and only got its line end
    assert all(line.startswith(b"{") and line.endswith(b"}\n") for line in lines_of(evidence))
    report = verify_file(evidence, [pub])
    assert report.ok, report.errors
    assert report.records > count and "no_final_newline" not in warnings(report)
    assert [p.name for p in tmp_path.iterdir()] == ["e.jsonl"]  # nothing was set aside


@pytest.mark.parametrize("extra", [b" ", b"\r", b"\t"], ids=["space", "cr", "tab"])
def test_a_recorder_does_not_write_after_a_last_line_that_is_no_whole_record(evidence, key, pub, extra):
    """A record with one more byte and no line end is a fragment to the verifier, which does not count it. The
    recorder must not go on as if it were a record: the next one would land on its end."""
    damaged = evidence.read_bytes()[:-1] + extra
    evidence.write_bytes(damaged)
    report = verify_file(evidence, [pub])
    assert report.incomplete_tail_bytes > 0 and "no_final_newline" not in warnings(report)
    sink = FileSink(evidence)
    try:
        with pytest.raises(SinkError, match="it has no line end and is not a whole record"):
            list(sink.existing())
        with pytest.raises(RecorderError):
            Recorder(sink, agent_id="support-bot", signing_key=key)
    finally:
        sink.close()
    assert evidence.read_bytes() == damaged


# --- 2. a blank line is refused -------------------------------------------------------------------------------------

@pytest.mark.parametrize("blank", [b"\n", b" \n", b"\t\n", b"\r\n", b"  \t \r\n"])
@pytest.mark.parametrize("where", [0, 3, -1])
def test_a_blank_line_is_an_error(evidence, pub, blank, where):
    full = verify_file(evidence, [pub])
    lines = lines_of(evidence)
    at = len(lines) if where == -1 else where
    lines.insert(at, blank)
    evidence.write_bytes(b"".join(lines))
    report = verify_file(evidence, [pub])
    assert not report.ok and errors(report) == ["parse"] and report.records == full.records
    (issue,) = report.errors
    assert issue.line == at + 1 and issue.message.startswith("line is blank")


def test_every_reader_refuses_a_blank_line(evidence, tmp_path, key, pub, capsys):
    lines = lines_of(evidence)
    evidence.write_bytes(b"".join([lines[0], b"\n", *lines[1:]]))
    body = page(evidence, pub)
    assert not body["report"]["ok"] and sum(1 for r in body["records"] if r.get("_unparseable")) == 1
    assert main(["inspect", str(evidence)]) == 1
    out = capsys.readouterr().out
    assert "1 record(s) could not be read" in out and "does NOT verify" in out
    copy = tmp_path / "copy.jsonl"
    assert main(["redact", str(evidence), str(copy)]) == 2
    assert not copy.exists() and not list(tmp_path.glob("*.partial"))
    sink = FileSink(evidence)
    try:
        with pytest.raises(SinkError, match="line 2 cannot be read"):
            list(sink.existing())
        with pytest.raises(RecorderError):
            Recorder(sink, agent_id="support-bot", signing_key=key)
    finally:
        sink.close()


def test_parse_line_refuses_what_is_not_one_record():
    assert parse_line(b'{"a":1}\n') == parse_line('{"a":1}\r\n') == parse_line('{"a":1}') == {"a": 1}
    for raw in (b"", b"\n", b" \t\n", "\r\n", b"\xff\n", b'{"a":\r1}\n', b'\r{"a":1}\n', b'{"a":1}\r\r\n',
                b'{"a":1}\r \n', b'{"a":1,"a":2}\n', b"NaN\n", b"[" * (MAX_DEPTH + 1) + b"]" * (MAX_DEPTH + 1)):
        with pytest.raises(LineError):
            parse_line(raw)


# --- 3. a carriage return only directly before the line end -----------------------------------------------------------

def test_crlf_line_ends_are_accepted(evidence, pub):
    full = verify_file(evidence, [pub])
    evidence.write_bytes(evidence.read_bytes().replace(b"\n", b"\r\n"))
    report = verify_file(evidence, [pub])
    assert report.ok and report.records == full.records and warnings(report) == warnings(full)


@pytest.mark.parametrize("edit", [
    lambda line: line.replace(b",", b",\r", 1),  # the finding: after the first comma, where JSON allows white space
    lambda line: b"\r" + line,
    lambda line: line[:-1] + b"\r\r\n",
    lambda line: line[:-1] + b"\r \n",
    lambda line: line[:-2] + b"\r}\n",
], ids=["after-a-comma", "at-the-start", "two-before-the-line-end", "then-a-space", "before-the-last-brace"])
def test_a_carriage_return_anywhere_else_is_an_error(evidence, pub, edit):
    full = verify_file(evidence, [pub])
    lines = lines_of(evidence)
    lines[1] = edit(lines[1])
    evidence.write_bytes(b"".join(lines))
    report = verify_file(evidence, [pub])
    assert not report.ok and report.records == full.records - 1
    (said,) = messages(report, "parse")
    assert said == "line holds a carriage return (CR) that is not directly before its line end"


# --- 4. a whole number past 2^53 - 1 has one spelling ---------------------------------------------------------------

def test_large_numbers_the_recorder_writes_stay_valid(tmp_path, key, pub):
    path = tmp_path / "e.jsonl"
    with Recorder(FileSink(path), agent_id="a", signing_key=key) as rec, rec.run() as run:
        run.tool_call("measure", {"limit": 2.0 ** 63}, {"total": 1.2345678901234567e19, "exact": 2.0 ** 53})
        run.note("sizes", amount=2.0 ** 63, total=1e21, below=-(2.0 ** 60))
    data = path.read_bytes()
    # Canonical JSON writes the shortest digits and zeros, which are not the exact integers of these doubles.
    assert b":9223372036854776000" in data and b":12345678901234567000" in data
    assert b"9223372036854775808" not in data and b"12345678901234567168" not in data
    report = verify_file(path, [pub])
    assert report.ok, report.errors
    with Recorder(FileSink(path), agent_id="a", signing_key=key) as rec, rec.run() as run:  # and can be resumed
        run.note("again")
    assert verify_file(path, [pub]).ok


def test_the_respelled_big_number_files_are_refused_and_the_unchanged_file_is_not():
    pin = (DATA / "big-number.pub").read_text("ascii").strip()
    assert verify_file(DATA / "big-number-unchanged.jsonl", [pin]).ok
    for name in ("big-number-plus-one.jsonl", "big-number-plus-65536.jsonl"):
        report = verify_file(DATA / name, [pin])
        assert not report.ok and "parse" in errors(report)
        (issue,) = [e for e in report.errors if e.code == "parse"]
        assert issue.line == 1 and issue.message.startswith("line is refused: the whole number")


@pytest.mark.parametrize("value, genuine, respelled", [
    (2.0 ** 53, b"9007199254740992", b"9007199254740993"),
    (2.0 ** 63, b"9223372036854776000", b"9223372036854775808"),
    (1e21, b"1e+21", b"1000000000000000000000"),
    (1e21, b"1e+21", b"1000000000000000065536"),
    (-(2.0 ** 53), b"-9007199254740992", b"-9007199254740993"),
])
def test_a_large_whole_number_in_another_spelling_is_an_error(tmp_path, key, pub, value, genuine, respelled):
    path = tmp_path / "e.jsonl"
    with Recorder(FileSink(path), agent_id="a", signing_key=key) as rec, rec.run() as run:
        run.note("a size", amount=value)
    assert verify_file(path, [pub]).ok
    data = path.read_bytes()
    assert data.count(b'"amount":' + genuine + b",") == 1
    path.write_bytes(data.replace(b'"amount":' + genuine + b",", b'"amount":' + respelled + b","))
    # Both spellings read as the same double, so no hash changes: only this rule tells them apart.
    assert float(respelled) == float(genuine)
    report = verify_file(path, [pub])
    assert not report.ok and "parse" in errors(report)
    assert any(said.startswith("line is refused: the whole number") for said in messages(report, "parse"))


@pytest.mark.parametrize("text, value", [
    ("9007199254740991", 2 ** 53 - 1), ("-9007199254740991", -(2 ** 53 - 1)), ("123456789012345", 123456789012345),
    ("9007199254740992", 2.0 ** 53), ("-9007199254740992", -(2.0 ** 53)), ("9007199254740994", 2.0 ** 53 + 2),
    ("9223372036854776000", 2.0 ** 63), ("12345678901234567000", 1.2345678901234567e19),
    ("100000000000000000000", 1e20), ("1e+21", 1e21), ("9007199254740993.0", 2.0 ** 53),
])
def test_parse_json_reads_a_number_in_its_canonical_spelling(text, value):
    read = parse_json(text)
    assert read == value and type(read) is type(value)


@pytest.mark.parametrize("text", [
    "9007199254740993", "-9007199254740993", "9223372036854775808", "123456789012345678", "1000000000000000000000",
    "1000000000000000065536", "1" * 400, "1" * 5000, "-" + "9" * 30,
])
def test_parse_json_refuses_a_large_whole_number_in_any_other_spelling(text):
    with pytest.raises(RefusedJSON, match="whole number"):
        parse_json(text)
    with pytest.raises(RefusedJSON):
        parse_json('{"a":[' + text + "]}")


def test_every_large_whole_number_reads_back_from_its_canonical_text():
    rng = random.Random(4)
    for _ in range(2000):
        x = float(rng.randrange(2 ** 53, 10 ** 21)) * rng.choice((1, -1))
        text = canonical_json(x).decode("ascii")
        assert parse_json(text) == x, text


# --- 5. nesting ----------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("before, after", [("[", "]"), ('{"a":', "}"), ('[{"a":', "}]")],
                         ids=["arrays", "objects", "both"])
def test_128_levels_are_read_and_129_are_refused(before, after):
    def text(levels, inner):
        per = 2 if before.startswith("[{") else 1
        return before * (levels // per) + inner + after * (levels // per)

    # Objects and arrays both count. Text and numbers add no level, and neither do brackets inside text.
    for inner in ('"[[[[{{{{"', "1", "null", "true"):
        if before == "[":
            assert parse_json(text(MAX_DEPTH, inner)) is not None
    assert parse_json(text(MAX_DEPTH - 2, "[[]]")) is not None  # the innermost array is level 128
    for inner in ("[[[]]]", '[[{"a":1}]]', "[{}, [[]]]"):  # level 129
        with pytest.raises(RefusedJSON, match="nested more than 128 levels deep"):
            parse_json(text(MAX_DEPTH - 2, inner))


def test_the_limit_is_counted_here_and_not_by_the_recursion_limit():
    for levels in (129, 1_000, 200_000):
        with pytest.raises(RefusedJSON):
            parse_json("[" * levels + "]" * levels)
        with pytest.raises(LineError, match="line is refused: a value is nested more than 128 levels deep"):
            parse_line("[" * levels + "]" * levels)
    assert parse_json('["' + "[{" * 5000 + '"]') == ["[{" * 5000]


def _with_deep_attribute(path, key, levels):
    """A signed file in which one event holds a value nested ``levels`` deep. The record is level 1, its
    attributes level 2, so the arrays under ``deep`` start at level 3."""
    records = load(record_demo(path, key))
    records[5]["attributes"] = {"deep": nested(levels - 2)}
    dump(path, reseal(records, key))
    return path


def test_a_record_nested_128_deep_verifies_and_129_does_not(tmp_path, key, pub):
    assert verify_file(_with_deep_attribute(tmp_path / "at.jsonl", key, 128), [pub]).ok
    report = verify_file(_with_deep_attribute(tmp_path / "over.jsonl", key, 129), [pub])
    assert not report.ok and "parse" in errors(report)
    assert "line is refused: a value is nested more than 128 levels deep" in messages(report, "parse")
    (issue,) = [e for e in report.errors if e.code == "parse"]
    assert issue.line == 6


def test_the_recorder_never_writes_a_record_its_verifier_refuses(tmp_path, key, pub):
    path = tmp_path / "e.jsonl"
    rec = Recorder(FileSink(path), agent_id="a", signing_key=key, strict=True)
    body = {"event_type": "note", "run_id": "r", "agent_id": "a"}
    with pytest.raises(RecorderError, match="nested more than 128 levels deep"):
        rec.append_event({**body, "attributes": {"deep": nested(127)}})
    rec.append_event({**body, "attributes": {"deep": nested(126)}})  # level 128 is written
    with rec.run() as run:  # what an agent hands over is flattened long before that
        run.note("deep", value=nested(500))
        run.tool_call("t", {"a": nested(500)}, nested(500))
        run.llm_call(provider="p", model="m", context=[Segment("user", nested(500))], output=nested(500))
    rec.close()
    report = verify_file(path, [pub])
    assert report.ok, report.errors
    assert b"<max depth exceeded>" in path.read_bytes()
    assert schema_problem(load(path)[0]) is None


# --- 6. salts ------------------------------------------------------------------------------------------------------

def _conversation(path, key, max_content_bytes=1_048_576):
    """One model call with two context values, an output and a tool call: five redactable values with salts.
    With a small ``max_content_bytes`` the second context value is left out (x-omitted) and keeps its salt."""
    with Recorder(FileSink(path), agent_id="a", signing_key=key, max_content_bytes=max_content_bytes) as rec, \
            rec.run() as run:
        run.llm_call(provider="p", model="m", context=[Segment("system", "Be brief."), Segment("web", "page " * 400)],
                     output="ok", tool_calls=[{"id": "t1", "name": "send", "arguments": {"to": "x"}}])
    return path


def _call(records):
    return next(r for r in records if r.get("event_type") == "llm_call")


def _slot(path, key, state):
    """The records of a file, and its second context value: stored, redacted by hand with the salt kept, or
    left out by the recorder."""
    records = load(_conversation(path, key, 1000 if state == "omitted" else 1_048_576))
    slot = _call(records)["context"][1]
    if state == "redacted":
        del slot["content"]
    assert ("content" in slot) == (state == "stored") and "content_salt" in slot
    assert ("x-omitted" in _call(records)) == (state == "omitted")
    return records, slot


def _other_spelling(salt):
    """The same 16 bytes with a spare bit of the last letter set: base64 that decodes, and is not canonical."""
    return salt[:21] + {"A": "B", "Q": "R", "g": "h", "w": "x"}[salt[21]] + "=="


@pytest.mark.parametrize("state", ["stored", "redacted", "omitted"])
@pytest.mark.parametrize("change", [
    lambda salt: salt + "\n", _other_spelling, lambda salt: "not base64!", lambda salt: salt[:-1],
    lambda salt: salt.replace("=", ""), lambda salt: "\u00e9" * 24, lambda salt: 7, lambda salt: None,
], ids=["newline", "spare-bit", "not-base64", "padding-cut", "no-padding", "not-ascii", "a-number", "null"])
def test_a_salt_that_is_not_canonical_base64_is_an_error(tmp_path, key, pub, state, change):
    records, slot = _slot(tmp_path / "e.jsonl", key, state)
    slot["content_salt"] = change(slot["content_salt"])
    dump(tmp_path / "e.jsonl", records)  # no hash covers a salt: nothing needs signing again
    report = verify_file(tmp_path / "e.jsonl", [pub])
    assert not report.ok and "salt" in errors(report)
    assert "context[1].content_salt is not base64 in its one canonical spelling" in messages(report, "salt")
    assert "record_hash" not in errors(report) and "signature" not in errors(report)


def test_the_same_salt_on_two_values_of_one_record_is_an_error(tmp_path, key, pub):
    path = _conversation(tmp_path / "e.jsonl", key)
    assert verify_file(path, [pub]).ok
    records = load(path)
    call = _call(records)
    first, second = call["context"][0], call["output"]
    second["content_salt"] = first["content_salt"]
    second["content_hash"] = salted_digest(second["content_salt"], second["content"])
    dump(path, reseal(records, key))
    report = verify_file(path, [pub])
    assert errors(report) == ["salt"]
    assert messages(report, "salt") == ["output.content_salt is also the salt of context[0].content: in one record "
                                        "every value has a salt of its own"]


def test_the_same_salt_in_two_records_is_not_checked(tmp_path, key, pub):
    path = tmp_path / "e.jsonl"
    with Recorder(FileSink(path), agent_id="a", signing_key=key, context_delta=False) as rec, rec.run() as run:
        for _ in range(2):
            run.llm_call(provider="p", model="m", context=[Segment("user", "hello")], output="ok")
    records = load(path)
    first, second = [r for r in records if r.get("event_type") == "llm_call"]
    slot = second["context"][0]
    slot["content_salt"] = first["context"][0]["content_salt"]
    slot["content_hash"] = salted_digest(slot["content_salt"], slot["content"])
    dump(path, reseal(records, key))
    assert verify_file(path, [pub]).ok


def test_the_warning_for_a_salt_without_its_value_does_not_call_the_salt_genuine(tmp_path, key, pub):
    records, _ = _slot(tmp_path / "e.jsonl", key, "redacted")
    dump(tmp_path / "e.jsonl", records)
    report = verify_file(tmp_path / "e.jsonl", [pub])
    assert report.ok and {"salt", "redacted"} <= set(warnings(report))
    (said,) = messages(report, "salt")
    assert said == ("context[1].content has a salt and not its value. With that salt the digest can be checked "
                    "against guesses of the value. A salt without its value is not covered by the signature, so "
                    "nothing shows it is the one the recorder made. Remove the salt too")


def test_an_omitted_value_without_its_salt_is_warned_about(tmp_path, key, pub):
    path = tmp_path / "e.jsonl"
    records, slot = _slot(path, key, "omitted")
    report = verify_file(path, [pub])
    assert report.ok and "omitted_salt" not in warnings(report) and "salt" not in warnings(report)
    del slot["content_salt"]
    dump(path, records)
    report = verify_file(path, [pub])
    assert report.ok and "omitted_salt" in warnings(report)
    assert messages(report, "omitted_salt") == [
        "context[1].content is listed as left out (x-omitted) and has no salt, so the original can no longer be "
        "checked against its digest. This is expected in a copy made by `mnestiq redact`, which removes those salts"]


def test_a_redacted_copy_of_a_file_with_an_omitted_value_gets_that_warning(tmp_path, key, pub, capsys):
    path = _conversation(tmp_path / "e.jsonl", key, 1000)
    copy = tmp_path / "copy.jsonl"
    assert main(["redact", str(path), str(copy)]) == 0
    report = verify_file(copy, [pub])
    assert report.ok and "omitted_salt" in warnings(report)
    assert all(said.endswith("expected in a copy made by `mnestiq redact`, which removes those salts")
               for said in messages(report, "omitted_salt"))


def test_a_redacted_value_without_a_salt_gets_no_omitted_salt_warning(tmp_path, key, pub):
    path = tmp_path / "e.jsonl"
    records, slot = _slot(path, key, "redacted")
    del slot["content_salt"]
    dump(path, records)
    report = verify_file(path, [pub])
    assert report.ok and warnings(report) == ["redacted"]


# --- 7. a schema pattern means what it means in JSON Schema ---------------------------------------------------------

@pytest.mark.parametrize("wall", ["2026-11-11T10:00:00.000000Z\n",
                                  "\u0662\u0660\u0662\u0666-11-11T10:00:00.000000Z"],
                         ids=["newline-after", "digits-of-another-script"])
def test_a_time_python_alone_would_let_through_breaks_the_schema(evidence, key, pub, wall):
    records = load(evidence)
    records[-1]["ts"]["wall"] = wall  # the last record, signed again: only the schema can object
    dump(evidence, reseal(records, key))
    report = verify_file(evidence, [pub])
    assert not report.ok and errors(report) == ["schema"]
    assert any(said.startswith("ts/wall:") for said in messages(report, "schema"))


def test_a_salt_with_a_newline_after_it_breaks_the_schema(tmp_path, key):
    record = _call(load(_conversation(tmp_path / "e.jsonl", key)))
    assert schema_problem(record) is None
    record["context"][0]["content_salt"] += "\n"
    assert (schema_problem(record, show_value=False) or "").startswith("context/0/content_salt:")


def test_patterns_are_read_as_json_schema_reads_them():
    end = _schema_pattern("^a$")
    assert end.search("a") and not end.search("a\n") and not end.search("ab")
    assert _schema_pattern(r"^a\$[$]$").search("a$$") and not _schema_pattern(r"^a\$[$]$").search("a$$\n")
    digits = _schema_pattern(r"^\d{2}[\d-]$")
    assert digits.search("12-") and digits.search("123") and not digits.search("\u0661\u0662-")
    assert not digits.search("12\u0663")
    assert _schema_pattern("^x-").search("x-anything\n")


# --- 8. keys -------------------------------------------------------------------------------------------------------

IDENTITY = (1).to_bytes(32, "little")  # the neutral point of the curve
SMALL_ORDER = [
    IDENTITY,
    (2 ** 255 - 20).to_bytes(32, "little"),  # order 2
    bytes(32),  # order 4
    bytes(31) + b"\x80",  # order 4
    bytes.fromhex("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"),  # order 8
    bytes.fromhex("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85"),
    bytes.fromhex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"),
    bytes.fromhex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa"),
]
NOT_A_POINT = [
    (2 ** 255 - 19).to_bytes(32, "little"),  # y is the field's size: another spelling of 0
    (2 ** 255 - 18).to_bytes(32, "little"),  # another spelling of the neutral point
    IDENTITY[:31] + b"\x80",  # x is 0 and the sign bit is set
    (2).to_bytes(32, "little"),  # no point of the curve has this y
]
TRIVIAL_SIGNATURE = base64.b64encode(IDENTITY + bytes(32)).decode("ascii")  # R the neutral point, S zero


def _b64(raw):
    return base64.b64encode(raw).decode("ascii")


def _id_of(raw):
    """What key_id would say for an Ed25519 key, for bytes that key_id refuses."""
    return "ed25519:" + hashlib.sha256(raw).hexdigest()[:16]


@pytest.mark.parametrize("raw", SMALL_ORDER)
def test_the_eight_points_of_small_order_are_refused(raw):
    assert "small order" in (ed25519_problem(raw) or "")
    for use in (alg_of_public, key_id, load_public_key_b64):
        with pytest.raises(WeakKeyError):
            use(_b64(raw))


@pytest.mark.parametrize("raw", NOT_A_POINT)
def test_bytes_that_are_not_a_point_in_its_one_encoding_are_refused(raw):
    assert "not the encoding" in (ed25519_problem(raw) or "")
    with pytest.raises(ValueError):
        key_id(_b64(raw))


def test_keys_made_from_a_private_key_are_never_refused():
    for _ in range(200):
        pub = public_key_b64(generate_private_key())
        assert ed25519_problem(base64.b64decode(pub)) is None and key_id(pub).startswith("ed25519:")
    assert key_id(public_key_b64(generate_private_key(P256))).startswith("p256:")


def _handed_over(path, first, second):
    """A chain that ``first`` signs and then hands over to ``second``. Returns its records."""
    rec = Recorder(FileSink(path), agent_id="a", signing_key=first)
    with rec.run() as run:
        run.note("before")
    rec.rotate_signer(second)
    with rec.run() as run:
        run.note("after")
    rec.close()
    return load(path)


@pytest.mark.parametrize("kinds", [("ed25519", "ed25519"), ("ed25519", P256), (P256, "ed25519")])
def test_a_hand_over_that_names_the_wrong_algorithm_is_an_error(tmp_path, kinds):
    first, second = (generate_private_key(kind) for kind in kinds)
    path = tmp_path / "e.jsonl"
    records = _handed_over(path, first, second)
    assert verify_file(path, [public_key_b64(first)]).ok
    handover = next(r for r in records if "next_key" in r)
    assert handover["next_key"]["sig_alg"] == kinds[1]
    handover["next_key"]["sig_alg"] = "ed25519" if kinds[1] == P256 else P256
    dump(path, reseal(records, first, second))  # signed by the pinned key, as in the finding
    report = verify_file(path, [public_key_b64(first)])
    assert not report.ok and "next_key" in errors(report)
    assert messages(report, "next_key") == ["next_key.sig_alg is not the algorithm of next_key.public_key"]
    assert report.rotations == []


def test_a_hand_over_in_a_newer_version_cannot_relabel_a_key_this_verifier_knows(tmp_path, key, pub):
    path = tmp_path / "e.jsonl"
    records = _handed_over(path, key, generate_private_key())
    for r in records:
        r["spec_version"] = "1.1"
    next(r for r in records if "next_key" in r)["next_key"]["sig_alg"] = "ml-dsa-65"
    dump(path, reseal(records, key))
    report = verify_file(path, [pub])
    assert not report.ok and "next_key.sig_alg is not the algorithm of next_key.public_key" in messages(
        report, "next_key")


def _handed_to_the_neutral_point(path, key):
    """The finding: the pinned key hands the chain over to the neutral point, and what follows carries the
    signature anyone can write."""
    records = _handed_over(path, key, generate_private_key())
    handover = next(r for r in records if "next_key" in r)
    handover["next_key"].update({"public_key": _b64(IDENTITY), "key_id": _id_of(IDENTITY)})
    for r in records[records.index(handover) + 1:]:
        if r["kind"] == "checkpoint":
            r.update({"public_key": _b64(IDENTITY), "key_id": _id_of(IDENTITY), "signature": TRIVIAL_SIGNATURE})
        elif r.get("event_type") == "note" and r["attributes"].get("message") == "after":
            r["attributes"]["message"] = "written by anyone"
    dump(path, reseal(records, key))
    return path


def test_a_hand_over_to_a_key_of_small_order_is_an_error(tmp_path, key, pub):
    path = _handed_to_the_neutral_point(tmp_path / "e.jsonl", key)
    report = verify_file(path, [pub])
    assert not report.ok and {"next_key", "signature"} <= set(errors(report))
    assert any("small order" in said for said in messages(report, "next_key"))
    assert report.rotations == []


def test_a_checkpoint_by_a_key_of_small_order_is_an_error_without_a_pinned_key(tmp_path, key):
    path = tmp_path / "e.jsonl"
    records = load(record_demo(path, key))
    for r in records:
        if r["kind"] == "checkpoint":
            r.update({"public_key": _b64(IDENTITY), "key_id": _id_of(IDENTITY), "signature": TRIVIAL_SIGNATURE})
    dump(path, reseal(records))
    report = verify_file(path)
    assert not report.ok and errors(report) == ["signature"]
    assert all(said.startswith("public_key is refused:") and "small order" in said
               for said in messages(report, "signature"))
    assert report.signer_keys == []


def test_a_pinned_key_of_small_order_is_refused_before_anything_is_verified(evidence, capsys):
    weak = _b64(IDENTITY)
    with pytest.raises(ValueError, match="a trusted key is refused"):
        verify_file(evidence, [weak])
    with pytest.raises(ValueError, match="a trusted key is refused"):
        ChainVerifier([weak])
    with pytest.raises(ValueError, match="a trusted key is refused"):
        verify_file(evidence.with_name("no such file"), [weak])  # the key is looked at first
    capsys.readouterr()
    for command in (["verify", str(evidence), "--trusted-key", weak],
                    ["dashboard", str(evidence), "--trusted-key", weak, "--no-open"]):
        assert main(command) == 2
        said = capsys.readouterr()
        assert "is refused" in said.err and "small order" in said.err
        assert "VALID" not in said.out


# --- 9. gzip -------------------------------------------------------------------------------------------------------

def test_verify_reads_a_gzip_file(evidence, tmp_path, pub, capsys):
    plain = verify_file(evidence, [pub])
    for name in ("e.jsonl.gz", "named-as-plain.jsonl"):  # told by its first two bytes, not by its name
        packed = tmp_path / name
        packed.write_bytes(gzip.compress(evidence.read_bytes()))
        assert verify_file(packed, [pub]).to_dict() == plain.to_dict()
        assert main(["verify", str(packed), "--trusted-key", pub]) == 0
        assert capsys.readouterr().out.startswith("VALID")
    with open(evidence, "rb") as fh:
        assert verify_stream(fh, [pub]).to_dict() == plain.to_dict()


def test_every_rule_holds_for_what_a_gzip_file_unpacks_to(evidence, tmp_path, pub):
    whole = evidence.read_bytes()
    first, rest = whole.split(b"\n", 1)
    packed = tmp_path / "e.jsonl.gz"
    for data in (whole + CUT, whole[:-1], first + b"\n\n" + rest, first.replace(b",", b",\r", 1) + b"\n" + rest,
                 whole.replace(b"\n", b"\r\n"), whole.replace(b"auto-approve-email", b"human-approved"), b""):
        evidence.write_bytes(data)
        packed.write_bytes(gzip.compress(data))
        assert verify_file(packed, [pub]).to_dict() == verify_file(evidence, [pub]).to_dict()


@pytest.mark.parametrize("damage", [lambda packed: packed[:-30], lambda packed: packed[:len(packed) // 2],
                                    lambda packed: packed + b"more bytes", lambda packed: packed[:10]],
                         ids=["end-cut", "half", "bytes-after", "header-only"])
def test_a_gzip_file_that_cannot_be_read_to_its_end_is_invalid(evidence, tmp_path, pub, damage):
    packed = tmp_path / "e.jsonl.gz"
    packed.write_bytes(damage(gzip.compress(evidence.read_bytes())))
    report = verify_file(packed, [pub])
    assert not report.ok and "gzip" in errors(report)
    (said,) = messages(report, "gzip")
    assert said.startswith("this is a gzip file and it could not be read to its end: it is damaged or cut short")


def test_one_line_of_a_gzip_file_has_a_limit(evidence, tmp_path, pub, monkeypatch):
    assert mnestiq.verify.MAX_GZIP_LINE == 64 * 1024 * 1024
    longest = max(len(line) for line in lines_of(evidence))
    packed = tmp_path / "e.jsonl.gz"
    packed.write_bytes(gzip.compress(evidence.read_bytes()))
    monkeypatch.setattr(mnestiq.verify, "MAX_GZIP_LINE", longest)
    assert verify_file(packed, [pub]).ok  # a line of exactly the limit is read
    monkeypatch.setattr(mnestiq.verify, "MAX_GZIP_LINE", longest - 1)
    report = verify_file(packed, [pub])
    assert not report.ok and "gzip" in errors(report)
    assert f"one line of it is longer than {longest - 1} bytes once unpacked" in messages(report, "gzip")[0]
    # A small file that unpacks to one endless line stops at the limit and is not read into memory.
    monkeypatch.setattr(mnestiq.verify, "MAX_GZIP_LINE", 4096)
    packed.write_bytes(gzip.compress(b" " * 5_000_000))
    report = verify_file(packed, [pub])
    assert errors(report) == ["empty", "gzip"] and report.records == 0


def test_the_other_commands_say_to_unpack_a_gzip_file_first(evidence, tmp_path, pub, capsys):
    packed = tmp_path / "packed.jsonl"
    packed.write_bytes(gzip.compress(evidence.read_bytes()))
    for command in (["inspect", str(packed)], ["redact", str(packed), str(tmp_path / "copy.jsonl")]):
        assert main(command) == 2
        assert "is a gzip file. Unpack it first" in capsys.readouterr().err
    assert not (tmp_path / "copy.jsonl").exists()
    body = page(packed, pub)
    assert not body["report"]["ok"] and body["records"] == []
    assert "gzip file, which the dashboard does not read" in body["report"]["errors"][0]["message"]


# --- 10. redact verifies first ---------------------------------------------------------------------------------------

def test_redact_refuses_an_input_that_does_not_verify(evidence, tmp_path, pub, capsys):
    """The finding: a seq written 3.0 reads as 3, so the redacted copy was the redaction of the genuine file and
    verified, made from an input that did not."""
    data = evidence.read_bytes()
    assert data.count(b'"seq":3,') == 1
    evidence.write_bytes(data.replace(b'"seq":3,', b'"seq":3.0,'))
    assert not verify_file(evidence, [pub]).ok
    copy = tmp_path / "copy.jsonl"
    assert main(["redact", str(evidence), str(copy)]) == 2
    said = capsys.readouterr()
    assert "does not verify" in said.err and "no redacted copy was written" in said.err
    assert "`mnestiq verify`" in said.err and "wrote" not in said.out
    assert not copy.exists() and not list(tmp_path.glob("*.partial"))


@pytest.mark.parametrize("change", [
    lambda data: data.replace(b"auto-approve-email", b"human-approved"),  # a record changed
    lambda data: b"".join(data.splitlines(keepends=True)[1:]),  # the first record gone
    lambda data: b"",  # nothing at all
    lambda data: data + data.splitlines(keepends=True)[-1],  # a line twice
], ids=["edited", "record-removed", "empty", "line-repeated"])
def test_redact_writes_nothing_from_a_file_with_errors(evidence, tmp_path, capsys, change):
    evidence.write_bytes(change(evidence.read_bytes()))
    assert not verify_file(evidence).ok
    copy = tmp_path / "copy.jsonl"
    assert main(["redact", str(evidence), str(copy)]) == 2
    assert "does not verify" in capsys.readouterr().err
    assert not copy.exists() and not list(tmp_path.glob("*.partial"))


def test_redact_still_copies_a_file_that_verifies_with_warnings(tmp_path, capsys):
    path = record_demo(tmp_path / "e.jsonl", None)  # unsigned: a warning, not an error
    assert verify_file(path).ok and "unsigned" in warnings(verify_file(path))
    copy = tmp_path / "copy.jsonl"
    assert main(["redact", str(path), str(copy)]) == 0
    assert verify_file(copy).ok and len(lines_of(copy)) == len(lines_of(path))


# --- 11. inspect says whether the file verifies ----------------------------------------------------------------------

def test_inspect_says_that_its_listing_is_not_a_check(evidence, capsys):
    assert main(["inspect", str(evidence)]) == 0
    last = capsys.readouterr().out.splitlines()[-1]
    assert last == ("This listing is not a check. The file verified without a pinned key, so who signed it was not "
                    "checked. Run `mnestiq verify --trusted-key` for that.")


def test_inspect_says_when_the_file_does_not_verify(evidence, capsys):
    """The finding: one letter changed, every record still listed, and nothing said."""
    evidence.write_bytes(evidence.read_bytes().replace(b"auto-approve-email", b"auto-approve-emaik"))
    report = verify_file(evidence)
    assert not report.ok
    assert main(["inspect", str(evidence), "--run", "no-such-run"]) == 0  # the whole file is checked all the same
    out = capsys.readouterr().out.splitlines()
    assert out == [f"This file does NOT verify: {len(report.errors)} problem(s). The listing shows what the file "
                   "says, not what was recorded. Run `mnestiq verify` on it."]


# --- 12. the dashboard's cache ---------------------------------------------------------------------------------------

def test_the_dashboard_does_not_reuse_a_verdict_for_other_bytes(evidence, pub):
    store = EvidenceStore(evidence, [pub])
    first = store.load(evidence)
    assert json.loads(first.payload)["report"]["ok"] and store.load(evidence) is first
    before = evidence.stat()
    evidence.write_bytes(evidence.read_bytes().replace(b"auto-approve-email", b"auto-approve-emaik"))
    os.utime(evidence, ns=(before.st_atime_ns, before.st_mtime_ns))
    after = evidence.stat()
    assert (after.st_size, after.st_mtime_ns) == (before.st_size, before.st_mtime_ns)
    second = store.load(evidence)
    assert not json.loads(second.payload)["report"]["ok"] and second.etag != first.etag
    assert store.load(evidence) is second  # the same bytes: the verdict is used again


# --- 13. readers that split at LF only -------------------------------------------------------------------------------

@pytest.mark.parametrize("text", ["a\u2028b", "a\u2028[1,2,3]\u2028b", "a\u2029b", "a\u0085b", "a\x1cb", "a\x0bb"])
def test_recorded_text_with_other_line_breaks_does_not_break_a_reader(tmp_path, key, pub, text):
    path = tmp_path / "e.jsonl"
    with Recorder(FileSink(path), agent_id="a", signing_key=key) as rec, rec.run() as run:
        run.note(text)
    report = verify_file(path, [pub])
    assert report.ok
    for reader in (load, _records):
        records = reader(path)
        assert len(records) == report.records and all(isinstance(r, dict) for r in records)
        assert text in [r.get("attributes", {}).get("message") for r in records]


def test_the_demo_reader_leaves_out_what_the_verifier_refuses(evidence):
    whole = evidence.read_bytes()
    count = len(lines_of(evidence))
    evidence.write_bytes(b"\n" + whole + b"[1]\n" + b"not json\n" + CUT)
    assert len(_records(evidence)) == count


# --- timestamp_token is text ----------------------------------------------------------------------------------------

@pytest.mark.parametrize("token", [None, ""], ids=["null", "empty"])
def test_a_timestamp_token_that_is_null_or_empty_is_invalid(evidence, pub, token):
    records = load(evidence)
    records[-1]["timestamp_token"] = token  # not signed, and covered by the record hash
    records[-1]["record_hash"] = record_hash(records[-1])
    dump(evidence, records)
    report = verify_file(evidence, [pub])
    assert not report.ok and errors(report) == ["schema", "timestamp"]
    assert any(said.startswith("timestamp_token:") for said in messages(report, "schema"))
    assert messages(report, "timestamp") == ["the RFC 3161 timestamp token is empty or not text"]
    assert (schema_problem(records[-1], show_value=False) or "").startswith("timestamp_token:")


# --- an integer field written with a fraction or an exponent (spec section 3) ---------------------------------------

@pytest.mark.parametrize("spelling", [b"1.0", b"1e0", b"1.00", b"10e-1"])
def test_an_integer_field_written_with_a_fraction_or_an_exponent_is_an_error(evidence, pub, spelling):
    """``"seq":1.0`` has the canonical bytes of ``"seq":1``, so every hash and signature still holds without the
    key. The verifier refuses it all the same: a field the schema types as an integer is written as one."""
    lines = lines_of(evidence)
    assert lines[1].count(b'"seq":1,') == 1
    lines[1] = lines[1].replace(b'"seq":1,', b'"seq":' + spelling + b",")
    evidence.write_bytes(b"".join(lines))
    report = verify_file(evidence, [pub])
    assert not report.ok and "seq" in errors(report)
