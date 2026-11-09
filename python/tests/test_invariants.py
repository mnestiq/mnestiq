"""The promises every reader of an evidence file keeps, tried on named kinds of damage, not random ones.

Each file below goes through verify, the rules, context expansion, inspect, redact and the dashboard (see
tests/fuzz/engine.py for what is checked). By default one seed file and a sample of positions, so it stays fast.
MNESTIQ_HARDENING_FULL=1 tries all four seed files at every position.
"""

import copy
import gzip
import json
import os
import subprocess
import sys
import threading
import urllib.request
from pathlib import Path

import pytest

from fuzz.engine import (
    JUNK_LINES,
    Case,
    Checker,
    Seed,
    Violation,
    _Deep,
    _dumps,
    _paths,
    _set_at,
    _tweak,
    _get_at,
    build_seeds,
    mutate,
)

import random

from mnestiq.dashboard import create_server
from mnestiq.findings import findings
from mnestiq.hashing import record_hash
from mnestiq.keys import generate_private_key, public_key_b64
from mnestiq.verify import verify_lines

FULL = os.environ.get("MNESTIQ_HARDENING_FULL") == "1"


@pytest.fixture(scope="module")
def all_seeds():
    return build_seeds()


@pytest.fixture(scope="module")
def seed(all_seeds):
    return next(s for s in all_seeds if s.name == "heartbeats")


def _seeds(all_seeds, one):
    return all_seeds if FULL else [one]


def _sample(items, every):
    return items if FULL else items[::every]


def _check(tmp_path, seed, data, label, resigned=False, moved=False):
    found = Checker(tmp_path).check(Case(seed, 0, data, [label], resigned, moved))
    assert not found, f"{label}: {[(v.invariant, v.surface, v.detail) for v in found]}"


def _lines(lines):
    return b"\n".join(lines) + b"\n"


# Structure of the file ---------------------------------------------------------------------------------------


def test_cut_at_any_byte(all_seeds, seed, tmp_path):
    for s in _seeds(all_seeds, seed):
        checker = Checker(tmp_path)
        data = s.data
        for n in _sample(list(range(len(data))), 251):
            assert not checker.check(Case(s, 0, data[:n], [f"cut at {n}"], False, False)), f"cut at {n}"


def test_each_line_deleted_duplicated_or_swapped(all_seeds, seed, tmp_path):
    for s in _seeds(all_seeds, seed):
        checker = Checker(tmp_path)
        count = len(s.lines)
        variants = []
        for i in range(count):
            variants.append(s.lines[:i] + s.lines[i + 1 :])
            variants.append([*s.lines[:i], s.lines[i], *s.lines[i:]])
            if i + 1 < count:
                variants.append([*s.lines[:i], s.lines[i + 1], s.lines[i], *s.lines[i + 2 :]])
        for lines in _sample(variants, 3):
            assert not checker.check(Case(s, 0, _lines(lines), ["line edit"], False, False))


@pytest.mark.parametrize("junk", JUNK_LINES, ids=lambda j: repr(j[:14]))
def test_a_bad_line_at_the_start_middle_or_end(seed, junk, tmp_path):
    checker = Checker(tmp_path)
    n = len(seed.lines)
    for at in (0, n // 2, n):
        data = _lines([*seed.lines[:at], junk, *seed.lines[at:]])
        found = checker.check(Case(seed, 0, data, [f"junk at {at}"], False, False))
        assert not found, [(v.invariant, v.surface, v.detail) for v in found]


@pytest.mark.parametrize(
    ("name", "change"),
    [
        ("no final newline", lambda d: d.rstrip(b"\n")),
        ("crlf", lambda d: d.replace(b"\n", b"\r\n")),
        ("bom", lambda d: b"\xef\xbb\xbf" + d),
        ("utf16", lambda d: d.decode().encode("utf-16")),
        ("utf16 no bom", lambda d: d.decode().encode("utf-16-le")),
        ("utf32", lambda d: d.decode().encode("utf-32")),
        ("latin1 byte", lambda d: d[:40] + b"\xe9" + d[40:]),
        ("nul in a line", lambda d: d[:40] + b"\x00" + d[40:]),
        ("bare carriage return", lambda d: d[: d.index(b",") + 1] + b"\r" + d[d.index(b",") + 1 :]),
        ("gzip", lambda d: gzip.compress(d, mtime=0)),
        ("empty", lambda d: b""),
        ("blank lines only", lambda d: b"\n \n\t\n"),
        ("blank lines between", lambda d: d.replace(b"\n", b"\n\n")),
        ("spaces between tokens", lambda d: d.replace(b'":', b'" : ')),
        ("line separators", lambda d: d.replace(b"\n", b"\xe2\x80\xa8")),
    ],
)
def test_encodings_and_framing(seed, name, change, tmp_path):
    _check(tmp_path, seed, change(seed.data), name)


# Content of a record ------------------------------------------------------------------------------------------


def test_a_change_of_the_right_type_on_every_field(all_seeds, seed, tmp_path):
    rng = random.Random(7)
    for s in _seeds(all_seeds, seed):
        checker = Checker(tmp_path)
        cases = [(i, p) for i, r in enumerate(s.records) for p in _paths(r)]
        for i, path in _sample(cases, 7):
            records = copy.deepcopy(s.records)
            before = _get_at(records[i], path)
            after = _tweak(rng, path[-1], before)
            _set_at(records[i], path, after)
            found = checker.check(Case(s, 0, _lines([_dumps(r) for r in records]), [f"{i} {path}"], False, False))
            assert not found, (i, path, [(v.invariant, v.detail) for v in found])
            if after != before:  # a real change to a signed record is never VALID
                assert not verify_lines([_dumps(r) for r in records], [s.pub]).ok, (i, path)


def test_the_same_change_with_the_records_own_hash_redone(seed, tmp_path):
    checker = Checker(tmp_path)
    rng = random.Random(11)
    cases = [(i, p) for i, r in enumerate(seed.records) for p in _paths(r) if p != ("record_hash",)]
    for i, path in _sample(cases, 9):
        records = copy.deepcopy(seed.records)
        _set_at(records[i], path, _tweak(rng, path[-1], _get_at(records[i], path)))
        records[i]["record_hash"] = record_hash(records[i])
        assert not checker.check(Case(seed, 0, _lines([_dumps(r) for r in records]), [f"{i} {path}"], False, False))


HUGE_FIELDS = (
    ["context", "tool_calls", "output", "attributes", "x-other", "chain_id", "run_id"] if FULL else ["context"]
)


@pytest.mark.parametrize("field", HUGE_FIELDS)
@pytest.mark.parametrize(
    ("label", "value"),
    [
        ("large text", "A" * 5_000_000),
        ("long list", [0] * 200_000),
        ("deep 100", _Deep(100)),
        ("deep 950", _Deep(950)),
        ("deep 100000", _Deep(100_000)),
    ],
    ids=lambda v: v if isinstance(v, str) and len(v) < 20 else "",
)
def test_huge_and_deep_values(seed, field, label, value, tmp_path):
    index = next(i for i, r in enumerate(seed.records) if r.get("event_type") == "llm_call")
    records = copy.deepcopy(seed.records)
    records[index][field] = value
    _check(tmp_path, seed, _lines([_dumps(r) for r in records]), f"{field} {label}")


def test_duplicate_keys_on_every_top_level_field(seed, tmp_path):
    checker = Checker(tmp_path)
    line = seed.lines[1]
    for name in seed.records[1]:
        extra = json.dumps({name: None})[1:-1].encode()
        for doubled in (line[:1] + extra + b"," + line[1:], line[:-1] + b"," + extra + b"}"):
            data = _lines([seed.lines[0], doubled, *seed.lines[2:]])
            found = checker.check(Case(seed, 0, data, [name], False, False))
            assert not found, (name, [(v.invariant, v.detail) for v in found])
            assert not verify_lines(data.splitlines(), [seed.pub]).ok


@pytest.mark.parametrize(
    "text", ["1e999", "-1e999", "NaN", "Infinity", "123456789012345678901234567890", "01", "1_000"]
)
def test_numbers_that_cannot_be_kept_exactly(seed, text, tmp_path):
    index = next(i for i, r in enumerate(seed.records) if r.get("event_type") == "llm_call")
    records = copy.deepcopy(seed.records)
    records[index]["step_id"] = "@@N@@"
    data = _lines([_dumps(r).replace(b'"@@N@@"', text.encode()) for r in records])
    _check(tmp_path, seed, data, text)
    assert not verify_lines(data.splitlines(), [seed.pub]).ok


# Heartbeats, extension fields, omitted values -----------------------------------------------------------------


@pytest.mark.parametrize("value", [0, -1, 1e308, "60", None, True, [], {}], ids=repr)
def test_heartbeat_interval_of_any_value(seed, value, tmp_path):
    index = next(i for i, r in enumerate(seed.records) if r.get("event_type") == "heartbeat")
    records = copy.deepcopy(seed.records)
    records[index]["attributes"]["interval_s"] = value
    _check(tmp_path, seed, _lines([_dumps(r) for r in records]), f"interval {value!r}")


@pytest.mark.parametrize("value", [5, True, "x", {}, None, [1], ["ok", 2], ["context[0].content (1 bytes)"]], ids=repr)
def test_x_omitted_on_a_correctly_linked_extra_line(all_seeds, value, tmp_path):
    seed = next(s for s in all_seeds if s.name == "omitted")
    event = next(r for r in reversed(seed.records) if r["kind"] == "event")
    extra = {
        **copy.deepcopy(event),
        "seq": seed.records[-1]["seq"] + 1,
        "prev_hash": seed.records[-1]["record_hash"],
        "x-omitted": value,
    }
    extra["record_hash"] = record_hash(extra)
    _check(tmp_path, seed, _lines([*seed.lines, _dumps(extra)]), f"x-omitted {value!r}")


def test_a_correctly_linked_extra_line_is_counted_as_unsigned(seed):
    event = next(r for r in reversed(seed.records) if r["kind"] == "event")
    extra = {**copy.deepcopy(event), "seq": seed.records[-1]["seq"] + 1, "prev_hash": seed.records[-1]["record_hash"]}
    extra["record_hash"] = record_hash(extra)
    report = verify_lines([*seed.lines, _dumps(extra)], [seed.pub])
    assert report.ok and report.unsigned_tail == 1
    assert "unsigned_tail" in {w.code for w in report.warnings}


# Checkpoints, keys and the head -------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("signature", ""),
        ("signature", "not base64"),
        ("signature", "AAAA"),
        ("public_key", ""),
        ("public_key", "AAAA"),
        ("key_id", "ed25519:0000000000000000"),
        ("sig_alg", "none"),
        ("sig_alg", "rsa"),
        ("merkle_root", "sha256:" + "0" * 64),
        ("covers", {"from_seq": 1, "to_seq": 2}),
        ("covers", {"from_seq": 5, "to_seq": 1}),
        ("covers", {}),
        ("timestamp_token", "AAAA"),
        ("timestamp_token", "not base64"),
        ("next_key", {}),
        ("next_key", {"sig_alg": "ed25519", "public_key": "AAAA", "key_id": "x"}),
    ],
)
def test_a_damaged_checkpoint_is_never_valid(all_seeds, seed, field, value, tmp_path):
    for s in _seeds(all_seeds, seed):
        index = next(i for i, r in enumerate(s.records) if r["kind"] == "checkpoint")
        records = copy.deepcopy(s.records)
        records[index][field] = value
        lines = [_dumps(r) for r in records]
        _check(tmp_path, s, _lines(lines), f"{field}={value!r}")
        assert not verify_lines(lines, [s.pub]).ok


def test_a_handover_to_another_key_inserted_later_is_refused(all_seeds):
    seed = next(s for s in all_seeds if s.name == "rotated-p256")
    theirs = public_key_b64(generate_private_key())
    records = copy.deepcopy(seed.records)
    index = next(i for i, r in enumerate(records) if r["kind"] == "checkpoint")
    records[index]["next_key"] = {"sig_alg": "ed25519", "public_key": theirs, "key_id": "x"}
    assert not verify_lines([_dumps(r) for r in records], [seed.pub]).ok


def _cli(*args, encoding="utf-8"):
    env = {**os.environ, "PYTHONIOENCODING": encoding}
    return subprocess.run(
        [sys.executable, "-m", "mnestiq.cli", *map(str, args)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=env,
        timeout=120,
    )


@pytest.mark.parametrize(
    "head",
    [
        b"",
        b"null",
        b"5",
        b"[]",
        b"{}",
        b"not json",
        b'{"kind":"event","seq":1}',
        b'{"kind":"checkpoint"}',
        b'{"kind":"checkpoint","seq":"x"}',
        b"\xff\xfe",
    ],
    ids=lambda h: repr(h[:16]),
)
def test_a_bad_head_file_is_a_clear_refusal_or_invalid(seed, head, tmp_path):
    evidence, pub, head_file = tmp_path / "e.jsonl", tmp_path / "e.pub", tmp_path / "h.json"
    evidence.write_bytes(seed.data)
    pub.write_text(seed.pub, "ascii")
    head_file.write_bytes(head)
    done = _cli("verify", evidence, "--trusted-key", pub, "--head", head_file)
    assert "Traceback" not in done.stdout + done.stderr
    assert done.returncode in (1, 2), "a head that says nothing must not read as a pass"


def test_a_head_from_another_place_in_the_file_or_another_chain(all_seeds, seed):
    other = next(s for s in all_seeds if s is not seed)
    first = next(r for r in seed.records if r["kind"] == "checkpoint")
    changed = {**seed.head, "record_hash": "sha256:" + "0" * 64}
    assert verify_lines(seed.lines, [seed.pub], first).ok, "an older genuine head still matches"
    assert not verify_lines(seed.lines, [seed.pub], other.head).ok
    assert not verify_lines(seed.lines, [seed.pub], changed).ok


@pytest.mark.parametrize("key", ["", "not a key", "AAAA", "x" * 5000])
def test_a_bad_trusted_key_is_a_clear_refusal(seed, key, tmp_path):
    evidence = tmp_path / "e.jsonl"
    evidence.write_bytes(seed.data)
    done = _cli("verify", evidence, "--trusted-key", key)
    assert "Traceback" not in done.stdout + done.stderr
    assert done.returncode in (1, 2)


def test_the_wrong_key_is_invalid_and_says_so(seed, tmp_path):
    evidence = tmp_path / "e.jsonl"
    evidence.write_bytes(seed.data)
    done = _cli("verify", evidence, "--trusted-key", public_key_b64(generate_private_key()))
    assert done.returncode == 1 and "untrusted_key" in done.stdout


@pytest.mark.parametrize("command", ["verify", "inspect", "redact", "dashboard"])
@pytest.mark.parametrize("target", ["missing", "folder", "binary"])
def test_a_path_that_is_not_an_evidence_file(command, target, tmp_path):
    path = tmp_path / target
    if target == "folder":
        path.mkdir()
    if target == "binary":
        path.write_bytes(bytes(range(256)) * 40)
    args = [command, path] + ([tmp_path / "out.jsonl"] if command == "redact" else [])
    if command == "dashboard" and target != "missing":
        pytest.skip("this one would serve the folder")
    done = _cli(*args)
    assert "Traceback" not in done.stdout + done.stderr
    assert done.returncode in (1, 2)


@pytest.mark.parametrize("command", ["verify", "inspect"])
def test_output_that_the_console_cannot_encode(seed, command, tmp_path):
    records = copy.deepcopy(seed.records)
    index = next(i for i, r in enumerate(records) if r.get("event_type") == "note")
    records[index]["attributes"] = {"message": "\ud800 \U0001f600"}
    records[index]["agent_id"] = "\u202e\U0001f600"
    path = tmp_path / "e.jsonl"
    path.write_bytes(_lines([_dumps(r) for r in records]))
    done = _cli(command, path, encoding="ascii")
    assert "Traceback" not in done.stdout + done.stderr


# The rules ----------------------------------------------------------------------------------------------------


def test_a_lost_finding_is_never_lost_in_silence(all_seeds, seed):
    """Whatever single field is changed: either the findings are the same, or the verdict is not VALID."""
    rng = random.Random(3)
    for s in _seeds(all_seeds, seed):
        base = [(f["rule"], f["seq"]) for f in s.base_findings]
        for i, record in enumerate(s.records):
            for path in _sample(_paths(record), 3):
                records = copy.deepcopy(s.records)
                _set_at(records[i], path, _tweak(rng, path[-1], _get_at(records[i], path)))
                got = [(f["rule"], f["seq"]) for f in findings(copy.deepcopy(records))]
                if got != base:
                    assert not verify_lines([_dumps(r) for r in records], [s.pub]).ok, (i, path)


# The folder view, over real HTTP -----------------------------------------------------------------------------


def _serve(folder, pub):
    server = create_server(folder, trusted_keys=[pub], port=0, key="k")
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def _get(server, path):
    port = server.server_address[1]
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", headers={"X-Mnestiq-Key": "k"})
    with urllib.request.urlopen(req, timeout=60) as response:
        return json.loads(response.read())


@pytest.mark.parametrize(
    "damage",
    [
        "x-omitted",
        "heartbeat",
        "deep first line",
        "deep record",
        "surrogate",
        "big number",
        "garbage after first line",
        "first line only",
    ],
)
def test_one_bad_file_never_takes_down_the_folder(seed, damage, tmp_path):
    records = copy.deepcopy(seed.records)
    lines = [_dumps(r) for r in records]
    extra = {**copy.deepcopy(records[-2]), "seq": records[-1]["seq"] + 1}
    if damage == "x-omitted":
        lines.append(_dumps({**extra, "x-omitted": 5}))
    elif damage == "heartbeat":
        lines.append(_dumps({**extra, "event_type": "heartbeat", "attributes": 5}))
    elif damage == "deep first line":
        lines[0] = b'{"spec_version":"1.0","chain_id":"c","x-a":' + b"[" * 100_000 + b"]" * 100_000 + b"}"
    elif damage == "deep record":
        lines.append(_dumps({**extra, "error": _Deep(5000)}))
    elif damage == "surrogate":
        lines.append(_dumps({**extra, "error": "\ud800"}))
    elif damage == "big number":
        lines.append(_dumps({**extra, "step_id": "@@"}).replace(b'"@@"', b"1e999"))
    elif damage == "garbage after first line":
        lines = [lines[0], bytes(range(256)) * 50]
    else:
        lines = lines[:1]
    (tmp_path / "bad.jsonl").write_bytes(_lines(lines))
    (tmp_path / "good.jsonl").write_bytes(seed.data)
    server = _serve(tmp_path, seed.pub)
    try:
        listing = {f["name"]: f for f in _get(server, "/api/files")["files"]}
        assert listing["good.jsonl"]["ok"] is True
        assert _get(server, "/api/file?name=good.jsonl")["report"]["ok"] is True
        if "bad.jsonl" in listing:
            assert listing["bad.jsonl"]["ok"] is False
    finally:
        server.shutdown()
        server.server_close()


# The checker itself: a fuzzer that cannot fail proves nothing -----------------------------------------------


def _violations(seed, tmp_path, data, **kwargs):
    return {v.invariant for v in Checker(tmp_path).check(Case(seed, 0, data, ["self test"], False, False, **kwargs))}


def test_the_checker_notices_a_verifier_that_always_says_valid(seed, tmp_path, monkeypatch):
    import fuzz.engine as engine

    real = engine.verify_lines

    def lenient(lines, keys=(), head=None):
        report = real(lines, keys, head)
        report.ok = True
        report.errors = []
        return report

    monkeypatch.setattr(engine, "verify_lines", lenient)
    records = copy.deepcopy(seed.records)
    records[1]["step_id"] = 99
    assert "signed_changed" in _violations(seed, tmp_path, _lines([_dumps(r) for r in records]))


def test_the_checker_notices_a_crash(seed, tmp_path, monkeypatch):
    import fuzz.engine as engine

    def broken(*args):
        raise TypeError("the shape of the first report")

    monkeypatch.setattr(engine, "findings", broken)
    assert "no_crash" in _violations(seed, tmp_path, seed.data)


def test_the_checker_notices_content_left_in_a_redacted_copy(seed, tmp_path, monkeypatch):
    import mnestiq.cli as cli

    monkeypatch.setattr(cli, "redact", lambda record: record)
    assert "redact_left" in _violations(seed, tmp_path, seed.data)


def test_the_checker_notices_a_folder_view_that_dies(seed, tmp_path, monkeypatch):
    import fuzz.engine as engine

    class Broken(engine.EvidenceStore):
        def load(self, path):
            raise TypeError("one file took the view down")

    monkeypatch.setattr(engine, "EvidenceStore", Broken)
    assert "no_crash" in _violations(seed, tmp_path, seed.data)


def test_mutation_is_repeatable(seed):
    assert mutate(seed, 12345).data == mutate(seed, 12345).data
    assert mutate(seed, 12345).data != mutate(seed, 12346).data


def test_every_kind_of_seed_was_built(all_seeds):
    assert isinstance(all_seeds[0], Seed) and Violation("a", "b", "c :: d").signature == "a|b|c"
    assert any("x-omitted" in r for s in all_seeds for r in s.records)
    assert any(r.get("event_type") == "heartbeat" for s in all_seeds for r in s.records)
    assert any("next_key" in r for s in all_seeds for r in s.records)
    assert any("context_base" in r for s in all_seeds for r in s.records)
    assert Path(__file__).exists()
