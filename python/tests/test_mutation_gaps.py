"""Checks in the verifier, the key file and the hashing that a mutation test found no test for.

Each test here fails if the check it names is removed or turned around. The witness logs are written by hand, the
keys are throwaway ones, and nothing leaves this machine.
"""

import base64
import os
import stat
import subprocess
from datetime import datetime, timezone

import pytest
from cryptography.exceptions import InvalidSignature

import mnestiq.keys
import mnestiq.signer_service
import mnestiq.timestamps
from mnestiq import FileSink, LocalSigner, Recorder, Segment, verify_file
from mnestiq.canonical import canonical_json
from mnestiq.cli import main
from mnestiq.hashing import digest_bytes, iter_redactable_paths, record_hash, signing_payload
from mnestiq.keys import (P256, P256_ORDER, generate_private_key, load_private_key, public_key_b64, save_keypair,
                          verify_signature)
from mnestiq.merkle import merkle_root
from mnestiq.verify import (RESTART_FIELD, WITNESS_FOLDER, _shown, _witnessed_root_matches, read_regular_file,
                            read_witness_log, schema_problem)

from conftest import dump, load

HEADER = {"chain_id": "c", "kind": "mnestiq-witness", "version": 1}
AT = "2026-01-01T00:00:00.000000Z"
HASH_A = "sha256:" + "ab" * 32


def codes(report):
    return {issue.code for issue in report.errors}


def notes(report):
    return {issue.code for issue in report.warnings}


def said(report, code):
    return [issue.message for issue in [*report.errors, *report.warnings] if issue.code == code]


def add_notes(rec, count):
    for i in range(count):
        rec.append_event({"event_type": "note", "run_id": "r", "agent_id": "a", "attributes": {"i": i}})


def unsigned_chain(path, count):
    """``count`` notes of chain "c" from seq 0 on, and no checkpoint."""
    rec = Recorder(FileSink(path), agent_id="a", chain_id="c", checkpoint_every=10**6)
    add_notes(rec, count)
    rec._sink.close()
    return load(path)


def signed_chain(path, key, count=5, every=3):
    """``count`` notes of chain "c", a checkpoint after every ``every`` records, and one at the end."""
    rec = Recorder(FileSink(path), agent_id="a", chain_id="c", signing_key=key, checkpoint_every=every)
    add_notes(rec, count)
    rec.close()
    return load(path)


def relink(records, start):
    """Redo the hashes from ``start`` on, as someone with write access would after changing a record."""
    for i in range(start, len(records)):
        if i:
            records[i]["prev_hash"] = records[i - 1]["record_hash"]
        records[i]["record_hash"] = record_hash(records[i])


def resign(record, key):
    """Sign a checkpoint again after a change to it, as the holder of ``key`` would."""
    record.pop("record_hash", None)
    record["signature"] = base64.b64encode(LocalSigner(key).sign(signing_payload(record))).decode("ascii")
    record["record_hash"] = record_hash(record)


def root_of(hashes):
    return "sha256:" + merkle_root([digest_bytes(h) for h in hashes]).hex()


def head_line(seq, record=HASH_A):
    return {"at": AT, "by": "head", "record_hash": record, "seq": seq}


def checkpoint_line(seq, first, root):
    return {"at": AT, "by": "checkpoint", "covers": {"from_seq": first, "to_seq": seq - 1}, "merkle_root": root,
            "request": "ab" * 32, "seq": seq}


def write_log(path, *entries, header=HEADER):
    path.write_bytes(b"".join(canonical_json(line) + b"\n" for line in (header, *entries)))
    return path


# The schema's anyOf: an agent identity names the agent by at least one id


def chain_with_identity(path, identity):
    records = unsigned_chain(path, 2)
    records[1]["agent_identity"] = identity
    relink(records, 1)
    dump(path, records)
    return records[1]


@pytest.mark.parametrize("identity", [
    {"provider": "entra"}, {"provider": "entra", "name": "bot", "tenant_id": "t", "blueprint_id": "b"},
], ids=["provider-only", "everything-but-an-id"])
def test_an_agent_identity_with_none_of_its_ids_breaks_the_schema(tmp_path, identity):
    path = tmp_path / "e.jsonl"
    record = chain_with_identity(path, identity)
    report = verify_file(path)
    assert not report.ok and codes(report) == {"schema"}
    assert all(message.startswith("agent_identity: ") for message in said(report, "schema"))
    assert schema_problem(record).startswith("agent_identity: ")


@pytest.mark.parametrize("ids", [
    {"id": "x"}, {"app_id": "x"}, {"object_id": "x"}, {"id": "x", "app_id": "y", "object_id": "z"},
], ids=["id", "app_id", "object_id", "all-three"])
def test_an_agent_identity_with_any_of_its_ids_passes(tmp_path, ids):
    path = tmp_path / "e.jsonl"
    record = chain_with_identity(path, {"provider": "entra", **ids})
    report = verify_file(path)
    assert report.ok, report.errors
    assert schema_problem(record) is None


# A restart note for exactly one record


def test_a_restart_that_takes_over_one_unsigned_record_is_recognised(tmp_path, key, pub):
    path = tmp_path / "e.jsonl"
    rec = Recorder(FileSink(path), agent_id="a", signing_key=key, checkpoint_every=1000)
    with rec.run() as run:
        run.note("signed")
        rec.checkpoint()
    rec._sink.close()  # a crash: the end of the run, at seq 3, is the one record nothing signed
    Recorder(FileSink(path), agent_id="a", signing_key=key).close()
    records = load(path)
    [note] = [r for r in records if RESTART_FIELD in (r.get("attributes") or {})]
    assert note["attributes"][RESTART_FIELD] == {"first_seq": 3, "last_seq": 3, "count": 1}
    report = verify_file(path, [pub])
    assert report.ok, report.errors
    [warning] = [w for w in report.warnings if w.code == "signed_after_restart"]
    assert warning.message.startswith("records 3..3 ") and warning.seq == note["seq"]
    assert report.restarts == [{"from_seq": 3, "to_seq": 3, "checkpoint_seq": records[-1]["seq"]}]


# A head that is an object but not a checkpoint


def an_event(records):
    return dict(records[0])


def no_kind(records):
    return {k: v for k, v in records[-1].items() if k != "kind"}


def seq_as_text(records):
    return {**records[-1], "seq": str(records[-1]["seq"])}


def no_seq(records):
    return {k: v for k, v in records[-1].items() if k != "seq"}


def seq_with_a_fraction(records):
    return {**records[-1], "seq": records[-1]["seq"] - 0.5}


@pytest.mark.parametrize("change", [an_event, no_kind, seq_as_text, no_seq, seq_with_a_fraction],
                         ids=lambda change: change.__name__)
def test_a_head_that_is_an_object_but_not_a_checkpoint_is_named_as_that(tmp_path, key, pub, change):
    path = tmp_path / "e.jsonl"
    records = signed_chain(path, key)
    assert verify_file(path, [pub], records[-1]).head_seq == records[-1]["seq"]  # the head as it was kept
    report = verify_file(path, [pub], change(records))
    assert not report.ok and report.head_seq is None
    assert codes(report) == {"head"} and said(report, "head") == ["the head is not a checkpoint record"]


def test_the_command_line_names_a_head_file_that_holds_an_event(tmp_path, key, pub, capsys):
    path = tmp_path / "e.jsonl"
    records = signed_chain(path, key)
    head = tmp_path / "head.json"
    head.write_bytes(canonical_json(records[0]))
    assert main(["verify", str(path), "--trusted-key", pub, "--head", str(head)]) != 0
    assert "the head is not a checkpoint record" in capsys.readouterr().out


# The witness log: how many bad lines are read, and what is read at all


@pytest.mark.parametrize("bad,given_up", [(1000, False), (1001, True)], ids=["at-the-cap", "one-over-the-cap"])
def test_a_witness_log_is_given_up_on_only_past_a_thousand_bad_lines(tmp_path, bad, given_up):
    log = tmp_path / "witness.jsonl"
    lines = [canonical_json(HEADER), canonical_json(head_line(0)), *[b"x"] * bad, canonical_json(head_line(1))]
    log.write_bytes(b"".join(line + b"\n" for line in lines))
    read = read_witness_log(log)
    assert read.damaged_lines == bad
    assert read.problem == ("more than 1000 of its lines cannot be read" if given_up else None)
    assert sorted(read.heads) == ([0] if given_up else [0, 1])  # past the cap the rest is not read


def test_a_link_in_place_of_a_file_is_not_read(tmp_path):
    target = tmp_path / "target.jsonl"
    write_log(target, head_line(0))
    link = tmp_path / "link.jsonl"
    try:
        os.symlink(target, link)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"this system refused to make a link ({type(exc).__name__})")
    assert read_regular_file(target, 10) == target.read_bytes()[:10]
    with pytest.raises(OSError, match="this is a link, not a file"):
        read_regular_file(link, 10)
    assert read_witness_log(link).problem.startswith("it could not be read")
    assert read_witness_log(target).problem is None


def test_a_file_the_system_calls_a_link_is_refused_before_it_is_opened(tmp_path, monkeypatch):
    """The same check where no link can be made, as on Windows without the right to: the answer of lstat is
    replaced for this one file. Without the check, Windows has nothing else that stops a link being followed."""
    path = tmp_path / "f.jsonl"
    path.write_bytes(b"data\n")
    assert read_regular_file(path, 10) == b"data\n"
    real = os.lstat

    class AsLink:
        st_mode = stat.S_IFLNK | 0o777

    def lstat(name, *args, **kwargs):
        return AsLink() if os.fspath(name) == str(path) else real(name, *args, **kwargs)

    with monkeypatch.context() as patched:
        patched.setattr(os, "lstat", lstat)
        with pytest.raises(OSError, match="this is a link, not a file"):
            read_regular_file(path, 10)


@pytest.mark.parametrize("change", [{"chain_id": 5}, {"extra": 1}, {"thinned": "3"}, {"thinned": True},
                                    {"thinned": -1}],
                         ids=["chain-a-number", "unknown-key", "thinned-as-text", "thinned-true", "thinned-negative"])
def test_each_fault_in_a_witness_header_makes_it_malformed(tmp_path, change):
    path = tmp_path / "e.jsonl"
    records = unsigned_chain(path, 2)
    log = write_log(tmp_path / "witness.jsonl", head_line(0, records[0]["record_hash"]), header={**HEADER, **change})
    read = read_witness_log(log)
    assert read.problem == "its header is malformed" and not read.entries and read.chain_id is None
    report = verify_file(path, witness=log)
    assert not report.ok and codes(report) == {"witness_unusable"}
    assert "its header is malformed" in said(report, "witness_unusable")[0]


def test_a_witness_header_that_says_how_many_entries_were_dropped_is_read(tmp_path):
    log = write_log(tmp_path / "witness.jsonl", head_line(0), header={**HEADER, "thinned": 3})
    read = read_witness_log(log)
    assert read.problem is None and read.thinned == 3 and read.heads == {0: HASH_A}


@pytest.mark.parametrize("entry", [
    {**head_line(5), "junk": 1},
    {**head_line(5), "record_hash": "sha256:" + "AB" * 32},
    {**head_line(5), "record_hash": "sha256:" + "ab" * 31},
    {**head_line(5), "record_hash": "ab" * 32},
    {**head_line(5), "record_hash": 5},
], ids=["extra-key", "hash-in-capitals", "hash-too-short", "hash-without-its-prefix", "hash-a-number"])
def test_a_head_line_with_wrong_keys_or_a_malformed_hash_is_not_taken(tmp_path, entry):
    log = write_log(tmp_path / "witness.jsonl", entry, head_line(6))
    read = read_witness_log(log)
    assert read.damaged_lines == 1 and read.reasons == ["the line for seq 5 is malformed"]
    assert read.heads == {6: HASH_A} and read.entries == [head_line(6)]


# A witnessed checkpoint that is not in the file: do its records match


PENDING = [(seq, "sha256:" + f"{seq:02x}" * 32) for seq in range(3, 8)]  # the records 3..7 since the last checkpoint
WITH_A_GAP = [PENDING[0], (9, "sha256:" + "09" * 32), *PENDING[2:]]  # 3, 9, 5, 6, 7: one seq out of place


def signed_over(low, high, pairs):
    return {"covers": {"from_seq": low, "to_seq": high}, "merkle_root": root_of([h for _, h in pairs])}


def test_a_witnessed_range_inside_the_file_matches_by_its_root():
    assert _witnessed_root_matches(PENDING, signed_over(4, 6, PENDING[1:4]))
    assert _witnessed_root_matches(PENDING, signed_over(3, 7, PENDING))
    assert not _witnessed_root_matches(PENDING, signed_over(4, 6, PENDING[1:3]))
    assert not _witnessed_root_matches([], signed_over(4, 6, PENDING[1:4]))


@pytest.mark.parametrize("pending,low,high", [(PENDING, 0, 7), (PENDING, 5, 9), (WITH_A_GAP, 4, 5),
                                              (WITH_A_GAP, 3, 4)],
                         ids=["starts-before", "ends-after", "another-seq-at-its-start", "another-seq-at-its-end"])
def test_a_witnessed_range_the_file_does_not_hold_never_matches(pending, low, high):
    """The root given is the root of the records that stand at those positions, so only the test of the range
    itself can refuse it. Each case breaks one part of that test and no other."""
    first = pending[0][0]
    at_those_positions = pending[low - first:high - first + 1]
    assert at_those_positions  # a root to match exists, so the range is what gets this refused
    assert not _witnessed_root_matches(pending, signed_over(low, high, at_those_positions))


# A witness log that cannot be used says why


def test_a_witness_log_of_another_chain_is_not_compared_and_says_so(tmp_path):
    path = tmp_path / "e.jsonl"
    records = unsigned_chain(path, 2)
    log = write_log(tmp_path / "witness.jsonl", head_line(0, records[0]["record_hash"]),
                    header={**HEADER, "chain_id": "other"})
    assert read_witness_log(log).problem is None  # nothing is wrong with the log itself
    report = verify_file(path, witness=log)
    assert not report.ok and codes(report) == {"witness_unusable"}
    assert "it belongs to chain 'other', not this one" in said(report, "witness_unusable")[0]
    assert report.witness["entries"] == 0 and report.witness["matched_through"] is None


def test_a_witness_log_with_another_problem_keeps_that_problems_words(tmp_path):
    path = tmp_path / "e.jsonl"
    records = unsigned_chain(path, 2)
    log = write_log(tmp_path / "witness.jsonl", head_line(0, records[0]["record_hash"]),
                    header={**HEADER, "version": 2})
    [message] = said(verify_file(path, witness=log), "witness_unusable")
    assert "it has version 2, and this verifier reads version 1" in message
    assert "belongs to chain" not in message


def test_a_valid_file_stays_valid_when_the_witness_folder_holds_no_log_for_it(tmp_path, key, pub):
    path = tmp_path / "e.jsonl"
    signed_chain(path, key)
    folder = tmp_path / "signer"
    (folder / WITNESS_FOLDER).mkdir(parents=True)
    report = verify_file(path, [pub], witness=folder)
    assert report.ok and report.errors == []
    assert "witness_none" in notes(report)
    assert report.witness["entries"] == 0 and report.witness["highest_seq"] is None
    assert report.records == len(load(path)) and report.checkpoints == 2  # every record was still checked


# How far the witness reached


@pytest.mark.parametrize("after", [0, 1, 3])
def test_the_tail_warning_names_exactly_the_records_after_the_last_send(tmp_path, after):
    path = tmp_path / "e.jsonl"
    records = unsigned_chain(path, 3 + after)
    log = write_log(tmp_path / "witness.jsonl", head_line(0, records[0]["record_hash"]),
                    head_line(2, records[2]["record_hash"]))
    report = verify_file(path, witness=log)
    assert report.ok, report.errors
    assert report.witness["highest_seq"] == 2 and report.witness["matched_through"] == 2
    assert report.witness["not_witnessed"] == after
    if after:
        [message] = said(report, "witness_tail")
        assert message.startswith(f"records 3..{2 + after} came after the last send")
    else:
        assert "witness_tail" not in notes(report)


@pytest.mark.parametrize("head_too,reached", [(False, 2), (True, 3)], ids=["checkpoint-only", "and-a-head"])
def test_a_lost_checkpoint_vouches_for_the_records_before_it_and_a_head_for_its_own(tmp_path, head_too, reached):
    """The service signed a checkpoint for seq 3 that never reached the file, and the recorder wrote an event
    there. The checkpoint covers records 0..2. Only a head sent for seq 3 says anything about the event."""
    path = tmp_path / "e.jsonl"
    records = unsigned_chain(path, 5)
    entries = [checkpoint_line(3, 0, root_of([r["record_hash"] for r in records[:3]]))]
    if head_too:
        entries.append(head_line(3, records[3]["record_hash"]))
    report = verify_file(path, witness=write_log(tmp_path / "witness.jsonl", *entries))
    assert report.ok, report.errors
    assert "witness_checkpoint_lost" in notes(report)
    assert report.witness["highest_seq"] == 3 and report.witness["matched_through"] == reached
    [message] = said(report, "witness_tail")
    assert message.startswith("records 4..4 came after the last send")


# The private key file


class AsWindows:
    """The os module as keys.py sees it, under the name of Windows: the branch that restricts the key file then
    runs on every system. Everything else is the real module."""

    name = "nt"

    def __getattr__(self, attribute):
        return getattr(os, attribute)


class Refused(Exception):
    pass


READ_ACCESS_LIST = (
    "$acl = [System.IO.File]::GetAccessControl($env:MNESTIQ_ACL_PATH); "
    "$names = $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]) "
    "| ForEach-Object { $_.IdentityReference.Value }; "
    "Write-Output ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value); "
    "Write-Output $acl.AreAccessRulesProtected; "
    "Write-Output ($names -join ' ')")


@pytest.mark.skipif(os.name != "nt", reason="access lists are how Windows keeps a file private")
def test_on_windows_the_private_key_file_names_only_the_current_user(tmp_path):
    key = generate_private_key()
    private, public = save_keypair(key, tmp_path / "keys")
    env = {k: v for k, v in os.environ.items() if k.upper() != "PSMODULEPATH"}
    result = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", READ_ACCESS_LIST],
                            capture_output=True, text=True, check=False, timeout=60,
                            env={**env, "MNESTIQ_ACL_PATH": str(private)})
    assert result.returncode == 0, result.stderr
    me, protected, names = (line.strip() for line in result.stdout.splitlines())
    assert names.split() == [me]  # one rule, for this user, and none taken over from the folder
    assert protected == "True"
    assert public_key_b64(load_private_key(private)) == public.read_text("ascii").strip() == public_key_b64(key)


@pytest.mark.skipif(os.name == "nt", reason="file modes are how POSIX keeps a file private")
def test_on_posix_the_private_key_file_has_mode_600(tmp_path):
    key = generate_private_key()
    private, public = save_keypair(key, tmp_path / "keys")
    assert stat.S_IMODE(private.stat().st_mode) == 0o600
    assert public_key_b64(load_private_key(private)) == public.read_text("ascii").strip() == public_key_b64(key)


def test_the_key_file_is_restricted_while_it_is_still_empty(tmp_path, monkeypatch):
    sizes = []
    monkeypatch.setattr(mnestiq.keys, "os", AsWindows())
    monkeypatch.setattr(mnestiq.signer_service, "restrict_to_owner", lambda path: sizes.append(path.stat().st_size))
    private, _ = save_keypair(generate_private_key(), tmp_path)
    assert sizes == [0] and private.stat().st_size > 0


def test_a_key_file_that_cannot_be_restricted_is_removed_and_the_error_is_raised(tmp_path, monkeypatch):
    def refuse(path):
        raise Refused(f"could not restrict {path.name}")

    monkeypatch.setattr(mnestiq.keys, "os", AsWindows())
    monkeypatch.setattr(mnestiq.signer_service, "restrict_to_owner", refuse)
    with pytest.raises(Refused, match=r"could not restrict signing\.key"):
        save_keypair(generate_private_key(), tmp_path)
    assert list(tmp_path.iterdir()) == []  # neither a half-made key file nor a public key for it
    monkeypatch.setattr(mnestiq.signer_service, "restrict_to_owner", lambda path: None)
    private, public = save_keypair(generate_private_key(), tmp_path)  # so the next try is not refused as an overwrite
    assert private.exists() and public.exists()


# P-256 signatures: the range of r and s


HALF = P256_ORDER // 2


def p256_signature(r, s):
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


@pytest.mark.parametrize("r,s", [(0, 1), (P256_ORDER, 1), (1, 0), (1, HALF + 1)],
                         ids=["r-zero", "r-the-group-order", "s-zero", "s-just-above-half"])
def test_a_p256_signature_out_of_range_is_refused_by_our_own_check(r, s):
    public = public_key_b64(generate_private_key(P256))
    # The library refuses most of these too, with no words. The words show that it was never asked.
    with pytest.raises(InvalidSignature, match="P-256 signature out of range"):
        verify_signature(P256, public, p256_signature(r, s), b"checkpoint")


@pytest.mark.parametrize("r,s", [(1, HALF), (P256_ORDER - 1, 1)], ids=["s-at-half", "r-just-below-the-order"])
def test_a_p256_signature_at_the_edge_of_the_range_goes_on_to_the_real_check(r, s):
    public = public_key_b64(generate_private_key(P256))
    with pytest.raises(InvalidSignature) as refused:
        verify_signature(P256, public, p256_signature(r, s), b"checkpoint")
    assert "out of range" not in str(refused.value)


# The path of a redactable slot


def test_a_redactable_slot_is_named_by_where_it_is():
    record = {"context": [{"content": "a", "content_hash": HASH_A}, {"source": "user"}, {"content_hash": HASH_A}],
              "output": {"content_salt": "c2FsdA=="},
              "tool_calls": [{"arguments": {}, "result": 1}]}
    assert [path for _, _, path in iter_redactable_paths(record)] == [
        "context[0].content", "context[2].content", "output.content", "tool_calls[0].arguments",
        "tool_calls[0].result"]


def test_a_salt_left_behind_is_reported_at_the_path_of_its_slot(tmp_path):
    path = tmp_path / "e.jsonl"
    rec = Recorder(FileSink(path), agent_id="a", chain_id="c", checkpoint_every=10**6)
    with rec.run() as run:
        run.llm_call(provider="p", model="m", output=[{"type": "text", "text": "ok"}],
                     context=[Segment("system", "s"), Segment("user", "hi"), Segment("web", "a page")])
    rec._sink.close()
    records = load(path)
    call = next(r for r in records if r["event_type"] == "llm_call")
    del call["context"][2]["content"], call["output"]["content"]  # redacted by hand, and the salts forgotten
    dump(path, records)
    report = verify_file(path)
    assert report.ok, report.errors
    assert [message.split(" ")[0] for message in said(report, "salt")] == ["context[2].content", "output.content"]


# Words of messages


def test_text_from_a_file_gets_dots_only_when_it_was_cut():
    assert _shown("a" * 200) == "a" * 200
    assert _shown("a" * 201) == "a" * 200 + "..."
    assert _shown("abc", limit=3) == "abc" and _shown("abcd", limit=3) == "abc..."


def test_a_schema_problem_shows_the_value_only_when_it_may(tmp_path):
    record = unsigned_chain(tmp_path / "e.jsonl", 1)[0]
    record["agent_id"] = ["sk-a-secret-value"]
    shown = schema_problem(record)
    assert shown == "agent_id: ['sk-a-secret-value'] is not of type 'string'"
    hidden = schema_problem(record, show_value=False)
    assert hidden.startswith("agent_id: breaks the schema's type rule") and "secret" not in hidden


@pytest.mark.parametrize("chain_id,shown", [("other", "'other'"), (7, "a value of type int")], ids=["text", "number"])
def test_a_record_of_another_chain_is_shown_by_its_id_or_by_its_type(tmp_path, chain_id, shown):
    path = tmp_path / "e.jsonl"
    records = unsigned_chain(path, 2)
    records[1]["chain_id"] = chain_id
    relink(records, 1)
    dump(path, records)
    assert said(verify_file(path), "chain_id") == [f"record belongs to chain {shown}, expected 'c'"]


# Checks the mutation test's survivors list called harmless to remove, and that are not


@pytest.mark.parametrize("change", [{"record_hash": 5}, {"seq": None}], ids=["hash-a-number", "no-seq"])
def test_a_record_too_malformed_to_link_gets_its_schema_errors_and_no_crash(tmp_path, change):
    """Such a record is not checked further. If it were, a hash that is a number would reach the comparison with a
    witnessed checkpoint, which reads each hash as text and is not made to survive anything else."""
    path = tmp_path / "e.jsonl"
    records = unsigned_chain(path, 3)
    root = root_of([r["record_hash"] for r in records])
    records[2].update(change)
    if change == {"seq": None}:
        del records[2]["seq"]
    dump(path, records)
    log = write_log(tmp_path / "witness.jsonl", checkpoint_line(3, 0, root))
    report = verify_file(path, witness=log)
    assert not report.ok and report.records == 3 and report.events == 2
    assert {issue.code for issue in report.errors if issue.line == 3} == {"schema"}
    assert "unreadable" not in codes(report)


def test_a_context_base_on_an_event_that_is_not_a_model_call_is_an_error(tmp_path):
    path = tmp_path / "e.jsonl"
    rec = Recorder(FileSink(path), agent_id="a", chain_id="c", checkpoint_every=10**6)
    with rec.run() as run:
        run.llm_call(provider="p", model="m", context=[Segment("user", "hi")])
        run.note("not a model call")
    rec._sink.close()
    assert verify_file(path).ok
    records = load(path)
    call, note = (next(i for i, r in enumerate(records) if r["event_type"] == kind) for kind in ("llm_call", "note"))
    # A base that would be in order on a model call: an earlier call of the same run, with that many segments.
    records[note]["context_base"] = {"seq": records[call]["seq"], "segments": 1}
    relink(records, note)
    dump(path, records)
    report = verify_file(path)
    assert not report.ok and codes(report) == {"context_base"}
    assert said(report, "context_base") == ["context_base belongs to model calls (llm_call) only"]


def test_a_checkpoint_time_that_is_no_real_date_does_not_break_its_timestamp_check(tmp_path, key, pub, monkeypatch):
    """The schema asks for digits in the right places, so a month 13 gets through. The comparison of the
    checkpoint's own time with the token's is then left out, and nothing else changes."""
    path = tmp_path / "e.jsonl"
    records = signed_chain(path, key, count=2, every=1000)
    last = records[-1]
    last["ts"]["wall"] = "9999-13-01T00:00:00.000000Z"
    last["timestamp_token"] = base64.b64encode(b"a token").decode("ascii")
    resign(last, key)
    dump(path, records)
    seen = datetime(2026, 1, 1, tzinfo=timezone.utc)
    monkeypatch.setattr(mnestiq.timestamps, "verify_token", lambda token, signature, roots: seen)
    report = verify_file(path, [pub], tsa_roots=[])
    assert report.ok, report.errors
    assert report.timestamps == [{"seq": last["seq"], "time": "2026-01-01T00:00:00Z"}]
