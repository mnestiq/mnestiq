"""The witness: a chain's newest head kept by the signing service, compared with the evidence at verify.

The vault is the stand-in from test_signers.py, the tokens and keys are throwaway ones, and nothing leaves this machine.
"""

import base64
import hashlib
import json
import threading
import time
from types import SimpleNamespace

import pytest

import mnestiq.recorder
import mnestiq.signer_service
import mnestiq.verify
from mnestiq import AzureKeyVaultSigner, FileSink, LocalSigner, Recorder, SignerClient, SignerError, verify_file
from mnestiq.canonical import canonical_json
from mnestiq.cli import main
from mnestiq.egress import instrument_egress, uninstrument_egress
from mnestiq.hashing import record_hash, signing_payload
from mnestiq.keys import generate_private_key, public_key_b64
from mnestiq.signer_service import SignerServer, SignerService, init_signer, key_vault_signer
from mnestiq.signers import WitnessUnsupported
from mnestiq.verify import WITNESS_FOLDER, read_witness_log, witness_file_name

from conftest import dump, load
from test_signer_keyvault_backend import KEY_URL, TOKEN, TroubledVault, checkpoint, log_of, serve
from test_signers import events

HASH_A, HASH_B = "sha256:" + "ab" * 32, "sha256:" + "cd" * 32


@pytest.fixture
def served(tmp_path):
    made = serve(tmp_path / "signer", TroubledVault())
    yield made
    made.client.close()
    made.server.close()


def witness(svc, chain="c", seq=0, record=HASH_A):
    return svc.handle({"op": "witness", "chain_id": chain, "seq": seq, "record_hash": record})


def log_path(served, chain):
    return served.dir / WITNESS_FOLDER / witness_file_name(chain)


def log_of_chain(served, chain):
    return read_witness_log(log_path(served, chain))


def flush(rec):
    """Stop the sender after its last send, for tests that crash the recorder or look at the log."""
    rec._witness.finish(5.0)


def crash(rec):
    """As if the process died: the file stays as it is, and no closing checkpoint is made."""
    if rec._witness is not None:
        flush(rec)
    rec._sink.close()


def relink(records, start):
    """Redo the hashes from ``start`` on, as someone with write access would after changing a record."""
    for i in range(start, len(records)):
        records[i]["prev_hash"] = records[i - 1]["record_hash"]
        records[i]["record_hash"] = record_hash(records[i])


def codes(report):
    return {issue.code for issue in report.errors}


def notes(report):
    return {issue.code for issue in report.warnings}


def checkpoint_indexes(records):
    return [i for i, r in enumerate(records) if r["kind"] == "checkpoint"]


def recording_with_a_tail(served, path, signed=4, tail=3):
    """``signed`` events and a checkpoint, then ``tail`` events the sender has reported and nothing signs."""
    rec = Recorder(FileSink(path), agent_id="a", signer=served.client, checkpoint_every=signed)
    events(rec, signed + tail)
    crash(rec)
    return load(path)


# The service endpoint


def test_a_head_is_kept_without_the_vault(served):
    served.vault.error = RuntimeError("the vault is down")
    assert witness(served.svc, seq=7) == {"witnessed": 7}
    assert served.vault.digests == []
    log = log_of_chain(served, "c")
    assert log.problem is None and log.chain_id == "c" and log.heads == {7: HASH_A}


def test_a_head_over_the_connection_needs_the_token(served):
    assert served.client.witness("c", 1, HASH_A) is True
    with pytest.raises(SignerError, match="did not accept the token"):
        SignerClient(served.server.address, "cd" * 32)


def test_seq_moves_forward_and_the_same_head_again_is_nothing_new(served):
    assert "witnessed" in witness(served.svc, seq=5)
    assert "witnessed" in witness(served.svc, seq=5)  # an answer was lost and it came again
    assert "must move forward" in witness(served.svc, seq=5, record=HASH_B)["error"]
    assert "must move forward" in witness(served.svc, seq=4)["error"]
    assert list(log_of_chain(served, "c").heads) == [5]


def test_a_refused_head_says_nothing_new_to_the_client(served):
    assert served.client.witness("c", 5, HASH_A) is True
    assert served.client.witness("c", 3, HASH_A) is False
    assert list(log_of_chain(served, "c").heads) == [5]


@pytest.mark.parametrize("change", [
    {"chain_id": ""}, {"chain_id": 5}, {"chain_id": "c" * (mnestiq.signer_service.MAX_CHAIN_ID + 1)},
    {"chain_id": "\ud800"}, {"seq": -1}, {"seq": "1"}, {"seq": True}, {"seq": 2.5}, {"seq": 2**53},
    {"record_hash": "sha256:ab"}, {"record_hash": 5}, {"record_hash": "SHA256:" + "AB" * 32}, {"extra": "x" * 100},
], ids=lambda change: next(iter(change)) + "-" + str(next(iter(change.values())))[:12])
def test_a_witness_request_that_breaks_the_bounds_is_refused_and_kept_nowhere(served, change):
    request = {"op": "witness", "chain_id": "c", "seq": 1, "record_hash": HASH_A, **change}
    assert "error" in served.svc.handle(request)
    assert not (served.dir / WITNESS_FOLDER).exists() or not list((served.dir / WITNESS_FOLDER).iterdir())


def test_a_refused_head_does_not_take_a_chains_place(tmp_path):
    made = serve(tmp_path / "signer", TroubledVault(), max_chains=1)
    try:
        for _ in range(3):
            assert "error" in made.svc.handle({"op": "witness", "chain_id": "a", "seq": -1, "record_hash": HASH_A})
        assert witness(made.svc, chain="b") == {"witnessed": 0}
    finally:
        made.client.close()
        made.server.close()


def test_one_request_cannot_end_a_chains_witness(served):
    assert "witnessed" in witness(served.svc, seq=0)
    assert "too far ahead" in witness(served.svc, seq=2**39)["error"]
    assert "witnessed" in witness(served.svc, seq=1)


def test_a_chain_id_is_kept_as_data_not_as_a_path(served):
    chain = "../../evil\nname"
    assert "witnessed" in witness(served.svc, chain=chain)
    assert log_path(served, chain).exists() and log_of_chain(served, chain).chain_id == chain
    assert not (served.dir.parent / "evil").exists()


def test_a_log_is_bounded_however_much_is_sent(served, small_caps):
    for seq in range(300):
        assert "witnessed" in witness(served.svc, seq=seq)
    log = log_of_chain(served, "c")
    assert len(log.entries) <= 16 and log.thinned > 0 and max(log.heads) == 299
    assert log_path(served, "c").stat().st_size < 16 * 200 + 200
    # A restart reads the log again and goes on from where it stood.
    again = SignerService(served.dir, signer=served.svc.signer)
    assert "must move forward" in witness(again, seq=299, record=HASH_B)["error"]
    assert "witnessed" in witness(again, seq=300)


def test_a_torn_last_line_does_not_stop_the_log(served):
    witness(served.svc, seq=1)
    path = log_path(served, "c")
    with open(path, "ab") as fh:
        fh.write(b'{"at":"half a line')
    again = SignerService(served.dir, signer=served.svc.signer)
    assert "witnessed" in witness(again, seq=2)
    log = read_witness_log(path)
    assert log.problem is None and sorted(log.heads) == [1, 2] and log.damaged_lines == 0 and not log.torn


@pytest.mark.parametrize("damage", [b"not a log\n", b'{"kind":"mnestiq-witness","version":1,"chain_id":"other"}\n'],
                         ids=["garbage", "another-chain"])
def test_a_damaged_log_is_refused_not_overwritten(served, damage):
    witness(served.svc, seq=1)
    path = log_path(served, "c")
    path.write_bytes(damage)
    again = SignerService(served.dir, signer=served.svc.signer)
    assert "damaged" in witness(again, seq=2)["error"]
    assert path.read_bytes() == damage


def test_a_write_failure_is_an_error_to_the_client_and_nothing_breaks(served, monkeypatch):
    def full(*args, **kwargs):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(served.svc, "_witness_append", full)
    assert witness(served.svc, seq=1) == {"error": "the signer could not write its witness log"}
    payload = base64.b64encode(checkpoint(served.pub)).decode()
    assert "signature" in served.svc.handle({"op": "sign", "payload": payload})


# The service witnesses what it signs


def test_each_signed_checkpoint_is_witnessed_with_no_send_at_all(served):
    payload = checkpoint(served.pub, seq=4, first=0)
    served.client.sign(payload)
    log = log_of_chain(served, "c")
    entry = log.checkpoints[4]
    assert entry["request"] == hashlib.sha256(payload).hexdigest()
    assert entry["covers"] == {"from_seq": 0, "to_seq": 3} and entry["merkle_root"] == "sha256:" + "ab" * 32


def test_a_repeat_is_not_witnessed_twice_but_fills_a_gap(served, monkeypatch):
    payload = checkpoint(served.pub)
    served.client.sign(payload)
    served.client.sign(payload)
    assert len(log_of_chain(served, "c").entries) == 1
    log_path(served, "c").unlink()
    served.svc._witnessed.clear()
    served.client.sign(payload)
    assert list(log_of_chain(served, "c").checkpoints) == [2]


def test_a_witness_failure_never_refuses_a_signature(served):
    def broken(*args):
        raise OSError(28, "No space left on device")

    served.svc._witness_append = broken
    assert served.client.sign(checkpoint(served.pub))
    assert len(log_of(served)) == 1


def test_a_refused_checkpoint_is_not_witnessed(served):
    with pytest.raises(SignerError):
        served.client.sign(checkpoint(served.pub, when="2020-01-01T00:00:00.000000Z"))
    assert not log_path(served, "c").exists()


# The three attacks, each with and without the witness


def rewrite_a_tail_record(records):
    target = checkpoint_indexes(records)[-1] + 2
    records[target]["attributes"] = {"i": "changed"}
    relink(records, target)
    return records


def remove_the_tail(records):
    return records[:checkpoint_indexes(records)[-1] + 1]


@pytest.mark.parametrize("attack,code", [(rewrite_a_tail_record, "witness_rewritten"),
                                         (remove_the_tail, "witness_cut_back")],
                         ids=["rewrite-unsigned-record", "remove-unsigned-end"])
def test_an_attack_on_the_unsigned_end_shows_only_with_the_witness(tmp_path, served, attack, code):
    path = tmp_path / "e.jsonl"
    dump(path, attack(recording_with_a_tail(served, path)))
    assert verify_file(path, [served.pub]).ok  # the hash chain alone cannot tell
    report = verify_file(path, [served.pub], witness=served.dir)
    assert not report.ok and code in codes(report)


def test_cut_back_to_a_checkpoint_shows_even_if_every_send_was_lost(tmp_path, served):
    class NoSends:
        can_extend = True

        def __init__(self, client):
            self.sign, self.sig_alg, self.public_key = client.sign, client.sig_alg, client.public_key

    path = tmp_path / "e.jsonl"
    rec = Recorder(FileSink(path), agent_id="a", signer=NoSends(served.client), checkpoint_every=2)
    events(rec, 6)
    crash(rec)
    records = load(path)
    cps = checkpoint_indexes(records)
    assert len(cps) == 3
    dump(path, records[:cps[0] + 1])  # back to the first of three checkpoints
    assert verify_file(path, [served.pub]).ok
    report = verify_file(path, [served.pub], witness=served.dir)
    assert not report.ok and "witness_cut_back" in codes(report)
    assert any("ends at seq" in issue.message for issue in report.errors)


def test_a_file_cut_back_to_before_a_witnessed_checkpoint_says_so_by_seq(tmp_path, served):
    path = tmp_path / "e.jsonl"
    records = recording_with_a_tail(served, path)
    dump(path, records[:2])
    assert not verify_file(path, [served.pub]).ok  # no checkpoint left, a pinned key vouches for nothing
    report = verify_file(path, [served.pub], witness=served.dir)
    assert "witness_cut_back" in codes(report)


def test_a_checkpoint_rewritten_with_a_stolen_key_differs_from_the_request_witnessed(tmp_path):
    made = serve(tmp_path / "signer", TroubledVault())
    try:
        path = tmp_path / "e.jsonl"
        recording_with_a_tail(made, path)
        records = load(path)
        target = checkpoint_indexes(records)[0]
        records[target]["ts"]["mono_us"] += 1  # what a re-signing attacker would change, whatever the signature says
        records[target]["record_hash"] = record_hash(records[target])
        relink(records, target + 1)
        dump(path, records)
        assert "witness_rewritten" in codes(verify_file(path, witness=made.dir))
    finally:
        made.client.close()
        made.server.close()


# What an honest file gets


def test_a_file_that_agrees_with_the_witness_is_valid_and_says_how_far_it_reached(tmp_path, served):
    path = tmp_path / "e.jsonl"
    records = recording_with_a_tail(served, path)
    report = verify_file(path, [served.pub], witness=served.dir)
    assert report.ok, report.errors
    assert report.witness["highest_seq"] == records[-1]["seq"]
    assert report.witness["matched_through"] == records[-1]["seq"]
    assert report.witness["entries"] >= 1


def test_records_after_the_last_send_are_reported_as_not_witnessed(tmp_path, served):
    path = tmp_path / "e.jsonl"
    rec = Recorder(FileSink(path), agent_id="a", signer=served.client, checkpoint_every=1000)
    events(rec, 2)
    flush(rec)
    events(rec, 3)  # the sender has stopped, so these are the records after the last send
    rec._sink.close()
    report = verify_file(path, [served.pub], witness=served.dir)
    assert "witness_tail" in notes(report) and report.witness["not_witnessed"] == 3
    assert any("says nothing about them" in issue.message for issue in report.warnings)


@pytest.mark.parametrize("name", ["folder", "subfolder", "file"])
def test_the_witness_can_be_named_by_file_or_folder(tmp_path, served, name):
    path = tmp_path / "e.jsonl"
    records = recording_with_a_tail(served, path)
    source = {"folder": served.dir, "subfolder": served.dir / WITNESS_FOLDER,
              "file": log_path(served, records[0]["chain_id"])}[name]
    assert verify_file(path, [served.pub], witness=source).witness["highest_seq"] == records[-1]["seq"]


def test_a_file_from_another_chain_in_a_folder_has_no_witness(tmp_path, served):
    path = tmp_path / "e.jsonl"
    rec = Recorder(FileSink(path), agent_id="a", signing_key=generate_private_key(), checkpoint_every=2)
    events(rec, 4)
    rec.close()
    report = verify_file(path, witness=served.dir)
    assert "witness_none" in notes(report) and report.witness["highest_seq"] is None


def test_verify_lines_takes_a_witness_too(tmp_path, served):
    from mnestiq.verify import verify_lines

    path = tmp_path / "e.jsonl"
    records = recording_with_a_tail(served, path)
    lines = [canonical_json(r) + b"\n" for r in records[:-1]]
    assert "witness_cut_back" in codes(verify_lines(lines, [served.pub], witness=served.dir))


def test_a_timestamp_token_does_not_look_like_a_rewrite(tmp_path, served):
    path = tmp_path / "e.jsonl"
    records = recording_with_a_tail(served, path)
    target = checkpoint_indexes(records)[0]
    records[target]["timestamp_token"] = base64.b64encode(b"token").decode()  # added after signing, as a real one is
    records[target]["record_hash"] = record_hash(records[target])
    relink(records, target + 1)
    dump(path, records)
    # The heads after it were witnessed before this edit, so only the checkpoint's own comparison is the point here.
    wrong = [issue for issue in verify_file(path, witness=served.dir).errors if issue.seq == records[target]["seq"]]
    assert all(issue.code != "witness_rewritten" for issue in wrong)


# A malformed witness log


GOOD_HEADER = b'{"chain_id":"c","kind":"mnestiq-witness","version":1}\n'


@pytest.mark.parametrize("content", [
    b"", b"\n", b"\xff\xfe\x00not utf8", b"not json", b'{"kind":"something else"}\n', b"[1,2,3]\n",
    b'{"chain_id":"c","kind":"mnestiq-witness","version":2}\n', b'{"chain_id":"c","kind":"mnestiq-witness"}\n',
    b'{"chain_id":"c","kind":"mnestiq-witness","version":"1"}\n',
    b'{"chain_id":"other","kind":"mnestiq-witness","version":1}\n',
    b"[" * 100_000,
], ids=["empty", "blank", "not-utf8", "not-json", "wrong-kind", "not-object", "newer-version", "no-version",
        "text-version", "another-chain", "deep-nesting"])
def test_a_witness_log_nothing_can_be_read_from_is_reported_and_not_a_crash(tmp_path, content):
    path = tmp_path / "e.jsonl"
    rec = Recorder(FileSink(path), agent_id="a", signing_key=generate_private_key(), chain_id="c", checkpoint_every=2)
    events(rec, 2)
    rec.close()
    bad = tmp_path / "witness.jsonl"
    bad.write_bytes(content)
    report = verify_file(path, witness=bad)
    assert not report.ok and "witness_unusable" in codes(report)
    assert report.witness["highest_seq"] is None
    bad.unlink()
    assert "witness_unusable" in codes(verify_file(path, witness=bad))  # a missing log as well


def good_head(seq, record=HASH_A):
    entry = {"at": "2026-01-01T00:00:00.000000Z", "by": "head", "record_hash": record, "seq": seq}
    return canonical_json(entry) + b"\n"


@pytest.mark.parametrize("line", [
    b"not json\n", b"[]\n", b'{"seq":5}\n', b'{"at":"t","by":"head","seq":"5","record_hash":"sha256:00"}\n',
    b'{"at":"t","by":"unknown","seq":5}\n', good_head(1).replace(b'"seq":1', b'"seq":-1'),
    good_head(1).replace(b'"by"', b'"junk":1,"by"'),
    b'{"at":"t","by":"checkpoint","covers":{"from_seq":0,"to_seq":9},"merkle_root":"sha256:00","request":"00","seq":5}\n',
], ids=["not-json", "not-object", "no-fields", "seq-as-text", "unknown-by", "negative-seq", "extra-field",
        "bad-checkpoint"])
def test_a_bad_line_is_an_error_and_the_good_ones_still_count(tmp_path, line):
    path = tmp_path / "e.jsonl"
    rec = Recorder(FileSink(path), agent_id="a", signing_key=generate_private_key(), chain_id="c", checkpoint_every=2)
    events(rec, 3)
    records = load(path)
    log = tmp_path / "witness.jsonl"
    first, second = good_head(0, records[0]["record_hash"]), good_head(1, records[1]["record_hash"])
    log.write_bytes(GOOD_HEADER + first + line + second)
    report = verify_file(path, witness=log)
    assert not report.ok and "witness_damaged" in codes(report) and report.witness["entries"] == 2
    assert report.witness["highest_seq"] == 1  # the lines that could be read are still compared


def test_a_line_that_goes_backwards_is_an_error(tmp_path):
    path = tmp_path / "e.jsonl"
    rec = Recorder(FileSink(path), agent_id="a", signing_key=generate_private_key(), chain_id="c", checkpoint_every=2)
    events(rec, 3)
    records = load(path)
    log = tmp_path / "witness.jsonl"
    log.write_bytes(GOOD_HEADER + good_head(1, records[1]["record_hash"]) + good_head(0, records[0]["record_hash"]))
    report = verify_file(path, witness=log)
    assert not report.ok and "witness_damaged" in codes(report)


# Told apart: a crash, a lost checkpoint and a change


class LosesTheAnswers:
    """In front of a real client: the service signs, and the answer never comes back."""

    can_extend = True

    def __init__(self, client, lose=1):
        self.client, self.sig_alg, self.public_key = client, client.sig_alg, client.public_key
        self.lose = lose

    def sign(self, payload, leaves=None):
        signature = self.client.sign(payload, leaves) if leaves is not None else self.client.sign(payload)
        if self.lose:
            self.lose -= 1
            raise SignerError("the signer at 127.0.0.1 is not reachable: the answer was lost")
        return signature


def lost_checkpoint(served, path, lose=1):
    rec = Recorder(FileSink(path), agent_id="a", signer=LosesTheAnswers(served.client, lose), checkpoint_every=1000)
    events(rec, 3)
    with pytest.raises(SignerError):
        rec.checkpoint()
    return rec


def test_a_signed_checkpoint_that_never_reached_the_file_is_not_a_cut_back(tmp_path, served):
    path = tmp_path / "e.jsonl"
    crash(lost_checkpoint(served, path))
    report = verify_file(path, witness=served.dir)  # no pinned key: this file has no checkpoint left to show for it
    assert report.ok, report.errors
    assert "witness_checkpoint_lost" in notes(report)
    assert any("The records it covers are unchanged" in i.message for i in report.warnings)
    assert report.witness["matched_through"] == 2


def test_records_changed_under_a_lost_checkpoint_are_a_rewrite(tmp_path, served):
    path = tmp_path / "e.jsonl"
    crash(lost_checkpoint(served, path))
    records = load(path)
    records[0]["attributes"] = {"i": "changed"}
    records[0]["record_hash"] = record_hash(records[0])
    relink(records, 1)
    dump(path, records)
    assert verify_file(path).ok  # the hash chain alone cannot tell
    report = verify_file(path, witness=served.dir)
    assert not report.ok and "witness_rewritten" in codes(report)


def test_an_extended_checkpoint_is_not_a_rewrite(tmp_path, served):
    """A lost checkpoint, then more records: the next checkpoint starts where the lost one started."""
    path = tmp_path / "e.jsonl"
    rec = lost_checkpoint(served, path)
    rec._next_try = 0.0
    events(rec, 2)
    assert rec.checkpoint() is not None
    crash(rec)
    report = verify_file(path, [served.pub], witness=served.dir)
    assert report.ok, report.errors
    assert "witness_checkpoint_lost" in notes(report)


def resumed_chain(served, path, sent=2):
    """Records 0..2 were written and head ``sent`` reached the witness. Then a crash, and a resume."""
    rec = Recorder(FileSink(path), agent_id="a", signer=served.client, checkpoint_every=1000)
    events(rec, 3)
    flush(rec)
    rec._sink.close()
    chain = load(path)[0]["chain_id"]
    log = log_of_chain(served, chain)
    assert log.heads and max(log.heads) == 2
    if sent != 2:  # as if only an earlier head had gone out
        lines = log_path(served, chain).read_bytes().splitlines(keepends=True)
        head = canonical_json({"at": "2026-01-01T00:00:00.000000Z", "by": "head",
                               "record_hash": load(path)[sent]["record_hash"], "seq": sent}) + b"\n"
        log_path(served, chain).write_bytes(lines[0] + head)
        served.svc._witnessed.clear()
    return chain


def resume(served, path):
    rec = Recorder(FileSink(path), agent_id="a", signer=served.client, checkpoint_every=1000)
    assert rec.checkpoint() is not None
    crash(rec)


def test_a_restart_range_that_matches_the_witness_says_so(tmp_path, served):
    path = tmp_path / "e.jsonl"
    resumed_chain(served, path)
    resume(served, path)
    report = verify_file(path, [served.pub], witness=served.dir)
    assert report.ok and "signed_after_restart" in notes(report)
    said = next(i.message for i in report.warnings if i.code == "signed_after_restart")
    assert "The witness matches them up to seq 2" in said and "crash, not a change" in said


def test_a_partly_witnessed_restart_range_says_how_far(tmp_path, served):
    path = tmp_path / "e.jsonl"
    resumed_chain(served, path, sent=1)
    resume(served, path)
    report = verify_file(path, [served.pub], witness=served.dir)
    said = next(i.message for i in report.warnings if i.code == "signed_after_restart")
    assert "up to seq 1" in said and "Records 2..2 were written after the last send" in said


def test_a_restart_range_changed_while_down_is_an_error(tmp_path, served):
    path = tmp_path / "e.jsonl"
    resumed_chain(served, path)
    records = load(path)
    records[1]["attributes"] = {"i": "changed"}
    records[1]["record_hash"] = record_hash(records[1])
    relink(records, 2)
    dump(path, records)
    resume(served, path)
    report = verify_file(path, [served.pub], witness=served.dir)
    assert not report.ok and "witness_restart" in codes(report) and "witness_rewritten" in codes(report)
    assert verify_file(path, [served.pub]).ok  # without the witness, one more restart to explain away


# The sender


def counting(served):
    seen = []
    real = served.svc.handle

    def handle(request):
        if isinstance(request, dict) and request.get("op") == "witness":
            seen.append(request["seq"])
        return real(request)

    served.svc.handle = handle
    return seen


def wait_for(condition, seconds=5.0):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if condition():
            return True
        time.sleep(0.01)
    return condition()


def test_the_sender_reports_the_newest_head_on_its_own(tmp_path, served):
    path = tmp_path / "e.jsonl"
    rec = Recorder(FileSink(path), agent_id="a", signer=served.client, checkpoint_every=1000)
    events(rec, 3)
    chain = rec.chain_id
    assert wait_for(lambda: log_path(served, chain).exists() and 2 in read_witness_log(log_path(served, chain)).heads)
    rec.close()


def test_the_sender_coalesces_to_the_newest_head(tmp_path, served):
    seen = counting(served)
    path = tmp_path / "e.jsonl"
    rec = Recorder(FileSink(path), agent_id="a", signer=served.client, checkpoint_every=100_000)
    started = time.monotonic()
    events(rec, 400)
    took = time.monotonic() - started
    rec.close()
    assert len(seen) <= took / mnestiq.recorder.WITNESS_INTERVAL_S + 3
    assert len(seen) < 400 and seen == sorted(seen)
    assert max(seen) == load(path)[-1]["seq"]  # and the closing checkpoint is what was sent last


def test_the_sender_thread_is_the_recorders_own(tmp_path, served):
    rec = Recorder(FileSink(tmp_path / "e.jsonl"), agent_id="a", signer=served.client, checkpoint_every=1000)
    assert rec._witness._thread.__dict__["_mnestiq_own"] is True and rec._witness._thread.daemon
    rec.close()


def test_the_senders_traffic_is_not_captured_as_the_agents(tmp_path, served):
    instrument_egress()
    path = tmp_path / "e.jsonl"
    try:
        rec = Recorder(FileSink(path), agent_id="a", signer=served.client, checkpoint_every=1000)
        with rec.run() as run:
            run.note("one")
            flush(rec)
        crash(rec)
    finally:
        uninstrument_egress()
    assert [r for r in load(path) if r.get("event_type") == "egress"] == []


def test_a_signer_without_a_witness_starts_no_sender(tmp_path):
    rec = Recorder(FileSink(tmp_path / "e.jsonl"), agent_id="a", signer=LocalSigner(generate_private_key()))
    assert rec._witness is None
    events(rec, 2)
    rec.close()


def test_azure_key_vault_used_directly_has_no_witness(tmp_path):
    vault = TroubledVault()
    signer = AzureKeyVaultSigner(KEY_URL, client=vault, public_key=public_key_b64(vault.key))
    assert not hasattr(signer, "witness")
    assert Recorder(FileSink(tmp_path / "e.jsonl"), agent_id="a", signer=signer)._witness is None


def test_an_older_service_stops_being_asked(tmp_path, served):
    seen = []
    real = served.svc.handle

    def older(request):
        if isinstance(request, dict) and request.get("op") == "witness":
            seen.append(request["seq"])
            return {"error": f"unknown op {request['op']!r}"}
        return real(request)

    served.svc.handle = older
    rec = Recorder(FileSink(tmp_path / "e.jsonl"), agent_id="a", signer=served.client, checkpoint_every=1000)
    events(rec, 1)
    assert wait_for(lambda: len(seen) == 1)
    assert wait_for(lambda: not rec._witness._thread.is_alive())
    events(rec, 20)
    time.sleep(0.05)
    assert seen == [seen[0]] and rec.failures == 0
    rec.close()
    assert rec.failures == 0


def test_the_client_says_an_older_service_cannot_witness(served):
    real = served.svc.handle
    served.svc.handle = lambda r: {"error": "unknown op 'witness'"} if r.get("op") == "witness" else real(r)
    with pytest.raises(WitnessUnsupported):
        served.client.witness("c", 1, HASH_A)


class HangingWitness:
    """A signer whose signing is fine and whose witness never answers until released."""

    can_extend = False

    def __init__(self):
        self.signer = LocalSigner(generate_private_key())
        self.sig_alg, self.public_key = self.signer.sig_alg, self.signer.public_key
        self.release = threading.Event()
        self.entered = threading.Event()

    def sign(self, payload):
        return self.signer.sign(payload)

    def witness(self, chain_id, seq, record_hash):
        self.entered.set()
        self.release.wait(30)
        return True


def test_a_hung_witness_cannot_block_or_deadlock_the_agent(tmp_path, monkeypatch):
    monkeypatch.setattr(mnestiq.recorder, "WITNESS_CLOSE_WAIT_S", 0.3)
    signer = HangingWitness()
    path = tmp_path / "e.jsonl"
    rec = Recorder(FileSink(path), agent_id="a", signer=signer, checkpoint_every=10)
    finished = threading.Event()

    def agent():
        events(rec, 1)
        assert signer.entered.wait(5)
        started = time.monotonic()
        events(rec, 200)  # takes the lock and writes and signs while the witness call is stuck
        assert time.monotonic() - started < 5
        rec.close()
        finished.set()

    thread = threading.Thread(target=agent)
    thread.start()
    thread.join(20)
    try:
        assert finished.is_set() and not thread.is_alive()
        assert verify_file(path).ok
    finally:
        signer.release.set()


def test_close_gives_a_hung_witness_a_bounded_time(tmp_path, monkeypatch):
    monkeypatch.setattr(mnestiq.recorder, "WITNESS_CLOSE_WAIT_S", 0.2)
    signer = HangingWitness()
    rec = Recorder(FileSink(tmp_path / "e.jsonl"), agent_id="a", signer=signer, checkpoint_every=1000)
    events(rec, 1)
    assert signer.entered.wait(5)
    started = time.monotonic()
    rec.close()
    assert time.monotonic() - started < 2
    signer.release.set()


def test_a_hung_service_cannot_hold_up_a_signature_over_the_real_connection(tmp_path, served):
    """Witness calls have their own connection, so a witness send stuck on the service does not block sign()."""
    release = threading.Event()
    real = served.svc.handle
    in_witness = threading.Event()

    def handle(request):
        if isinstance(request, dict) and request.get("op") == "witness":
            in_witness.set()
            release.wait(30)
        return real(request)

    served.svc.handle = handle
    client = SignerClient(served.server.address, TOKEN)
    rec = Recorder(FileSink(tmp_path / "e.jsonl"), agent_id="a", signer=client, checkpoint_every=1000)
    try:
        events(rec, 1)
        assert in_witness.wait(5)
        started = time.monotonic()
        assert rec.checkpoint() is not None
        assert time.monotonic() - started < 2
    finally:
        release.set()
        rec.close()
        client.close()


def test_a_failing_witness_never_reaches_the_agent(tmp_path):
    class Explodes(HangingWitness):
        def witness(self, chain_id, seq, record_hash):
            self.entered.set()
            raise RuntimeError("boom")

    signer = Explodes()
    path = tmp_path / "e.jsonl"
    with Recorder(FileSink(path), agent_id="a", signer=signer, checkpoint_every=2) as rec:
        events(rec, 5)
        assert signer.entered.wait(5)
    assert rec.failures == 0 and verify_file(path).ok


def test_a_witness_refusal_does_not_stop_the_sends(tmp_path, served):
    path = tmp_path / "e.jsonl"
    rec = Recorder(FileSink(path), agent_id="a", signer=served.client, checkpoint_every=1000)
    assert served.client.witness(rec.chain_id, 40, HASH_A)  # ahead of the recorder, as after a resume
    events(rec, 1)
    time.sleep(0.05)
    events(rec, 44)
    assert wait_for(lambda: max(read_witness_log(log_path(served, rec.chain_id)).heads) == 44)
    rec.close()


def test_close_sends_the_last_head(tmp_path, served):
    path = tmp_path / "e.jsonl"
    rec = Recorder(FileSink(path), agent_id="a", signer=served.client, checkpoint_every=1000)
    events(rec, 2)
    rec.close()
    log = log_of_chain(served, rec.chain_id)
    assert load(path)[-1]["seq"] == max(log.heads)


def test_a_rotated_signer_takes_over_the_sends(tmp_path):
    made = serve(tmp_path / "a", TroubledVault(), allow_handover=True)
    other = serve(tmp_path / "b", TroubledVault())
    try:
        rec = Recorder(FileSink(tmp_path / "e.jsonl"), agent_id="a", signer=made.client, checkpoint_every=1000)
        events(rec, 2)
        rec.rotate_signer(other.client)
        events(rec, 1)
        assert wait_for(lambda: log_path(other, rec.chain_id).exists())
        rec.close()
    finally:
        for served_one in (made, other):
            served_one.client.close()
            served_one.server.close()


# checkpoint_on


def agent_steps(rec):
    with rec.run() as run:
        run.tool_call("fetch", {"u": 1}, "ok")
        run.note("a note")
        run.egress({"egress_id": "e", "protocol": "tcp", "dest_ip": "203.0.113.1", "dest_port": 443})


def test_checkpoint_on_signs_right_after_those_events(tmp_path):
    path = tmp_path / "e.jsonl"
    rec = Recorder(FileSink(path), agent_id="a", signing_key=generate_private_key(), checkpoint_every=1000,
                   checkpoint_on=("tool_call", "egress"))
    agent_steps(rec)
    rec.close()
    records = load(path)
    for i, record in enumerate(records):
        if record.get("event_type") in ("tool_call", "egress"):
            assert records[i + 1]["kind"] == "checkpoint"
    assert verify_file(path).ok


def test_without_checkpoint_on_nothing_changes(tmp_path):
    path = tmp_path / "e.jsonl"
    rec = Recorder(FileSink(path), agent_id="a", signing_key=generate_private_key(), checkpoint_every=1000)
    agent_steps(rec)
    assert [r for r in load(path) if r["kind"] == "checkpoint"] == []
    rec.close()


def test_checkpoint_on_true_means_tool_calls_and_egress(tmp_path):
    path = tmp_path / "e.jsonl"
    rec = Recorder(FileSink(path), agent_id="a", signing_key=generate_private_key(), checkpoint_every=1000,
                   checkpoint_on=True)
    agent_steps(rec)
    rec.close()
    kinds = [r.get("event_type") for r in load(path)]
    assert kinds.index("tool_call") >= 0 and sum(1 for r in load(path) if r["kind"] == "checkpoint") >= 3


@pytest.mark.parametrize("bad", ["nope", ("tool_call", "nope")])
def test_checkpoint_on_rejects_what_is_not_an_event_type(tmp_path, bad):
    with pytest.raises(ValueError, match="unknown event type"):
        Recorder(FileSink(tmp_path / "e.jsonl"), agent_id="a", checkpoint_on=bad)


def test_checkpoint_on_respects_the_retry_time(tmp_path):
    class Failing:
        def __init__(self):
            self.signer = LocalSigner(generate_private_key())
            self.sig_alg, self.public_key = self.signer.sig_alg, self.signer.public_key
            self.calls = 0

        def sign(self, payload):
            self.calls += 1
            raise SignerError("the signer is not reachable")

    signer = Failing()
    rec = Recorder(FileSink(tmp_path / "e.jsonl"), agent_id="a", signer=signer, checkpoint_every=1000,
                   checkpoint_on="tool_call", retry_after=60)
    with rec.run() as run:
        for _ in range(5):
            run.tool_call("fetch", {}, "ok")
    assert signer.calls == 1 and rec.failures == 1  # one try, and the wait, not one try per tool call


# Checkpoint retry times beside the evidence


@pytest.fixture
def fresh_times(monkeypatch):
    monkeypatch.setattr(mnestiq.recorder, "SAME_ATTEMPT_S", 0)


def times_file(path):
    return path.with_name(path.name + ".checkpoint-times")


def test_the_time_is_on_disk_before_the_request_goes_out(tmp_path, served):
    path = tmp_path / "e.jsonl"
    seen = {}

    class Watching(LosesTheAnswers):
        def sign(self, payload, leaves=None):
            seen["kept"] = times_file(path).exists()
            return super().sign(payload, leaves)

    signer = Watching(served.client, lose=0)
    rec = Recorder(FileSink(path), agent_id="a", signer=signer, checkpoint_every=1000)
    events(rec, 2)
    assert rec.checkpoint() is not None
    assert seen == {"kept": True}
    assert not times_file(path).exists()  # removed once the checkpoint is written
    rec.close()


def test_a_restart_finds_the_answer_that_was_lost(tmp_path, served):
    path = tmp_path / "e.jsonl"
    rec = Recorder(FileSink(path), agent_id="a", signer=LosesTheAnswers(served.client), checkpoint_every=1000,
                   retry_after=0)
    events(rec, 2)
    with pytest.raises(SignerError):
        rec.checkpoint()
    signed = log_of(served)[0]
    crash(rec)
    assert times_file(path).exists()
    again = Recorder(FileSink(path), agent_id="a", signer=served.client, checkpoint_every=1000)
    records = load(path)
    assert records[2]["kind"] == "checkpoint" and records[2]["signature"] == signed["signature"]
    assert not any(r.get("attributes", {}).get("inherited_unsigned") for r in records)  # nothing was inherited
    assert len(served.vault.digests) == 1 and log_of(served)[1].get("repeat") is True
    assert not times_file(path).exists()
    again.close()
    report = verify_file(path, [served.pub], witness=served.dir)
    assert report.ok and "signed_after_restart" not in notes(report), report.errors


def test_a_restart_uses_times_from_earlier_tries_too(tmp_path, served, fresh_times):
    path = tmp_path / "e.jsonl"
    rec = Recorder(FileSink(path), agent_id="a", signer=LosesTheAnswers(served.client, lose=1), checkpoint_every=1000,
                   retry_after=0)
    events(rec, 2)
    with pytest.raises(SignerError):
        rec.checkpoint()
    time.sleep(0.02)
    rec._signer.lose = 1  # the search finds the time asked for first, and its answer is lost again
    with pytest.raises(SignerError):
        rec.checkpoint()
    crash(rec)
    assert len(json.loads(times_file(path).read_text())["times"]) >= 2
    again = Recorder(FileSink(path), agent_id="a", signer=served.client, checkpoint_every=1000)
    assert load(path)[2]["kind"] == "checkpoint" and len(served.vault.digests) == 1
    again.close()


def test_the_times_file_is_bounded(tmp_path, fresh_times):
    class Refuses:
        can_extend = True

        def __init__(self):
            self.signer = LocalSigner(generate_private_key())
            self.sig_alg, self.public_key = self.signer.sig_alg, self.signer.public_key

        def sign(self, payload, leaves=None):
            raise SignerError("chain 'c' was signed up to seq 9, and this checkpoint covers from 0")

    path = tmp_path / "e.jsonl"
    rec = Recorder(FileSink(path), agent_id="a", signer=Refuses(), checkpoint_every=1000, retry_after=0)
    events(rec, 2)
    for _ in range(40):
        with pytest.raises(SignerError):
            rec.checkpoint()
        time.sleep(0.002)
    assert len(json.loads(times_file(path).read_text())["times"]) == mnestiq.recorder.MAX_EARLIER_TIMES + 1
    assert times_file(path).stat().st_size < mnestiq.recorder._MAX_TIMES_BYTES


@pytest.mark.parametrize("content", [
    b"", b"not json", b"[]", b'{"version":2}', b"[" * 100_000, b"x" * 5000,
    b'{"chain_id":"other","covers":[0,1],"times":[{"wall":"2026-01-01T00:00:00.000000Z","mono_us":1}],"version":1}',
    b'{"chain_id":"c","covers":[0,9],"times":[{"wall":"2026-01-01T00:00:00.000000Z","mono_us":1}],"version":1}',
    b'{"chain_id":"c","covers":[0,1],"times":[{"wall":"not a time","mono_us":1},{"wall":5}],"version":1}',
    b'{"chain_id":"c","covers":[0,1],"times":"none","version":1}',
], ids=["empty", "not-json", "not-object", "other-version", "deep", "oversized", "other-chain", "other-range",
        "bad-times", "times-not-a-list"])
def test_a_bad_times_file_is_ignored_and_removed(tmp_path, served, content):
    path = tmp_path / "e.jsonl"
    rec = Recorder(FileSink(path), agent_id="a", signer=served.client, chain_id="c", checkpoint_every=1000)
    events(rec, 2)
    crash(rec)
    times_file(path).write_bytes(content)
    again = Recorder(FileSink(path), agent_id="a", signer=served.client, chain_id="c", checkpoint_every=1000)
    records = load(path)
    assert records[2].get("attributes", {}).get("inherited_unsigned") is not None  # the ordinary resume
    assert not times_file(path).exists()
    again.close()


def test_a_times_file_with_a_good_time_for_records_never_signed_gets_nothing(tmp_path, served):
    path = tmp_path / "e.jsonl"
    rec = Recorder(FileSink(path), agent_id="a", signer=served.client, chain_id="c", checkpoint_every=1000)
    events(rec, 2)
    crash(rec)
    forged = {"version": 1, "chain_id": "c", "covers": [0, 1],
              "times": [{"wall": "2026-01-01T00:00:00.000000Z", "mono_us": 7}]}
    times_file(path).write_text(json.dumps(forged))
    again = Recorder(FileSink(path), agent_id="a", signer=served.client, chain_id="c", checkpoint_every=1000)
    assert served.vault.digests == []  # the service was asked for an answer it never gave, and signed nothing
    assert load(path)[2].get("attributes", {}).get("inherited_unsigned") is not None
    again.close()


def test_a_signature_got_through_the_times_file_is_still_checked(tmp_path, served):
    class WrongAnswer:
        can_extend = True

        def __init__(self, client):
            self.sig_alg, self.public_key, self.sign = client.sig_alg, client.public_key, client.sign

        def repeat(self, payload):
            return b"\x01" * 64

    path = tmp_path / "e.jsonl"
    rec = Recorder(FileSink(path), agent_id="a", signer=LosesTheAnswers(served.client), checkpoint_every=1000,
                   retry_after=0)
    events(rec, 2)
    with pytest.raises(SignerError):
        rec.checkpoint()
    crash(rec)
    again = Recorder(FileSink(path), agent_id="a", signer=WrongAnswer(served.client), checkpoint_every=1000)
    records = load(path)
    assert [r["kind"] for r in records].count("checkpoint") == 0 and records[2]["attributes"]["inherited_unsigned"]
    again.close()


def test_an_older_service_cannot_be_fooled_into_a_fresh_signature_by_the_times_file(tmp_path, served):
    real = served.svc.handle
    asked = []

    def older(request):
        if isinstance(request, dict) and request.get("op") == "repeat":
            asked.append(True)
            return {"error": "unknown op 'repeat'"}
        return real(request)

    path = tmp_path / "e.jsonl"
    rec = Recorder(FileSink(path), agent_id="a", signer=served.client, checkpoint_every=1000)
    events(rec, 2)
    crash(rec)
    forged = {"version": 1, "chain_id": load(path)[0]["chain_id"], "covers": [0, 1],
              "times": [{"wall": "2026-01-01T00:00:00.000000Z", "mono_us": 7}]}
    times_file(path).write_text(json.dumps(forged))
    served.svc.handle = older
    again = Recorder(FileSink(path), agent_id="a", signer=served.client, checkpoint_every=1000)
    assert asked and served.vault.digests == []
    assert load(path)[2]["attributes"]["inherited_unsigned"]  # the note, not a signature
    again.close()


def test_a_service_repeat_never_signs_anew(served):
    payload = checkpoint(served.pub)
    with pytest.raises(SignerError, match="was signed up to"):
        served.client.repeat(payload)
    assert served.vault.digests == [] and log_of(served) == []
    signature = served.client.sign(payload)
    assert served.client.repeat(payload) == signature and len(served.vault.digests) == 1


# Chain limits


def test_new_chains_past_the_limit_are_refused_and_old_ones_keep_working(tmp_path):
    made = serve(tmp_path / "signer", TroubledVault(), max_chains=2)
    try:
        assert "signature" in made.svc.handle(
            {"op": "sign", "payload": base64.b64encode(checkpoint(made.pub, chain="a")).decode()})
        assert "witnessed" in witness(made.svc, chain="b")
        assert "signature" in made.svc.handle(
            {"op": "sign", "payload": base64.b64encode(checkpoint(made.pub, chain="b2")).decode()})
        third = {"op": "sign", "payload": base64.b64encode(checkpoint(made.pub, chain="c")).decode()}
        assert "--max-chains" in made.svc.handle(third)["error"]
        assert "witnessed" in witness(made.svc, chain="d")
        assert "--max-chains" in witness(made.svc, chain="e")["error"]
        assert "signature" in made.svc.handle(
            {"op": "sign", "payload": base64.b64encode(checkpoint(made.pub, chain="a", seq=4, first=3)).decode()})
        assert "witnessed" in witness(made.svc, chain="b", seq=1)
        assert len(made.vault.digests) == 3  # a refused chain never reached the vault
    finally:
        made.client.close()
        made.server.close()


def test_the_limit_is_remembered_across_a_restart(tmp_path):
    made = serve(tmp_path / "signer", TroubledVault(), max_chains=1)
    try:
        assert "witnessed" in witness(made.svc, chain="b")
        again = SignerService(made.dir, signer=made.svc.signer, max_chains=1)
        assert "--max-chains" in witness(again, chain="new")["error"]
        assert "witnessed" in witness(again, chain="b", seq=1)
    finally:
        made.client.close()
        made.server.close()


def test_a_refused_signature_does_not_take_a_chains_place(tmp_path):
    made = serve(tmp_path / "signer", TroubledVault(), max_chains=1)
    try:
        for chain in ("a", "b"):
            late = checkpoint(made.pub, chain=chain, when="2020-01-01T00:00:00.000000Z")
            assert "error" in made.svc.handle({"op": "sign", "payload": base64.b64encode(late).decode()})
        assert "signature" in made.svc.handle(
            {"op": "sign", "payload": base64.b64encode(checkpoint(made.pub, chain="c")).decode()})
    finally:
        made.client.close()
        made.server.close()


@pytest.mark.parametrize("value", [0, -1, True, 1.5])
def test_a_max_chains_that_is_not_a_whole_positive_number_is_refused(tmp_path, value):
    init_signer(tmp_path / "s")
    with pytest.raises(SignerError, match="max_chains"):
        SignerService(tmp_path / "s", max_chains=value)


def test_serve_takes_max_chains(tmp_path, monkeypatch):
    seen = []
    monkeypatch.setattr(SignerServer, "wait", lambda self: (seen.append(self.service.max_chains), self.close()))
    assert main(["signer", "init", str(tmp_path / "s")]) == 0
    assert main(["signer", "serve", str(tmp_path / "s"), "--listen", "127.0.0.1:0", "--max-chains", "5"]) == 0
    assert main(["signer", "serve", str(tmp_path / "s"), "--listen", "127.0.0.1:0"]) == 0
    assert seen == [5, mnestiq.signer_service.DEFAULT_MAX_CHAINS]
    assert main(["signer", "serve", str(tmp_path / "s"), "--listen", "127.0.0.1:0", "--max-chains", "0"]) == 2


# The key read at start-up


def test_a_key_read_that_hangs_is_given_up_on(monkeypatch):
    release = threading.Event()

    def stuck(*args, **kwargs):
        release.wait(30)
        raise AssertionError("never reached")

    monkeypatch.setattr(mnestiq.signer_service, "AzureKeyVaultSigner", stuck)
    started = time.monotonic()
    with pytest.raises(SignerError, match=r"did not answer within 0\.2 seconds") as refused:
        key_vault_signer(KEY_URL, deadline=0.2)
    assert time.monotonic() - started < 2
    assert "vault" in str(refused.value)
    release.set()


def test_the_key_read_answers_when_the_vault_does(monkeypatch):
    marker = SimpleNamespace(public_key="x")
    monkeypatch.setattr(mnestiq.signer_service, "AzureKeyVaultSigner", lambda *args, **kwargs: marker)
    assert key_vault_signer(KEY_URL, deadline=5) is marker


# The command line


def test_the_command_line_compares_and_reports(tmp_path, served, capsys):
    path = tmp_path / "e.jsonl"
    records = recording_with_a_tail(served, path)
    assert main(["verify", str(path), "--trusted-key", served.pub, "--witness", str(served.dir)]) == 0
    out = capsys.readouterr().out
    assert f"witness   saw this chain up to seq {records[-1]['seq']}" in out
    assert "Records written after the last send were not witnessed" in out
    dump(path, records[:checkpoint_indexes(records)[-1] + 1])
    assert main(["verify", str(path), "--trusted-key", served.pub, "--witness", str(served.dir)]) == 1
    out = capsys.readouterr().out
    assert "INVALID" in out and "witness_cut_back" in out


def test_a_witness_that_does_not_exist_is_a_usage_error(tmp_path, served, capsys):
    path = tmp_path / "e.jsonl"
    recording_with_a_tail(served, path)
    assert main(["verify", str(path), "--witness", str(tmp_path / "missing")]) == 2
    assert "does not exist" in capsys.readouterr().err


def test_the_json_report_carries_the_witness(tmp_path, served, capsys):
    path = tmp_path / "e.jsonl"
    recording_with_a_tail(served, path)
    assert main(["verify", str(path), "--trusted-key", served.pub, "--witness", str(served.dir), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["witness"]["highest_seq"] is not None


def test_a_signed_checkpoint_entry_compares_the_signing_payload_not_the_record(tmp_path, served):
    path = tmp_path / "e.jsonl"
    records = recording_with_a_tail(served, path)
    target = records[checkpoint_indexes(records)[0]]
    entry = read_witness_log(log_path(served, target["chain_id"])).checkpoints[target["seq"]]
    assert entry["request"] == hashlib.sha256(signing_payload(target)).hexdigest()


# What the review found: flooding, far heads, durability, budgets, hostile logs


@pytest.fixture
def no_rate(monkeypatch):
    monkeypatch.setattr(mnestiq.signer_service, "WITNESS_HEADS_PER_S", 1e9)
    monkeypatch.setattr(mnestiq.signer_service, "WITNESS_HEAD_BURST", 1e9)


@pytest.fixture
def small_caps(monkeypatch, no_rate):
    monkeypatch.setattr(mnestiq.signer_service, "MAX_WITNESS_HEADS", 16)
    monkeypatch.setattr(mnestiq.signer_service, "MAX_WITNESS_CHECKPOINTS", 16)


def flood(served, chain, first, count):
    for seq in range(first, first + count):
        assert witness(served.svc, chain=chain, seq=seq, record=HASH_B) == {"witnessed": seq}


def test_heads_are_rate_limited_per_chain(served):
    answers = [witness(served.svc, seq=seq) for seq in range(500)]
    taken = [a for a in answers if "witnessed" in a]
    assert len(taken) < 80 and answers[-1]["refused"] == "rate"
    assert len(log_of_chain(served, "c").heads) == len(taken)
    assert "witnessed" in witness(served.svc, chain="other chain")  # one chain's flood is its own


def test_a_slow_honest_sender_is_never_rate_limited(served):
    pace = mnestiq.signer_service.WITNESS_HEADS_PER_S / 2
    for seq in range(100):  # far past the burst: only the refill keeps this going
        log = served.svc._witnessed.get(witness_file_name("c"))
        if log is not None:
            log.filled_at -= 1 / pace
        assert "witnessed" in witness(served.svc, seq=seq)


def old_head(minutes_ago, seq, record):
    moment = time.time() - minutes_ago * 60
    at = mnestiq.signer_service._wall_at(moment)
    return canonical_json({"at": at, "by": "head", "record_hash": record, "seq": seq}) + b"\n"


def test_a_burst_only_displaces_its_own_moment(served, small_caps, monkeypatch):
    monkeypatch.setattr(mnestiq.signer_service, "MAX_WITNESS_HEADS", 32)
    assert witness(served.svc, chain="c", seq=0, record=HASH_A)
    path = log_path(served, "c")
    header = path.read_bytes().splitlines(keepends=True)[0]
    older = [old_head(30 - i, i, HASH_A) for i in range(12)]  # one real head in each of twelve older minutes
    path.write_bytes(header + b"".join(older))
    again = SignerService(served.dir, signer=served.svc.signer)
    served_again = SimpleNamespace(svc=again, dir=served.dir)
    flood(served_again, "c", 12, 60)
    log = log_of_chain(served, "c")
    assert all(seq in log.heads and log.heads[seq] == HASH_A for seq in range(12))
    assert max(log.heads) == 71 and log.thinned > 0


def test_the_first_heads_of_a_moment_survive_a_flood_that_follows(tmp_path, served, small_caps):
    path = tmp_path / "e.jsonl"
    records = recording_with_a_tail(served, path)
    chain = records[0]["chain_id"]
    real = dict(log_of_chain(served, chain).heads)
    assert real
    flood(served, chain, records[-1]["seq"] + 1, 200)
    assert set(real) & set(log_of_chain(served, chain).heads), "a real head must be left"
    dump(path, rewrite_a_tail_record(records))
    report = verify_file(path, [served.pub], witness=served.dir)
    assert not report.ok and "witness_rewritten" in codes(report)
    assert "witness_thinned" in notes(report)
    assert any("dropped" in issue.message for issue in report.warnings if issue.code == "witness_thinned")


def test_heads_never_displace_a_checkpoint(tmp_path, served, small_caps):
    path = tmp_path / "e.jsonl"
    rec = Recorder(FileSink(path), agent_id="a", signer=served.client, checkpoint_every=2)
    events(rec, 6)
    crash(rec)
    records = load(path)
    chain = records[0]["chain_id"]
    signed = [r["seq"] for r in records if r["kind"] == "checkpoint"]
    flood(served, chain, records[-1]["seq"] + 1, 300)
    assert set(signed) <= set(log_of_chain(served, chain).checkpoints)
    forged = records[:checkpoint_indexes(records)[0] + 1]  # cut back past the signed checkpoints, heads flooded away
    dump(path, forged)
    assert verify_file(path, [served.pub]).ok
    assert not verify_file(path, [served.pub], witness=served.dir).ok


def test_checkpoints_have_a_quota_of_their_own(served, monkeypatch):
    monkeypatch.setattr(mnestiq.signer_service, "MAX_WITNESS_CHECKPOINTS", 8)
    first = 0
    for seq in range(2, 60, 2):
        assert "signature" in served.svc.handle(
            {"op": "sign", "payload": base64.b64encode(checkpoint(served.pub, seq=seq, first=first)).decode()})
        first = seq + 1
    log = log_of_chain(served, "c")
    assert 0 < len(log.checkpoints) <= 8 and max(log.checkpoints) == 58


def test_a_full_log_stays_under_its_cap_over_the_years(served, small_caps):
    assert witness(served.svc, chain="c", seq=0, record=HASH_A)
    path = log_path(served, "c")
    header = path.read_bytes().splitlines(keepends=True)[0]
    days = [old_head(60 * 24 * (40 - i), i, HASH_A) for i in range(15)]  # one head a day, all in buckets of their own
    path.write_bytes(header + b"".join(days))
    again = SignerService(served.dir, signer=served.svc.signer)
    assert "witnessed" in witness(again, seq=15)
    assert "witnessed" in witness(again, seq=16)
    assert len(read_witness_log(path).heads) <= 16


def test_a_far_forward_head_is_refused_and_real_heads_go_on(tmp_path, served):
    path = tmp_path / "e.jsonl"
    rec = Recorder(FileSink(path), agent_id="a", signer=served.client, checkpoint_every=1000)
    events(rec, 3)
    flush_heads = wait_for(lambda: log_path(served, rec.chain_id).exists())
    assert flush_heads
    attacker = SignerClient(served.server.address, TOKEN)
    assert attacker.witness(rec.chain_id, rec._seq + 2**39, HASH_B) is False
    attacker.close()
    events(rec, 5)
    rec.close()
    report = verify_file(path, [served.pub], witness=served.dir)
    assert report.ok, report.errors
    assert report.witness["highest_seq"] == load(path)[-1]["seq"]


def test_the_allowed_jump_grows_only_with_time(served, monkeypatch):
    monkeypatch.setattr(mnestiq.signer_service, "WITNESS_JUMP_FLOOR", 10)
    monkeypatch.setattr(mnestiq.signer_service, "WITNESS_RECORDS_PER_S", 100)
    assert "witnessed" in witness(served.svc, seq=5)
    assert witness(served.svc, seq=1000)["refused"] == "too_far"
    served.svc._witnessed[witness_file_name("c")].since -= 20  # the honest case: the agent was busy for 20 seconds
    assert "witnessed" in witness(served.svc, seq=1000)


def test_a_long_chains_first_head_gets_in_after_a_short_wait(served, monkeypatch):
    monkeypatch.setattr(mnestiq.signer_service, "WITNESS_JUMP_FLOOR", 10)
    monkeypatch.setattr(mnestiq.signer_service, "WITNESS_RECORDS_PER_S", 100)
    assert witness(served.svc, seq=5000)["refused"] == "too_far"
    assert not log_path(served, "c").exists() and witness_file_name("c") not in served.svc._head_only
    served.svc._first_asked[witness_file_name("c")] -= 60
    assert "witnessed" in witness(served.svc, seq=5000)


class RefusesFirst(HangingWitness):
    def __init__(self, refuse):
        super().__init__()
        self.refuse = refuse
        self.calls = []

    def witness(self, chain_id, seq, record_hash):
        self.calls.append(seq)
        return len(self.calls) > self.refuse


def test_a_refused_head_warns_and_is_not_counted_as_sent(tmp_path, caplog):
    signer = RefusesFirst(1)
    with caplog.at_level("WARNING", logger="mnestiq"):
        rec = Recorder(FileSink(tmp_path / "e.jsonl"), agent_id="a", signer=signer, checkpoint_every=1000)
        events(rec, 1)
        assert wait_for(lambda: len(signer.calls) >= 2, 8)
    assert rec.witness_refused == 1 and signer.calls[0] == signer.calls[1]  # the same head again, not given up on
    assert "witness refused the head" in caplog.text
    rec.close()


def test_the_file_is_on_disk_before_the_head_is_sent(tmp_path, monkeypatch):
    import os

    order = []
    real = os.fsync

    def spy(fd):
        order.append("sync")
        return real(fd)

    class Watches(HangingWitness):
        def witness(self, chain_id, seq, record_hash):
            order.append("send")
            return True

    monkeypatch.setattr(mnestiq.recorder.os, "fsync", spy)
    signer = Watches()
    path = tmp_path / "e.jsonl"
    rec = Recorder(FileSink(path), agent_id="a", signer=signer, checkpoint_every=1000)
    events(rec, 2)
    assert wait_for(lambda: "send" in order)
    assert order[:2] == ["sync", "send"]
    rec.close()


def test_a_hung_disk_costs_the_sender_and_not_the_agent(tmp_path, monkeypatch):
    import os

    monkeypatch.setattr(mnestiq.recorder, "WITNESS_CLOSE_WAIT_S", 0.3)
    release, sent = threading.Event(), []

    class Slow(HangingWitness):
        def witness(self, chain_id, seq, record_hash):
            sent.append(seq)
            return True

    real = os.fsync
    entered = threading.Event()

    def stuck(fd):
        entered.set()
        release.wait(30)
        return real(fd)

    monkeypatch.setattr(mnestiq.recorder.os, "fsync", stuck)
    signer = Slow()
    path = tmp_path / "e.jsonl"
    rec = Recorder(FileSink(path), agent_id="a", signer=signer, checkpoint_every=100_000)
    try:
        events(rec, 1)
        assert entered.wait(5)
        started = time.monotonic()
        events(rec, 200)  # with sink.sync() this would wait for the sink's lock
        rec.close()
        assert time.monotonic() - started < 5 and sent == []
    finally:
        release.set()


def test_the_final_send_still_syncs_after_the_sink_closed(tmp_path, served):
    path = tmp_path / "e.jsonl"
    rec = Recorder(FileSink(path), agent_id="a", signer=served.client, checkpoint_every=1000)
    events(rec, 2)
    rec.close()
    assert max(log_of_chain(served, rec.chain_id).heads) == load(path)[-1]["seq"]


def test_the_errors_for_a_gone_record_explain_what_a_crash_can_do(tmp_path, served):
    path = tmp_path / "e.jsonl"
    records = recording_with_a_tail(served, path)
    dump(path, records[:-1])
    message = next(i.message for i in verify_file(path, witness=served.dir).errors if i.code == "witness_cut_back")
    assert "gone from the end" in message and "storage lost" in message and "false head" in message


def test_heads_cannot_use_up_signings_budget(tmp_path):
    made = serve(tmp_path / "signer", TroubledVault(), max_chains=2)
    try:
        for chain in ("junk0", "junk1"):
            assert "witnessed" in witness(made.svc, chain=chain)
        assert "--max-chains" in witness(made.svc, chain="junk2")["error"]
        again = SignerService(made.dir, signer=made.svc.signer, max_chains=2)  # it survives a restart as well
        for chain in ("real1", "real2"):
            payload = base64.b64encode(checkpoint(made.pub, chain=chain)).decode()
            assert "signature" in again.handle({"op": "sign", "payload": payload})
        assert "--max-chains" in again.handle(
            {"op": "sign", "payload": base64.b64encode(checkpoint(made.pub, chain="real3")).decode()})["error"]
        assert "--max-chains" in witness(again, chain="junk3")["error"]
    finally:
        made.client.close()
        made.server.close()


def test_a_chain_that_gets_signed_stops_counting_as_head_only(tmp_path):
    made = serve(tmp_path / "signer", TroubledVault(), max_chains=1)
    try:
        assert "witnessed" in witness(made.svc, chain="a")
        assert "--max-chains" in witness(made.svc, chain="b")["error"]
        payload = base64.b64encode(checkpoint(made.pub, chain="a")).decode()
        assert "signature" in made.svc.handle({"op": "sign", "payload": payload})
        assert witness_file_name("a") in made.svc._chains and witness_file_name("a") not in made.svc._head_only
        assert "witnessed" in witness(made.svc, chain="b")
    finally:
        made.client.close()
        made.server.close()


def test_a_failed_first_request_cannot_undercount_a_signed_chain(tmp_path):
    entered, release = threading.Event(), threading.Event()

    class FailsOnce(TroubledVault):
        calls = 0

        def sign(self, algorithm, digest):
            type(self).calls += 1
            if type(self).calls == 1:
                entered.set()
                release.wait(10)
                raise RuntimeError("the vault failed")
            return super().sign(algorithm, digest)

    made = serve(tmp_path / "signer", FailsOnce(), max_chains=1)
    try:
        answers = []
        payload = base64.b64encode(checkpoint(made.pub, chain="c")).decode()
        first = threading.Thread(target=lambda: answers.append(made.svc.handle({"op": "sign", "payload": payload})))
        first.start()
        assert entered.wait(5)
        second = threading.Thread(target=lambda: answers.append(made.svc.handle({"op": "sign", "payload": payload})))
        second.start()
        time.sleep(0.1)  # it is waiting for the chain's turn
        release.set()
        first.join(10)
        second.join(10)
        assert sum("signature" in a for a in answers) == 1
        assert witness_file_name("c") in made.svc._chains
        other = base64.b64encode(checkpoint(made.pub, chain="d")).decode()
        assert "--max-chains" in made.svc.handle({"op": "sign", "payload": other})["error"]
    finally:
        release.set()
        made.client.close()
        made.server.close()


def test_a_refused_first_head_cannot_undercount_another_head(served, monkeypatch):
    monkeypatch.setattr(mnestiq.signer_service, "WITNESS_JUMP_FLOOR", 0)
    monkeypatch.setattr(mnestiq.signer_service, "WITNESS_RECORDS_PER_S", 0)
    answers = []
    start = threading.Barrier(2)

    def send(seq):
        start.wait()
        answers.append(witness(served.svc, seq=seq))

    threads = [threading.Thread(target=send, args=(s,)) for s in (0, 10**6)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    if log_path(served, "c").exists():
        assert witness_file_name("c") in served.svc._head_only


def test_a_hostile_log_costs_a_bounded_number_of_root_checks(tmp_path, monkeypatch):
    path = tmp_path / "e.jsonl"
    rec = Recorder(FileSink(path), agent_id="a", chain_id="c", checkpoint_every=10**6)
    events(rec, 300)
    log = tmp_path / "witness.jsonl"
    line = (b'{"at":"x","by":"checkpoint","covers":{"from_seq":0,"to_seq":%d},"merkle_root":"%s","request":"%s",'
            b'"seq":%d}\n')
    body = b"".join(line % (i - 1, HASH_A.encode(), b"ab" * 32, i) for i in range(1, 300))
    log.write_bytes(GOOD_HEADER + body)
    calls = []
    real = mnestiq.verify.merkle_root
    monkeypatch.setattr(mnestiq.verify, "merkle_root", lambda leaves: (calls.append(len(leaves)), real(leaves))[1])
    report = verify_file(path, witness=log)
    assert not report.ok and len(calls) <= 70
    assert any(i.code == "witness_unusable" and "not all checked" in i.message for i in report.errors)


def test_a_long_chain_with_one_lost_checkpoint_is_checked_by_position(tmp_path, served):
    path = tmp_path / "e.jsonl"
    rec = Recorder(FileSink(path), agent_id="a", signer=LosesTheAnswers(served.client), checkpoint_every=100_000)
    events(rec, 200)
    with pytest.raises(SignerError):
        rec.checkpoint()
    crash(rec)
    report = verify_file(path, witness=served.dir)
    assert report.ok and "witness_checkpoint_lost" in notes(report), report.errors


def test_a_log_cut_to_its_header_fails_closed(tmp_path, served):
    path = tmp_path / "e.jsonl"
    records = recording_with_a_tail(served, path)
    log = log_path(served, records[0]["chain_id"])
    log.write_bytes(log.read_bytes().split(b"\n", 1)[0] + b"\n")
    report = verify_file(path, [served.pub], witness=served.dir)
    assert not report.ok and "witness_unusable" in codes(report)


def test_a_torn_last_line_is_only_a_warning(tmp_path):
    path = tmp_path / "e.jsonl"
    rec = Recorder(FileSink(path), agent_id="a", signing_key=generate_private_key(), chain_id="c", checkpoint_every=2)
    events(rec, 3)
    records = load(path)
    log = tmp_path / "witness.jsonl"
    log.write_bytes(GOOD_HEADER + good_head(0, records[0]["record_hash"]) + b'{"at":"half')
    report = verify_file(path, witness=log)
    assert report.ok, report.errors
    assert "witness_torn" in notes(report) and "witness_damaged" not in codes(report)


def test_a_blank_line_in_the_log_is_damage(tmp_path):
    path = tmp_path / "e.jsonl"
    rec = Recorder(FileSink(path), agent_id="a", signing_key=generate_private_key(), chain_id="c", checkpoint_every=2)
    events(rec, 3)
    log = tmp_path / "witness.jsonl"
    log.write_bytes(GOOD_HEADER + good_head(0, load(path)[0]["record_hash"]) + b"\n")
    assert "witness_damaged" in codes(verify_file(path, witness=log))


def test_a_chain_id_that_says_unknown_op_is_only_a_chain_id(served):
    chain = "x unknown op 'witness'"
    assert served.client.witness(chain, 5, HASH_A) is True
    assert served.client.witness(chain, 4, HASH_A) is False  # a refusal, not an older service


def test_a_refusal_is_a_field_of_the_reply(served):
    witness(served.svc, seq=5)
    assert witness(served.svc, seq=4)["refused"] == "behind"
    assert witness(served.svc, seq=5, record=HASH_B)["refused"] == "behind"


@pytest.mark.skipif(not hasattr(__import__("os"), "mkfifo"), reason="no named pipes on this system")
def test_a_planted_pipe_does_not_hang_the_recorder(tmp_path, served):
    import os

    path = tmp_path / "e.jsonl"
    rec = Recorder(FileSink(path), agent_id="a", signer=served.client, chain_id="c", checkpoint_every=1000)
    events(rec, 2)
    crash(rec)
    os.mkfifo(times_file(path))
    done = threading.Event()

    def start():
        Recorder(FileSink(path), agent_id="a", signer=served.client, chain_id="c", checkpoint_every=1000).close()
        done.set()

    threading.Thread(target=start, daemon=True).start()
    assert done.wait(10)


def link_or_skip(target, link):
    import os

    try:
        os.symlink(target, link)
    except (OSError, NotImplementedError):
        pytest.skip("this account cannot make links")


def test_a_planted_tmp_link_is_not_followed(tmp_path, served):
    path = tmp_path / "e.jsonl"
    victim = tmp_path / "victim.txt"
    victim.write_text("keep me")
    link_or_skip(victim, path.with_name(path.name + ".checkpoint-times.tmp"))
    rec = Recorder(FileSink(path), agent_id="a", signer=served.client, checkpoint_every=1000)
    events(rec, 2)
    assert rec.checkpoint() is not None
    assert victim.read_text() == "keep me"
    rec.close()


def test_a_planted_times_link_is_not_read(tmp_path, served):
    path = tmp_path / "e.jsonl"
    rec = Recorder(FileSink(path), agent_id="a", signer=served.client, chain_id="c", checkpoint_every=1000)
    events(rec, 2)
    crash(rec)
    forged = tmp_path / "forged.json"
    forged.write_text(json.dumps({"version": 1, "chain_id": "c", "covers": [0, 1],
                                  "times": [{"wall": "2026-01-01T00:00:00.000000Z", "mono_us": 7}]}))
    link_or_skip(forged, times_file(path))
    from mnestiq.recorder import _read_times

    assert _read_times(times_file(path), "c", (0, 1)) == []
    assert forged.exists()


def test_a_log_of_endless_bad_lines_is_given_up_on_quickly(tmp_path):
    path = tmp_path / "e.jsonl"
    rec = Recorder(FileSink(path), agent_id="a", signing_key=generate_private_key(), chain_id="c", checkpoint_every=2)
    events(rec, 3)
    log = tmp_path / "witness.jsonl"
    log.write_bytes(GOOD_HEADER + b"x\n" * 2_000_000)
    started = time.monotonic()
    report = verify_file(path, witness=log)
    assert time.monotonic() - started < 5
    assert not report.ok and "witness_unusable" in codes(report)


def test_a_covers_that_is_not_a_whole_number_is_damage(tmp_path):
    path = tmp_path / "e.jsonl"
    rec = Recorder(FileSink(path), agent_id="a", signing_key=generate_private_key(), chain_id="c", checkpoint_every=2)
    events(rec, 3)
    log = tmp_path / "witness.jsonl"
    line = (b'{"at":"x","by":"checkpoint","covers":{"from_seq":0,"to_seq":true},"merkle_root":"%s","request":"%s",'
            b'"seq":2}\n' % (HASH_A.encode(), b"ab" * 32))
    log.write_bytes(GOOD_HEADER + line)
    assert read_witness_log(log).damaged_lines == 1
