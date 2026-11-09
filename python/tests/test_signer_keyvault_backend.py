"""The signing service in front of Azure Key Vault: every rule holds, and a refusal never reaches the vault.

The vault is the stand-in from test_signers.py. Nothing here leaves this machine.
"""

import base64
import hashlib
import json
import socket
import threading
import time
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

import mnestiq.recorder
import mnestiq.signer_service
from mnestiq import (AzureKeyVaultSigner, FileSink, LocalSigner, Recorder, SignerClient, SignerError,
                     verify_file)
from mnestiq.canonical import canonical_json
from mnestiq.cli import main
from mnestiq.egress import instrument_egress, uninstrument_egress
from mnestiq.hashing import signing_payload
from mnestiq.keys import P256, generate_private_key, key_id, public_key_b64
from mnestiq.proxy.server import ModelProxy, _Server
from mnestiq.recorder import current_run
from mnestiq.signer_service import SignerServer, SignerService, init_signer, key_vault_signer

from conftest import load
from test_signers import FakeKeyVault, codes, events

KEY_URL = "https://v.vault.azure.net/keys/k/1"
TOKEN = "ab" * 32
LEAKY = "tenant 1234 refused client secret hunter2"


class TroubledVault(FakeKeyVault):
    """Fails with ``error``, or answers with ``answer``, until they are cleared."""

    def __init__(self, high_s=False):
        super().__init__(high_s)
        self.error = None
        self.answer = None

    def sign(self, algorithm, digest):
        if self.error is not None:
            raise self.error
        if self.answer is not None:
            return SimpleNamespace(signature=self.answer)
        return super().sign(algorithm, digest)


class AzureStyleError(Exception):
    status_code = 403


def stand_in(vault):
    return AzureKeyVaultSigner(KEY_URL, client=vault, public_key=public_key_b64(vault.key))


def serve(directory, vault, **options):
    directory.mkdir(exist_ok=True)
    (directory / "signer.token").write_text(TOKEN + "\n", encoding="ascii")  # and no signer.key: the vault is the key
    pub = public_key_b64(vault.key)
    svc = SignerService(directory, signer=AzureKeyVaultSigner(KEY_URL, client=vault, public_key=pub), **options)
    server = svc.start("127.0.0.1:0")
    return SimpleNamespace(svc=svc, server=server, client=SignerClient(server.address, TOKEN), vault=vault, pub=pub,
                           dir=directory)


@pytest.fixture
def backed(tmp_path):
    served = serve(tmp_path / "signer", TroubledVault())
    yield served
    served.client.close()
    served.server.close()


def wall(offset=0.0):
    moment = datetime.now(timezone.utc) + timedelta(seconds=offset)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def checkpoint(pub, seq=2, first=0, root="ab", when=None, chain="c", **extra):
    return canonical_json({
        "kind": "checkpoint", "chain_id": chain, "seq": seq, "covers": {"from_seq": first, "to_seq": seq - 1},
        "merkle_root": "sha256:" + root * 32, "sig_alg": P256, "public_key": pub, "key_id": key_id(pub),
        "ts": {"wall": when or wall(), "mono_us": 0}, **extra})


def log_of(served):
    path = served.dir / "signatures.jsonl"
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


def unsigned(record):
    return {k: v for k, v in record.items() if k not in ("signature", "record_hash")}


def ask(svc, payload):
    return svc.handle({"op": "sign", "payload": base64.b64encode(payload).decode()})


def edit_state(served, change, chain="c"):
    path = served.dir / "state.json"
    state = json.loads(path.read_text())
    change(state[chain])
    path.write_text(json.dumps(state))


def local_checkpoint(signer, seq=2, first=0):
    return canonical_json({
        "kind": "checkpoint", "chain_id": "c", "seq": seq, "covers": {"from_seq": first, "to_seq": seq - 1},
        "merkle_root": "sha256:" + "ab" * 32, "sig_alg": signer.sig_alg, "public_key": signer.public_key,
        "key_id": key_id(signer.public_key), "ts": {"wall": wall(), "mono_us": 0}})


def record(served, path, n=4, every=2):
    rec = Recorder(FileSink(path), agent_id="a", signer=served.client, checkpoint_every=every)
    events(rec, n)
    rec.close()
    return [r for r in load(path) if r["kind"] == "checkpoint"]


# The whole way through


@pytest.mark.parametrize("high_s", [False, True])
def test_recorder_to_valid_under_the_pinned_vault_key(tmp_path, high_s):
    served = serve(tmp_path / "signer", TroubledVault(high_s))
    try:
        assert (served.client.sig_alg, served.client.public_key) == (P256, served.pub)
        assert served.svc.key_id == key_id(served.pub) and served.svc.key_id.startswith("p256:")
        assert not (served.dir / "signer.key").exists()
        path = tmp_path / "e.jsonl"
        checkpoints = record(served, path, n=5)
        report = verify_file(path, [served.pub])
        assert report.ok and report.unsigned_tail == 0, report.errors
        assert {c["sig_alg"] for c in checkpoints} == {P256}
        assert {c["key_id"] for c in checkpoints} == {key_id(served.pub)}
        assert "untrusted_key" in codes(verify_file(path, [public_key_b64(generate_private_key(P256))]))
        # Only a digest of each checkpoint went to the vault, and the service's log matches the evidence.
        assert served.vault.digests == [hashlib.sha256(signing_payload(c)).digest() for c in checkpoints]
        log = log_of(served)
        assert [e["seq"] for e in log] == [c["seq"] for c in checkpoints]
        assert [e["signature"] for e in log] == [c["signature"] for c in checkpoints]
        assert {e["key_id"] for e in log} == {key_id(served.pub)}
    finally:
        served.client.close()
        served.server.close()


# Every refusal stops before the vault


@pytest.mark.parametrize("over", [{"when": "2020-01-01T00:00:00.000000Z"}, {"seq": 5, "first": 7}],
                         ids=["backdated", "covers-do-not-fit"])
def test_a_bad_checkpoint_never_reaches_the_vault(backed, over):
    with pytest.raises(SignerError, match=r"from this signer's clock|does not cover"):
        backed.client.sign(checkpoint(backed.pub, **over))
    assert backed.vault.digests == [] and log_of(backed) == []


def test_a_future_time_outside_the_skew_never_reaches_the_vault(backed):
    with pytest.raises(SignerError, match="from this signer's clock"):
        backed.client.sign(checkpoint(backed.pub, when=wall(3600)))
    assert backed.vault.digests == []


def test_only_checkpoints_for_the_vault_key_reach_the_vault(backed):
    with pytest.raises(SignerError, match="only checkpoint"):
        backed.client.sign(b'{"kind":"event"}')
    with pytest.raises(SignerError, match="another key"):
        backed.client.sign(checkpoint(public_key_b64(generate_private_key(P256))))
    assert backed.vault.digests == []


def test_history_is_not_signed_again(tmp_path, backed):
    checkpoints = record(backed, tmp_path / "e.jsonl")
    asked = len(backed.vault.digests)
    forged = unsigned(checkpoints[0])
    forged["merkle_root"] = "sha256:" + "ab" * 32
    with pytest.raises(SignerError, match="only the next checkpoint"):
        backed.client.sign(signing_payload(forged))
    assert len(backed.vault.digests) == asked and len(log_of(backed)) == asked


def test_positions_are_remembered_across_a_restart(tmp_path, backed):
    checkpoints = record(backed, tmp_path / "e.jsonl", n=2)
    backed.client.close()
    backed.server.close()
    again = serve(backed.dir, backed.vault)
    try:
        asked = len(backed.vault.digests)
        replay = unsigned(checkpoints[0])
        replay["ts"] = {"wall": wall(), "mono_us": 1}
        replay["merkle_root"] = "sha256:" + "ef" * 32
        with pytest.raises(SignerError, match="only the next checkpoint"):
            again.client.sign(signing_payload(replay))
        assert len(backed.vault.digests) == asked
    finally:
        again.client.close()
        again.server.close()


def test_a_byte_identical_repeat_gets_the_same_signature_without_the_vault(backed):
    payload = checkpoint(backed.pub)
    first = backed.client.sign(payload)
    assert backed.client.sign(payload) == first  # ECDSA would differ if it were signed twice
    assert len(backed.vault.digests) == 1
    backed.vault.error = AzureStyleError(LEAKY)
    assert backed.client.sign(payload) == first  # and an answer already given survives an outage
    log = log_of(backed)
    assert len(log) == 3 and {e["signature"] for e in log} == {base64.b64encode(first).decode()}
    assert [e.get("repeat") for e in log] == [None, True, True]  # the log says which lines are not new signatures


def test_a_repeat_after_a_restart_comes_from_the_disk(backed):
    payload = checkpoint(backed.pub)
    first = backed.client.sign(payload)
    again = SignerService(backed.dir, signer=backed.svc.signer)
    assert base64.b64decode(ask(again, payload)["signature"]) == first and len(backed.vault.digests) == 1


def test_a_repeat_outside_the_clock_window_is_still_the_answer_already_given(backed):
    payload = checkpoint(backed.pub, when=wall(-0.5))
    first = backed.client.sign(payload)
    strict = SignerService(backed.dir, signer=backed.svc.signer, max_skew=0.01)
    assert base64.b64decode(ask(strict, payload)["signature"]) == first and len(backed.vault.digests) == 1
    assert "clock" in ask(strict, checkpoint(backed.pub, seq=4, first=3, when=wall(-0.5)))["error"]


@pytest.mark.parametrize("damage", ["", "AAAA", "abc", "!!!!", 123, base64.b64encode(b"\x01" * 64).decode()],
                         ids=["empty", "short", "bad-length", "not-base64", "wrong-type", "wrong-signature"])
def test_a_damaged_stored_signature_is_never_served_or_replaced(backed, damage):
    payload = checkpoint(backed.pub)
    backed.client.sign(payload)
    edit_state(backed, lambda entry: entry.update(signature=damage))
    reply = ask(SignerService(backed.dir, signer=backed.svc.signer), payload)
    assert reply == {"error": "the signer's record of this checkpoint is damaged, so it was not sent again"}
    assert len(backed.vault.digests) == 1 and len(log_of(backed)) == 1


def test_a_stored_signature_with_stray_characters_is_damaged(backed):
    payload = checkpoint(backed.pub)
    good = base64.b64encode(backed.client.sign(payload)).decode()
    edit_state(backed, lambda entry: entry.update(signature=good[:4] + "!" + good[4:]))
    assert "damaged" in ask(SignerService(backed.dir, signer=backed.svc.signer), payload)["error"]


def test_a_missing_stored_signature_is_found_in_the_log_or_refused(backed):
    payload = checkpoint(backed.pub)
    first = backed.client.sign(payload)
    edit_state(backed, lambda entry: entry.pop("signature"))
    fresh = SignerService(backed.dir, signer=backed.svc.signer)
    assert base64.b64decode(ask(fresh, payload)["signature"]) == first
    assert all(e["signature"] == base64.b64encode(first).decode() for e in log_of(backed))  # no line without one
    (backed.dir / "signatures.jsonl").unlink()
    assert "damaged" in ask(SignerService(backed.dir, signer=backed.svc.signer), payload)["error"]
    assert len(backed.vault.digests) == 1


def test_a_state_from_before_exact_repeats_proves_the_repeat_from_the_log(backed):
    payload = checkpoint(backed.pub)
    first = backed.client.sign(payload)
    edit_state(backed, lambda entry: [entry.pop(k, None) for k in ("request", "signature", "key_id", "unlogged")])
    fresh = SignerService(backed.dir, signer=backed.svc.signer)
    assert base64.b64decode(ask(fresh, payload)["signature"]) == first and len(backed.vault.digests) == 1
    later = checkpoint(backed.pub, when=wall(1))  # the same records, not the same request
    assert "only the next checkpoint" in ask(fresh, later)["error"]


def test_the_same_position_with_other_content_is_refused(backed):
    backed.client.sign(checkpoint(backed.pub))
    with pytest.raises(SignerError, match="only the next checkpoint"):
        backed.client.sign(checkpoint(backed.pub, root="cd"))
    assert len(backed.vault.digests) == 1


def test_two_racing_requests_for_one_position_get_one_signature(backed):
    payloads = [checkpoint(backed.pub, root=root) for root in ("ab", "cd")]
    outcomes = []
    real_sign = backed.vault.sign

    def slow(algorithm, digest):
        time.sleep(0.2)  # the time a real vault takes, during which the other request arrives
        return real_sign(algorithm, digest)

    backed.vault.sign = slow
    ask = [threading.Thread(target=lambda p=p: outcomes.append(backed.svc.handle(
        {"op": "sign", "payload": base64.b64encode(p).decode()}))) for p in payloads]
    for thread in ask:
        thread.start()
    for thread in ask:
        thread.join()
    assert sorted("signature" in o for o in outcomes) == [False, True]
    assert len(backed.vault.digests) == 1 and len(log_of(backed)) == 1


# Hand-overs


def test_a_handover_is_refused_and_never_reaches_the_vault(tmp_path, backed):
    rec = Recorder(FileSink(tmp_path / "e.jsonl"), agent_id="a", signer=backed.client, checkpoint_every=2)
    events(rec, 2)
    asked = len(backed.vault.digests)
    with pytest.raises(SignerError, match="does not hand a chain over"):
        rec.rotate_signer(generate_private_key(P256))
    assert len(backed.vault.digests) == asked


def test_a_handover_signed_when_the_operator_allows_it(tmp_path):
    served = serve(tmp_path / "signer", TroubledVault(), allow_handover=True)
    try:
        path = tmp_path / "e.jsonl"
        new = generate_private_key(P256)
        rec = Recorder(FileSink(path), agent_id="a", signer=served.client, checkpoint_every=2)
        events(rec, 2)
        handover = rec.rotate_signer(new)
        assert handover["key_id"] == key_id(served.pub)
        events(rec, 2)
        rec.close()
        report = verify_file(path, [served.pub])
        assert report.ok, report.errors
        assert [r["to_key"] for r in report.rotations] == [key_id(public_key_b64(new))]
    finally:
        served.client.close()
        served.server.close()


# A vault that fails


@pytest.mark.parametrize("error", [AzureStyleError(LEAKY), ConnectionError(LEAKY), TimeoutError(LEAKY)],
                         ids=["http-error", "connection", "timeout"])
def test_a_vault_failure_is_clean_and_a_retry_works(backed, error):
    payload = checkpoint(backed.pub)
    backed.vault.error = error
    with pytest.raises(SignerError, match="nothing was signed") as refused:
        backed.client.sign(payload)
    assert "hunter2" not in str(refused.value) and "1234" not in str(refused.value)
    assert log_of(backed) == [] and not (backed.dir / "state.json").exists()
    backed.vault.error = None
    assert backed.client.sign(payload)  # the same request goes through once the vault is back
    assert len(log_of(backed)) == 1


@pytest.mark.parametrize("answer", [b"\0" * 64, b"short", b"\x01" * 32 + b"\x7f" * 32],
                         ids=["zeros", "malformed", "well-formed-but-wrong"])
def test_a_signature_that_does_not_verify_moves_nothing(backed, answer):
    payload = checkpoint(backed.pub)
    backed.vault.answer = answer
    with pytest.raises(SignerError, match="nothing was signed"):
        backed.client.sign(payload)
    assert log_of(backed) == [] and not (backed.dir / "state.json").exists()
    backed.vault.answer = None
    assert backed.client.sign(payload)


def test_the_recorder_rides_out_a_vault_outage(tmp_path, backed):
    path = tmp_path / "e.jsonl"
    backed.vault.error = AzureStyleError(LEAKY)
    rec = Recorder(FileSink(path), agent_id="a", signer=backed.client, checkpoint_every=2, retry_after=60)
    events(rec, 3)
    assert rec.failures == 1 and log_of(backed) == []
    backed.vault.error = None
    rec.checkpoint()
    rec.close()
    report = verify_file(path, [backed.pub])
    assert report.ok and report.unsigned_tail == 0, report.errors


def test_the_operator_log_names_the_failure_without_its_text(backed, caplog):
    backed.vault.error = AzureStyleError(LEAKY)
    with pytest.raises(SignerError):
        backed.client.sign(checkpoint(backed.pub))
    assert "AzureStyleError (HTTP 403)" in caplog.text and "hunter2" not in caplog.text


# The command line and start-up


def test_serve_uses_the_vault_key_and_prints_it(tmp_path, monkeypatch, capsys):
    vault = TroubledVault()
    pub = public_key_b64(vault.key)
    (tmp_path / "s").mkdir()
    (tmp_path / "s" / "signer.token").write_text(TOKEN, encoding="ascii")
    asked = []

    def stand_in(url):
        asked.append(url)
        return AzureKeyVaultSigner(url, client=vault, public_key=pub)

    monkeypatch.setattr(mnestiq.signer_service, "key_vault_signer", stand_in)
    monkeypatch.setattr(SignerServer, "wait", lambda self: self.close())
    assert main(["signer", "serve", str(tmp_path / "s"), "--listen", "127.0.0.1:0", "--azure-key", KEY_URL]) == 0
    out = capsys.readouterr().out
    assert asked == [KEY_URL] and pub in out and key_id(pub) in out


def test_without_the_option_the_folders_own_key_is_used(tmp_path):
    signer = init_signer(tmp_path / "s")
    svc = SignerService(tmp_path / "s")
    assert (svc.signer.sig_alg, svc.signer.public_key) == (signer.sig_alg, signer.public_key)


def test_a_key_url_needs_a_version_and_the_right_shape():
    pytest.importorskip("azure.keyvault.keys")
    with pytest.raises(SignerError, match="no key version"):
        key_vault_signer("https://v.vault.azure.net/keys/k")
    with pytest.raises(SignerError, match="not the URL of a Key Vault key"):
        key_vault_signer("https://v.vault.azure.net/secrets")


def test_a_failure_at_start_up_is_clean(tmp_path, monkeypatch, capsys):
    def fails(*args, **kwargs):
        raise AzureStyleError(LEAKY)

    (tmp_path / "s").mkdir()
    (tmp_path / "s" / "signer.token").write_text(TOKEN, encoding="ascii")
    monkeypatch.setattr(mnestiq.signer_service, "AzureKeyVaultSigner", fails)
    assert main(["signer", "serve", str(tmp_path / "s"), "--azure-key", KEY_URL]) == 2
    err = capsys.readouterr().err
    assert "AzureStyleError (HTTP 403)" in err and "hunter2" not in err


# Bounds on what one request can do


def test_a_checkpoint_may_cover_a_generous_range_and_no_more(backed):
    limit = mnestiq.signer_service.MAX_COVERED
    assert "signature" in ask(backed.svc, checkpoint(backed.pub, seq=limit))
    assert len(backed.vault.digests) == 1
    with pytest.raises(SignerError, match="covers more than"):
        backed.client.sign(checkpoint(backed.pub, seq=2 * limit + 2, first=limit + 1))
    assert len(backed.vault.digests) == 1


def test_one_request_cannot_end_a_chain_on_a_local_key_either(tmp_path):
    signer = init_signer(tmp_path / "s")
    svc = SignerService(tmp_path / "s")
    top = local_checkpoint(signer, seq=2**53 - 1, first=0)
    assert "covers more than" in ask(svc, top)["error"]
    assert not (tmp_path / "s" / "state.json").exists()


def test_only_the_range_is_kept_from_covers(backed):
    body = json.loads(checkpoint(backed.pub))
    body["covers"]["junk"] = "A" * 1000
    assert "signature" in ask(backed.svc, canonical_json(body))
    assert json.loads((backed.dir / "state.json").read_text())["c"]["covers"] == {"from_seq": 0, "to_seq": 1}
    assert log_of(backed)[0]["covers"] == {"from_seq": 0, "to_seq": 1}


def test_a_very_long_chain_id_is_refused(backed):
    body = json.loads(checkpoint(backed.pub))
    body["chain_id"] = "c" * (mnestiq.signer_service.MAX_CHAIN_ID + 1)
    assert "chain_id" in ask(backed.svc, canonical_json(body))["error"]
    assert backed.vault.digests == []


@pytest.mark.parametrize("root", ["sha256:" + "AB" * 32, "sha256:ab", "ab" * 32, "", None, 5])
def test_a_merkle_root_in_the_wrong_format_is_refused(backed, root):
    body = json.loads(checkpoint(backed.pub))
    body["merkle_root"] = root
    assert "merkle_root" in ask(backed.svc, canonical_json(body))["error"]
    assert backed.vault.digests == []


@pytest.mark.parametrize("value", [None, {}, "", 0, False])
def test_a_falsy_next_key_is_still_a_handover(backed, value):
    with pytest.raises(SignerError, match="does not hand a chain over"):
        backed.client.sign(checkpoint(backed.pub, next_key=value))
    assert backed.vault.digests == []


def test_a_chain_id_cannot_write_lines_into_the_log(backed, caplog):
    forged = "c\nmnestiq signer: FORGED"
    body = json.loads(checkpoint(backed.pub))
    body["chain_id"] = forged
    assert "signature" in ask(backed.svc, canonical_json(body))
    body["merkle_root"] = "sha256:" + "cd" * 32
    assert "only the next checkpoint" in ask(backed.svc, canonical_json(body))["error"]
    assert "\nmnestiq signer: FORGED" not in caplog.text and "FORGED" in caplog.text


# A slow or stuck vault


class SlowVault(TroubledVault):
    delay = 0.0

    def sign(self, algorithm, digest):
        time.sleep(self.delay)
        return super().sign(algorithm, digest)


def test_a_slow_vault_holds_up_only_its_own_chain(tmp_path):
    vault = SlowVault()
    vault.delay = 0.5
    served = serve(tmp_path / "signer", vault)
    try:
        replies = []
        payloads = [checkpoint(served.pub, chain=c) for c in ("a", "b", "c", "d")]
        requests = [threading.Thread(target=lambda p=p: replies.append(ask(served.svc, p))) for p in payloads]
        started = time.monotonic()
        for thread in requests:
            thread.start()
        for thread in requests:
            thread.join()
        assert time.monotonic() - started < 1.5  # one after another would take 2 seconds
        assert all("signature" in reply for reply in replies) and len(log_of(served)) == 4
    finally:
        served.client.close()
        served.server.close()


def test_a_request_that_waited_its_turn_is_checked_against_the_clock_again(tmp_path):
    vault = SlowVault()
    served = serve(tmp_path / "signer", vault, max_skew=0.5)
    try:
        vault.delay = 0.9
        holder = threading.Thread(target=ask, args=(served.svc, checkpoint(served.pub)))
        holder.start()
        time.sleep(0.2)
        late = ask(served.svc, checkpoint(served.pub, seq=4, first=3))
        holder.join()
        assert "from this signer's clock" in late["error"] and len(vault.digests) == 1
    finally:
        served.client.close()
        served.server.close()


def test_a_signature_that_arrives_outside_the_clock_window_is_dropped(tmp_path):
    vault = SlowVault()
    vault.delay = 0.7
    served = serve(tmp_path / "signer", vault, max_skew=0.5)
    try:
        assert "from this signer's clock" in ask(served.svc, checkpoint(served.pub))["error"]
        assert len(vault.digests) == 1 and log_of(served) == [] and not (served.dir / "state.json").exists()
    finally:
        served.client.close()
        served.server.close()


def test_a_vault_that_never_answers_is_given_up_on(tmp_path):
    release = threading.Event()

    class Stuck(TroubledVault):
        stuck = True

        def sign(self, algorithm, digest):
            if self.stuck:
                release.wait(30)
            return super().sign(algorithm, digest)

    vault = Stuck()
    served = serve(tmp_path / "signer", vault, sign_deadline=0.3)
    try:
        payload = checkpoint(served.pub)
        started = time.monotonic()
        with pytest.raises(SignerError, match="nothing was signed"):
            served.client.sign(payload)
        assert time.monotonic() - started < 3
        assert log_of(served) == [] and not (served.dir / "state.json").exists()
        vault.stuck = False
        signature = served.client.sign(payload)  # the abandoned call is still waiting, and the retry does not
        release.set()
        time.sleep(0.1)  # its late answer arrives now and is dropped
        assert len(log_of(served)) == 1 and base64.b64encode(signature).decode() == log_of(served)[0]["signature"]
    finally:
        release.set()
        served.client.close()
        served.server.close()


def test_requests_queued_on_a_stuck_chain_are_answered_by_the_deadline(tmp_path):
    release = threading.Event()

    class Stuck(TroubledVault):
        def sign(self, algorithm, digest):
            release.wait(30)
            return super().sign(algorithm, digest)

    served = serve(tmp_path / "signer", Stuck(), sign_deadline=0.3)
    try:
        replies = []
        waiting = [threading.Thread(target=lambda: replies.append(ask(served.svc, checkpoint(served.pub))))
                   for _ in range(3)]
        started = time.monotonic()
        for thread in waiting:
            thread.start()
        for thread in waiting:
            thread.join()
        assert time.monotonic() - started < 2 and all("error" in reply for reply in replies)
    finally:
        release.set()
        served.client.close()
        served.server.close()


# The log


def test_the_state_is_saved_before_the_log_line(backed):
    seen = []
    real = backed.svc._append_log

    def spy(entry):
        seen.append(json.loads((backed.dir / "state.json").read_text())["c"]["seq"])
        real(entry)

    backed.svc._append_log = spy
    backed.client.sign(checkpoint(backed.pub))
    assert seen == [2]


def test_a_log_failure_says_so_and_the_identical_retry_completes_it(backed):
    payload = checkpoint(backed.pub)
    real = backed.svc._append_log

    def full(entry):
        raise OSError(28, "No space left on device")

    backed.svc._append_log = full
    reply = ask(backed.svc, payload)
    assert "signed" in reply["error"] and "send the identical request again" in reply["error"]
    assert "did not sign" not in reply["error"]
    assert json.loads((backed.dir / "state.json").read_text())["c"]["seq"] == 2 and log_of(backed) == []
    backed.svc._append_log = real
    signature = ask(backed.svc, payload)["signature"]
    log = log_of(backed)
    assert [e["signature"] for e in log] == [signature] and "repeat" not in log[0]
    assert len(backed.vault.digests) == 1


def test_a_log_line_still_missing_after_a_restart_is_written_once(backed):
    payload = checkpoint(backed.pub)

    def full(entry):
        raise OSError(28, "No space left on device")

    backed.svc._append_log = full
    ask(backed.svc, payload)
    fresh = SignerService(backed.dir, signer=backed.svc.signer)
    assert "signature" in ask(fresh, payload)
    assert [e.get("repeat") for e in log_of(backed)] == [None]
    fresh = SignerService(backed.dir, signer=backed.svc.signer)  # the saved flag is out of date: the log is read
    assert "signature" in ask(fresh, payload)
    assert [e.get("repeat") for e in log_of(backed)] == [None, True]


def test_the_next_checkpoint_fills_in_a_missing_log_line_first(backed):
    real = backed.svc._append_log

    def full(entry):
        raise OSError(28, "No space left on device")

    backed.svc._append_log = full
    ask(backed.svc, checkpoint(backed.pub))
    next_one = checkpoint(backed.pub, seq=4, first=3)
    assert "did not sign" in ask(backed.svc, next_one)["error"]  # this one really was not signed
    backed.svc._append_log = real
    assert "signature" in ask(backed.svc, next_one)
    assert [e["seq"] for e in log_of(backed)] == [2, 4]


# The folder


def test_two_services_cannot_serve_one_folder(backed):
    other = SignerService(backed.dir, signer=backed.svc.signer)
    with pytest.raises(SignerError, match="already serving"):
        other.start("127.0.0.1:0")
    backed.server.close()
    other.start("127.0.0.1:0").close()


@pytest.mark.parametrize("state", ['{"c": 5}', '{"c": {}}', '{"c": {"seq": "x"}}', "[]"])
def test_a_damaged_state_stops_the_service(tmp_path, state):
    directory = tmp_path / "s"
    directory.mkdir()
    (directory / "signer.token").write_text(TOKEN, encoding="ascii")
    (directory / "state.json").write_text(state)
    vault = TroubledVault()
    with pytest.raises(SignerError, match="damaged"):
        SignerService(directory, signer=stand_in(vault))


@pytest.mark.parametrize("token", ["", "\n", "short", "a" * 31])
def test_a_token_that_is_empty_or_short_stops_the_service(tmp_path, token):
    directory = tmp_path / "s"
    directory.mkdir()
    (directory / "signer.token").write_text(token, encoding="ascii")
    vault = TroubledVault()
    with pytest.raises(SignerError, match=r"signer\.token holds fewer"):
        SignerService(directory, signer=stand_in(vault))


@pytest.mark.parametrize("value", ["nan", "inf", "-inf", "0", "-1"])
def test_a_max_skew_that_is_not_a_positive_number_is_refused(tmp_path, monkeypatch, capsys, value):
    monkeypatch.setattr(SignerServer, "wait", lambda self: self.close())
    assert main(["signer", "init", str(tmp_path / "s")]) == 0
    assert main(["signer", "serve", str(tmp_path / "s"), "--listen", "127.0.0.1:0", f"--max-skew={value}"]) == 2
    assert "max_skew" in capsys.readouterr().err


def test_init_without_a_key_writes_only_the_token(tmp_path, capsys):
    assert main(["signer", "init", str(tmp_path / "s"), "--no-key"]) == 0
    assert (tmp_path / "s" / "signer.token").exists() and not (tmp_path / "s" / "signer.key").exists()
    assert main(["signer", "init", str(tmp_path / "s"), "--no-key"]) == 2
    assert "signer.token" in capsys.readouterr().out


def test_init_on_a_folder_with_a_token_leaves_no_new_key(tmp_path):
    assert main(["signer", "init", str(tmp_path / "s")]) == 0
    (tmp_path / "s" / "signer.key").unlink()
    assert main(["signer", "init", str(tmp_path / "s")]) == 2
    assert not (tmp_path / "s" / "signer.key").exists()


def test_a_folder_with_chains_from_another_key_is_refused(backed):
    backed.client.sign(checkpoint(backed.pub))
    vault = TroubledVault()
    with pytest.raises(SignerError, match="use a new folder"):
        SignerService(backed.dir, signer=stand_in(vault))


def test_a_folder_of_an_older_local_key_is_refused(tmp_path):
    signer = init_signer(tmp_path / "s")
    assert "signature" in ask(SignerService(tmp_path / "s"), local_checkpoint(signer))
    state_path = tmp_path / "s" / "state.json"
    state = json.loads(state_path.read_text())
    del state["c"]["key_id"]  # the format that named no key
    state_path.write_text(json.dumps(state))
    SignerService(tmp_path / "s")  # its own key is fine
    vault = TroubledVault()
    with pytest.raises(SignerError, match="use a new folder"):
        SignerService(tmp_path / "s", signer=stand_in(vault))


# How the Azure clients are built


def stand_in_azure(monkeypatch, credential=None):
    azure_keys = pytest.importorskip("azure.keyvault.keys")
    crypto = pytest.importorskip("azure.keyvault.keys.crypto")
    identity = pytest.importorskip("azure.identity")
    made = {}
    key = generate_private_key(P256).public_key().public_numbers()

    class FakeKeyClient:
        def __init__(self, url, cred, **options):
            made["keys"] = options

        def get_key(self, name, version):
            jwk = SimpleNamespace(crv="P-256", x=key.x.to_bytes(32, "big"), y=key.y.to_bytes(32, "big"))
            return SimpleNamespace(key=jwk)

    def fake_crypto(url, cred, **options):
        made["crypto"] = options
        return object()

    def fake_credential(**options):
        made["credential"] = options
        if credential is not None:
            raise credential
        return object()

    monkeypatch.setattr(azure_keys, "KeyClient", FakeKeyClient)
    monkeypatch.setattr(crypto, "CryptographyClient", fake_crypto)
    monkeypatch.setattr(identity, "DefaultAzureCredential", fake_credential)
    return made


def test_the_time_limits_reach_every_azure_client(monkeypatch):
    made = stand_in_azure(monkeypatch)
    key_vault_signer(KEY_URL)
    options = {"retry_total": 0, "connection_timeout": 3, "read_timeout": 4}  # no retry, so no wait on Retry-After
    assert made["keys"] == options and made["crypto"] == options
    assert made["credential"] == {"process_timeout": 5, **options}


@pytest.mark.parametrize("error", [ValueError, FileNotFoundError, PermissionError])
def test_a_bad_service_certificate_has_its_own_error(monkeypatch, error):
    stand_in_azure(monkeypatch, credential=error("Failed to read certificate at C:/secret/path"))
    with pytest.raises(SignerError, match=r"sign-in could not be set up") as refused:
        key_vault_signer(KEY_URL)
    assert "secret" not in str(refused.value) and "URL" not in str(refused.value)


# A lost answer, and no new record to carry it


class LosesTheAnswer:
    """In front of a real client: the service signs, and the first answer never comes back."""

    can_extend = True

    def __init__(self, client):
        self.client, self.sig_alg, self.public_key = client, client.sig_alg, client.public_key
        self.lose = True
        self.asked = []

    def sign(self, payload, leaves=None):
        self.asked.append(json.loads(payload)["ts"])
        signature = self.client.sign(payload, leaves) if leaves is not None else self.client.sign(payload)
        if self.lose:
            self.lose = False
            raise SignerError("the signer at 127.0.0.1 is not reachable: the answer was lost")
        return signature


@pytest.fixture
def fresh_times(monkeypatch):
    monkeypatch.setattr(mnestiq.recorder, "SAME_ATTEMPT_S", 0)  # every try gets a new time, as after four minutes


def test_a_lost_answer_recovers_with_no_new_record(tmp_path, backed, fresh_times):
    path = tmp_path / "e.jsonl"
    signer = LosesTheAnswer(backed.client)
    rec = Recorder(FileSink(path), agent_id="a", signer=signer, checkpoint_every=1000, retry_after=0)
    events(rec, 2)
    with pytest.raises(SignerError, match="not reachable"):
        rec.checkpoint()
    time.sleep(0.01)
    assert rec.checkpoint() is not None
    assert len(backed.vault.digests) == 1  # the signature that was lost, not a second one
    assert signer.asked[-1] == signer.asked[0]
    assert [e.get("repeat") for e in log_of(backed)] == [None, True]
    rec.close()  # the clean-close note brings a checkpoint of its own
    report = verify_file(path, [backed.pub])
    assert report.ok and report.unsigned_tail == 0, report.errors
    recovered = next(r for r in load(path) if r["kind"] == "checkpoint")
    assert recovered["ts"] == signer.asked[0]
    assert recovered["signature"] == log_of(backed)[0]["signature"]


def test_a_recovered_signature_survives_a_failed_write(tmp_path, backed, fresh_times, monkeypatch):
    path = tmp_path / "e.jsonl"
    signer = LosesTheAnswer(backed.client)
    rec = Recorder(FileSink(path), agent_id="a", signer=signer, checkpoint_every=1000, retry_after=0)
    events(rec, 2)
    with pytest.raises(SignerError):
        rec.checkpoint()
    signed_time = signer.asked[0]
    time.sleep(0.05)
    real_write = rec._write

    def full(record):
        if record.get("kind") == "checkpoint":
            raise OSError(28, "No space left on device")
        return real_write(record)

    rec._write = full
    with pytest.raises(OSError):
        rec.checkpoint()
    rec._write = real_write
    monkeypatch.setattr(mnestiq.recorder, "SAME_ATTEMPT_S", 240)  # the next try keeps the time of this one
    assert rec.checkpoint()["ts"] == signed_time
    assert len(backed.vault.digests) == 1
    rec.close()
    assert verify_file(path, [backed.pub]).ok


def test_a_lost_answer_recovers_on_a_local_key_too(tmp_path, fresh_times):
    signer = init_signer(tmp_path / "s")
    server = SignerService(tmp_path / "s").start("127.0.0.1:0")
    client = SignerClient(server.address, (tmp_path / "s" / "signer.token").read_text().strip())
    try:
        path = tmp_path / "e.jsonl"
        lossy = LosesTheAnswer(client)
        rec = Recorder(FileSink(path), agent_id="a", signer=lossy, checkpoint_every=1000, retry_after=0)
        events(rec, 2)
        with pytest.raises(SignerError):
            rec.checkpoint()
        time.sleep(0.01)
        rec.checkpoint()
        rec.close()
        report = verify_file(path, [signer.public_key])
        assert report.ok and report.unsigned_tail == 0, report.errors
    finally:
        client.close()
        server.close()


class Scripted:
    """A signer that always refuses, or fails as ``failure`` says once ``refuse_first`` calls have been refused."""

    can_extend = True

    def __init__(self):
        self.signer = LocalSigner(generate_private_key())
        self.sig_alg, self.public_key = self.signer.sig_alg, self.signer.public_key
        self.calls = 0
        self.refuse_first = None
        self.failure = "the signer is not reachable"

    def sign(self, payload, leaves=None):
        self.calls += 1
        if self.refuse_first is None or self.calls <= self.refuse_first:
            raise SignerError("chain 'c' was signed up to seq 9, and this checkpoint covers from 0")
        raise SignerError(self.failure)


def test_the_earlier_times_are_bounded_and_each_try_is_finite(tmp_path, fresh_times):
    signer = Scripted()
    rec = Recorder(FileSink(tmp_path / "e.jsonl"), agent_id="a", signer=signer, checkpoint_every=1000, retry_after=0)
    events(rec, 2)
    limit = mnestiq.recorder.MAX_EARLIER_TIMES
    for attempt in range(30):
        before = signer.calls
        with pytest.raises(SignerError):
            rec.checkpoint()
        assert signer.calls - before <= limit + 2  # this request, the kept times, the records' hashes
        assert len(rec._earlier_times) == min(attempt, limit)


def test_a_signer_in_trouble_ends_the_search(tmp_path, fresh_times):
    signer = Scripted()
    signer.refuse_first = 0
    rec = Recorder(FileSink(tmp_path / "e.jsonl"), agent_id="a", signer=signer, checkpoint_every=1000, retry_after=0)
    events(rec, 2)
    for _ in range(4):  # the service is down: times pile up, and nothing is sent again
        with pytest.raises(SignerError, match="not reachable"):
            rec.checkpoint()
    assert len(rec._earlier_times) == 3 and signer.calls == 4
    signer.calls, signer.refuse_first = 0, 1  # refused, and down again at the first earlier time
    with pytest.raises(SignerError, match="not reachable"):
        rec.checkpoint()
    assert signer.calls == 2


def test_a_refusal_during_the_search_stays_out_of_the_agent_unless_strict(tmp_path):
    signer = Scripted()
    rec = Recorder(FileSink(tmp_path / "e.jsonl"), agent_id="a", signer=signer, checkpoint_every=2, retry_after=0)
    events(rec, 5)  # returns: the records are written and the failures counted
    assert rec.failures >= 1
    rec.close()
    strict = Recorder(FileSink(tmp_path / "s.jsonl"), agent_id="a", signer=Scripted(), checkpoint_every=2,
                      retry_after=0, strict=True)
    with pytest.raises(SignerError, match="was signed up to"):
        events(strict, 2)


def test_new_records_start_the_earlier_times_again(tmp_path, fresh_times):
    signer = Scripted()
    rec = Recorder(FileSink(tmp_path / "e.jsonl"), agent_id="a", signer=signer, checkpoint_every=1000, retry_after=0)
    events(rec, 2)
    for _ in range(3):
        with pytest.raises(SignerError):
            rec.checkpoint()
    assert len(rec._earlier_times) == 2
    events(rec, 1)
    with pytest.raises(SignerError):
        rec.checkpoint()
    assert rec._earlier_times == []


def test_the_newest_earlier_time_is_asked_first_and_an_old_one_may_be_outside_the_clock(tmp_path, fresh_times):
    class ClockThenSigned(Scripted):
        def __init__(self):
            super().__init__()
            self.refuse_first = 0
            self.seen = []
            self.answering = False

        def sign(self, payload, leaves=None):
            self.seen.append(json.loads(payload)["ts"])
            if not self.answering:
                raise SignerError("the signer is not reachable")
            if len(self.seen) == 1:
                raise SignerError("chain 'c' was signed up to seq 3, and this checkpoint covers from 0")
            if len(self.seen) == 2:
                raise SignerError("the checkpoint's time is 900s from this signer's clock (at most 300s)")
            return self.signer.sign(payload)

    signer = ClockThenSigned()
    path = tmp_path / "e.jsonl"
    rec = Recorder(FileSink(path), agent_id="a", signer=signer, checkpoint_every=1000, retry_after=0)
    events(rec, 2)
    for _ in range(3):
        with pytest.raises(SignerError):
            rec.checkpoint()
        time.sleep(0.05)  # the clock may tick only every 15 ms
    times = list(signer.seen)  # the three tries, oldest first
    assert times[0] != times[1] != times[2] != times[0]
    signer.seen.clear()
    signer.answering = True
    assert rec.checkpoint() is not None
    assert signer.seen[1:] == [times[2], times[1]]
    assert [r["ts"] for r in load(path) if r["kind"] == "checkpoint"] == [times[1]]


# The service's and the proxy's threads are not the agent's


@pytest.fixture
def inside_a_run(tmp_path):
    instrument_egress()
    rec = Recorder(FileSink(tmp_path / "agent.jsonl"), agent_id="a")
    try:
        with rec.run() as run:
            assert current_run() is run
            yield run
    finally:
        rec.close()
        uninstrument_egress()


def test_the_signers_threads_do_not_inherit_a_run(tmp_path, inside_a_run):
    seen = []

    class Watching(TroubledVault):
        def sign(self, algorithm, digest):
            seen.append(current_run())
            return super().sign(algorithm, digest)

    served = serve(tmp_path / "signer", Watching())
    answered = []
    real_handle = served.svc.handle

    def handle(request):
        answered.append(current_run())
        return real_handle(request)

    served.svc.handle = handle
    try:
        served.client.sign(checkpoint(served.pub))  # its connection thread, then the thread that asks the vault
        ask_directly = checkpoint(served.pub, seq=4, first=3)
        assert "signature" in real_handle({"op": "sign", "payload": base64.b64encode(ask_directly).decode()})
        assert seen == [None, None] and answered and all(run is None for run in answered)
        assert served.server._thread.__dict__["_mnestiq_own"] is True
    finally:
        served.client.close()
        served.server.close()


def test_the_proxys_threads_do_not_inherit_a_run(tmp_path, inside_a_run, monkeypatch):
    seen = {}
    handled = threading.Event()
    real_serve, real_request = _Server.serve_forever, _Server.process_request_thread

    def serve_forever(self, *args, **kwargs):
        seen["acceptor"] = current_run()
        return real_serve(self, *args, **kwargs)

    def process_request_thread(self, request, client_address):
        seen["handler"] = current_run()
        handled.set()
        return real_request(self, request, client_address)

    monkeypatch.setattr(_Server, "serve_forever", serve_forever)
    monkeypatch.setattr(_Server, "process_request_thread", process_request_thread)
    rec = Recorder(FileSink(tmp_path / "proxy.jsonl"), agent_id="p")
    proxy = ModelProxy(rec, listen="127.0.0.1:0")
    host, port = proxy.start()
    try:
        with socket.create_connection((host, port), timeout=5):
            assert handled.wait(5)
        assert seen == {"acceptor": None, "handler": None}
    finally:
        proxy.close(wait=1)
        rec.close()
