"""Signing outside the agent: P-256, signed key hand-overs, the signer service, Azure Key Vault."""

import base64
import hashlib
import json
import time
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

import mnestiq.recorder
from mnestiq import (AzureKeyVaultSigner, FileSink, LocalSigner, MemorySink, Recorder, RecorderError,
                     SignerClient, SignerError, verify_file, verify_lines)
from mnestiq.canonical import canonical_json
from mnestiq.cli import main
from mnestiq.hashing import record_hash, signing_payload
from mnestiq.keys import (P256, P256_ORDER, generate_private_key, key_id, normalize_p256, public_key_b64,
                          verify_signature)
from mnestiq.signer_service import SignerService, init_signer

from conftest import dump, load, record_demo


def codes(report):
    return {i.code for i in report.errors}


def warnings(report):
    return {i.code for i in report.warnings}


def events(rec, n, run="r"):
    for i in range(n):
        rec.append_event({"event_type": "note", "run_id": run, "agent_id": "a", "attributes": {"i": i}})


def resign(record, key):
    """Re-sign a checkpoint with ``key`` after editing it, as an attacker holding that key would."""
    signer = LocalSigner(key)
    record.update({"sig_alg": signer.sig_alg, "public_key": signer.public_key, "key_id": key_id(signer.public_key)})
    record.pop("record_hash", None)
    record["signature"] = base64.b64encode(signer.sign(signing_payload(record))).decode("ascii")
    record["record_hash"] = record_hash(record)


def relink(records):
    """Fix every prev_hash / record_hash after an edit (what someone rewriting the file would do)."""
    prev = records[0]["prev_hash"]
    for r in records:
        r["prev_hash"] = prev
        r.pop("record_hash", None)
        r["record_hash"] = record_hash(r)
        prev = r["record_hash"]


# P-256


def test_p256_chain_verifies_and_pins(tmp_path):
    key = generate_private_key(P256)
    path = record_demo(tmp_path / "e.jsonl", key)
    pub = public_key_b64(key)
    assert len(base64.b64decode(pub)) == 65 and key_id(pub).startswith("p256:")
    report = verify_file(path, [pub])
    assert report.ok, report.errors
    records = load(path)
    assert {r["sig_alg"] for r in records if r["kind"] == "checkpoint"} == {P256}
    assert {r["spec_version"] for r in records} == {"0.2"}
    other = public_key_b64(generate_private_key(P256))
    assert "untrusted_key" in codes(verify_file(path, [other]))


def test_p256_tampering_is_caught(tmp_path):
    key = generate_private_key(P256)
    path = record_demo(tmp_path / "e.jsonl", key)
    records = load(path)
    records[1]["agent_id"] = "someone-else"
    relink(records)
    dump(path, records)
    assert "signature" in codes(verify_file(path, [public_key_b64(key)])) or \
        "merkle_root" in codes(verify_file(path, [public_key_b64(key)]))


def test_only_low_s_signatures_are_accepted():
    key = generate_private_key(P256)
    pub = public_key_b64(key)
    payload = b"checkpoint"
    low = LocalSigner(key).sign(payload)
    verify_signature(P256, pub, low, payload)
    s = int.from_bytes(low[32:], "big")
    high = low[:32] + (P256_ORDER - s).to_bytes(32, "big")
    # Mathematically valid, but a second encoding of the same signature: refused.
    with pytest.raises(Exception, match="low form"):
        verify_signature(P256, pub, high, payload)
    assert normalize_p256(high) == low


def test_algorithm_must_match_the_key():
    ed = generate_private_key()
    sig = LocalSigner(ed).sign(b"x")
    with pytest.raises(Exception, match="cannot come from"):
        verify_signature(P256, public_key_b64(ed), sig, b"x")


def test_version_0_1_records_still_verify_but_cannot_use_p256(tmp_path, monkeypatch, key, pub):
    monkeypatch.setattr(mnestiq.recorder, "SPEC_VERSION", "0.1")
    old = record_demo(tmp_path / "old.jsonl", key)
    assert {r["spec_version"] for r in load(old)} == {"0.1"}
    assert verify_file(old, [pub]).ok
    p256 = generate_private_key(P256)
    bad = record_demo(tmp_path / "bad.jsonl", p256)
    assert "spec_version" in codes(verify_file(bad, [public_key_b64(p256)]))


def test_a_chain_may_upgrade_its_version_but_not_go_back(tmp_path, monkeypatch, key, pub):
    path = tmp_path / "e.jsonl"
    monkeypatch.setattr(mnestiq.recorder, "SPEC_VERSION", "0.1")
    rec = Recorder(FileSink(path), agent_id="a", signing_key=key, checkpoint_every=2)
    events(rec, 2)
    rec.close()
    monkeypatch.setattr(mnestiq.recorder, "SPEC_VERSION", "0.2")
    rec = Recorder(FileSink(path), agent_id="a", signing_key=key, checkpoint_every=2)
    events(rec, 2)
    rec.close()
    assert verify_file(path, [pub]).ok
    records = load(path)
    records[-1]["spec_version"] = "0.1"
    relink(records)
    resign(records[-1], key)
    dump(path, records)
    assert "spec_version" in codes(verify_file(path, [pub]))


# Key hand-over


def test_signed_handover_to_a_new_key(tmp_path, key, pub):
    path = tmp_path / "e.jsonl"
    new = generate_private_key(P256)
    rec = Recorder(FileSink(path), agent_id="a", signing_key=key, checkpoint_every=3)
    events(rec, 4)
    handover = rec.rotate_signer(new)
    assert handover["key_id"] == key_id(pub) and handover["next_key"]["key_id"] == key_id(public_key_b64(new))
    events(rec, 4)
    rec.close()
    # Pinning the first key is enough: it vouched for the second.
    report = verify_file(path, [pub])
    assert report.ok, report.errors
    assert report.rotations == [{"seq": handover["seq"], "from_key": key_id(pub),
                                 "to_key": key_id(public_key_b64(new))}]
    note = [r for r in load(path) if r.get("attributes", {}).get("message") == "key rotation"]
    assert note and note[0]["attributes"]["to_key"] == key_id(public_key_b64(new))
    # Resuming the file needs the new key now.
    with pytest.raises(RecorderError, match=r"Recorder\.rotate_signer"):
        Recorder(FileSink(path), agent_id="a", signing_key=key)
    Recorder(FileSink(path), agent_id="a", signing_key=new).close()


def test_a_key_change_without_handover_is_an_error_even_unpinned(tmp_path, key):
    """Someone with their own key re-signs the end of the file."""
    path = record_demo(tmp_path / "e.jsonl", key, checkpoint_every=3)
    records = load(path)
    resign(records[-1], generate_private_key())
    dump(path, records)
    report = verify_file(path)
    assert "signer_changed" in codes(report)


def test_a_handover_by_an_untrusted_key_does_not_extend_trust(tmp_path, key, pub):
    attacker, accomplice = generate_private_key(), generate_private_key()
    rec = Recorder(FileSink(tmp_path / "e.jsonl"), agent_id="a", signing_key=attacker, checkpoint_every=2)
    events(rec, 2)
    rec.rotate_signer(accomplice)
    events(rec, 2)
    rec.close()
    report = verify_file(tmp_path / "e.jsonl", [pub])
    assert "untrusted_key" in codes(report)
    assert all(i.code != "signer_changed" for i in report.errors)


def test_resuming_with_another_key_is_refused(tmp_path, key):
    path = record_demo(tmp_path / "e.jsonl", key)
    with pytest.raises(RecorderError, match="signed by ed25519:"):
        Recorder(FileSink(path), agent_id="a", signing_key=generate_private_key())


# Remote signers that fail


class Flaky:
    def __init__(self, key):
        self.inner = LocalSigner(key)
        self.sig_alg, self.public_key = self.inner.sig_alg, self.inner.public_key
        self.down = True
        self.calls = 0

    def sign(self, payload):
        self.calls += 1
        if self.down:
            raise ConnectionError("signer unreachable")
        return self.inner.sign(payload)


def test_a_signer_outage_loses_nothing(tmp_path, key, pub, recwarn):
    flaky = Flaky(key)
    path = tmp_path / "e.jsonl"
    rec = Recorder(FileSink(path), agent_id="a", signer=flaky, checkpoint_every=2, retry_after=60)
    with rec.run() as run:
        for _ in range(5):
            assert run.note("working") is not None  # the agent carries on
    assert rec.failures == 1 and flaky.calls == 1  # tried once, then waits retry_after
    flaky.down = False
    rec.checkpoint()
    rec.close()
    report = verify_file(path, [pub])
    assert report.ok and report.unsigned_tail == 0


def test_a_wrong_signature_never_reaches_the_evidence(tmp_path, key):
    class Liar(Flaky):
        def sign(self, payload):
            return b"\0" * 64

    rec = Recorder(MemorySink(), agent_id="a", signer=Liar(key), checkpoint_every=1, strict=True)
    with pytest.raises(RecorderError, match="does not match its public key"):
        events(rec, 1)
    assert all(r["kind"] == "event" for r in rec._sink.records)


# Azure Key Vault (a stand-in client: tests never leave this machine)


class FakeKeyVault:
    """Behaves like azure.keyvault.keys.crypto.CryptographyClient.sign for ES256."""

    def __init__(self, high_s=False):
        self.key = generate_private_key(P256)
        self.digests = []
        self.high_s = high_s

    def sign(self, algorithm, digest):
        assert str(getattr(algorithm, "value", algorithm)) == "ES256" and len(digest) == 32
        self.digests.append(digest)
        from cryptography.hazmat.primitives.asymmetric.utils import Prehashed

        r, s = decode_dss_signature(self.key.sign(digest, ec.ECDSA(Prehashed(hashes.SHA256()))))
        if self.high_s and s <= P256_ORDER // 2:
            s = P256_ORDER - s
        return SimpleNamespace(signature=r.to_bytes(32, "big") + s.to_bytes(32, "big"))


@pytest.mark.parametrize("high_s", [False, True])
def test_azure_key_vault_signer(tmp_path, high_s):
    vault = FakeKeyVault(high_s)
    pub = public_key_b64(vault.key)
    signer = AzureKeyVaultSigner("https://v.vault.azure.net/keys/k/1", client=vault, public_key=pub)
    path = tmp_path / "e.jsonl"
    rec = Recorder(FileSink(path), agent_id="a", signer=signer, checkpoint_every=2)
    events(rec, 4)
    rec.close()
    assert verify_file(path, [pub]).ok
    # Only a 32-byte digest of each checkpoint went to the key store, never records.
    checkpoints = [r for r in load(path) if r["kind"] == "checkpoint"]
    assert vault.digests == [hashlib.sha256(signing_payload(c)).digest() for c in checkpoints]


def test_azure_needs_a_key_version():
    pytest.importorskip("azure.keyvault.keys")
    with pytest.raises(SignerError, match="no key version"):
        AzureKeyVaultSigner("https://v.vault.azure.net/keys/k", credential=object())


# The signer service


@pytest.fixture
def service(tmp_path):
    signer = init_signer(tmp_path / "signer")
    svc = SignerService(tmp_path / "signer")
    server = svc.start("127.0.0.1:0")
    token = (tmp_path / "signer" / "signer.token").read_text().strip()
    yield SimpleNamespace(svc=svc, server=server, token=token, pub=signer.public_key, dir=tmp_path / "signer")
    server.close()


def test_the_agent_signs_through_the_service(tmp_path, service):
    client = SignerClient(service.server.address, service.token)
    assert client.public_key == service.pub
    path = tmp_path / "e.jsonl"
    rec = Recorder(FileSink(path), agent_id="a", signer=client, checkpoint_every=2)
    events(rec, 5)
    rec.close()
    client.close()
    assert verify_file(path, [service.pub]).ok
    log = [json.loads(line) for line in (service.dir / "signatures.jsonl").read_text().splitlines()]
    checkpoints = [r for r in load(path) if r["kind"] == "checkpoint"]
    assert [e["seq"] for e in log] == [c["seq"] for c in checkpoints]
    assert [e["signature"] for e in log] == [c["signature"] for c in checkpoints]


def test_the_service_will_not_resign_history(tmp_path, service):
    """A hijacked agent rewrites the file and asks for the old checkpoints to be signed again."""
    client = SignerClient(service.server.address, service.token)
    path = tmp_path / "e.jsonl"
    rec = Recorder(FileSink(path), agent_id="a", signer=client, checkpoint_every=2)
    events(rec, 4)
    rec.close()
    records = load(path)
    first = next(r for r in records if r["kind"] == "checkpoint")
    forged = {k: v for k, v in first.items() if k not in ("signature", "record_hash")}
    forged["merkle_root"] = "sha256:" + "ab" * 32
    with pytest.raises(SignerError, match="only the next checkpoint"):
        client.sign(signing_payload(forged))


def test_the_service_signs_checkpoints_only_and_near_its_clock(service):
    client = SignerClient(service.server.address, service.token)
    with pytest.raises(SignerError, match="only checkpoint"):
        client.sign(b'{"kind":"event"}')
    with pytest.raises(SignerError, match="not JSON"):
        client.sign(b"\x00raw bytes")
    stale = {"kind": "checkpoint", "chain_id": "c", "seq": 2, "covers": {"from_seq": 0, "to_seq": 1},
             "sig_alg": client.sig_alg, "public_key": client.public_key, "key_id": key_id(client.public_key),
             "ts": {"wall": "2020-01-01T00:00:00.000000Z", "mono_us": 0}}
    with pytest.raises(SignerError, match="from this signer's clock"):
        client.sign(canonical_json(stale))
    other = dict(stale, public_key=public_key_b64(generate_private_key()))
    with pytest.raises(SignerError, match="another key"):
        client.sign(canonical_json(other))


def test_the_service_needs_the_token(service):
    with pytest.raises(SignerError, match="did not accept the token"):
        SignerClient(service.server.address, "0" * 64)


def test_the_service_remembers_chains_across_restarts(tmp_path, service):
    client = SignerClient(service.server.address, service.token)
    path = tmp_path / "e.jsonl"
    rec = Recorder(FileSink(path), agent_id="a", signer=client, checkpoint_every=2)
    events(rec, 2)
    rec.close()
    service.server.close()
    again = SignerService(service.dir).start("127.0.0.1:0")
    try:
        client = SignerClient(again.address, service.token)
        cp = next(r for r in load(path) if r["kind"] == "checkpoint")
        replay = {k: v for k, v in cp.items() if k not in ("signature", "record_hash")}
        replay["ts"] = {"wall": time.strftime("%Y-%m-%dT%H:%M:%S.000000Z", time.gmtime()), "mono_us": 1}
        with pytest.raises(SignerError, match="only the next checkpoint"):
            client.sign(signing_payload(replay))
    finally:
        again.close()


def test_signer_cli(tmp_path, capsys):
    assert main(["signer", "init", str(tmp_path / "s"), "--alg", P256]) == 0
    out = capsys.readouterr().out
    assert "p256:" in out and "signer.token" in out
    assert main(["signer", "init", str(tmp_path / "s")]) == 2  # never overwrites a key
    assert main(["keygen", "--out", str(tmp_path / "k"), "--alg", P256]) == 0
    assert key_id((tmp_path / "k" / "signing.pub").read_text().strip()).startswith("p256:")


def test_verify_cli_shows_handovers(tmp_path, key, pub, capsys):
    path = tmp_path / "e.jsonl"
    rec = Recorder(FileSink(path), agent_id="a", signing_key=key, checkpoint_every=2)
    events(rec, 2)
    rec.rotate_signer(generate_private_key(P256))
    rec.close()
    capsys.readouterr()
    assert main(["verify", str(path), "--trusted-key", pub]) == 0
    assert "handover" in capsys.readouterr().out


def test_unsigned_lines_from_memory(key, pub):
    sink = MemorySink()
    rec = Recorder(sink, agent_id="a", signing_key=key, checkpoint_every=2)
    events(rec, 3)
    rec.close()
    assert verify_lines((canonical_json(r) for r in sink.records), [pub]).ok


@pytest.mark.skipif(not hasattr(__import__("socket"), "AF_UNIX") or __import__("os").name == "nt",
                    reason="Unix sockets")
def test_the_service_on_a_unix_socket(tmp_path):
    import tempfile

    init_signer(tmp_path / "s")
    # macOS limits socket paths to 104 bytes, and its temporary folders are long.
    sock = tempfile.mkdtemp(prefix="mnq", dir="/tmp") + "/s.sock"
    server = SignerService(tmp_path / "s").start(sock)
    try:
        client = SignerClient(server.address, (tmp_path / "s" / "signer.token").read_text().strip())
        rec = Recorder(MemorySink(), agent_id="a", signer=client, checkpoint_every=1)
        events(rec, 2)
        rec.close()
        assert verify_lines(canonical_json(r) for r in rec._sink.records).ok
    finally:
        server.close()


def test_a_silent_connection_does_not_hold_up_the_service(service, monkeypatch):
    import socket

    import mnestiq.signer_service

    monkeypatch.setattr(mnestiq.signer_service, "HANDSHAKE_SECONDS", 0.5)
    host, port = service.server.address.split(":")
    silent = socket.create_connection((host, int(port)))  # connects and never answers the challenge
    try:
        started = time.monotonic()
        client = SignerClient(service.server.address, service.token, timeout=5)
        assert client.public_key == service.pub
        assert time.monotonic() - started < 2
        client.close()
        silent.settimeout(5)
        silent.recv(1024)  # the challenge
        assert silent.recv(1024) == b""  # then the service hangs up
    finally:
        silent.close()


def test_the_client_gives_up_on_a_silent_signer():
    import socket

    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    try:
        started = time.monotonic()
        with pytest.raises(SignerError, match="not reachable"):
            SignerClient(f"127.0.0.1:{listener.getsockname()[1]}", "0" * 64, timeout=0.5)
        assert time.monotonic() - started < 5
    finally:
        listener.close()


def test_the_service_state_reaches_the_disk_before_it_is_swapped_in(tmp_path, service, monkeypatch):
    import os

    import mnestiq.signer_service

    steps = []
    real_fsync, real_replace = os.fsync, os.replace
    tmp = service.dir / "state.json.tmp"
    monkeypatch.setattr(mnestiq.signer_service.os, "fsync",
                        lambda fd: (steps.append("fsync new state" if tmp.exists() else "fsync"), real_fsync(fd))[1])
    monkeypatch.setattr(mnestiq.signer_service.os, "replace",
                        lambda a, b: (steps.append("replace"), real_replace(a, b))[1])
    client = SignerClient(service.server.address, service.token)
    rec = Recorder(FileSink(tmp_path / "e.jsonl"), agent_id="a", signer=client, checkpoint_every=1)
    events(rec, 1)
    rec.close()
    client.close()
    assert "replace" in steps and steps[steps.index("replace") - 1] == "fsync new state"
    assert not tmp.exists()
