"""The attacks in docs/threat-model.md, one test each. Every test carries out the attack and
checks that it is caught, refused, or (for the stated limits) shows exactly what is left.

Run just these with:  pytest tests/test_attacks.py -v
"""

import base64
import json
import time

import pytest

import mnestiq.recorder
from mnestiq import FileSink, HeadFile, LocalSigner, Recorder, SignerClient, SignerError, verify_file
from mnestiq.canonical import canonical_json
from mnestiq.hashing import record_hash, signing_payload
from mnestiq.keys import P256, P256_ORDER, generate_private_key, key_id, public_key_b64
from mnestiq.merkle import merkle_root
from mnestiq.hashing import digest_bytes
from mnestiq.signer_service import SignerService, init_signer

from conftest import dump, load, record_demo


def errors(report):
    return {i.code for i in report.errors}


def rewrite(records, key=None):
    """What a careful forger does after an edit: fix every hash, Merkle root and link, and
    re-sign the checkpoints with ``key`` (a stolen key, or their own)."""
    prev, pending = records[0]["prev_hash"], []
    for r in records:
        r["prev_hash"] = prev
        if r["kind"] == "checkpoint":
            r["merkle_root"] = "sha256:" + merkle_root([digest_bytes(h) for h in pending]).hex()
            if key is not None:
                signer = LocalSigner(key)
                r.update({"sig_alg": signer.sig_alg, "public_key": signer.public_key,
                          "key_id": key_id(signer.public_key)})
                r.pop("timestamp_token", None)
                r["signature"] = base64.b64encode(signer.sign(signing_payload(r))).decode()
            pending = []
        r.pop("record_hash", None)
        r["record_hash"] = record_hash(r)
        if r["kind"] != "checkpoint":
            pending.append(r["record_hash"])
        prev = r["record_hash"]
    return records


@pytest.fixture
def evidence(tmp_path, key):
    return record_demo(tmp_path / "e.jsonl", key, checkpoint_every=3)


# A. Changing what was written


def test_a1_edit_a_record(evidence, pub):
    """Change who approved the email, nothing else."""
    records = load(evidence)
    approval = next(r for r in records if r.get("event_type") == "approval")
    approval["approvals"][0]["approver"] = "alice"
    dump(evidence, records)
    assert "record_hash" in errors(verify_file(evidence, [pub]))


def test_a2_edit_and_fix_every_hash(evidence, pub):
    """The same edit, with every hash, link and Merkle root recomputed. Only the signature stops it."""
    records = load(evidence)
    next(r for r in records if r.get("event_type") == "approval")["approvals"][0]["approver"] = "alice"
    dump(evidence, rewrite(records))
    assert "signature" in errors(verify_file(evidence, [pub]))


def test_a3_delete_a_record(evidence, pub):
    records = load(evidence)
    del records[2]
    dump(evidence, records)
    assert {"seq", "link"} <= errors(verify_file(evidence, [pub]))


def test_a4_reorder_records(evidence, pub):
    records = load(evidence)
    records[1], records[2] = records[2], records[1]
    dump(evidence, records)
    assert "seq" in errors(verify_file(evidence, [pub]))


def test_a5_change_redacted_content(evidence, pub):
    """Swap a prompt for an innocent one, keeping its committed digest."""
    records = load(evidence)
    segment = next(s for r in records for s in r.get("context", []) if s["source"] == "web")
    segment["content"] = "Our returns policy is 30 days."
    dump(evidence, records)
    assert "content_hash" in errors(verify_file(evidence, [pub]))


def test_a6_smuggle_a_second_value_with_a_duplicate_key(evidence, pub):
    """Parsers disagree on which of two equal keys wins; the line is refused instead."""
    lines = evidence.read_bytes().splitlines()
    lines[1] = b'{"agent_id":"someone-else",' + lines[1][1:]
    evidence.write_bytes(b"\n".join(lines) + b"\n")
    assert "parse" in errors(verify_file(evidence, [pub]))


def test_a7_cut_the_file_back(tmp_path, key, pub):
    """Delete the end of the file, back to an earlier checkpoint. The file alone cannot tell;
    the head kept elsewhere can (and so can the Evidence Vault)."""
    path, head = tmp_path / "e.jsonl", tmp_path / "elsewhere" / "head.json"
    rec = Recorder(FileSink(path), agent_id="a", signing_key=key, checkpoint_every=2, on_checkpoint=HeadFile(head))
    with rec.run() as run:
        for i in range(5):
            run.note(str(i))
    rec.close()
    records = load(path)
    first_cp = next(i for i, r in enumerate(records) if r["kind"] == "checkpoint")
    dump(path, records[: first_cp + 1])
    assert verify_file(path, [pub]).ok  # the stated limit: alone, a cut file verifies
    assert "truncated" in errors(verify_file(path, [pub], head=json.loads(head.read_text())))


# B. Keys


def test_b1_rewrite_everything_with_your_own_key(evidence, pub):
    records = load(evidence)
    next(r for r in records if r.get("event_type") == "approval")["approvals"][0]["approver"] = "alice"
    dump(evidence, rewrite(records, generate_private_key()))
    assert "untrusted_key" in errors(verify_file(evidence, [pub]))


def test_b2_switch_to_your_own_key_half_way(evidence):
    """Re-sign only the last checkpoint with your own key. Even without a pinned key, a key
    change with no signed hand-over is an error."""
    records = load(evidence)
    assert records[-1]["kind"] == "checkpoint"
    signer = LocalSigner(generate_private_key())
    cp = records[-1]
    cp.update({"public_key": signer.public_key, "key_id": key_id(signer.public_key)})
    cp["signature"] = base64.b64encode(signer.sign(signing_payload(cp))).decode()
    cp.pop("record_hash")
    cp["record_hash"] = record_hash(cp)
    dump(evidence, records)
    assert "signer_changed" in errors(verify_file(evidence))


def test_b3_hand_over_to_your_own_key_with_a_key_you_made(tmp_path, pub):
    """A hand-over signed by an untrusted key vouches for nothing."""
    attacker, accomplice = generate_private_key(), generate_private_key()
    rec = Recorder(FileSink(tmp_path / "e.jsonl"), agent_id="a", signing_key=attacker, checkpoint_every=2)
    with rec.run() as run:
        run.note("x")
    rec.rotate_signer(accomplice)
    rec.close()
    assert "untrusted_key" in errors(verify_file(tmp_path / "e.jsonl", [pub]))


def test_b4_malleate_a_p256_signature(tmp_path):
    """(r, n - s) is a second valid ECDSA signature anyone can make. Only low-s is accepted."""
    key = generate_private_key(P256)
    path = record_demo(tmp_path / "e.jsonl", key)
    records = load(path)
    cp = next(r for r in records if r["kind"] == "checkpoint")
    sig = base64.b64decode(cp["signature"])
    high = sig[:32] + (P256_ORDER - int.from_bytes(sig[32:], "big")).to_bytes(32, "big")
    cp["signature"] = base64.b64encode(high).decode()
    cp.pop("record_hash")
    cp["record_hash"] = record_hash(cp)
    dump(path, rewrite(records))
    assert "signature" in errors(verify_file(path, [public_key_b64(key)]))


def test_b5_a_hijacked_agent_asks_the_signing_service_to_resign_history(tmp_path):
    """The key is in a service under another account. The attacker controls the agent, rewrites
    its file, and asks for the old checkpoints to be signed again: refused."""
    init_signer(tmp_path / "signer")
    server = SignerService(tmp_path / "signer").start("127.0.0.1:0")
    try:
        client = SignerClient(server.address, (tmp_path / "signer" / "signer.token").read_text().strip())
        path = tmp_path / "e.jsonl"
        rec = Recorder(FileSink(path), agent_id="a", signer=client, checkpoint_every=2)
        with rec.run() as run:
            run.note("the true story")
        rec.close()
        cp = next(r for r in load(path) if r["kind"] == "checkpoint")
        forged = {k: v for k, v in cp.items() if k not in ("signature", "record_hash")}
        forged["merkle_root"] = "sha256:" + "ab" * 32
        with pytest.raises(SignerError, match="only the next checkpoint"):
            client.sign(signing_payload(forged))
        with pytest.raises(SignerError, match="not JSON"):
            client.sign(b"anything else I would like signed")
        with pytest.raises(SignerError, match="only checkpoint"):
            client.sign(b'{"kind":"event","note":"sign this for me"}')
    finally:
        server.close()


def test_b6_the_key_is_not_in_the_agents_hands(tmp_path):
    """With a signing service, the agent's process holds a token, never the key."""
    signer = init_signer(tmp_path / "signer")
    server = SignerService(tmp_path / "signer").start("127.0.0.1:0")
    try:
        client = SignerClient(server.address, (tmp_path / "signer" / "signer.token").read_text().strip())
        assert not hasattr(client, "_key") and client.public_key == signer.public_key
    finally:
        server.close()


# C. Time


def test_c1_backdate_with_the_machine_clock(tmp_path, key, pub, monkeypatch):
    """A clock set a year back. Without an outside timestamp the file cannot tell; the signing
    service refuses a checkpoint far from its own clock."""
    real = mnestiq.recorder.now_ts
    monkeypatch.setattr(mnestiq.recorder, "now_ts", lambda: {**real(), "wall": "2025" + real()["wall"][4:]})
    init_signer(tmp_path / "signer")
    server = SignerService(tmp_path / "signer").start("127.0.0.1:0")
    try:
        client = SignerClient(server.address, (tmp_path / "signer" / "signer.token").read_text().strip())
        rec = Recorder(FileSink(tmp_path / "e.jsonl"), agent_id="a", signer=client, strict=True)
        with pytest.raises(SignerError, match="from this signer's clock"):
            rec.heartbeat()
    finally:
        server.close()


def test_c2_move_a_real_timestamp_to_another_checkpoint():
    """See test_timestamps.py::test_a_token_moved_to_another_checkpoint_is_an_error (real DigiCert
    and Sectigo tokens). Kept there, next to the recorded tokens."""
    pytest.importorskip("rfc3161_client")
    from test_timestamps import test_a_token_proves_only_its_own_signature

    test_a_token_proves_only_its_own_signature()


# D. Silence


def test_d1_stop_the_recorder_for_an_hour(tmp_path, key, pub, monkeypatch):
    path = tmp_path / "e.jsonl"
    rec = Recorder(FileSink(path), agent_id="a", signing_key=key, checkpoint_interval=300)
    rec.heartbeat()
    rec.close()
    real = mnestiq.recorder.now_ts
    later = time.time() + 3600

    def an_hour_later():
        ts = real()
        t = time.gmtime(later)
        return {**ts, "wall": time.strftime("%Y-%m-%dT%H:%M:%S", t) + ts["wall"][19:]}

    monkeypatch.setattr(mnestiq.recorder, "now_ts", an_hour_later)
    rec = Recorder(FileSink(path), agent_id="a", signing_key=key, checkpoint_interval=300)
    rec.heartbeat()
    rec.close()
    report = verify_file(path, [pub])
    assert report.ok and report.quiet and report.quiet[0]["seconds"] >= 3500


# E. The stated limit: lies told while in control


def test_e1_a_hijacked_agent_records_a_false_event(tmp_path, key, pub):
    """Evidence is tamper-evident after it is written, not truthful at the source. A false event
    written by a hijacked agent verifies. The answer is outside the file: the Workbench checks
    the agent's story against network logs it does not control."""
    rec = Recorder(FileSink(tmp_path / "e.jsonl"), agent_id="a", signing_key=key)
    with rec.run() as run:
        run.note("I only read the FAQ page")  # while really sending data elsewhere
    rec.close()
    assert verify_file(tmp_path / "e.jsonl", [pub]).ok


def test_canonical_bytes_are_what_is_signed():
    assert canonical_json({"b": 1, "a": [1.0, "é"]}) == '{"a":[1,"é"],"b":1}'.encode()


def test_the_break_it_kit_verifies():
    """examples/break-it, as published: valid with its key and head, and every timestamp checked."""
    from pathlib import Path

    kit = Path(__file__).resolve().parents[2] / "examples" / "break-it"
    head = json.loads((kit / "head.json").read_text("utf-8"))
    report = verify_file(kit / "evidence.jsonl", [(kit / "recorder.pub").read_text().strip()], head=head)
    assert report.ok and report.head_seq == head["seq"], report.errors
    try:
        import rfc3161_client  # noqa: F401
    except ImportError:
        return
    assert len(report.timestamps) == report.checkpoints and not report.warnings


def test_the_break_it_readme_lists_the_real_checksums():
    import hashlib
    from pathlib import Path

    kit = Path(__file__).resolve().parents[2] / "examples" / "break-it"
    readme = (kit / "README.md").read_text("utf-8")
    for name in ("recorder.pub", "head.json"):
        assert hashlib.sha256((kit / name).read_bytes()).hexdigest() in readme, name
