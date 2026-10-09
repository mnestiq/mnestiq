"""RFC 3161 timestamps, checked against real DigiCert and Sectigo tokens recorded in tests/data.

The tokens were fetched once (see test data generation in the docstring of each test);
the tests themselves never leave this machine.
"""

import base64
import http.server
import threading
from pathlib import Path

import pytest

pytest.importorskip("rfc3161_client")

from cryptography import x509

from mnestiq import FileSink, Recorder, Timestamper, TimestampError, verify_file
from mnestiq.cli import main
from mnestiq.hashing import record_hash
from mnestiq.timestamps import default_roots, split_certificates, verify_token

from conftest import dump, load

DATA = Path(__file__).parent / "data"
EVIDENCE = DATA / "timestamped.jsonl"
PUB = (DATA / "timestamped.pub").read_text().strip()


def checkpoints():
    return [r for r in load(EVIDENCE) if r["kind"] == "checkpoint"]


def token_of(cp):
    return base64.b64decode(cp["timestamp_token"]), base64.b64decode(cp["signature"])


def test_real_tokens_verify_offline():
    report = verify_file(EVIDENCE, [PUB])
    assert report.ok, report.errors
    assert report.warnings == []
    assert [t["seq"] for t in report.timestamps] == [c["seq"] for c in checkpoints()]


def test_both_authorities_are_in_the_fixture():
    issuers = set()
    for cp in checkpoints():
        certs, _ = split_certificates(token_of(cp)[0])
        issuers |= {c.subject.rfc4514_string() for c in certs}
    assert any("DigiCert" in i for i in issuers) and any("Sectigo" in i for i in issuers)


def test_a_token_proves_only_its_own_signature():
    first, second = checkpoints()[:2]
    token, _ = token_of(first)
    with pytest.raises(TimestampError, match="Mismatch"):
        verify_token(token, token_of(second)[1], default_roots())


def test_a_token_moved_to_another_checkpoint_is_an_error(tmp_path):
    """Someone copies a genuine token onto a checkpoint it was never issued for."""
    records = load(EVIDENCE)
    cps = [r for r in records if r["kind"] == "checkpoint"]
    cps[1]["timestamp_token"] = cps[0]["timestamp_token"]
    _rehash_from(records, cps[1]["seq"])
    dump(tmp_path / "e.jsonl", records)
    report = verify_file(tmp_path / "e.jsonl", [PUB])
    assert "timestamp" in {i.code for i in report.errors}


def test_an_untrusted_root_is_refused(tmp_path):
    digicert_only = [c for c in default_roots() if "DigiCert" in c.subject.rfc4514_string()]
    report = verify_file(EVIDENCE, [PUB], tsa_roots=digicert_only)
    errors = [i for i in report.errors if i.code == "timestamp"]
    sectigo = [c for c in checkpoints()
               if any("Sectigo" in x.subject.rfc4514_string() for x in split_certificates(token_of(c)[0])[0])]
    assert sectigo and [i.seq for i in errors] == [c["seq"] for c in sectigo]  # DigiCert ones still verify
    assert len(report.timestamps) == len(checkpoints()) - len(sectigo)


def _with_certs(token, certs):
    """The token with its certificate list replaced, which the TSA's signature does not cover."""
    from cryptography.hazmat.primitives.serialization import Encoding

    from mnestiq.timestamps import _children, _der, _read

    _, bare = split_certificates(token)
    tag, body, _ = _read(bare, 0)
    oid, explicit = _children(body)[:2]
    _, inner, _ = _read(explicit, 0)
    _, signed_data, _ = _read(inner, 0)
    parts = _children(signed_data)
    listed = _der(0xA0, b"".join(c.public_bytes(Encoding.DER) for c in certs))
    signed = _der(0x30, b"".join(parts[:-1]) + listed + parts[-1])
    return _der(tag, oid + _der(explicit[0], signed))


def test_a_root_brought_by_the_token_is_not_trusted():
    """Certificates in a token are not signed by anyone: a self-signed one in there must not become
    a trust anchor. Here the token carries DigiCert's root while only Sectigo's is trusted."""
    digicert = next(c for c in checkpoints()
                    if any("DigiCert" in x.subject.rfc4514_string() for x in split_certificates(token_of(c)[0])[0]))
    token, signature = token_of(digicert)
    g4 = next(c for c in default_roots() if "DigiCert" in c.subject.rfc4514_string())
    sectigo_only = [c for c in default_roots() if "DigiCert" not in c.subject.rfc4514_string()]
    carried = _with_certs(token, split_certificates(token)[0] + [g4])
    assert verify_token(carried, signature, default_roots())  # still fine against the real roots
    with pytest.raises(TimestampError, match="does not chain to a trusted root"):
        verify_token(carried, signature, sectigo_only)


def test_a_self_signed_tsa_is_not_trusted():
    """A forger's own TSA certificate, self-signed with the time-stamping usage, is refused."""
    import datetime

    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    from mnestiq.timestamps import _chain_to_root

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Forged TSA")])
    start = datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc)
    forged = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
              .serial_number(1).not_valid_before(start).not_valid_after(start.replace(year=2040))
              .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.TIME_STAMPING]), critical=True)
              .sign(key, hashes.SHA256()))
    with pytest.raises(TimestampError, match="does not chain to a trusted root"):
        _chain_to_root(forged, [forged], default_roots(), start.replace(year=2026))


def test_a_changed_token_is_refused():
    token, signature = token_of(checkpoints()[0])
    _, bare = split_certificates(token)
    flipped = bytearray(bare)
    flipped[len(flipped) // 2] ^= 1  # inside the signed time-stamp info
    with pytest.raises(TimestampError):
        verify_token(bytes(flipped), signature, default_roots())


def test_split_keeps_what_the_tsa_signed():
    token, signature = token_of(checkpoints()[0])
    certs, bare = split_certificates(token)
    assert len(certs) >= 2 and len(bare) < len(token)
    assert all(isinstance(c, x509.Certificate) for c in certs)
    assert verify_token(token, signature, default_roots())


def test_cli_shows_the_proven_time(capsys):
    assert main(["verify", str(EVIDENCE), "--trusted-key", PUB]) == 0
    assert "timestamped by an outside authority" in capsys.readouterr().out


def test_cli_tsa_root_option(tmp_path, capsys):
    pem = tmp_path / "roots.pem"
    pem.write_bytes((Path(__file__).parents[1] / "src" / "mnestiq" / "tsa_roots.pem").read_bytes())
    assert main(["verify", str(EVIDENCE), "--trusted-key", PUB, "--tsa-root", str(pem)]) == 0


class _Answer(http.server.BaseHTTPRequestHandler):
    body = b""
    status = 200

    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", 0)))
        self.send_response(self.status)
        self.end_headers()
        self.wfile.write(self.body)

    def log_message(self, *args):
        pass


@pytest.fixture
def tsa():
    servers = []

    def make(status, body):
        handler = type("H", (_Answer,), {"status": status, "body": body})
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        servers.append(server)
        return f"http://127.0.0.1:{server.server_port}/"

    yield make
    for s in servers:
        s.shutdown()


def test_timestamper_tries_each_authority_then_gives_up(tsa):
    down, garbage = tsa(500, b"busy"), tsa(200, b"\x30\x03\x02\x01\x02")  # status 2: rejection
    with pytest.raises(TimestampError) as err:
        Timestamper([down, garbage], timeout=5)(b"s" * 64)
    assert down in str(err.value) and garbage in str(err.value)


def test_a_replayed_answer_is_refused(tsa):
    """An answer for another request (old nonce, other signature) is not accepted."""
    cp = checkpoints()[0]
    token = base64.b64decode(cp["timestamp_token"])
    replay = tsa(200, _response(token))
    with pytest.raises(TimestampError):
        Timestamper([replay], timeout=5)(base64.b64decode(cp["signature"]))


def test_no_authority_means_no_token_but_a_signed_checkpoint(tmp_path, tsa, key, pub, caplog):
    rec = Recorder(FileSink(tmp_path / "e.jsonl"), agent_id="a", signing_key=key,
                   timestamper=Timestamper([tsa(503, b"")], timeout=5))
    with rec.run() as run:
        run.note("x")
    rec.close()
    cp = next(r for r in load(tmp_path / "e.jsonl") if r["kind"] == "checkpoint")
    assert "timestamp_token" not in cp
    assert verify_file(tmp_path / "e.jsonl", [pub]).ok
    assert "timestamping failed" in caplog.text


def _response(token):
    from mnestiq.timestamps import _der

    return _der(0x30, _der(0x30, b"\x02\x01\x00") + token)


def _rehash_from(records, seq):
    prev = records[seq - 1]["record_hash"] if seq else records[0]["prev_hash"]
    for r in records[seq:]:
        r["prev_hash"] = prev
        r.pop("record_hash", None)
        r["record_hash"] = record_hash(r)
        prev = r["record_hash"]


def test_without_the_library_tokens_are_reported_unchecked(monkeypatch):
    import mnestiq.timestamps

    def missing():
        raise TimestampError("timestamps need: pip install mnestiq[timestamps]")

    monkeypatch.setattr(mnestiq.timestamps, "_rfc3161", missing)
    report = verify_file(EVIDENCE, [PUB])
    assert report.ok and "timestamp_unverified" in {w.code for w in report.warnings}
