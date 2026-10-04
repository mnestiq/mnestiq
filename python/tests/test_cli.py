import json

from mnestiq.cli import main

from conftest import record_demo


def test_keygen_verify_redact_inspect(tmp_path, capsys):
    assert main(["keygen", "--out", str(tmp_path / "keys")]) == 0
    from mnestiq.keys import load_private_key

    key = load_private_key(tmp_path / "keys" / "signing.key")
    path = record_demo(tmp_path / "e.jsonl", key)
    pub = str(tmp_path / "keys" / "signing.pub")

    assert main(["verify", str(path), "--trusted-key", pub]) == 0
    assert "VALID" in capsys.readouterr().out

    assert main(["verify", str(path), "--trusted-key", pub, "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["ok"] is True

    out = tmp_path / "redacted.jsonl"
    assert main(["redact", str(path), str(out)]) == 0
    assert main(["verify", str(out), "--trusted-key", pub]) == 0
    capsys.readouterr()

    assert main(["inspect", str(path)]) == 0
    timeline = capsys.readouterr().out
    assert "result_source=web" in timeline and "checkpoint" in timeline


def test_verify_exit_code_on_tamper(tmp_path, key, capsys):
    path = record_demo(tmp_path / "e.jsonl", key)
    path.write_text(path.read_text("utf-8").replace("auto-approve-email", "human-approved"), "utf-8")
    assert main(["verify", str(path)]) == 1
    assert "INVALID" in capsys.readouterr().out


def test_keygen_refuses_overwrite(tmp_path, capsys):
    assert main(["keygen", "--out", str(tmp_path)]) == 0
    assert main(["keygen", "--out", str(tmp_path)]) == 2
