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


def test_escape_codes_in_evidence_are_not_sent_to_the_terminal(tmp_path, capsys):
    """A forged file whose chain_id holds terminal escapes could move the cursor up and redraw the
    INVALID line as VALID."""
    import json

    from mnestiq import FileSink, Recorder

    path = tmp_path / "e.jsonl"
    rec = Recorder(FileSink(path), agent_id="a")
    with rec.run():
        pass
    rec.close()
    lines = [json.loads(line) for line in path.read_text().splitlines()]
    lines[0]["chain_id"] = "x\x1b[1A\x1b[2K\rVALID  forged.jsonl"
    path.write_text("".join(json.dumps(r) + "\n" for r in lines))
    main(["verify", str(path)])
    main(["inspect", str(path)])
    out = capsys.readouterr().out
    assert "\x1b" not in out and out.startswith("INVALID")


def test_a_redacted_file_says_so_when_verified(tmp_path, key, pub):
    """A selective redaction verifies, by design. It used to say nothing, though the detection rules
    can no longer see the content that was removed."""
    from mnestiq import verify_file

    src = record_demo(tmp_path / "e.jsonl", key)
    assert main(["redact", str(src), str(tmp_path / "r.jsonl")]) == 0
    report = verify_file(tmp_path / "r.jsonl", [pub])
    assert report.ok and "redacted" in {w.code for w in report.warnings}
    assert "redacted" not in {w.code for w in verify_file(src, [pub]).warnings}
