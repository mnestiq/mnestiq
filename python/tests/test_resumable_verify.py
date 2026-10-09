"""ChainVerifier: lines fed in parts give exactly the report of verify_lines over all of them, so a
collector following a growing file checks only what is new."""

import json
from dataclasses import asdict
from pathlib import Path

import pytest

from mnestiq import FileSink, HeadFile, Recorder
from mnestiq.keys import generate_private_key, public_key_b64
from mnestiq.verify import ChainVerifier, verify_lines

KEY = generate_private_key()
NEXT = generate_private_key()


def _chain(path: Path, rotate: bool = False, heartbeat: bool = False) -> list[bytes]:
    rec = Recorder(FileSink(path), agent_id="bot", signing_key=KEY, checkpoint_every=7,
                   on_checkpoint=HeadFile(path.with_suffix(".head.json")))
    for n in range(40):
        with rec.run(run_id=f"r{n}") as run:
            run.note(f"step {n}")
        if heartbeat and n == 10:
            rec.heartbeat()
        if rotate and n == 20:
            rec.rotate_signer(NEXT)
    rec.close()
    return path.read_bytes().splitlines(keepends=True)


def _tampered(lines: list[bytes]) -> list[bytes]:
    rec = json.loads(lines[12])
    rec["attributes"] = {"message": "edited"}
    return [*lines[:12], json.dumps(rec).encode() + b"\n", *lines[13:]]


def _same(lines: list[bytes], cuts: list[int], keys: list[str], head: dict | None = None) -> None:
    whole = verify_lines(lines, keys, head)
    verifier = ChainVerifier(keys)
    start = 0
    for cut in [*cuts, len(lines)]:
        verifier.feed(lines[start:cut])
        start = cut
        verifier.result(head)  # asking in between changes nothing
    assert asdict(verifier.result(head)) == asdict(whole)


@pytest.mark.parametrize("kind", ["plain", "rotate", "heartbeat", "tampered", "cut", "garbage"])
@pytest.mark.parametrize("pinned", [True, False])
def test_feeding_in_parts_gives_the_same_report(tmp_path, kind, pinned):
    lines = _chain(tmp_path / "e.jsonl", rotate=kind == "rotate", heartbeat=kind == "heartbeat")
    if kind == "tampered":
        lines = _tampered(lines)
    elif kind == "cut":
        lines = lines[:25]
    elif kind == "garbage":
        lines = [*lines[:5], b"not json\n", b"\n", b"[1, 2]\n", *lines[5:]]
    keys = [public_key_b64(KEY)] if pinned else []
    head = json.loads((tmp_path / "e.head.json").read_text())
    for cuts in ([], [1], [3, 9, 10, 30], list(range(1, len(lines)))):
        _same(lines, cuts, keys)
        _same(lines, cuts, keys, head)


def test_a_result_is_a_copy(tmp_path):
    lines = _chain(tmp_path / "e.jsonl")
    verifier = ChainVerifier([public_key_b64(KEY)])
    verifier.feed(lines[:10])
    early = verifier.result()
    early.errors.append(None)  # type: ignore[arg-type]
    verifier.feed(lines[10:])
    assert verifier.result().ok
