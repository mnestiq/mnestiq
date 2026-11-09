"""The fast fuzzing tier: a fixed set of mutated files on every run, and every saved case replayed.

MNESTIQ_FUZZ_FILES sets how many files (default 400). The long tier is tests/fuzz/run_long.py.
"""

import os
import shutil
from pathlib import Path

import pytest

from fuzz.dashboard_path import html
from fuzz.engine import Checker, _unexplained_not_evaluated, build_seeds, load_case, mutate, page_script, run_page_batch

from mnestiq.dashboard import EvidenceStore
from mnestiq.findings import NOT_EVALUATED

FILES = int(os.environ.get("MNESTIQ_FUZZ_FILES", "400"))
CORPUS = Path(__file__).parent / "fuzz" / "corpus"


@pytest.fixture(scope="module")
def seeds():
    return build_seeds()


def _describe(case, found):
    return (
        f"case {case.number} of {case.seed.name}, {case.trace}: {[(v.invariant, v.surface, v.detail) for v in found]}"
    )


@pytest.mark.parametrize(
    ("detail", "seq", "expected"),
    [
        ("llm_call context is incomplete: the call it builds on was not found", 6, False),
        ("llm_call output was not captured", 6, False),
        ("llm_call context is incomplete: the call it builds on was not found", 5, True),
        ("a field the rules need cannot be read", 6, True),
    ],
)
def test_only_an_unsigned_record_may_explain_not_evaluated(detail, seq, expected):
    parsed = [{"kind": "event", "seq": 4}, {"kind": "checkpoint", "seq": 5}, {"kind": "event", "seq": 6}]
    assert _unexplained_not_evaluated([{"rule": NOT_EVALUATED, "detail": detail, "seq": seq}], parsed) is expected


def test_every_seed_file_is_clean(seeds, tmp_path):
    checker = Checker(tmp_path)
    for seed in seeds:
        case = mutate.__globals__["Case"](seed, 0, seed.data, [], False, False)
        assert checker.check(case) == []
        assert seed.base_findings, "the seed must hold something for the rules to find"


def test_mutated_files_keep_every_promise(seeds, tmp_path):
    checker = Checker(tmp_path)
    broken = []
    for n in range(FILES):
        case = mutate(seeds[n % len(seeds)], n)
        found = checker.check(case)
        if found:
            broken.append(_describe(case, found))
    assert not broken, f"{len(broken)} of {FILES} files broke a promise. First: {broken[:3]}"


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_the_page_renders_every_payload(seeds, tmp_path):
    payloads, cases = [], []
    path = tmp_path / "e.jsonl"
    for n in range(min(FILES, 300)):
        case = mutate(seeds[n % len(seeds)], n)
        path.write_bytes(case.data)
        payloads.append(EvidenceStore(path, [case.seed.pub]).load(path).payload)
        cases.append(case)
    script = tmp_path / "page.js"
    script.write_text(page_script(html()), "utf-8")
    bad = run_page_batch(script, payloads, tmp_path)
    assert not bad, f"{len(bad)} payloads broke the page. First: {bad[:3]}"


@pytest.mark.parametrize("path", sorted(CORPUS.glob("*.json")), ids=lambda p: p.stem)
def test_a_saved_case_stays_fixed(path, tmp_path):
    case = load_case(path)
    found = Checker(tmp_path).check(case)
    assert not found, _describe(case, found)
