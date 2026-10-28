"""The published test vectors (spec/vectors) are up to date and get the verdicts they promise."""

import importlib.util
import json
from pathlib import Path

import pytest

from mnestiq.verify import verify_file

VECTORS = Path(__file__).resolve().parents[2] / "spec" / "vectors"
if not (VECTORS / "expected.json").exists():  # the source package on PyPI has no spec folder
    pytest.skip("needs spec/vectors from the repository", allow_module_level=True)
EXPECTED = json.loads((VECTORS / "expected.json").read_text("utf-8"))


def _generator():
    spec = importlib.util.spec_from_file_location("vectors_generate", VECTORS / "generate.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_files_match_what_the_generator_writes():
    for name, data in _generator().build().items():
        assert (VECTORS / name).read_bytes() == data, f"{name} is out of date: run spec/vectors/generate.py"


@pytest.mark.parametrize("name", sorted(EXPECTED["vectors"]))
def test_each_vector_gets_its_verdict(name):
    want = EXPECTED["vectors"][name]
    report = verify_file(VECTORS / name, [EXPECTED["trusted_key"]])
    assert report.ok is want["ok"]
    assert sorted({i.code for i in report.errors}) == want["errors"]
    assert sorted({i.code for i in report.warnings}) == want["warnings"]
