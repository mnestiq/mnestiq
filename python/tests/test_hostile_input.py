"""A hostile or damaged evidence file is reported, never a crash: every field of a valid file replaced
with values of the wrong type, through the verifier, context expansion and the detection rules."""

import copy
import json
from pathlib import Path

import pytest

from mnestiq.context import expanded
from mnestiq.findings import findings
from mnestiq.verify import verify_lines

VECTORS = Path(__file__).resolve().parents[2] / "spec" / "vectors"
PUB = json.loads((VECTORS / "expected.json").read_text("utf-8"))["trusted_key"]
BASE = [json.loads(line) for line in (VECTORS / "valid.jsonl").read_text("utf-8").splitlines()]
WRONG = (1.5, "0", [], {}, None, True, [1, "x"])


def _paths(obj, path=()):
    if path:
        yield path
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from _paths(v, (*path, k))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from _paths(v, (*path, i))


CASES = [(i, path) for i, rec in enumerate(BASE) for path in _paths(rec)]


@pytest.mark.parametrize(("index", "path"), CASES, ids=[f"{i}:{'.'.join(map(str, p))}" for i, p in CASES])
def test_a_field_of_the_wrong_type_is_reported_not_a_crash(index, path):
    for bad in WRONG:
        records = copy.deepcopy(BASE)
        parent = records[index]
        for step in path[:-1]:
            parent = parent[step]
        parent[path[-1]] = bad
        report = verify_lines([json.dumps(r) for r in records], [PUB])
        if path[-1] not in ("content", "arguments", "result"):  # replacing these is content, caught by digest
            assert not report.ok
        expanded(copy.deepcopy(records))
        findings(copy.deepcopy(records))
