import json
import math
import random
import shutil
import struct
import subprocess

import pytest

from mnestiq import verify_file
from mnestiq.canonical import CanonicalizationError, canonical_json, parse_json

from conftest import record_demo


@pytest.mark.parametrize(
    "value, expected",
    [
        (0.002, "0.002"),
        (1e-6, "0.000001"),
        (1e-7, "1e-7"),
        (4.5, "4.5"),
        (123.456, "123.456"),
        (-0.0, "0"),
        (1e16, "10000000000000000"),
        (1e20, "100000000000000000000"),
        (1e21, "1e+21"),
        (333333333.3333333, "333333333.3333333"),
        (5e-324, "5e-324"),
        (1.7976931348623157e308, "1.7976931348623157e+308"),
        (-1.5e-10, "-1.5e-10"),
    ],
)
def test_numbers_match_ecmascript(value, expected):
    assert canonical_json(value).decode() == expected


def test_rfc8785_key_ordering_uses_utf16_code_units():
    # Example from RFC 8785 section 3.2.3: the emoji (a surrogate pair in UTF-16)
    # sorts before U+FB33, unlike plain code point order.
    obj = {
        "\u20ac": "Euro Sign",
        "\r": "Carriage Return",
        "\ufb33": "Hebrew Letter Dalet With Dagesh",
        "1": "One",
        "\U0001F600": "Emoji: Grinning Face",
        "\u0080": "Control",
        "\u00f6": "Latin Small Letter O With Diaeresis",
    }
    out = canonical_json(obj).decode()
    order = ["\\r", "1", "\u0080", "\u00f6", "\u20ac", "\U0001F600", "\ufb33"]
    positions = [out.index(f'"{k}":') for k in order]
    assert positions == sorted(positions)


def test_whitespace_and_escaping():
    assert canonical_json({"b": [1, True, None], "a": "x\u000fy\n"}) == b'{"a":"x\\u000fy\\n","b":[1,true,null]}'


@pytest.mark.parametrize("bad", [float("nan"), float("inf"), 2**53, {1: "x"}, object()])
def test_rejects_non_interoperable_values(bad):
    with pytest.raises(CanonicalizationError):
        canonical_json(bad)


# RFC 8785, Appendix B: IEEE-754 bit patterns and their canonical text.
RFC8785_NUMBERS = [
    ("0000000000000000", "0"),
    ("8000000000000000", "0"),
    ("0000000000000001", "5e-324"),
    ("8000000000000001", "-5e-324"),
    ("7fefffffffffffff", "1.7976931348623157e+308"),
    ("ffefffffffffffff", "-1.7976931348623157e+308"),
    ("4340000000000000", "9007199254740992"),
    ("c340000000000000", "-9007199254740992"),
    ("4430000000000000", "295147905179352830000"),
    ("44b52d02c7e14af5", "9.999999999999997e+22"),
    ("44b52d02c7e14af6", "1e+23"),
    ("44b52d02c7e14af7", "1.0000000000000001e+23"),
    ("444b1ae4d6e2ef4e", "999999999999999700000"),
    ("444b1ae4d6e2ef4f", "999999999999999900000"),
    ("444b1ae4d6e2ef50", "1e+21"),
    ("3eb0c6f7a0b5ed8c", "9.999999999999997e-7"),
    ("3eb0c6f7a0b5ed8d", "0.000001"),
    ("41b3de4355555553", "333333333.3333332"),
    ("41b3de4355555554", "333333333.33333325"),
    ("41b3de4355555555", "333333333.3333333"),
    ("41b3de4355555556", "333333333.3333334"),
    ("41b3de4355555557", "333333333.33333343"),
    ("becbf647612f3696", "-0.0000033333333333333333"),
    ("43143ff3c1cb0959", "1424953923781206.2"),
]


@pytest.mark.parametrize("bits, expected", RFC8785_NUMBERS)
def test_rfc8785_appendix_b_numbers(bits, expected):
    value = struct.unpack(">d", bytes.fromhex(bits))[0]
    assert canonical_json(value).decode() == expected


@pytest.mark.parametrize("bits", ["7fffffffffffffff", "7ff0000000000000", "fff0000000000000"])
def test_rfc8785_appendix_b_invalid_numbers(bits):
    with pytest.raises(CanonicalizationError):
        canonical_json(struct.unpack(">d", bytes.fromhex(bits))[0])


def test_rfc8785_section_3_2_2_example():
    # Input and output exactly as printed in RFC 8785, section 3.2.2.
    text = r"""{"numbers": [333333333.33333329, 1E30, 4.50, 2e-3, 0.000000000000000000000000001], "string": "\u20ac$\u000F\u000aA'\u0042\u0022\u005c\\\"\/", "literals": [null, true, false]}"""  # noqa: E501 (verbatim from the RFC)
    expected = r"""{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"\u20ac$\u000f\nA'B\"\\\\\"/"}""".replace(r"\u20ac", "\u20ac")  # noqa: E501 (verbatim from the RFC)
    assert canonical_json(parse_json(text)).decode("utf-8") == expected


def test_large_whole_number_doubles_survive_a_round_trip():
    for value in (2987532083918071300.0, 1e20, -9.007199254740994e15):
        text = canonical_json(value)
        assert b"e" not in text and b"." not in text
        assert canonical_json(parse_json(text)) == text


# Reading evidence: one line, one meaning.


@pytest.mark.parametrize("text", ['{"a": 1, "a": 2}', '{"x": {"b": 1, "b": 1}}', '[{"k": 0}, {"k": 0, "k": 0}]'])
def test_duplicate_keys_are_refused(text):
    with pytest.raises(CanonicalizationError, match="duplicate key"):
        parse_json(text)


@pytest.mark.parametrize("text", ["NaN", "[Infinity]", '{"a": -Infinity}'])
def test_nan_and_infinity_are_refused(text):
    with pytest.raises(CanonicalizationError):
        parse_json(text)


def test_a_line_with_a_duplicate_key_fails_verification(tmp_path, key, pub):
    """Python keeps the last of two equal keys, JavaScript too, other parsers the first: a
    reader keeping the first would see agent "evil" in a record whose hash still checks out."""
    path = record_demo(tmp_path / "e.jsonl", key)
    lines = path.read_bytes().splitlines()
    lines[1] = b'{"agent_id":"evil",' + lines[1][1:]
    path.write_bytes(b"\n".join(lines) + b"\n")
    report = verify_file(path, [pub])
    assert not report.ok and "parse" in {i.code for i in report.errors}


# Fuzz: random values, and a second implementation to compare with.


def _random_string(rng):
    pools = ["abcXYZ019 ", "\x00\x01\x1f\x7f\"\\/\n\t", "\u00e9\u20ac\u0430\u4e2d\ufb33\uffff", "\U0001F600\U00010000"]
    return "".join(rng.choice(rng.choice(pools)) for _ in range(rng.randint(0, 8)))


def _random_float(rng):
    while True:
        x = struct.unpack(">d", rng.getrandbits(64).to_bytes(8, "big"))[0]
        if math.isfinite(x):
            return x if rng.random() < 0.7 else round(x, rng.randint(0, 6)) if abs(x) < 1e15 else x


def _random_value(rng, depth=0):
    kind = rng.randint(0, 7 if depth < 4 else 4)
    if kind == 0:
        return rng.choice([None, True, False])
    if kind == 1:
        return rng.randint(-(2**53 - 1), 2**53 - 1) if rng.random() < 0.5 else rng.randint(-1000, 1000)
    if kind in (2, 3):
        return _random_float(rng)
    if kind == 4:
        return _random_string(rng)
    if kind in (5, 6):
        return {_random_string(rng): _random_value(rng, depth + 1) for _ in range(rng.randint(0, 5))}
    return [_random_value(rng, depth + 1) for _ in range(rng.randint(0, 5))]


def test_fuzz_round_trip_is_stable():
    rng = random.Random(8785)
    for _ in range(3000):
        value = _random_value(rng)
        once = canonical_json(value)
        assert canonical_json(parse_json(once)) == once
        assert parse_json(once) == json.loads(json.dumps(value))  # same value, different spelling


# The reference implementation from RFC 8785 section 3.2: JavaScript sorts strings by UTF-16
# code units and formats numbers with Number.prototype.toString, which JCS is defined by.
_JS_JCS = r"""
const jcs = (v) => Array.isArray(v) ? "[" + v.map(jcs).join(",") + "]"
  : v !== null && typeof v === "object"
    ? "{" + Object.keys(v).sort().map((k) => JSON.stringify(k) + ":" + jcs(v[k])).join(",") + "}"
    : JSON.stringify(v);
let input = "";
process.stdin.on("data", (d) => input += d);
process.stdin.on("end", () => process.stdout.write(JSON.stringify(JSON.parse(input).map(jcs))));
"""


@pytest.mark.skipif(shutil.which("node") is None, reason="Node.js not installed")
def test_fuzz_matches_the_javascript_reference():
    rng = random.Random(3339)
    values = [_random_value(rng) for _ in range(3000)] + [_random_float(rng) for _ in range(5000)]
    out = subprocess.run(["node", "-e", _JS_JCS], input=json.dumps(values), capture_output=True,
                         text=True, encoding="utf-8", check=True, timeout=120).stdout
    expected = json.loads(out)
    mismatches = [(v, e, canonical_json(v).decode()) for v, e in zip(values, expected, strict=True)
                  if canonical_json(v).decode() != e]
    assert not mismatches, mismatches[:3]
