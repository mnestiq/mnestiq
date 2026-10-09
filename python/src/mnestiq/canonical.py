"""Canonical JSON serialization (RFC 8785 / JCS).

Every hash in the evidence format is computed over canonical bytes, so two
implementations in different languages must serialize identically. JCS gives us
that: object keys sorted by UTF-16 code units, no insignificant whitespace,
ECMAScript number formatting, and JSON.stringify string escaping.
"""

from __future__ import annotations

import json
import math
from decimal import Decimal
from typing import Any

# Integers outside this range cannot round-trip through an IEEE-754 double,
# which is what JCS (and every JavaScript verifier) uses for numbers.
MAX_SAFE_INTEGER = 2**53 - 1


class CanonicalizationError(ValueError):
    pass


def parse_json(data: str | bytes) -> Any:
    """Parse JSON as every verifier must: no duplicate keys, no NaN or Infinity.

    Python's ``json.loads`` keeps the last of two equal keys, other parsers keep the first,
    and it accepts ``NaN``. Either would let one evidence line mean two different things to
    two verifiers, so both are refused.
    """
    return json.loads(data, object_pairs_hook=_no_duplicates, parse_constant=_no_constant, parse_int=_number)


def _number(text: str) -> int | float:
    """Integers past 2^53 read as doubles, as in JavaScript. JCS writes a large whole-number
    double such as 3e18 as ``3000000000000000000``, which must read back as that double."""
    value = int(text)
    if abs(value) <= MAX_SAFE_INTEGER:
        return value
    as_float = float(text)
    if math.isinf(as_float):
        raise CanonicalizationError(f"number {text[:20]}... is too large for JSON")
    return as_float


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict:
    obj = dict(pairs)
    if len(obj) != len(pairs):
        seen: set[str] = set()
        dup = next(k for k, _ in pairs if k in seen or seen.add(k))  # type: ignore[func-returns-value]
        raise CanonicalizationError(f"duplicate key {dup!r} in a JSON object")
    return obj


def _no_constant(name: str) -> Any:
    raise CanonicalizationError(f"{name} is not valid JSON")


def canonical_json(value: Any) -> bytes:
    """Return the RFC 8785 canonical UTF-8 encoding of ``value``."""
    parts: list[str] = []
    _write(value, parts)
    try:
        return "".join(parts).encode("utf-8")
    except UnicodeEncodeError as exc:  # lone surrogates
        raise CanonicalizationError(f"string is not valid Unicode: {exc}") from exc


def _write(value: Any, out: list[str]) -> None:
    if value is None:
        out.append("null")
    elif value is True:
        out.append("true")
    elif value is False:
        out.append("false")
    elif isinstance(value, int):
        if abs(value) > MAX_SAFE_INTEGER:
            raise CanonicalizationError(
                f"integer {value} exceeds 2^53-1; encode it as a string instead"
            )
        out.append(str(int(value)))  # int(): a subclass (IntEnum, numpy) may print itself otherwise
    elif isinstance(value, float):
        out.append(_format_number(float(value)))
    elif isinstance(value, str):
        out.append(json.dumps(value, ensure_ascii=False))
    elif isinstance(value, (list, tuple)):
        out.append("[")
        for i, item in enumerate(value):
            if i:
                out.append(",")
            _write(item, out)
        out.append("]")
    elif isinstance(value, dict):
        for key in value:
            if not isinstance(key, str):
                raise CanonicalizationError(f"object keys must be strings, got {key!r}")
        out.append("{")
        for i, key in enumerate(sorted(value, key=lambda k: k.encode("utf-16-be"))):
            if i:
                out.append(",")
            out.append(json.dumps(key, ensure_ascii=False))
            out.append(":")
            _write(value[key], out)
        out.append("}")
    else:
        raise CanonicalizationError(f"type {type(value).__name__} is not JSON-serializable")


def _format_number(x: float) -> str:
    """Format a double the way ECMAScript Number.prototype.toString does."""
    if math.isnan(x) or math.isinf(x):
        raise CanonicalizationError("NaN and Infinity are not valid JSON")
    if x == 0:
        return "0"  # also covers -0.0
    sign = "-" if x < 0 else ""
    # repr() yields the shortest round-tripping digits, same as ECMAScript.
    _, digit_tuple, exp = Decimal(repr(abs(x))).as_tuple()
    assert isinstance(exp, int)  # NaN / Infinity were rejected above
    exponent = exp
    digits = "".join(map(str, digit_tuple)).rstrip("0")
    exponent += len("".join(map(str, digit_tuple))) - len(digits)
    k = len(digits)
    n = exponent + k  # value == 0.digits * 10^n
    if k <= n <= 21:
        body = digits + "0" * (n - k)
    elif 0 < n <= 21:
        body = digits[:n] + "." + digits[n:]
    elif -6 < n <= 0:
        body = "0." + "0" * (-n) + digits
    else:
        e = n - 1
        mantissa = digits if k == 1 else digits[0] + "." + digits[1:]
        body = f"{mantissa}e{'+' if e > 0 else '-'}{abs(e)}"
    return sign + body
