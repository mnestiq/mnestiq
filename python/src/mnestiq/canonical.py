"""Canonical JSON serialization (RFC 8785 / JCS).

Every hash in the evidence format is computed over canonical bytes, so two
implementations in different languages must serialize identically. JCS gives us
that: object keys sorted by UTF-16 code units, no insignificant whitespace,
ECMAScript number formatting, and JSON.stringify string escaping.
"""

from __future__ import annotations

import json
import math
import re
from decimal import Decimal
from typing import Any

# Integers outside this range cannot round-trip through an IEEE-754 double,
# which is what JCS (and every JavaScript verifier) uses for numbers.
MAX_SAFE_INTEGER = 2**53 - 1

# How deep a value may be nested. The outermost value is level 1, and every object or array inside another
# adds one level. Text, numbers, true, false and null add none. Level 128 is read, level 129 is refused.
MAX_DEPTH = 128


class CanonicalizationError(ValueError):
    pass


class RefusedJSON(CanonicalizationError):
    """JSON that parses, and that this format does not accept: a value nested past ``MAX_DEPTH``, or a large
    whole number that is not written the way canonical JSON writes it."""


def parse_json(data: str | bytes) -> Any:
    """Parse JSON as every verifier must: no duplicate keys, no NaN or Infinity, nothing nested deeper than
    ``MAX_DEPTH``, and one spelling for a whole number past 2^53 - 1.

    Python's ``json.loads`` keeps the last of two equal keys, other parsers keep the first,
    and it accepts ``NaN``. Either would let one evidence line mean two different things to
    two verifiers, so both are refused. How deep a parser can go differs between languages and
    between versions of Python, so the limit is counted here and is the same everywhere.
    """
    if isinstance(data, bytes):  # json.loads would guess: UTF-16 or a BOM must not read here and fail in the verifier
        data = data.decode("utf-8")
    if nested_too_deep(data):
        raise RefusedJSON(f"a value is nested more than {MAX_DEPTH} levels deep")
    return json.loads(data, object_pairs_hook=_no_duplicates, parse_constant=_no_constant, parse_int=_number,
                      parse_float=_float)


# A whole string, which may hold brackets of its own and may be cut off, or one bracket. The closing quote is
# optional so that text with no end to a string is passed over once, not once for every quote in it.
_STRUCTURE = re.compile(r'"[^"\\]*(?:\\.[^"\\]*)*"?|[\[\]{}]', re.DOTALL)


def nested_too_deep(text: str) -> bool:
    """Whether JSON text holds a value nested more than ``MAX_DEPTH`` levels deep. Counted on the text, by this
    code alone, before any parser sees it. For text that is not JSON the answer does not matter: the parser
    refuses it."""
    if text.count("[") + text.count("{") <= MAX_DEPTH:  # nearly every line: too few brackets to get there
        return False
    depth = 0
    for match in _STRUCTURE.finditer(text):
        token = match.group()
        if token in ("[", "{"):
            depth += 1
            if depth > MAX_DEPTH:
                return True
        elif token in ("]", "}"):
            depth -= 1
    return False


class MinusZero(int):
    """The integer 0 as read from the text ``-0``. It is 0 to everything that computes, compares or writes with it,
    and canonical JSON writes it ``0``, so no hash can tell the two apart. The schema check can: a field typed as
    an integer has one spelling for each integer, and refuses this one."""

    __slots__ = ()

    def __repr__(self) -> str:
        return "-0"


MINUS_ZERO = MinusZero(0)

_MAX_PLAIN_DIGITS = 21  # canonical JSON writes a number of 1e21 or more with an exponent, never as digits alone


def _number(text: str) -> int | float:
    """Integers past 2^53 - 1 read as doubles, as in JavaScript. JCS writes a large whole-number
    double such as 3e18 as ``3000000000000000000``, which must read back as that double.

    Many integer texts read as the same double: ``9007199254740993`` is 2^53 to this parser and another
    number to one with exact integers. Past 2^53 - 1 only the text canonical JSON writes for the double is
    accepted, so a number has one spelling there and every reader gets the value that was hashed."""
    if len(text) <= 15:  # too short to be past 2^53 - 1
        return MINUS_ZERO if text == "-0" else int(text)
    if len(text.lstrip("-")) > _MAX_PLAIN_DIGITS:  # also keeps int() away from text of any length
        raise RefusedJSON(f"the whole number {text[:24]}... is not written as canonical JSON writes a number "
                          "of that size")
    value = int(text)
    if abs(value) <= MAX_SAFE_INTEGER:
        return value
    as_float = float(text)
    spelling = _format_number(as_float)
    if spelling != text:
        raise RefusedJSON(f"the whole number {text} is past 2^53 - 1 and is not written as canonical JSON "
                          f"writes the number it is read as ({spelling})")
    return as_float


def _float(text: str) -> float:
    value = float(text)
    if math.isinf(value):  # 1e999: JSON can spell it, and nothing can hash or send it on
        raise CanonicalizationError(f"number {text[:20]} is too large for JSON")
    return value


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
        try:
            ordered = sorted(value, key=lambda k: k.encode("utf-16-be"))
        except UnicodeEncodeError as exc:  # a lone surrogate in a key
            raise CanonicalizationError(f"object key is not valid Unicode: {exc}") from exc
        out.append("{")
        for i, key in enumerate(ordered):
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
