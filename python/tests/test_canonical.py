import pytest

from mnestiq.canonical import CanonicalizationError, canonical_json


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
