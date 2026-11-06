"""Byte-level interoperability controls for the public canonicalizer."""
from __future__ import annotations

import hashlib

import pytest

from wcm import canonical_hash, canonicalize


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (0.0, b"0"),
        (-0.0, b"0"),
        (1.0, b"1"),
        (1e-7, b"1e-7"),
        (-1e-7, b"-1e-7"),
        (1e-6, b"0.000001"),
        (-1e-6, b"-0.000001"),
        (1e16, b"10000000000000000"),
        (1e20, b"100000000000000000000"),
        (1e21, b"1e+21"),
        (1.2345678901234567, b"1.2345678901234567"),
        (5e-324, b"5e-324"),
        (1.7976931348623157e308, b"1.7976931348623157e+308"),
    ],
)
def test_ecmascript_number_byte_forms(value, expected):
    assert canonicalize(value) == expected
    assert canonicalize({"v": value}) == b'{"v":' + expected + b"}"


@pytest.mark.parametrize("text", ["\x7f", "\x80", "\x9f", "\u2028", "\u2029"])
def test_nfc_characters_outside_json_control_range_are_literal(text):
    literal = text.encode("utf-8")
    assert canonicalize(text) == b'"' + literal + b'"'
    assert canonicalize({text: text}) == b'{"' + literal + b'":"' + literal + b'"}'


def test_existing_projection_nfc_and_json_escape_contracts_are_preserved():
    assert canonicalize({"n": None, "v": "plain"}) == b'{"v":"plain"}'
    assert canonicalize({"n": None}, exclude_none=False) == b'{"n":null}'
    assert canonicalize('\x00\n\t"\\') == b'"\\u0000\\n\\t\\"\\\\"'
    with pytest.raises(ValueError, match="not NFC"):
        canonicalize("e\u0301")


def test_public_hash_uses_interoperable_nested_bytes():
    expected = '{"s":"\u2028","v":0.000001}'.encode()
    assert canonical_hash({"v": 1e-6, "s": "\u2028"}) == (
        "sha256:" + hashlib.sha256(expected).hexdigest()
    )
