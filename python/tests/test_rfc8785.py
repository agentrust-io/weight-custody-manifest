"""RFC 8785 (JCS) conformance for the canonicalizer.

The signing pre-image is RFC 8785 canonical JSON, and the family's interop claim
("a manifest signed by one tool verifies under another") rests on it. These
check the structural rules WCM relies on: UTF-16 key ordering, string escaping,
NFC normalization, and primitive formatting.

Scope note: full ECMAScript number canonicalization (RFC 8785 section 3.2.2.3)
is NOT claimed — manifests are float-free (hashes/enums/ints/strings), and the
canonicalizer rejects NaN/Infinity. Simple integer-valued and short decimal
floats are handled; the pathological float suite is out of scope.
"""
from __future__ import annotations

from wcm import canonicalize


def test_key_ordering_bmp():
    # BMP keys: UTF-16 order == code-point order.
    assert canonicalize({"b": 1, "a": 2, "c": 3}) == b'{"a":2,"b":1,"c":3}'


def test_key_ordering_utf16_code_units():
    # RFC 8785 section 3.2.3: sort by UTF-16 code units, not code points. The
    # emoji U+1F600 has lead surrogate 0xD83D, which is < 0xE000, so it MUST
    # sort before a U+E000 key -- the opposite of code-point order.
    emoji = "\U0001F600"
    bmp = ""
    out = canonicalize({emoji: 1, bmp: 2}).decode()
    assert out.index(":1") < out.index(":2"), "emoji key (0xD83D…) must precede U+E000"


def test_string_escaping():
    # Control chars use short escapes / \\uXXXX; forward slash is NOT escaped.
    assert canonicalize("\n\t\b\f\r") == b'"\\n\\t\\b\\f\\r"'
    assert canonicalize("a/b") == b'"a/b"'
    assert canonicalize('"\\') == b'"\\"\\\\"'
    assert canonicalize("\x00") == b'"\\u0000"'


def test_nfc_normalization():
    # NFC: precomposed e-acute (U+00E9) and decomposed (e + U+0301) canonicalize
    # to identical bytes.
    assert canonicalize("é") == canonicalize("é")


def test_primitives():
    assert canonicalize(True) == b"true"
    assert canonicalize(False) == b"false"
    assert canonicalize(None, exclude_none=False) == b"null"
    assert canonicalize(0) == b"0"
    assert canonicalize(-42) == b"-42"
    assert canonicalize(1.0) == b"1"  # integer-valued float -> no decimal point


def test_nested_and_arrays():
    obj = {"z": [3, 2, 1], "a": {"y": 1, "x": 2}}
    assert canonicalize(obj) == b'{"a":{"x":2,"y":1},"z":[3,2,1]}'


def test_no_insignificant_whitespace():
    assert canonicalize({"a": 1, "b": [1, 2]}) == b'{"a":1,"b":[1,2]}'
