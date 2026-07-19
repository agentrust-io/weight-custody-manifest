from __future__ import annotations

import math

import pytest

from wcm import canonical_hash, canonicalize


def test_key_ordering_is_codepoint():
    assert canonicalize({"b": 1, "a": 2}) == b'{"a":2,"b":1}'


def test_nested_ordering():
    obj = {"z": {"y": 1, "x": 2}, "a": [3, 2, 1]}
    assert canonicalize(obj) == b'{"a":[3,2,1],"z":{"x":2,"y":1}}'


def test_none_excluded_by_default():
    assert canonicalize({"a": 1, "b": None}) == b'{"a":1}'


def test_none_kept_when_requested():
    assert canonicalize({"a": None}, exclude_none=False) == b'{"a":null}'


def test_bool_before_int():
    assert canonicalize({"t": True, "f": False}) == b'{"f":false,"t":true}'


def test_unicode_nfc_normalization():
    # U+00E9 (é) and U+0065 U+0301 (e + combining acute) normalize equal.
    assert canonicalize("é") == canonicalize("é")


def test_control_chars_escaped():
    assert canonicalize("\n\t") == b'"\\n\\t"'


def test_float_integer_form():
    assert canonicalize(1.0) == b"1"


def test_reject_nan_and_inf():
    with pytest.raises(ValueError):
        canonicalize(math.nan)
    with pytest.raises(ValueError):
        canonicalize(math.inf)


def test_reject_unserializable():
    with pytest.raises(TypeError):
        canonicalize({"x": object()})


def test_depth_limit():
    obj: dict = {}
    cur = obj
    for _ in range(70):
        cur["n"] = {}
        cur = cur["n"]
    with pytest.raises(ValueError):
        canonicalize(obj)


def test_canonical_hash_prefix():
    h = canonical_hash({"a": 1})
    assert h.startswith("sha256:")
    assert len(h.split(":")[1]) == 64


def test_canonical_hash_shake256():
    h = canonical_hash({"a": 1}, algorithm="shake256")
    assert h.startswith("shake256:")


def test_canonical_hash_bad_algorithm():
    with pytest.raises(ValueError):
        canonical_hash({"a": 1}, algorithm="md5")
