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


NFC_E = "caf\u00e9"
NFD_E = "cafe\u0301"


def test_nfc_string_is_plain_rfc8785():
    assert canonicalize(NFC_E) == b'"caf\xc3\xa9"'


def test_non_nfc_value_is_refused():
    # GHSA-99p4: normalizing made the NFD spelling share the NFC pre-image.
    with pytest.raises(ValueError, match="not NFC"):
        canonicalize({"name": NFD_E})


def test_non_nfc_key_is_refused():
    # Two keys that normalized alike used to serialize as duplicate names.
    with pytest.raises(ValueError, match="not NFC"):
        canonicalize({NFC_E: 1, NFD_E: 2})


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


@pytest.mark.parametrize("bad_int", [2**53, -(2**53), 2**53 + 1, 10**30])
def test_reject_integers_outside_rfc8785_safe_domain(bad_int):
    with pytest.raises(ValueError, match="safe integer domain"):
        canonicalize({"v": bad_int})


def test_accept_safe_integer_boundary():
    assert canonicalize({"v": 2**53 - 1}) == b'{"v":9007199254740991}'
    assert canonicalize({"v": -(2**53 - 1)}) == b'{"v":-9007199254740991}'


@pytest.mark.parametrize("bad_key", [1, None, (1, 2)])
def test_reject_non_string_dict_key(bad_key):
    with pytest.raises(TypeError, match="not a string"):
        canonicalize({bad_key: "v"})


@pytest.mark.parametrize(
    "payload",
    [
        {"k": chr(0xD800)},
        {"k2": chr(0xDFFF)},
        {chr(0xD800): "v"},
        [chr(0xDC00)],
    ],
)
def test_reject_lone_utf16_surrogate(payload):
    from wcm._canonicalize import _quote

    with pytest.raises(ValueError, match="lone UTF-16 surrogate"):
        canonicalize(payload)
    with pytest.raises(ValueError, match="lone UTF-16 surrogate"):
        _quote(chr(0xD800))
