"""The sovereign self-custody demo must run green, and its core threshold
property (a single share cannot reconstruct, any quorum can) must hold."""
from __future__ import annotations

import importlib.util
import pathlib

from wcm import combine_shares, split_secret

EXAMPLES = pathlib.Path(__file__).resolve().parent.parent / "examples"


def _load_demo():
    spec = importlib.util.spec_from_file_location("sovereign_self_custody", EXAMPLES / "sovereign_self_custody.py")
    mod = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(mod)
    return mod


def test_demo_runs_green(capsys):
    assert _load_demo().main() == 0
    out = capsys.readouterr().out
    assert "manifest valid            : True" in out
    assert "attestation gate passed   : True" in out
    assert "sovereign's single share -> key    : False" in out


def test_threshold_2_of_3_single_share_insufficient():
    key = b"a-32-byte-demo-key-aaaaaaaaaaaaa"
    b, s, c = split_secret(key, threshold=2, shares=3)
    # Any quorum of two reconstructs.
    assert combine_shares([b, s]) == key
    assert combine_shares([b, c]) == key
    assert combine_shares([s, c]) == key
    # A single share does not (the decision-15 property).
    assert combine_shares([s]) != key
    assert combine_shares([b]) != key
