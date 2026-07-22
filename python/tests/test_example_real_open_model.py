"""The real-open-model demo must run end to end and catch a tampered fork.

CI-safe: uses --local on a tiny temp file (the flow hashes raw bytes, it does not
parse safetensors), so no model download and no transformers/torch are needed.
"""
from __future__ import annotations

import importlib.util
import pathlib

EXAMPLES = pathlib.Path(__file__).resolve().parent.parent / "examples"


def _load_demo():
    spec = importlib.util.spec_from_file_location("real_open_model", EXAMPLES / "real_open_model.py")
    mod = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(mod)
    return mod


def test_runs_end_to_end_on_local_file(tmp_path, monkeypatch, capsys):
    weights = tmp_path / "model.safetensors"
    weights.write_bytes(b"pretend-open-weight-bytes" * 100)
    monkeypatch.setattr("sys.argv", ["real_open_model.py", "--local", str(weights)])
    assert _load_demo().main() == 0
    out = capsys.readouterr().out
    assert "manifest signature valid: True" in out
    assert "gate released     : True" in out
    assert "lineage ok : True" in out
    # The tamper check must show the flipped-byte hash does not match the manifest.
    assert "tampered matches manifest? : False" in out


def test_hash_is_stable_and_tamper_differs(tmp_path):
    mod = _load_demo()
    f = tmp_path / "w.bin"
    f.write_bytes(b"abc" * 1000)
    clean = mod.sha256_file(f)
    again = mod.sha256_file(f)
    tampered = mod.sha256_file(f, flip_first_byte=True)
    assert clean == again          # deterministic
    assert tampered != clean       # one flipped byte changes the digest
