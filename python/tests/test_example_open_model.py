"""The open-model end-to-end example must keep running (it doubles as a tutorial)."""
from __future__ import annotations

import importlib.util
import pathlib

import pytest

EXAMPLE = pathlib.Path(__file__).resolve().parent.parent / "examples" / "open_model_e2e.py"


def _load():
    spec = importlib.util.spec_from_file_location("open_model_e2e", EXAMPLE)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_example_runs(capsys):
    _load().main()
    out = capsys.readouterr().out
    # The load-bearing beats of the open-weight story are present.
    assert "manifest signature valid: True" in out
    assert "gate released: True" in out
    assert "lineage ok : True" in out
    assert "derived_from" in out


def test_manifest_and_lineage_helpers():
    mod = _load()
    base_doc = mod.build_manifest(
        weights_hash=mod.sha256(b"base"),
        license_text="Apache-2.0",
        serving_measurement=mod.sha256(b"serving"),
        builder_id="gov",
        custodian_id="gov",
        derivatives="fine-tune-only",
    )
    from wcm import WeightCustodyManifest

    base = WeightCustodyManifest.model_validate(base_doc)
    assert base.release_terms.derivatives.value == "fine-tune-only"
    assert base.derived_from is None  # a base manifest is a lineage root
