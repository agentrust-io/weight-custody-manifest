"""The SNP replay demo must verify the committed synthetic bundle end-to-end,
and reject a bundle whose nonce does not match (the anti-replay gate)."""
from __future__ import annotations

import copy
import importlib.util
import json
import pathlib

import pytest

EXAMPLES = pathlib.Path(__file__).resolve().parent.parent / "examples"
FIXTURES = pathlib.Path(__file__).resolve().parent / "fixtures"
BUNDLE = FIXTURES / "snp_quote_synthetic.json"
AZURE_BUNDLE = FIXTURES / "snp_quote_azure.json"


def _load_demo():
    spec = importlib.util.spec_from_file_location("snp_replay", EXAMPLES / "snp_replay.py")
    mod = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(mod)
    return mod


def test_replay_demo_verifies_synthetic_bundle(monkeypatch, capsys):
    monkeypatch.setattr("sys.argv", ["snp_replay.py"])  # default bundle
    assert _load_demo().main() == 0
    out = capsys.readouterr().out
    assert "verified            : True" in out


def test_replay_rejects_wrong_nonce(tmp_path, monkeypatch):
    bundle = json.loads(BUNDLE.read_text(encoding="utf-8"))
    forged = copy.deepcopy(bundle)
    forged["expected_nonce"] = "cd" * 32  # a nonce the report_data does not bind
    p = tmp_path / "wrong_nonce.json"
    p.write_text(json.dumps(forged), encoding="utf-8")
    monkeypatch.setattr("sys.argv", ["snp_replay.py", str(p)])
    assert _load_demo().main() == 1  # KBS would refuse


def test_synthetic_bundle_is_labelled_not_real():
    bundle = json.loads(BUNDLE.read_text(encoding="utf-8"))
    assert bundle["source"] == "synthetic"
    assert bundle["kind"] == "wcm-snp-quote-bundle/v1"


@pytest.mark.filterwarnings("ignore::DeprecationWarning")  # real AMD VCEK serial is 0
def test_real_azure_bundle_verifies(monkeypatch, capsys):
    # A GENUINE quote captured from a real Azure SEV-SNP CVM (vTPM NV 0x01400001,
    # real VCEK->ASK->ARK). Proves the WCM path verifies actual silicon, offline.
    if not AZURE_BUNDLE.exists():
        pytest.skip("no captured Azure bundle committed")
    bundle = json.loads(AZURE_BUNDLE.read_text(encoding="utf-8"))
    assert bundle["source"] == "azure-sev-snp-vtpm"
    monkeypatch.setattr("sys.argv", ["snp_replay.py", str(AZURE_BUNDLE)])
    assert _load_demo().main() == 0
    out = capsys.readouterr().out
    assert "VCEK chains to root : True" in out
    assert "report signature ok : True" in out
    assert "genuine hardware quote" in out


def test_azure_vtpm_topology_verifies_chain_and_signature(tmp_path, monkeypatch, capsys):
    # Azure vTPM path: REPORT_DATA binds the AK, not our nonce, so expected_nonce
    # is null. The demo must still verify chain + report signature (the parts that
    # are genuine on Azure) and skip the guest-nonce gate. Derive such a bundle
    # from the synthetic one so the branch is covered before a real capture.
    bundle = json.loads(BUNDLE.read_text(encoding="utf-8"))
    azure = copy.deepcopy(bundle)
    azure["source"] = "azure-sev-snp-vtpm"
    azure["expected_nonce"] = None
    p = tmp_path / "azure.json"
    p.write_text(json.dumps(azure), encoding="utf-8")
    monkeypatch.setattr("sys.argv", ["snp_replay.py", str(p)])
    assert _load_demo().main() == 0
    out = capsys.readouterr().out
    assert "report signature ok : True" in out
    assert "paravisor-bound to the" in out  # the honest Azure freshness note
