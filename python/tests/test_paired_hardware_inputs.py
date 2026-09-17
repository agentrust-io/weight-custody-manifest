"""Relying-party inputs must not be inferred from the host under test."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.serialization import Encoding
from wcm import SoftwareProvider

from tests.test_azure_vtpm_verify import BINDING, MEASUREMENT, NONCE, NOW, _bundle

MODULE = Path(__file__).parents[1] / "tools" / "paired_hardware_release.py"
spec = importlib.util.spec_from_file_location("paired_hardware_release_inputs", MODULE)
assert spec and spec.loader
paired = importlib.util.module_from_spec(spec)
spec.loader.exec_module(paired)


def _selected(example_dict):
    return example_dict["release_policy"]["required_serving_image"]["accepted_measurements"][0]["measurement"]


def test_pinned_manifest_is_not_rewritten_from_observed_gpu(example_dict):
    raw = json.dumps(example_dict).encode()
    manifest = paired._manifest(raw, hashlib.sha256(raw).hexdigest(), _selected(example_dict))
    assert manifest.release_policy.required_gpu_measurement.rim_pin == example_dict["release_policy"]["required_gpu_measurement"]["rim_pin"]


@pytest.mark.parametrize("attack", ["gpu", "image", "whitespace"])
def test_changed_manifest_cannot_be_approved_by_its_own_contents(example_dict, attack):
    raw = json.dumps(example_dict).encode()
    pin = hashlib.sha256(raw).hexdigest()
    if attack == "gpu":
        example_dict["release_policy"]["required_gpu_measurement"]["rim_pin"] = "attacker-selected"
    elif attack == "image":
        example_dict["release_policy"]["required_serving_image"]["accepted_measurements"][0]["measurement"] = "sha256:" + "00" * 32
    changed = json.dumps(example_dict).encode() + (b" " if attack == "whitespace" else b"")
    with pytest.raises(ValueError, match="independently approved digest"):
        paired._manifest(changed, pin, _selected(example_dict))


@pytest.mark.parametrize("pin", ["", "ab" * 31, "AB" * 32, "zz" * 32])
def test_manifest_pin_must_be_explicit_canonical_sha256(example_dict, pin):
    with pytest.raises(ValueError, match="64 lowercase"):
        paired._manifest(json.dumps(example_dict).encode(), pin, _selected(example_dict))


@pytest.mark.parametrize("selection", ["retiring", "revoked", "absent"])
def test_serving_measurement_must_be_current_in_pinned_manifest(example_dict, selection):
    raw = json.dumps(example_dict).encode()
    accepted = example_dict["release_policy"]["required_serving_image"]["accepted_measurements"]
    measurement = next((v["measurement"] for v in accepted if v["status"] == selection), "sha256:" + "00" * 32)
    with pytest.raises(ValueError, match="must be current"):
        paired._manifest(raw, hashlib.sha256(raw).hexdigest(), measurement)


def test_manifest_without_gpu_requirement_is_not_paired_validation(example_dict):
    example_dict["release_policy"]["required_gpu_measurement"] = None
    raw = json.dumps(example_dict).encode()
    with pytest.raises(ValueError, match="approved GPU"):
        paired._manifest(raw, hashlib.sha256(raw).hexdigest(), _selected(example_dict))


def test_cpu_root_is_pinned_not_chosen_by_evidence():
    raw, trust = _bundle()
    _, untrusted = _bundle()
    verifier = paired._cpu_verifier(trust.roots[0].public_bytes(Encoding.PEM))
    wrong_verifier = paired._cpu_verifier(untrusted.roots[0].public_bytes(Encoding.PEM))
    kwargs = dict(expected_nonce=NONCE, channel_binding=BINDING,
                  expected_workload_measurement=MEASUREMENT, now=NOW)
    assert verifier.verify(raw, **kwargs).verified
    assert not wrong_verifier.verify(raw, **kwargs).verified


def test_cli_requires_trust_inputs_before_accessing_devices(monkeypatch, tmp_path):
    def unexpected():
        pytest.fail("device access before the relying party supplied trust inputs")
    monkeypatch.setattr(paired.AzureSnpVtpmProvider, "is_available", unexpected)
    monkeypatch.setattr(sys, "argv", [str(MODULE), "--out", str(tmp_path / "report.json"),
                                     "--release-candidate", "test"])
    with pytest.raises(SystemExit) as raised:
        paired.main()
    assert raised.value.code == 2
    assert not (tmp_path / "report.json").exists()


@pytest.mark.parametrize("wrong_gpu", [False, True])
def test_harness_uses_approved_gpu_and_reports_only_its_test_scope(monkeypatch, tmp_path, example_dict, wrong_gpu):
    # Orchestration-only test: deliberately synthetic verifiers and providers.
    # KBS challenge consumption, manifest authorization and sealing are real.
    approved_gpu = example_dict["release_policy"]["required_gpu_measurement"]["rim_pin"]
    raw = json.dumps(example_dict).encode()
    manifest = tmp_path / "manifest.json"
    manifest.write_bytes(raw)
    root = tmp_path / "root.pem"
    root.write_bytes(b"test-only-root-input")
    output = tmp_path / "report.json"
    monkeypatch.setattr(sys, "argv", [
        str(MODULE), "--out", str(output), "--release-candidate", "synthetic-test",
        "--cpu-root", str(root), "--gpu-root", str(root), "--manifest", str(manifest),
        "--manifest-sha256", hashlib.sha256(raw).hexdigest(),
        "--serving-image", _selected(example_dict),
    ])
    monkeypatch.setattr(paired.AzureSnpVtpmProvider, "is_available", lambda: True)
    monkeypatch.setattr(paired.NvidiaCcProvider, "is_available", lambda: True)
    class SyntheticVerifier:
        def verify(self, *args, **kwargs):
            return SimpleNamespace(verified=True, reason="synthetic test", leaf_subject="synthetic")
    monkeypatch.setattr(paired, "_cpu_verifier", lambda root: SyntheticVerifier())
    monkeypatch.setattr(paired, "build_gpu_verifier", lambda root: SyntheticVerifier())
    class SyntheticProvider:
        def produce(self, challenge, **kwargs):
            evidence = SoftwareProvider().produce(
                challenge, gpu_measurement="unapproved-gpu" if wrong_gpu else approved_gpu, **kwargs,
            )
            evidence.cpu.quote_b64 = "c3ludGhldGlj"
            evidence.gpu.quote_b64 = "c3ludGhldGlj"
            return evidence
    monkeypatch.setattr(paired, "HardwareCompositeProvider", lambda *args: SyntheticProvider())
    monkeypatch.setattr(paired, "_command", lambda args: "synthetic-test-command")
    if wrong_gpu:
        with pytest.raises(RuntimeError, match="independently approved manifest"):
            paired.main()
        assert not output.exists()
    else:
        assert paired.main() == 0
        report = json.loads(output.read_text())
        assert report["passed"] is True
        assert report["claim_scope"] == "report-authentication-and-sealed-test-key-release"
        assert report["test_material_only"] is True
        assert report["confidential_inference_validated"] is False
        assert report["cpu_gpu_protected_path_validated"] is False
        assert report["gpu_firmware_rim_appraised"] is False
        assert report["trust_inputs"]["manifest_sha256"] == hashlib.sha256(raw).hexdigest()
        assert report["happy_release"]["plaintext_key_returned"] is False
