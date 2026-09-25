from __future__ import annotations

import base64
import importlib.util
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest


SPEC = importlib.util.spec_from_file_location(
    "nvat_adapter", Path(__file__).parents[1] / "tools" / "nvat_adapter.py"
)
assert SPEC and SPEC.loader
nvat_adapter = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(nvat_adapter)

NONCE = "ab" * 32


def _jwt(payload: dict) -> str:
    encoded = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    return f"eyJhbGciOiJub25lIn0.{encoded}."


def _cert_claims() -> dict:
    return {
        "x-nvidia-cert-ocsp-nonce-matches": True,
        "x-nvidia-cert-ocsp-response-valid": True,
        "x-nvidia-cert-ocsp-status": "good",
        "x-nvidia-cert-status": "valid",
    }


def _documents() -> tuple[dict, dict]:
    evidence = {
        "result_code": 0,
        "evidences": [{
            "arch": "HOPPER",
            "certificate": base64.b64encode(b"-----BEGIN CERTIFICATE-----\nX\n-----END CERTIFICATE-----\n").decode(),
            "evidence": base64.b64encode(b"raw-report").decode(),
            "nonce": NONCE,
        }],
    }
    gpu = {name: True for name in nvat_adapter._REQUIRED_TRUE}
    gpu.update({
        "eat_nonce": NONCE,
        "x-nvidia-mismatch-measurement-records": None,
        "x-nvidia-gpu-driver-version": "595.71.05",
        "x-nvidia-gpu-vbios-version": "96.00.9F.00.04",
        "x-nvidia-gpu-attestation-report-cert-chain": _cert_claims(),
        "x-nvidia-gpu-driver-rim-cert-chain": _cert_claims(),
        "x-nvidia-gpu-vbios-rim-cert-chain": _cert_claims(),
    })
    appraisal = {
        "result_code": 0,
        "detached_eat": [
            ["JWT", _jwt({"x-nvidia-overall-att-result": True})],
            {"GPU-0": _jwt(gpu)},
        ],
    }
    return evidence, appraisal


def test_adapt_success() -> None:
    evidence, appraisal = _documents()
    output = nvat_adapter.adapt(evidence, appraisal, NONCE)
    assert output["measurement"] == (
        "nvidia-rim:arch=HOPPER;driver=595.71.05;vbios=96.00.9F.00.04"
    )
    container = json.loads(base64.b64decode(output["report_b64"]))
    assert base64.b64decode(container["report_b64"]) == b"raw-report"


def test_adapt_does_not_assert_confidential_compute_mode() -> None:
    """The mode is not in any signed NVIDIA evidence, so the adapter says so.

    It previously emitted True unconditionally, which made the gate added in
    GHSA-j665-99rh-w85h read this file rather than the device and gave it no
    way to deny along this path.
    """
    evidence, appraisal = _documents()
    output = nvat_adapter.adapt(evidence, appraisal, NONCE)
    assert output["cc_mode"] is None
    assert output["cc_mode"] is not True


def test_no_appraisal_claim_is_read_as_the_mode() -> None:
    """A claim that merely mentions the mode must not be mistaken for it.

    If NVIDIA adds one, wiring it in is a deliberate change here with a capture
    behind it, not something an unrelated claim name turns on by accident.
    """
    evidence, appraisal = _documents()
    claims = json.loads(
        base64.urlsafe_b64decode(
            appraisal["detached_eat"][1]["GPU-0"].split(".")[1] + "=="
        )
    )
    claims["x-nvidia-gpu-cc-mode"] = True
    claims["x-nvidia-gpu-confidential-compute"] = "on"
    appraisal["detached_eat"][1]["GPU-0"] = _jwt(claims)

    output = nvat_adapter.adapt(evidence, appraisal, NONCE)
    assert output["cc_mode"] is None


@pytest.mark.parametrize("target", ["evidence", "appraisal"])
def test_adapt_rejects_wrong_nonce(target: str) -> None:
    evidence, appraisal = _documents()
    if target == "evidence":
        evidence["evidences"][0]["nonce"] = "cd" * 32
    else:
        appraisal["detached_eat"][1]["GPU-0"] = _jwt({"eat_nonce": "cd" * 32})
    with pytest.raises(nvat_adapter.NvatAdapterError, match="nonce"):
        nvat_adapter.adapt(evidence, appraisal, NONCE)


def test_adapt_rejects_measurement_mismatch() -> None:
    evidence, appraisal = _documents()
    gpu = nvat_adapter._jwt_payload(appraisal["detached_eat"][1]["GPU-0"])
    gpu["x-nvidia-mismatch-measurement-records"] = [9]
    appraisal["detached_eat"][1]["GPU-0"] = _jwt(gpu)
    with pytest.raises(nvat_adapter.NvatAdapterError, match="mismatched measurement"):
        nvat_adapter.adapt(evidence, appraisal, NONCE)


def test_adapt_rejects_bad_ocsp() -> None:
    evidence, appraisal = _documents()
    gpu = nvat_adapter._jwt_payload(appraisal["detached_eat"][1]["GPU-0"])
    gpu["x-nvidia-gpu-driver-rim-cert-chain"]["x-nvidia-cert-ocsp-status"] = "revoked"
    appraisal["detached_eat"][1]["GPU-0"] = _jwt(gpu)
    with pytest.raises(nvat_adapter.NvatAdapterError, match="OCSP"):
        nvat_adapter.adapt(evidence, appraisal, NONCE)

def _gpu_report_from(emitted, nonce):
    """Build the GpuReport exactly as NvidiaCcProvider.gpu_report does.

    Mirrors _hw_providers: only a JSON boolean counts, so the adapter's unknown
    arrives at the gate as None rather than becoming on.
    """
    from wcm.attestation import GpuReport

    return GpuReport(
        platform="nvidia-cc-gpu",
        measurement=str(emitted["measurement"]),
        cc_mode=emitted["cc_mode"] if isinstance(emitted.get("cc_mode"), bool) else None,
        nonce_echo=nonce,
        quote_b64=emitted.get("report_b64"),
    )


def _gate(manifest, emitted, nonce):
    """Run the adapter's own output through verify_and_release.

    The manifest pins the measurement this adapter emits, so the GPU check
    reaches the confidential-mode condition rather than stopping earlier on a
    measurement mismatch. That is the point: the refusal has to be about the
    mode, not about something else being wrong.
    """
    from wcm import KeyBrokerService, SoftwareProvider, manifest_identity

    policy = manifest.release_policy
    manifest = manifest.model_copy(update={"release_policy": policy.model_copy(update={
        "required_gpu_measurement": policy.required_gpu_measurement.model_copy(
            update={"rim_pin": emitted["measurement"]})
    })})
    key = b"decryption-key-for-these-weights"
    kbs = KeyBrokerService(
        {manifest.weights_hash: key},
        now=lambda: datetime(2026, 7, 19, 12, 0, 0, tzinfo=timezone.utc),
        trusted_manifest_identities={manifest_identity(manifest)},
    )
    accepted = manifest.release_policy.required_serving_image.accepted_measurements
    current = next(m.measurement for m in accepted if m.status.value == "current")
    challenge = kbs.issue_challenge()
    evidence = SoftwareProvider().produce(
        challenge, serving_image_measurement=current,
        gpu_measurement=emitted["measurement"],
    )
    evidence = evidence.model_copy(
        update={"gpu": _gpu_report_from(emitted, challenge.nonce)}
    )
    return manifest, kbs.verify_and_release(manifest, evidence)


def test_the_adapter_output_is_refused_by_the_release_gate(example_manifest) -> None:
    """What the adapter returns, carried through the gate, does not release.

    The unit assertions above say what adapt() returns. This says what that
    return value does, which is the part that matters: a deployment on this
    adapter stops rather than releasing on an assertion nothing established.
    """
    emitted = nvat_adapter.adapt(*_documents(), NONCE)
    assert emitted["cc_mode"] is None

    _, decision = _gate(example_manifest, emitted, NONCE)

    assert decision.released is False
    assert decision.key is None
    gpu = next(check for check in decision.checks if check.name == "gpu")
    assert gpu.passed is False
    assert "unstated" in gpu.detail


def test_the_waiver_is_explicit_and_is_not_set_here(example_manifest) -> None:
    """A deployment can still release, by saying so in the signed manifest.

    require_cc_mode is the existing waiver. This adapter does not set it and
    must not: choosing to release without an established mode belongs to
    whoever signs the manifest.
    """
    emitted = nvat_adapter.adapt(*_documents(), NONCE)
    pinned, refused = _gate(example_manifest, emitted, NONCE)
    assert refused.released is False

    policy = pinned.release_policy
    waived = pinned.model_copy(update={"release_policy": policy.model_copy(update={
        "required_gpu_measurement": policy.required_gpu_measurement.model_copy(
            update={"require_cc_mode": False})
    })})
    _, decision = _gate(waived, emitted, NONCE)

    assert decision.released is True
    gpu = next(check for check in decision.checks if check.name == "gpu")
    assert "waived" in gpu.detail
