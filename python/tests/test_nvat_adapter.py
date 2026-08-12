from __future__ import annotations

import base64
import importlib.util
import json
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
