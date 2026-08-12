#!/usr/bin/env python3
"""Adapt NVIDIA ``nvattest`` output to ``WCM_NVIDIA_ATTESTATION_CMD``.

The adapter deliberately composes two checks:

* NVIDIA local appraisal verifies RIMs, reference measurements, certificate
  status, the report signature, and nonce binding.
* WCM independently verifies the raw report certificate chain, signature, and
  nonce after this adapter returns the evidence container.

The emitted ``measurement`` is a canonical identity derived only after the
required NVIDIA appraisal claims pass. It is suitable for a manifest
``required_gpu_measurement.rim_pin``.
"""
from __future__ import annotations

import argparse
import base64
import json
import subprocess
from typing import Any


class NvatAdapterError(RuntimeError):
    pass


def _jwt_payload(token: str) -> dict[str, Any]:
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        value = json.loads(base64.urlsafe_b64decode(payload))
    except (IndexError, ValueError, TypeError, json.JSONDecodeError) as exc:
        raise NvatAdapterError(f"unparseable NVIDIA appraisal token: {exc}") from exc
    if not isinstance(value, dict):
        raise NvatAdapterError("NVIDIA appraisal token payload is not an object")
    return value


def _gpu_claims(appraisal: dict[str, Any]) -> dict[str, Any]:
    if appraisal.get("result_code") != 0:
        raise NvatAdapterError(
            f"NVIDIA local appraisal failed: {appraisal.get('result_message', 'unknown')}"
        )
    detached = appraisal.get("detached_eat")
    try:
        overall = _jwt_payload(detached[0][1])
        gpu = _jwt_payload(detached[1]["GPU-0"])
    except (KeyError, IndexError, TypeError) as exc:
        raise NvatAdapterError("NVIDIA appraisal is missing GPU-0 detached EAT claims") from exc
    if overall.get("x-nvidia-overall-att-result") is not True:
        raise NvatAdapterError("NVIDIA overall attestation result is not true")
    return gpu


_REQUIRED_TRUE = (
    "secboot",
    "x-nvidia-gpu-arch-check",
    "x-nvidia-gpu-attestation-report-cert-chain-fwid-match",
    "x-nvidia-gpu-attestation-report-nonce-match",
    "x-nvidia-gpu-attestation-report-parsed",
    "x-nvidia-gpu-attestation-report-signature-verified",
    "x-nvidia-gpu-driver-rim-fetched",
    "x-nvidia-gpu-driver-rim-measurements-available",
    "x-nvidia-gpu-driver-rim-signature-verified",
    "x-nvidia-gpu-driver-rim-version-match",
    "x-nvidia-gpu-vbios-index-no-conflict",
    "x-nvidia-gpu-vbios-rim-fetched",
    "x-nvidia-gpu-vbios-rim-measurements-available",
    "x-nvidia-gpu-vbios-rim-signature-verified",
    "x-nvidia-gpu-vbios-rim-version-match",
)


def _require_cert_good(claims: dict[str, Any], name: str) -> None:
    value = claims.get(name)
    if not isinstance(value, dict):
        raise NvatAdapterError(f"NVIDIA appraisal is missing {name}")
    required = (
        "x-nvidia-cert-ocsp-nonce-matches",
        "x-nvidia-cert-ocsp-response-valid",
    )
    if any(value.get(field) is not True for field in required):
        raise NvatAdapterError(f"NVIDIA appraisal failed certificate checks in {name}")
    if value.get("x-nvidia-cert-status") != "valid":
        raise NvatAdapterError(f"NVIDIA certificate status is not valid in {name}")
    if value.get("x-nvidia-cert-ocsp-status") != "good":
        raise NvatAdapterError(f"NVIDIA OCSP status is not good in {name}")


def adapt(
    evidence_doc: dict[str, Any], appraisal_doc: dict[str, Any], expected_nonce: str
) -> dict[str, Any]:
    if evidence_doc.get("result_code") != 0:
        raise NvatAdapterError(
            f"NVIDIA evidence collection failed: {evidence_doc.get('result_message', 'unknown')}"
        )
    evidences = evidence_doc.get("evidences")
    if not isinstance(evidences, list) or len(evidences) != 1:
        raise NvatAdapterError("exactly one NVIDIA GPU evidence item is required")
    evidence = evidences[0]
    if not isinstance(evidence, dict):
        raise NvatAdapterError("NVIDIA GPU evidence item is not an object")
    if evidence.get("nonce") != expected_nonce:
        raise NvatAdapterError("collected NVIDIA evidence nonce does not match WCM challenge")

    claims = _gpu_claims(appraisal_doc)
    if claims.get("eat_nonce") != expected_nonce:
        raise NvatAdapterError("NVIDIA appraisal nonce does not match WCM challenge")
    failed = [name for name in _REQUIRED_TRUE if claims.get(name) is not True]
    if failed:
        raise NvatAdapterError("NVIDIA appraisal checks failed: " + ", ".join(failed))
    if claims.get("x-nvidia-mismatch-measurement-records") is not None:
        raise NvatAdapterError("NVIDIA appraisal reports mismatched measurement records")
    for name in (
        "x-nvidia-gpu-attestation-report-cert-chain",
        "x-nvidia-gpu-driver-rim-cert-chain",
        "x-nvidia-gpu-vbios-rim-cert-chain",
    ):
        _require_cert_good(claims, name)

    arch = evidence.get("arch")
    driver = claims.get("x-nvidia-gpu-driver-version")
    vbios = claims.get("x-nvidia-gpu-vbios-version")
    if not all(isinstance(value, str) and value for value in (arch, driver, vbios)):
        raise NvatAdapterError("NVIDIA appraisal is missing arch/driver/VBIOS identity")

    try:
        cert_chain_pem = base64.b64decode(evidence["certificate"], validate=True).decode()
        base64.b64decode(evidence["evidence"], validate=True)
    except (KeyError, ValueError, UnicodeDecodeError) as exc:
        raise NvatAdapterError(f"NVIDIA raw evidence is malformed: {exc}") from exc
    verifier_container = {
        "report_b64": evidence["evidence"],
        "cert_chain_pem": cert_chain_pem,
    }
    quote_b64 = base64.b64encode(
        json.dumps(verifier_container, separators=(",", ":")).encode()
    ).decode()
    measurement = f"nvidia-rim:arch={arch};driver={driver};vbios={vbios}"
    return {
        "measurement": measurement,
        "cc_mode": True,
        "report_b64": quote_b64,
        "appraisal": "nvidia-local",
    }


def _run(command: list[str], timeout: int) -> dict[str, Any]:
    completed = subprocess.run(
        command, capture_output=True, text=True, timeout=timeout, check=True
    )
    value = json.loads(completed.stdout)
    if not isinstance(value, dict):
        raise NvatAdapterError("nvattest output is not a JSON object")
    return value


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--nonce", required=True)
    parser.add_argument("--nvattest", default="nvattest")
    args = parser.parse_args()
    if len(args.nonce) != 64:
        raise SystemExit("--nonce must be exactly 32 bytes of hex")
    try:
        bytes.fromhex(args.nonce)
        evidence = _run(
            [args.nvattest, "--format=json", "collect-evidence", "--device", "gpu", "--nonce", args.nonce],
            120,
        )
        appraisal = _run(
            [args.nvattest, "--format=json", "attest", "--device", "gpu", "--verifier", "local", "--nonce", args.nonce],
            300,
        )
        print(json.dumps(adapt(evidence, appraisal, args.nonce), separators=(",", ":")))
    except (ValueError, OSError, subprocess.SubprocessError, json.JSONDecodeError, NvatAdapterError) as exc:
        raise SystemExit(f"NVAT adapter failed: {exc}") from exc
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
