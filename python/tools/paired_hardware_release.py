#!/usr/bin/env python3
"""Run one fail-closed Azure SNP/vTPM plus NVIDIA CC key release.

This is the live partner-node closure for WCM issue #77. Raw attestation
evidence and key material stay in memory. The retained report contains hashes,
public identities, and exact verifier decisions only.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import subprocess
import urllib.request
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from wcm import (
    AzureSnpVtpmProvider,
    AzureSnpVtpmVerifier,
    HardwareCompositeProvider,
    KeyBrokerService,
    NvidiaCcProvider,
    SealError,
    TrustStore,
    WeightCustodyManifest,
    build_gpu_verifier,
    generate_transport_keypair,
    open_sealed,
)

THIM_URL = "http://169.254.169.254/metadata/THIM/amd/certification"
SERVING_IMAGE = "sha256:" + "5e2d" * 16
DEK = hashlib.sha256(b"wcm-issue-77-live-validation-dek").digest()


def _split_pems(blob: str) -> list[str]:
    marker = "-----END CERTIFICATE-----"
    return [
        part + marker + "\n"
        for part in blob.split(marker)
        if "BEGIN CERTIFICATE" in part
    ]


def _cpu_verifier() -> AzureSnpVtpmVerifier:
    req = urllib.request.Request(THIM_URL, headers={"Metadata": "true"})
    with urllib.request.urlopen(req, timeout=10) as response:  # nosec B310, fixed IMDS URL
        thim = json.loads(response.read())
    chain = _split_pems(thim.get("certificateChain", ""))
    if not chain:
        raise RuntimeError("Azure THIM did not return an AMD certificate chain")
    trust = TrustStore()
    trust.add_root_pem(chain[-1])
    return AzureSnpVtpmVerifier(trust)


def _manifest(root: Path, gpu_measurement: str) -> WeightCustodyManifest:
    value = json.loads((root / "python/examples/manifest.example.json").read_text())
    value["release_policy"]["required_gpu_measurement"]["rim_pin"] = gpu_measurement
    return WeightCustodyManifest.model_validate(value)


def _checks(decision: Any) -> list[dict[str, Any]]:
    return [asdict(check) for check in decision.checks]


def _quote_hash(value: str | None) -> str | None:
    return hashlib.sha256(value.encode()).hexdigest() if value else None


def _evidence_summary(
    label: str, evidence: Any, cpu_result: Any, gpu_result: Any
) -> dict[str, Any]:
    return {
        "label": label,
        "challenge_nonce": evidence.cpu.nonce_echo,
        "transport_public_key": evidence.cpu.transport_public_key,
        "cpu": {
            "platform": evidence.cpu.platform,
            "attestation_key_id": evidence.cpu.attestation_key_id,
            "quote_sha256": _quote_hash(evidence.cpu.quote_b64),
            "verified": cpu_result.verified,
            "reason": cpu_result.reason,
            "leaf_subject": cpu_result.leaf_subject,
        },
        "gpu": {
            "platform": evidence.gpu.platform,
            "measurement": evidence.gpu.measurement,
            "cc_mode": evidence.gpu.cc_mode,
            "quote_sha256": _quote_hash(evidence.gpu.quote_b64),
            "verified": gpu_result.verified,
            "reason": gpu_result.reason,
            "leaf_subject": gpu_result.leaf_subject,
        },
    }


def _command(args: list[str]) -> str:
    return subprocess.check_output(args, text=True, stderr=subprocess.STDOUT).strip()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--release-candidate", required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    if not AzureSnpVtpmProvider.is_available() or not NvidiaCcProvider.is_available():
        raise SystemExit("paired Azure SNP/vTPM and NVIDIA providers are required")

    cpu_verifier = _cpu_verifier()
    gpu_root = (
        root / "python/tests/fixtures/nvidia_device_identity_ca.pem"
    ).read_text()
    gpu_verifier = build_gpu_verifier(gpu_root)
    provider = HardwareCompositeProvider(AzureSnpVtpmProvider(), NvidiaCcProvider())

    example = json.loads((root / "python/examples/manifest.example.json").read_text())
    weights_hash = example["weights_hash"]
    kbs = KeyBrokerService(
        {weights_hash: DEK},
        challenge_ttl_seconds=1800,
        cpu_quote_verifier=cpu_verifier,
        gpu_report_verifier=gpu_verifier,
        require_channel_binding=True,
        require_cpu_quote_verification=True,
    )

    captures: list[tuple[str, Any, Any, str]] = []
    for label in ("happy", "substitution-b", "substitution-c"):
        challenge = kbs.issue_challenge()
        private_key, public_key = generate_transport_keypair()
        evidence = provider.produce(
            challenge,
            serving_image_measurement=SERVING_IMAGE,
            transport_public_key=public_key,
        )
        if evidence.gpu is None or not evidence.gpu.quote_b64:
            raise RuntimeError("NVIDIA evidence is absent")
        captures.append((label, evidence, private_key, public_key))

    measurements = {item[1].gpu.measurement for item in captures}
    if len(measurements) != 1:
        raise RuntimeError("GPU identity changed across the contemporaneous run")
    manifest = _manifest(root, next(iter(measurements)))

    summaries = []
    for label, evidence, _, public_key in captures:
        cpu_result = cpu_verifier.verify(
            evidence.cpu.quote_b64,
            expected_nonce=evidence.cpu.nonce_echo,
            channel_binding=bytes.fromhex(public_key),
        )
        gpu_result = gpu_verifier.verify(
            evidence.gpu.quote_b64,
            expected_nonce=evidence.gpu.nonce_echo,
        )
        if not cpu_result.verified or not gpu_result.verified:
            raise RuntimeError(
                f"independent cryptographic verification failed for {label}"
            )
        summaries.append(_evidence_summary(label, evidence, cpu_result, gpu_result))

    happy_evidence = captures[0][1]
    happy_private = captures[0][2]
    happy = kbs.verify_and_release(manifest, happy_evidence)
    if not happy.released or happy.key is not None or happy.sealed_key is None:
        raise RuntimeError("happy path did not return only a sealed key")
    if open_sealed(happy.sealed_key, happy_private) != DEK:
        raise RuntimeError("attested transport key did not recover the released DEK")
    wrong_private, _ = generate_transport_keypair()
    try:
        open_sealed(happy.sealed_key, wrong_private)
    except SealError:
        wrong_transport_refused = True
    else:
        wrong_transport_refused = False
    if not wrong_transport_refused:
        raise RuntimeError("a substituted transport key opened the sealed release")

    b = captures[1][1]
    c = captures[2][1]
    b_cpu_c_gpu = b.model_copy(update={"gpu": c.gpu})
    c_cpu_b_gpu = c.model_copy(update={"gpu": b.gpu})
    negative_cpu = kbs.verify_and_release(manifest, b_cpu_c_gpu)
    negative_gpu = kbs.verify_and_release(manifest, c_cpu_b_gpu)
    if negative_cpu.released or negative_gpu.released:
        raise RuntimeError("cross-run CPU/GPU evidence substitution was accepted")

    report = {
        "kind": "wcm-paired-hardware-release/v1",
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "classification": "OPAQUE internal validation evidence",
        "release_candidate": args.release_candidate,
        "provider_topology": "Azure SNP/vTPM freshness quote + NVIDIA H100 NVAT local appraisal",
        "environment": {
            "kernel": platform.release(),
            "nvidia": _command(
                [
                    "nvidia-smi",
                    "--query-gpu=name,driver_version,vbios_version,pci.bus_id",
                    "--format=csv,noheader",
                ]
            ),
            "nvidia_cc": _command(["nvidia-smi", "conf-compute", "-f"]),
            "nvattest": _command(["nvattest", "version"]),
        },
        "evidence": summaries,
        "happy_release": {
            "released": happy.released,
            "plaintext_key_returned": happy.key is not None,
            "sealed_key_sha256": hashlib.sha256(happy.sealed_key).hexdigest(),
            "released_key_sha256": hashlib.sha256(DEK).hexdigest(),
            "correct_transport_recovered": True,
            "wrong_transport_refused": wrong_transport_refused,
            "checks": _checks(happy),
        },
        "negative_cross_run_cpu_substitution": {
            "released": negative_cpu.released,
            "checks": _checks(negative_cpu),
        },
        "negative_cross_run_gpu_substitution": {
            "released": negative_gpu.released,
            "checks": _checks(negative_gpu),
        },
    }
    report["passed"] = (
        happy.released
        and wrong_transport_refused
        and not negative_cpu.released
        and not negative_gpu.released
    )
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"passed": report["passed"], "out": str(args.out)}))
    return int(not report["passed"])


if __name__ == "__main__":
    raise SystemExit(main())
