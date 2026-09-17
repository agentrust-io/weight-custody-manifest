#!/usr/bin/env python3
"""Run one fail-closed Azure SNP/vTPM plus NVIDIA CC key release.

This checks authenticated reports and sealed release of a PUBLIC TEST KEY.
It does not run inference or establish CPU/GPU co-location, protected transfer,
or firmware-to-RIM appraisal. Trust roots and the manifest must be selected
independently of the host and supplied by the relying party. Raw reports stay
in memory; the retained report still contains device-identifying metadata.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import re
import subprocess
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
    manifest_identity,
    open_sealed,
)

DEK = hashlib.sha256(b"wcm-issue-77-live-validation-dek").digest()


def _cpu_verifier(root_pem: bytes) -> AzureSnpVtpmVerifier:
    # Endorsements may arrive with evidence, but the evidence source must never
    # get to choose the relying party's trust root.
    trust = TrustStore()
    trust.add_root_pem(root_pem.decode("ascii"))
    return AzureSnpVtpmVerifier(trust)


def _manifest(raw: bytes, expected_sha256: str, serving_image: str) -> WeightCustodyManifest:
    if not re.fullmatch(r"[0-9a-f]{64}", expected_sha256):
        raise ValueError("manifest SHA-256 must be 64 lowercase hexadecimal characters")
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise ValueError("manifest bytes do not match the independently approved digest")
    manifest = WeightCustodyManifest.model_validate(json.loads(raw))
    policy = manifest.release_policy
    if policy.required_gpu_measurement is None:
        raise ValueError("paired validation requires an independently approved GPU measurement")
    approved = policy.required_serving_image.accepted_measurements
    if not any(str(item.measurement) == serving_image and item.status.value == "current"
               for item in approved):
        raise ValueError("serving image must be current in the pinned manifest")
    return manifest


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
    parser.add_argument("--cpu-root", type=Path, required=True,
                        help="independently obtained AMD trust-root PEM")
    parser.add_argument("--gpu-root", type=Path, required=True,
                        help="independently obtained NVIDIA device trust-root PEM")
    parser.add_argument("--manifest", type=Path, required=True,
                        help="relying-party approved manifest; never learned from this run")
    parser.add_argument("--manifest-sha256", required=True,
                        help="independently approved digest of the exact manifest file bytes")
    parser.add_argument("--serving-image", required=True,
                        help="current serving-image measurement from the pinned manifest")
    args = parser.parse_args()
    manifest_raw = args.manifest.read_bytes()
    manifest = _manifest(manifest_raw, args.manifest_sha256, args.serving_image)
    cpu_root = args.cpu_root.read_bytes()
    gpu_root = args.gpu_root.read_bytes()
    cpu_verifier = _cpu_verifier(cpu_root)
    gpu_verifier = build_gpu_verifier(gpu_root)
    if not AzureSnpVtpmProvider.is_available() or not NvidiaCcProvider.is_available():
        raise SystemExit("paired Azure SNP/vTPM and NVIDIA providers are required")

    provider = HardwareCompositeProvider(AzureSnpVtpmProvider(), NvidiaCcProvider())

    weights_hash = str(manifest.weights_hash)
    kbs = KeyBrokerService(
        {weights_hash: DEK},
        challenge_ttl_seconds=1800,
        cpu_quote_verifier=cpu_verifier,
        gpu_report_verifier=gpu_verifier,
        require_channel_binding=True,
        require_cpu_quote_verification=True,
        require_gpu_report_verification=True,
        trusted_manifest_identities={manifest_identity(manifest)},
    )

    captures: list[tuple[str, Any, Any, str]] = []
    for label in ("happy", "substitution-b", "substitution-c"):
        challenge = kbs.issue_challenge()
        private_key, public_key = generate_transport_keypair()
        evidence = provider.produce(
            challenge,
            serving_image_measurement=args.serving_image,
            transport_public_key=public_key,
        )
        if evidence.gpu is None or not evidence.gpu.quote_b64:
            raise RuntimeError("NVIDIA evidence is absent")
        captures.append((label, evidence, private_key, public_key))

    measurements = {item[1].gpu.measurement for item in captures}
    if len(measurements) != 1:
        raise RuntimeError("GPU identity changed across the contemporaneous run")
    if next(iter(measurements)) != manifest.release_policy.required_gpu_measurement.rim_pin:
        raise RuntimeError("observed GPU identity does not match the independently approved manifest")

    summaries = []
    for label, evidence, _, public_key in captures:
        cpu_result = cpu_verifier.verify(
            evidence.cpu.quote_b64,
            expected_nonce=evidence.cpu.nonce_echo,
            channel_binding=bytes.fromhex(public_key),
            expected_workload_measurement=args.serving_image,
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
        "kind": "wcm-paired-hardware-release/v2",
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "release_candidate": args.release_candidate,
        "claim_scope": "report-authentication-and-sealed-test-key-release",
        "test_material_only": True,
        "confidential_inference_validated": False,
        "cpu_gpu_protected_path_validated": False,
        "gpu_firmware_rim_appraised": False,
        "trust_inputs": {
            "source": "relying-party supplied; not learned from observed evidence",
            "cpu_root_pem_sha256": hashlib.sha256(cpu_root).hexdigest(),
            "gpu_root_pem_sha256": hashlib.sha256(gpu_root).hexdigest(),
            "manifest_sha256": hashlib.sha256(manifest_raw).hexdigest(),
            "serving_image_measurement": args.serving_image,
        },
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
