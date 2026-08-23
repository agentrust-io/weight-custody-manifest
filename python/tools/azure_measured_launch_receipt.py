#!/usr/bin/env python3
"""Capture a sanitized Azure SNP/vTPM PCR-23 measured-launch receipt."""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import subprocess
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

from wcm import (
    AzureSnpVtpmProvider,
    AzureSnpVtpmVerifier,
    ChallengeStore,
    TrustStore,
    generate_transport_keypair,
)
from wcm.azure_vtpm import expected_pcr23_digest

THIM_URL = "http://169.254.169.254/metadata/THIM/amd/certification"
SERVING_IMAGE = "sha256:" + "5e2d" * 16
WRONG_SERVING_IMAGE = "sha256:" + "43" * 32


def _split_pems(blob: str) -> list[str]:
    marker = "-----END CERTIFICATE-----"
    return [
        part + marker + "\n"
        for part in blob.split(marker)
        if "BEGIN CERTIFICATE" in part
    ]


def _verifier() -> AzureSnpVtpmVerifier:
    request = urllib.request.Request(THIM_URL, headers={"Metadata": "true"})
    with urllib.request.urlopen(request, timeout=10) as response:  # nosec B310
        thim = json.loads(response.read())
    chain = _split_pems(thim.get("certificateChain", ""))
    if not chain:
        raise RuntimeError("Azure THIM did not return an AMD certificate chain")
    trust = TrustStore()
    trust.add_root_pem(chain[-1])
    return AzureSnpVtpmVerifier(trust)


def _tool_version() -> str:
    result = subprocess.run(
        ["tpm2_getcap", "--version"],
        check=True,
        capture_output=True,
        text=True,
        timeout=20,
    )
    return (result.stdout or result.stderr).strip().splitlines()[0]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--release-candidate", required=True)
    parser.add_argument("--vm-sku", required=True)
    args = parser.parse_args()

    if not AzureSnpVtpmProvider.is_available():
        raise SystemExit("Azure SNP/vTPM provider is not available")

    challenge = ChallengeStore().issue()
    _, transport_public_key = generate_transport_keypair()
    evidence = AzureSnpVtpmProvider().cpu_quote(
        challenge,
        serving_image_measurement=SERVING_IMAGE,
        transport_public_key=transport_public_key,
    )
    verifier = _verifier()
    channel_binding = bytes.fromhex(transport_public_key)
    positive = verifier.verify(
        evidence.quote_b64 or "",
        expected_nonce=challenge.nonce,
        channel_binding=channel_binding,
        expected_workload_measurement=SERVING_IMAGE,
    )
    wrong_measurement = verifier.verify(
        evidence.quote_b64 or "",
        expected_nonce=challenge.nonce,
        channel_binding=channel_binding,
        expected_workload_measurement=WRONG_SERVING_IMAGE,
    )

    passed = positive.verified and not wrong_measurement.verified
    report = {
        "kind": "wcm-azure-measured-launch/v1",
        "captured_at": datetime.now(UTC).isoformat(),
        "classification": "sanitized public validation evidence",
        "release_candidate": args.release_candidate,
        "environment": {
            "provider": "Microsoft Azure",
            "confidential_vm_sku": args.vm_sku,
            "cpu_tee": "AMD SEV-SNP",
            "guest_kernel": platform.release(),
            "tpm2_tools": _tool_version(),
        },
        "measurement": {
            "algorithm": "sha256",
            "pcr": 23,
            "serving_image_sha256": SERVING_IMAGE.removeprefix("sha256:"),
            "expected_pcr23_sha256": expected_pcr23_digest(SERVING_IMAGE).hex(),
        },
        "evidence": {
            "quote_sha256": hashlib.sha256(
                (evidence.quote_b64 or "").encode()
            ).hexdigest(),
            "challenge_sha256": hashlib.sha256(
                bytes.fromhex(challenge.nonce)
            ).hexdigest(),
            "transport_public_key_sha256": hashlib.sha256(channel_binding).hexdigest(),
        },
        "positive": {"verified": positive.verified, "reason": positive.reason},
        "negative_wrong_measurement": {
            "verified": wrong_measurement.verified,
            "reason": wrong_measurement.reason,
        },
        "passed": passed,
        "limits": [
            "Proves one fresh AK-signed quote selected SHA-256 PCR 23 after the WCM reset-and-extend procedure.",
            "Does not prove immunity to physical extraction, memory-bus attacks, or later remapping.",
        ],
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"passed": passed, "out": str(args.out)}))
    return int(not passed)


if __name__ == "__main__":
    raise SystemExit(main())
