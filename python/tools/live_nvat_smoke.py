#!/usr/bin/env python3
"""Live WCM -> NVAT adapter -> WCM verifier smoke test on an H100 CVM."""
from __future__ import annotations

import argparse
import json
import os

from wcm import KeyBrokerService, NvidiaCcProvider, build_gpu_verifier


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--device-root", required=True)
    parser.add_argument("--adapter", default="/usr/local/bin/wcm-nvat-adapter")
    args = parser.parse_args()

    os.environ["WCM_NVIDIA_ATTESTATION_CMD"] = args.adapter
    challenge = KeyBrokerService({}).issue_challenge()
    report = NvidiaCcProvider().gpu_report(challenge)
    if not report.quote_b64:
        raise SystemExit("adapter returned no cryptographic GPU evidence")
    with open(args.device_root, encoding="utf-8") as handle:
        verifier = build_gpu_verifier(handle.read())
    verified = verifier.verify(report.quote_b64, expected_nonce=challenge.nonce)
    result = {
        "nonce": challenge.nonce,
        "platform": report.platform,
        "measurement": report.measurement,
        "cc_mode": report.cc_mode,
        "raw_report_verified": verified.verified,
        "verification_reason": verified.reason,
        "leaf_subject": verified.leaf_subject,
    }
    print(json.dumps(result, indent=2))
    return 0 if verified.verified else 1


if __name__ == "__main__":
    raise SystemExit(main())
