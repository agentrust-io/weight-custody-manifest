"""Binding and lifecycle boundary experiment for the stateless planner.

1. Re-sign six admission receipts with the trusted test key, each with one
   application binding changed. Each must verify as a signature and still be
   refused by the planner, naming the changed field.
2. Admit, revoke, then submit the original admission to the same planner. A
   stateless planner is expected to return a Service: that is the lifecycle
   limit the controller experiment addresses.

Usage: [RGS_BACKEND=reference|pinned] python boundary_experiment.py
Prints a JSON object; exits 0 when both observations match.
"""
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import backend as b  # noqa: E402

FIELDS = ["tenant_fingerprint", "weights_hash", "encrypted_artifact_hash", "workload_hash", "policy_hash",
          "transport_hash"]


def main() -> dict:
    grant, host, signing_key = b.new_session()
    planner = b.make_planner(grant, "confidential-model-host", host.public_key_b64url)
    receipt = host.start(grant.bindings())
    assert planner.service_manifest(receipt)["kind"] == "Service"
    observed = []
    for field in FIELDS:
        changed = json.loads(json.dumps(receipt))
        changed[field] = "sha256:" + hashlib.sha256((field + "-different").encode()).hexdigest()
        verification = changed.pop("verification")
        verification["signature_b64url"] = base64.urlsafe_b64encode(
            signing_key.sign(b.canonical(changed))).rstrip(b"=").decode()
        changed["verification"] = verification
        valid, errors = b.verify_receipt(changed)
        assert valid, errors  # the signature is valid; only the expected binding differs
        try:
            planner.service_manifest(changed)
        except ValueError as exc:
            assert f"admission {field} mismatch" in str(exc), str(exc)
            observed.append(field)
        else:
            raise AssertionError("accepted mismatched " + field)
    host.revoke(b.RevocationReason.policy)
    old_accepted = planner.service_manifest(receipt)["kind"] == "Service"
    assert old_accepted
    return {"backend": b.NAME, "valid_signature_wrong_binding_rejections": observed, "rejections": len(observed),
            "old_admission_after_revocation_accepted_by_planner": old_accepted,
            "limit": "A controller must persist lifecycle state and refuse a stale admission; the planner cannot."}


if __name__ == "__main__":
    print(json.dumps(main(), indent=2))
