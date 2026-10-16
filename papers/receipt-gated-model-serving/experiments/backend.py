"""One interface over the two implementations the experiments can run against.

RGS_BACKEND=reference (default) uses reference/receipt_gate.py in this folder.
RGS_BACKEND=pinned imports the evaluated planner from a snapshot of the pinned
commit (level2.model_host, level2.orchestrator and the hosting fixture in
tests/test_controls.py) from the current working directory. This file contains
no evaluated source; the pinned backend imports it at run time.
"""
from __future__ import annotations

import hashlib
import importlib.util
import os
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

NAME = os.environ.get("RGS_BACKEND", "reference")
IMAGE = "registry.example/model-host@sha256:" + "a" * 64


def _digest(label: str) -> str:
    return "sha256:" + hashlib.sha256(label.encode()).hexdigest()


if NAME == "pinned":
    from level2.model_host import (HostingGrant, RevocationReason, _canonical as canonical,  # noqa: F401
                                   receipt_hash, verify_hosting_receipt as verify_receipt)
    from level2.orchestrator import AdmissionGatedKubernetesPlanner as Planner, KubernetesHostConfig
    PREFIX = "opaque.co"

    def _fixture_class():
        spec = importlib.util.spec_from_file_location("hosting_fixture", Path("tests/test_controls.py").resolve())
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module.ConfidentialModelHostingTests

    def new_session():
        f = _fixture_class()()
        f.setUp()
        return f.grant, f.host, f.signing_key

    def planner_key(planner):
        return planner._receipt_key

    def session_label(planner):
        return planner._session_label

    def serve_once(host, grant):
        from level2.model_host import HostingRequest, digest_prompt
        request = HostingRequest(request_id="request-1", tenant_fingerprint=grant.tenant_fingerprint,
                                 weights_hash=grant.weights_hash, policy_hash=grant.policy_hash,
                                 prompt_digest=digest_prompt("synthetic prompt"))
        return host.serve(request, "synthetic prompt").receipt
else:
    sys.path.insert(0, str(Path(__file__).resolve().parent / "reference"))
    from receipt_gate import (HostingGrant, RevocationReason, canonical, receipt_hash,  # noqa: F401
                              verify_receipt, AdmissionGatedPlanner as Planner, KubernetesHostConfig,
                              ModelHost, LABEL_PREFIX as PREFIX)

    def new_session():
        key = Ed25519PrivateKey.generate()
        raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        grant = HostingGrant(
            session_nonce_hash=_digest("session-nonce"), tenant_fingerprint=_digest("tenant"),
            weights_hash=_digest("weights"), encrypted_artifact_hash=_digest("ciphertext"),
            workload_hash=_digest("workload"), policy_hash=_digest("policy"),
            transport_hash=_digest("transport"), receipt_signing_key_hash="sha256:" + hashlib.sha256(raw).hexdigest())
        host = ModelHost(grant, key, release_key=lambda: b"synthetic-model-key", wipe=lambda: None)
        return grant, host, key

    def planner_key(planner):
        return planner._receipt_key

    def session_label(planner):
        return planner.session_label

    def serve_once(host, grant):
        return host.record_inference("request-1", _digest("synthetic prompt"), _digest("synthetic result"))

ADMISSION_ANNOTATION = PREFIX + "/admission-receipt-hash"


def make_planner(grant, name: str, key_b64url: str):
    return Planner(grant, KubernetesHostConfig(
        name=name, namespace="model-hosting", image=IMAGE, runtime_class="confidential-gpu",
        encrypted_model_claim="encrypted-model",
        container_args=("serve-confidential-model", "--await-attested-release")),
        receipt_public_key_b64url=key_b64url)
