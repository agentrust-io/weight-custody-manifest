"""Unit tests for the reference implementation. Run: python -m pytest -q experiments/reference"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(Path(__file__).resolve().parent))
from receipt_gate import (AdmissionGatedPlanner, HostingGrant, KubernetesHostConfig, LABEL_PREFIX,  # noqa: E402
                          ModelHost, RevocationReason, receipt_hash)

IMAGE = "registry.example/model-host@sha256:" + "a" * 64


def digest(label):
    return "sha256:" + hashlib.sha256(label.encode()).hexdigest()


def session(key=None):
    key = key or Ed25519PrivateKey.generate()
    raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    grant = HostingGrant(digest("nonce"), digest("tenant"), digest("weights"), digest("ciphertext"),
                         digest("workload"), digest("policy"), digest("transport"),
                         "sha256:" + hashlib.sha256(raw).hexdigest())
    host = ModelHost(grant, key, release_key=lambda: b"k", wipe=lambda: None)
    return grant, host, key


def planner_for(grant, key_b64url):
    return AdmissionGatedPlanner(grant, KubernetesHostConfig(
        name="confidential-model-host", namespace="model-hosting", image=IMAGE, runtime_class="confidential-gpu",
        encrypted_model_claim="encrypted-model", container_args=("serve",)), receipt_public_key_b64url=key_b64url)


def test_workload_contains_ciphertext_but_no_key_or_secret():
    grant, host, _ = session()
    pod = planner_for(grant, host.public_key_b64url).workload_manifest()
    text = json.dumps(pod).lower()
    assert pod["kind"] == "Pod" and pod["spec"]["restartPolicy"] == "Never"
    assert pod["spec"]["automountServiceAccountToken"] is False
    assert "encrypted-model" in text and "model-key" not in text and '"secret"' not in text
    security = pod["spec"]["containers"][0]["securityContext"]
    assert security["readOnlyRootFilesystem"] and security["capabilities"]["drop"] == ["ALL"]


def test_service_only_for_pinned_admission():
    grant, host, _ = session()
    admission = host.start(grant.bindings())
    service = planner_for(grant, host.public_key_b64url).service_manifest(admission)
    assert service["kind"] == "Service" and service["spec"]["type"] == "ClusterIP"
    assert service["metadata"]["annotations"][LABEL_PREFIX + "/admission-receipt-hash"] == receipt_hash(admission)


def test_tampered_or_denied_admission_refused():
    grant, host, key = session()
    planner = planner_for(grant, host.public_key_b64url)
    tampered = json.loads(json.dumps(host.start(grant.bindings())))
    tampered["decision"] = "deny"
    with pytest.raises(ValueError, match="receipt signature invalid"):
        planner.service_manifest(tampered)
    denied_host = ModelHost(grant, key, release_key=lambda: b"k", wipe=lambda: None)
    denial = denied_host.start({**grant.bindings(), "workload_hash": digest("wrong-workload")})
    with pytest.raises(ValueError, match="admission state mismatch"):
        planner.service_manifest(denial)


def test_wrong_signer_or_session_refused():
    grant, host, key = session()
    other_grant, other_host, _ = session()
    with pytest.raises(ValueError, match="independently pinned key"):
        planner_for(grant, host.public_key_b64url).service_manifest(other_host.start(other_grant.bindings()))
    # Same signer, different session: a second grant that differs only in its nonce.
    sibling = HostingGrant(**{**grant.bindings(), "session_nonce_hash": digest("another-nonce")})
    sibling_host = ModelHost(sibling, key, release_key=lambda: b"k", wipe=lambda: None)
    with pytest.raises(ValueError, match="session identity mismatch"):
        planner_for(grant, host.public_key_b64url).service_manifest(sibling_host.start(sibling.bindings()))


def test_digest_pinned_image_required():
    with pytest.raises(ValueError, match="pinned"):
        KubernetesHostConfig(name="h", namespace="n", image="registry.example/model-host:latest",
                             runtime_class="r", encrypted_model_claim="c", container_args=("serve",))


def test_chained_revocation_authorizes_service_delete():
    grant, host, _ = session()
    planner = planner_for(grant, host.public_key_b64url)
    admission = host.start(grant.bindings())
    revocation = host.revoke(RevocationReason.policy)
    target = planner.service_delete_target(revocation, expected_previous_hash=receipt_hash(admission))
    assert target["operation"] == "delete" and target["kind"] == "Service"
    assert target["metadata"]["annotations"][LABEL_PREFIX + "/revocation-receipt-hash"] == receipt_hash(revocation)
    with pytest.raises(ValueError, match="predecessor mismatch"):
        planner.service_delete_target(revocation, expected_previous_hash=digest("wrong-predecessor"))


def test_pinned_key_must_match_grant():
    grant, _, _ = session()
    _, other_host, _ = session()
    with pytest.raises(ValueError, match="receipt_signing_key_hash"):
        planner_for(grant, other_host.public_key_b64url)


def test_served_requests_move_the_chain_head():
    grant, host, _ = session()
    planner = planner_for(grant, host.public_key_b64url)
    admission = host.start(grant.bindings())
    served = host.record_inference("r1", digest("prompt"), digest("result"))
    revocation = host.revoke(RevocationReason.emergency)
    with pytest.raises(ValueError, match="predecessor mismatch"):
        planner.service_delete_target(revocation, expected_previous_hash=receipt_hash(admission))
    assert planner.service_delete_target(revocation, expected_previous_hash=receipt_hash(served))["operation"] == "delete"
