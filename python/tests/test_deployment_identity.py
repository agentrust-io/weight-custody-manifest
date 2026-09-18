"""Owner-side approval and synthetic signed-SNP substitution tests, not hardware evidence."""
from dataclasses import asdict, replace
import hashlib
import json
import subprocess
import sys

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

from wcm import generate_transport_keypair
from wcm._challenge import ChallengeError
from wcm.deployment_identity import (
    DeploymentApproval, ROLES, SnpLaunchParameters, derive_approval, load_approval,
)
from wcm.provisioning import OwnerProvisioner, open_provisioned_key
from tests.test_provisioning import KEY, POLICY, report_for
from tests.test_snp import NOW, _vcek_chain

LAUNCH = SnpLaunchParameters(vmm_type="QEMU", vcpus=1, vcpu_type="EPYC-v4", guest_features="0x1")


@pytest.fixture
def artifacts(tmp_path):
    files = {}
    for role in ROLES:
        files[role] = tmp_path / role
        files[role].write_bytes(("synthetic " + role + "\n").encode())
    return files


def approval_for(files, policy=POLICY):
    return derive_approval(artifacts=files, launch=LAUNCH,
                           expected_measurement_hex=policy.measurement_hex, policy=policy)


def test_derivation_is_independent_of_paths_and_dictionary_order(artifacts, tmp_path):
    approval = approval_for(artifacts)
    # Independent serializer/hash, including bytes read directly from artifacts.
    expected = {
        "profile": "wcm/snp-direct-boot-initrd/v1",
        "artifacts": [{"role": role, "sha256": hashlib.sha256(artifacts[role].read_bytes()).hexdigest(),
                       "size": len(artifacts[role].read_bytes())} for role in sorted(artifacts)],
        "launch": {"vmm_type": "QEMU", "vcpus": 1, "vcpu_type": "EPYC-v4", "guest_features": "0x1"},
        "expected_measurement_hex": "11" * 48,
        "effective_configuration_sha256": "22" * 32,
        "provisioning_policy_sha256": hashlib.sha256(POLICY.context()).hexdigest(),
    }
    encoded = json.dumps(expected, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    assert approval.canonical_bytes() == encoded
    assert approval.identity() == "sha256:" + hashlib.sha256(b"wcm/deployment-approval/v1\0" + encoded).hexdigest()
    relocated = {}
    for role in reversed(ROLES):
        relocated[role] = tmp_path / (role + ".copy")
        relocated[role].write_bytes(artifacts[role].read_bytes())
    assert approval_for(relocated).identity() == approval.identity()
    approval.require_artifacts(relocated)


@pytest.mark.parametrize("role", ROLES)
def test_each_artifact_substitution_is_rejected(artifacts, role):
    approval = approval_for(artifacts)
    artifacts[role].write_bytes(b"substituted bytes")
    with pytest.raises(ValueError, match="substitution"):
        approval.require_artifacts(artifacts)
    assert approval_for(artifacts).identity() != approval.identity()


@pytest.mark.parametrize("attack", ["missing", "extra", "empty", "duplicate", "reordered", "unsupported", "uppercase", "extra-field"])
def test_ambiguous_or_unsupported_identity_refused(artifacts, attack):
    approval = approval_for(artifacts)
    if attack in {"missing", "extra", "empty"}:
        if attack == "missing":
            artifacts.pop("application")
        elif attack == "extra":
            artifacts["unmeasured_disk"] = artifacts["application"]
        else:
            artifacts["application"].write_bytes(b"")
        with pytest.raises(ValueError):
            approval_for(artifacts)
        return
    raw = approval.model_dump(mode="json")
    if attack == "duplicate":
        raw["artifacts"].append(raw["artifacts"][0])
    elif attack == "reordered":
        raw["artifacts"].reverse()
    elif attack == "unsupported":
        raw["profile"] = "wcm/oci-is-attestation/v1"
    elif attack == "uppercase":
        raw["expected_measurement_hex"] = "AA" * 48
    else:
        raw["hardware_validated"] = True
    with pytest.raises(ValidationError):
        DeploymentApproval.model_validate_json(json.dumps(raw))


def test_approval_pin_and_duplicate_members_are_checked(artifacts, tmp_path):
    approval = approval_for(artifacts)
    path = tmp_path / "approval.json"
    path.write_bytes(approval.canonical_bytes())
    assert load_approval(path, approval.identity()) == approval
    with pytest.raises(ValueError, match="owner pin"):
        load_approval(path, "sha256:" + "00" * 32)
    path.write_text('{"profile":"first",' + approval.canonical_bytes().decode()[1:])
    with pytest.raises(ValueError, match="duplicate"):
        load_approval(path, approval.identity())


@pytest.mark.parametrize("changes", [
    {"measurement_hex": "44" * 48}, {"configuration_sha256": "44" * 32},
    {"epoch": 2}, {"weights_hash": "sha256:" + "44" * 32},
    {"guest_policy": 1}, {"minimum_tcb_le_hex": "00" * 8},
    {"required_platform_fields": frozenset()}, {"forbidden_platform_fields": frozenset()},
])
def test_owner_refuses_policy_not_covered_by_pinned_approval(artifacts, changes):
    root, _, _ = _vcek_chain()
    with pytest.raises(ValueError, match="deployment approval"):
        OwnerProvisioner(replace(POLICY, **changes), deployment_approval=approval_for(artifacts),
                         owner_signing_key=Ed25519PrivateKey.generate(), trusted_root=root, now=lambda: NOW)


@pytest.mark.parametrize("attack", [None, "measurement", "configuration", "transport", "replay", "policy-update"])
def test_identity_constrained_provisioning_uses_real_signed_report_and_sealed_key(artifacts, attack):
    root, vcek, signing = _vcek_chain()
    owner_key = Ed25519PrivateKey.generate()
    owner = OwnerProvisioner(POLICY, deployment_approval=approval_for(artifacts),
                             owner_signing_key=owner_key, trusted_root=root, now=lambda: NOW)
    private, public = generate_transport_keypair()
    nonce = owner.issue_challenge().nonce
    report_policy = replace(POLICY, configuration_sha256="44" * 32) if attack == "configuration" else POLICY
    raw = report_for(signing, nonce, public, report_policy,
                     measurement=b"m" * 48 if attack == "measurement" else None)
    args = dict(nonce=nonce, report=raw, vcek=vcek, intermediates=[],
                transport_public_key="99" * 32 if attack == "transport" else public, model_key=KEY)
    if attack == "policy-update":
        with pytest.raises(ValueError, match="deployment approval"):
            owner.update_policy(replace(POLICY, epoch=2))
    if attack in {"measurement", "configuration", "transport"}:
        with pytest.raises(ValueError):
            owner.provision(**args)
        return
    envelope = owner.provision(**args)
    assert open_provisioned_key(envelope, policy=POLICY, transport_private_key=private,
                               trusted_owner=owner_key.public_key()) == KEY
    if attack == "replay":
        with pytest.raises(ChallengeError, match="already used"):
            owner.provision(**args)


def test_cli_derives_and_checks_before_deployment(artifacts, tmp_path):
    policy = asdict(POLICY)
    for name in ("required_platform_fields", "forbidden_platform_fields"):
        policy[name] = sorted(policy[name])
    (tmp_path / "policy.json").write_text(json.dumps(policy))
    inputs = tmp_path / "inputs.json"
    inputs.write_text(json.dumps({
        "artifacts": {role: str(path) for role, path in artifacts.items()},
        "launch": LAUNCH.model_dump(), "expected_measurement_hex": POLICY.measurement_hex,
        "policy_file": "policy.json",
    }))
    command = [sys.executable, "-m", "wcm.deployment_identity", str(inputs)]
    candidate = subprocess.run(command, capture_output=True, text=True, check=True)
    approval = DeploymentApproval.model_validate_json(candidate.stdout)
    path = tmp_path / "approval.json"
    path.write_text(candidate.stdout)
    command += ["--verify-approval", str(path), "--expected-identity", approval.identity(), "--identity-only"]
    assert subprocess.run(command, capture_output=True, text=True, check=True).stdout.strip() == approval.identity()
    artifacts["application"].write_bytes(b"different program")
    denied = subprocess.run(command, capture_output=True, text=True)
    assert denied.returncode == 1
    assert not denied.stdout
    assert "different program" not in denied.stderr
