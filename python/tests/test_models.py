from __future__ import annotations

import pytest
from pydantic import ValidationError

from wcm import (
    MemoryFingerprintChallenge,
    TrustedTimeSource,
    WeightCustodyManifest,
)


def test_example_parses(example_manifest):
    assert example_manifest.manifest_version == "0.1"
    assert example_manifest.weights_hash.algorithm == "sha256"
    rp = example_manifest.release_policy
    assert rp.trusted_time_source is TrustedTimeSource.secure_tsc
    assert rp.memory_fingerprint_challenge is MemoryFingerprintChallenge.not_required


def test_extra_fields_forbidden(example_dict):
    example_dict["unexpected_top_level"] = 1
    with pytest.raises(ValidationError):
        WeightCustodyManifest.model_validate(example_dict)


def test_bad_hash_rejected(example_dict):
    example_dict["weights_hash"] = "sha256:short"
    with pytest.raises(ValidationError):
        WeightCustodyManifest.model_validate(example_dict)


def test_retiring_requires_retire_after(example_dict):
    ams = example_dict["release_policy"]["required_serving_image"]["accepted_measurements"]
    for m in ams:
        if m["status"] == "retiring":
            del m["retire_after"]
    with pytest.raises(ValidationError):
        WeightCustodyManifest.model_validate(example_dict)


def test_retire_after_only_on_retiring(example_dict):
    ams = example_dict["release_policy"]["required_serving_image"]["accepted_measurements"]
    for m in ams:
        if m["status"] == "current":
            m["retire_after"] = "2026-07-16T00:00:00Z"
    with pytest.raises(ValidationError):
        WeightCustodyManifest.model_validate(example_dict)


def test_sovereign_enabled_requires_signer(example_dict):
    sp = example_dict["release_policy"]["sovereign_profile"]
    sp["enabled"] = True
    sp["sovereign_signer"] = None
    with pytest.raises(ValidationError):
        WeightCustodyManifest.model_validate(example_dict)


def test_sovereign_enabled_requires_quorum_revocation(example_dict):
    example_dict["release_policy"]["sovereign_profile"]["enabled"] = True
    example_dict["release_policy"]["sovereign_profile"]["sovereign_signer"] = "sov-team"
    example_dict["release_policy"]["revocation_authority"] = "builder-and-opaque-joint"
    with pytest.raises(ValidationError):
        WeightCustodyManifest.model_validate(example_dict)


def test_sovereign_enabled_valid(example_dict):
    example_dict["release_policy"]["sovereign_profile"]["enabled"] = True
    example_dict["release_policy"]["sovereign_profile"]["sovereign_signer"] = "sov-team"
    example_dict["release_policy"]["revocation_authority"] = "quorum"
    m = WeightCustodyManifest.model_validate(example_dict)
    assert m.release_policy.sovereign_profile.enabled


def test_unsigned_dict_excludes_signatures(example_manifest):
    assert "signatures" not in example_manifest.unsigned_dict()


def test_with_signatures_revalidates(example_manifest):
    block = {
        "role": "builder",
        "signer": "example-builder",
        "algorithm": "Ed25519",
        "key_id": "a" * 64,
        "key_type": "software",
        "signature_value": "AA",
    }
    m = example_manifest.with_signatures([block])
    assert len(m.signatures) == 1
    assert m.signatures[0].signer == "example-builder"
