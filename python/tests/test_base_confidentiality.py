"""Explicit base-confidentiality mode and symmetric BYOM (SPEC.md 3.1, section 2).

Covers the schema (defaults, signing, the byom-symmetric structural rule) and
the verifier's non-blocking consistency notes.
"""
from __future__ import annotations

import copy

import pytest
from pydantic import ValidationError

from wcm import (
    BaseConfidentiality,
    DeploymentModel,
    Ed25519Signer,
    VerificationContext,
    WeightCustodyManifest,
    generate_ed25519,
    verify_manifest,
)
from wcm._signing import WCM_SIGNED_FIELDS


def _sign(manifest, kp, role, signer):
    return Ed25519Signer(kp).sign(manifest.unsigned_dict(), role=role, signer=signer)


def _signed(doc: dict):
    m = WeightCustodyManifest.model_validate(doc)
    b, c = generate_ed25519(), generate_ed25519()
    m = m.with_signatures(
        [_sign(m, b, "builder", doc["builder"]["identity"]),
         _sign(m, c, "custodian", doc["custody"]["custodian"])]
    )
    ctx = VerificationContext()
    ctx.add_key(b.public_bytes)
    ctx.add_key(c.public_bytes)
    return m, ctx


# --- schema -----------------------------------------------------------------


def test_defaults_are_confidential_builder_to_customer(example_manifest):
    # The example omits both fields; a manifest that predates them is read as the
    # original posture, not rejected.
    assert example_manifest.base_confidentiality is BaseConfidentiality.confidential
    assert example_manifest.deployment_model is DeploymentModel.builder_to_customer


def test_both_fields_are_signed():
    assert "base_confidentiality" in WCM_SIGNED_FIELDS
    assert "deployment_model" in WCM_SIGNED_FIELDS


def test_tampering_with_base_confidentiality_breaks_the_signature(example_dict):
    doc = copy.deepcopy(example_dict)
    doc["base_confidentiality"] = "open"
    m, ctx = _signed(doc)
    # Flip the value after signing: the pre-image no longer matches.
    forged = m.model_copy(update={"base_confidentiality": BaseConfidentiality.confidential})
    assert not verify_manifest(forged, ctx).ok


def test_byom_symmetric_requires_self_custody(example_dict):
    doc = copy.deepcopy(example_dict)
    doc["deployment_model"] = "byom-symmetric"  # custody is opaque-hosted in the example
    with pytest.raises(ValidationError, match="customer-self-custody"):
        WeightCustodyManifest.model_validate(doc)


def test_byom_symmetric_with_self_custody_is_valid(example_dict):
    doc = copy.deepcopy(example_dict)
    doc["deployment_model"] = "byom-symmetric"
    doc["custody"]["custodian_type"] = "customer-self-custody"
    m = WeightCustodyManifest.model_validate(doc)
    assert m.deployment_model is DeploymentModel.byom_symmetric


# --- verifier consistency notes (non-blocking) ------------------------------


def test_open_base_emits_a_secrecy_disclaimer_note(example_dict):
    doc = copy.deepcopy(example_dict)
    doc["base_confidentiality"] = "open"
    m, ctx = _signed(doc)
    result = verify_manifest(m, ctx)
    assert result.ok  # a note never changes ok
    assert any("does NOT protect the secrecy" in n for n in result.notes)


def test_open_base_flags_secrecy_only_controls(example_dict):
    doc = copy.deepcopy(example_dict)
    doc["base_confidentiality"] = "open"
    doc["release_policy"]["tenancy"] = "dedicated"
    doc["release_policy"]["physical_hardening"] = (
        "tamper-evident-enclosure+access-control+chain-of-custody"
    )
    m, ctx = _signed(doc)
    notes = "\n".join(verify_manifest(m, ctx).notes)
    assert "add little for an open base" in notes
    assert "tenancy=dedicated" in notes
    assert "physical_hardening" in notes


def test_confidential_base_emits_no_notes(example_dict):
    # The default posture is the one the spec was written around: nothing to warn about.
    m, ctx = _signed(copy.deepcopy(example_dict))
    assert verify_manifest(m, ctx).notes == []


def test_gated_open_emits_license_gated_note(example_dict):
    doc = copy.deepcopy(example_dict)
    doc["base_confidentiality"] = "gated-open"
    m, ctx = _signed(doc)
    assert any("license-gated" in n for n in verify_manifest(m, ctx).notes)


def test_byom_symmetric_note_confirms_single_identity(example_dict):
    doc = copy.deepcopy(example_dict)
    doc["deployment_model"] = "byom-symmetric"
    doc["custody"]["custodian_type"] = "customer-self-custody"
    doc["custody"]["custodian"] = doc["builder"]["identity"]  # same org, both roles
    m, ctx = _signed(doc)
    assert any("holding both roles" in n for n in verify_manifest(m, ctx).notes)


def test_byom_symmetric_note_warns_on_differing_identities(example_dict):
    doc = copy.deepcopy(example_dict)
    doc["deployment_model"] = "byom-symmetric"
    doc["custody"]["custodian_type"] = "customer-self-custody"
    # builder 'example-builder' vs custodian 'opaque-systems' differ
    m, ctx = _signed(doc)
    assert any("confirm both belong to the same governing org" in n
               for n in verify_manifest(m, ctx).notes)
