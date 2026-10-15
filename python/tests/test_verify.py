from __future__ import annotations

import pytest

from wcm import (
    Ed25519Signer,
    SignatureRole,
    VerificationContext,
    generate_ed25519,
    verify_manifest,
)


def _sign(manifest, kp, role, signer):
    return Ed25519Signer(kp).sign(manifest.unsigned_dict(), role=role, signer=signer)


def test_joint_signature_verifies(example_manifest):
    builder, custodian = generate_ed25519(), generate_ed25519()
    signed = example_manifest.with_signatures(
        [
            _sign(example_manifest, builder, "builder", "example-builder"),
            _sign(example_manifest, custodian, "custodian", "example-custodian"),
        ]
    )
    ctx = VerificationContext()
    ctx.add_key(builder.public_bytes)
    ctx.add_key(custodian.public_bytes)

    result = verify_manifest(signed, ctx)
    assert result.ok
    assert not result.missing_roles
    assert all(s.valid for s in result.signatures)


def test_missing_custodian_fails(example_manifest):
    builder = generate_ed25519()
    signed = example_manifest.with_signatures(
        [_sign(example_manifest, builder, "builder", "example-builder")]
    )
    ctx = VerificationContext()
    ctx.add_key(builder.public_bytes)

    result = verify_manifest(signed, ctx)
    assert not result.ok
    assert SignatureRole.custodian in result.missing_roles


def test_untrusted_key_fails(example_manifest):
    builder, custodian = generate_ed25519(), generate_ed25519()
    signed = example_manifest.with_signatures(
        [
            _sign(example_manifest, builder, "builder", "example-builder"),
            _sign(example_manifest, custodian, "custodian", "example-custodian"),
        ]
    )
    ctx = VerificationContext()
    ctx.add_key(builder.public_bytes)  # custodian key NOT trusted

    result = verify_manifest(signed, ctx)
    assert not result.ok
    custodian_res = [s for s in result.signatures if s.role is SignatureRole.custodian][0]
    assert not custodian_res.valid
    assert "untrusted" in (custodian_res.reason or "")


def test_tampered_manifest_fails(example_manifest):
    builder, custodian = generate_ed25519(), generate_ed25519()
    signed = example_manifest.with_signatures(
        [
            _sign(example_manifest, builder, "builder", "example-builder"),
            _sign(example_manifest, custodian, "custodian", "example-custodian"),
        ]
    )
    # Tamper after signing: bump the attestation cadence.
    tampered = signed.model_copy(deep=True)
    tampered.custody.attestation_cadence = "9999h"

    ctx = VerificationContext()
    ctx.add_key(builder.public_bytes)
    ctx.add_key(custodian.public_bytes)

    result = verify_manifest(tampered, ctx)
    assert not result.ok
    assert not all(s.valid for s in result.signatures)


def test_sovereign_requires_declared_signer(example_dict):
    from wcm import WeightCustodyManifest

    example_dict["release_policy"]["sovereign_profile"]["enabled"] = True
    example_dict["release_policy"]["sovereign_profile"]["sovereign_signer"] = "sov-team"
    example_dict["release_policy"]["revocation_authority"] = "quorum"
    manifest = WeightCustodyManifest.model_validate(example_dict)

    builder, custodian, sovereign = (
        generate_ed25519(),
        generate_ed25519(),
        generate_ed25519(),
    )
    ctx = VerificationContext()
    for kp in (builder, custodian, sovereign):
        ctx.add_key(kp.public_bytes)

    # Wrong sovereign identity: signature is valid but signer != sov-team.
    wrong = manifest.with_signatures(
        [
            _sign(manifest, builder, "builder", "example-builder"),
            _sign(manifest, custodian, "custodian", "example-custodian"),
            _sign(manifest, sovereign, "sovereign", "not-sov-team"),
        ]
    )
    assert not verify_manifest(wrong, ctx).ok

    # Correct sovereign identity.
    right = manifest.with_signatures(
        [
            _sign(manifest, builder, "builder", "example-builder"),
            _sign(manifest, custodian, "custodian", "example-custodian"),
            _sign(manifest, sovereign, "sovereign", "sov-team"),
        ]
    )
    assert verify_manifest(right, ctx).ok


def _relabel(block, role, signer):
    # role and signer sit outside the signed pre-image, so relabelling a block
    # leaves its signature valid.
    return {**block, "role": role, "signer": signer}


def test_one_key_cannot_sign_as_both_builder_and_custodian(example_manifest):
    builder, custodian = generate_ed25519(), generate_ed25519()
    ctx = VerificationContext()
    ctx.add_key(builder.public_bytes)
    ctx.add_key(custodian.public_bytes)
    block = _sign(example_manifest, builder, "builder", "example-builder")
    forged = example_manifest.with_signatures(
        [block, _relabel(block, "custodian", "example-custodian")]
    )

    result = verify_manifest(forged, ctx)
    assert not result.ok
    assert SignatureRole.custodian in result.missing_roles
    assert any("its own key" in e for e in result.errors)


def test_builder_key_cannot_stand_in_for_the_sovereign(example_dict):
    from wcm import WeightCustodyManifest

    example_dict["release_policy"]["sovereign_profile"]["enabled"] = True
    example_dict["release_policy"]["sovereign_profile"]["sovereign_signer"] = "sov-team"
    example_dict["release_policy"]["revocation_authority"] = "quorum"
    manifest = WeightCustodyManifest.model_validate(example_dict)
    builder, custodian, sovereign = (generate_ed25519() for _ in range(3))
    ctx = VerificationContext()
    for kp in (builder, custodian, sovereign):
        ctx.add_key(kp.public_bytes)
    b = _sign(manifest, builder, "builder", "example-builder")
    forged = manifest.with_signatures(
        [b, _sign(manifest, custodian, "custodian", "example-custodian"),
         _relabel(b, "sovereign", "sov-team")]
    )

    result = verify_manifest(forged, ctx)
    assert not result.ok
    assert SignatureRole.sovereign in result.missing_roles


def test_byom_symmetric_single_identity_may_use_one_key(example_dict):
    from wcm import WeightCustodyManifest

    example_dict["deployment_model"] = "byom-symmetric"
    example_dict["custody"]["custodian_type"] = "customer-self-custody"
    example_dict["custody"]["custodian"] = example_dict["builder"]["identity"]
    manifest = WeightCustodyManifest.model_validate(example_dict)
    org = generate_ed25519()
    ctx = VerificationContext()
    ctx.add_key(org.public_bytes)
    block = _sign(manifest, org, "builder", example_dict["builder"]["identity"])
    signed = manifest.with_signatures(
        [block, _relabel(block, "custodian", example_dict["builder"]["identity"])]
    )

    assert verify_manifest(signed, ctx).ok


def _bound_context(manifest, builder, custodian):
    ctx = VerificationContext()
    ctx.bind_key(ctx.add_key(builder.public_bytes), role=SignatureRole.builder,
                 signer=manifest.builder.identity)
    ctx.bind_key(ctx.add_key(custodian.public_bytes), role=SignatureRole.custodian,
                 signer=manifest.custody.custodian)
    return ctx


def test_bound_roles_accept_and_flat_trust_keeps_legacy_behavior(example_manifest):
    builder, custodian, other = (generate_ed25519() for _ in range(3))
    ctx = _bound_context(example_manifest, builder, custodian)
    ctx.add_key(other.public_bytes)
    good = example_manifest.with_signatures([
        _sign(example_manifest, builder, "builder", example_manifest.builder.identity),
        _sign(example_manifest, custodian, "custodian", example_manifest.custody.custodian),
    ])
    assert verify_manifest(good, ctx).ok
    wrong = example_manifest.with_signatures([
        _sign(example_manifest, other, "builder", example_manifest.builder.identity),
        good.signatures[1].model_dump(mode="json"),
    ])
    result = verify_manifest(wrong, ctx)
    assert not result.ok
    assert not result.signatures[0].valid
    assert "not bound" in result.signatures[0].reason
    flat = VerificationContext()
    for key in (builder, custodian, other):
        flat.add_key(key.public_bytes)
    assert verify_manifest(wrong, flat).ok


@pytest.mark.parametrize("case", ["only-builder", "wrong-role", "wrong-identity", "relabel"])
def test_binding_refusals_never_fall_back_to_flat_trust(example_manifest, case):
    builder, custodian = generate_ed25519(), generate_ed25519()
    ctx = VerificationContext()
    ctx.bind_key(ctx.add_key(builder.public_bytes), role=SignatureRole.builder,
                 signer=example_manifest.builder.identity)
    custody_id = ctx.add_key(custodian.public_bytes)
    if case != "only-builder":
        ctx.bind_key(custody_id,
                     role=SignatureRole.builder if case == "wrong-role" else SignatureRole.custodian,
                     signer="other-custodian" if case == "wrong-identity"
                     else example_manifest.custody.custodian)
    signed = example_manifest.with_signatures([
        _sign(example_manifest, builder, "builder", example_manifest.builder.identity),
        _sign(example_manifest, custodian, "custodian",
              "other-custodian" if case == "relabel" else example_manifest.custody.custodian),
    ])
    result = verify_manifest(signed, ctx)
    assert not result.ok
    assert SignatureRole.custodian in result.missing_roles
    assert not result.signatures[1].valid
    assert "not bound" in result.signatures[1].reason


def test_binding_does_not_bypass_signature_verification(example_manifest):
    builder, custodian = generate_ed25519(), generate_ed25519()
    ctx = _bound_context(example_manifest, builder, custodian)
    signed = example_manifest.with_signatures([
        _sign(example_manifest, builder, "builder", example_manifest.builder.identity),
        _sign(example_manifest, custodian, "custodian", example_manifest.custody.custodian),
    ])
    signed.custody.attestation_cadence = "9999h"
    result = verify_manifest(signed, ctx)
    assert not result.ok
    assert all(not sig.valid and "verification failed" in sig.reason for sig in result.signatures)


def test_bound_sovereign_requires_its_own_identity_and_binding(example_dict):
    from wcm import WeightCustodyManifest

    example_dict["release_policy"]["sovereign_profile"].update(
        enabled=True, sovereign_signer="sov-team")
    example_dict["release_policy"]["revocation_authority"] = "quorum"
    manifest = WeightCustodyManifest.model_validate(example_dict)
    builder, custodian, sovereign = (generate_ed25519() for _ in range(3))
    ctx = _bound_context(manifest, builder, custodian)
    sovereign_id = ctx.add_key(sovereign.public_bytes)
    signed = manifest.with_signatures([
        _sign(manifest, builder, "builder", manifest.builder.identity),
        _sign(manifest, custodian, "custodian", manifest.custody.custodian),
        _sign(manifest, sovereign, "sovereign", "sov-team"),
    ])
    assert not verify_manifest(signed, ctx).ok
    ctx.bind_key(sovereign_id, role=SignatureRole.sovereign, signer="other-sovereign")
    assert not verify_manifest(signed, ctx).ok
    ctx.bind_key(sovereign_id, role=SignatureRole.sovereign, signer="sov-team")
    assert verify_manifest(signed, ctx).ok


def test_multiple_bound_keys_support_rotation(example_manifest):
    builder, custodian, rotated = (generate_ed25519() for _ in range(3))
    ctx = _bound_context(example_manifest, builder, custodian)
    ctx.bind_key(ctx.add_key(rotated.public_bytes), role=SignatureRole.builder,
                 signer=example_manifest.builder.identity)
    for key in (builder, rotated):
        signed = example_manifest.with_signatures([
            _sign(example_manifest, key, "builder", example_manifest.builder.identity),
            _sign(example_manifest, custodian, "custodian", example_manifest.custody.custodian),
        ])
        assert verify_manifest(signed, ctx).ok


def test_bound_self_custody_still_requires_both_role_bindings(example_dict):
    from wcm import WeightCustodyManifest

    example_dict["deployment_model"] = "byom-symmetric"
    example_dict["custody"]["custodian_type"] = "customer-self-custody"
    example_dict["custody"]["custodian"] = example_dict["builder"]["identity"]
    manifest = WeightCustodyManifest.model_validate(example_dict)
    org = generate_ed25519()
    block = _sign(manifest, org, "builder", manifest.builder.identity)
    signed = manifest.with_signatures([
        block, _relabel(block, "custodian", manifest.custody.custodian)])
    ctx = VerificationContext()
    key_id = ctx.add_key(org.public_bytes)
    ctx.bind_key(key_id, role=SignatureRole.builder, signer=manifest.builder.identity)
    assert not verify_manifest(signed, ctx).ok
    ctx.bind_key(key_id, role=SignatureRole.custodian, signer=manifest.custody.custodian)
    assert verify_manifest(signed, ctx).ok


def test_invalid_binding_cannot_enable_partial_policy(example_manifest):
    ctx = VerificationContext()
    key_id = ctx.add_key(generate_ed25519().public_bytes)
    with pytest.raises(ValueError, match="untrusted"):
        ctx.bind_key("unknown", role=SignatureRole.builder, signer=example_manifest.builder.identity)
    with pytest.raises(ValueError, match="nonempty"):
        ctx.bind_key(key_id, role=SignatureRole.builder, signer=" ")
    with pytest.raises(ValueError):
        ctx.bind_key(key_id, role="unknown", signer=example_manifest.builder.identity)
    assert not ctx._bindings
