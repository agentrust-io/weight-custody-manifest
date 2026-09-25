from __future__ import annotations

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
            _sign(example_manifest, custodian, "custodian", "opaque-systems"),
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
            _sign(example_manifest, custodian, "custodian", "opaque-systems"),
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
            _sign(example_manifest, custodian, "custodian", "opaque-systems"),
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
            _sign(manifest, custodian, "custodian", "opaque-systems"),
            _sign(manifest, sovereign, "sovereign", "not-sov-team"),
        ]
    )
    assert not verify_manifest(wrong, ctx).ok

    # Correct sovereign identity.
    right = manifest.with_signatures(
        [
            _sign(manifest, builder, "builder", "example-builder"),
            _sign(manifest, custodian, "custodian", "opaque-systems"),
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
        [block, _relabel(block, "custodian", "opaque-systems")]
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
        [b, _sign(manifest, custodian, "custodian", "opaque-systems"),
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
