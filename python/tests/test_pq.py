"""Post-quantum profile: ML-DSA-65 and the Ed25519+ML-DSA-65 hybrid.

Uses cryptography's native ML-DSA (FIPS 204) — no external liboqs, fully
exercised in CI. Covers the primitives and manifest joint-verification across
the standard, post-quantum, and hybrid profiles.
"""
from __future__ import annotations

import pytest
from cryptography.exceptions import InvalidSignature

from wcm import (
    HybridSigner,
    HybridVerifier,
    MlDsa65Signer,
    MlDsa65Verifier,
    VerificationContext,
    generate_ed25519,
    generate_hybrid,
    generate_ml_dsa65,
    ml_dsa65_from_seed_b64url,
    verify_manifest,
)


# -- ML-DSA-65 primitive -------------------------------------------------------


def test_ml_dsa65_sign_verify_roundtrip(example_manifest):
    kp = generate_ml_dsa65()
    block = MlDsa65Signer(kp).sign(
        example_manifest.unsigned_dict(), role="builder", signer="b"
    )
    assert block["algorithm"] == "ML-DSA-65"
    MlDsa65Verifier(kp.public_bytes).verify(
        example_manifest.unsigned_dict(), block["signature_value"]
    )


def test_ml_dsa65_tamper_fails(example_manifest):
    kp = generate_ml_dsa65()
    block = MlDsa65Signer(kp).sign(example_manifest.unsigned_dict(), role="builder", signer="b")
    tampered = example_manifest.unsigned_dict()
    tampered["weights_hash"] = "sha256:" + "0" * 64
    with pytest.raises(InvalidSignature):
        MlDsa65Verifier(kp.public_bytes).verify(tampered, block["signature_value"])


def test_ml_dsa65_wrong_key_fails(example_manifest):
    kp, other = generate_ml_dsa65(), generate_ml_dsa65()
    block = MlDsa65Signer(kp).sign(example_manifest.unsigned_dict(), role="builder", signer="b")
    with pytest.raises(InvalidSignature):
        MlDsa65Verifier(other.public_bytes).verify(
            example_manifest.unsigned_dict(), block["signature_value"]
        )


def test_ml_dsa65_seed_roundtrip():
    kp = generate_ml_dsa65()
    restored = ml_dsa65_from_seed_b64url(kp.private_b64url())
    assert restored.key_id == kp.key_id


def test_ml_dsa65_keypair_repr_redacts():
    kp = generate_ml_dsa65()
    assert "REDACTED" in repr(kp)


# -- hybrid primitive ----------------------------------------------------------


def test_hybrid_sign_verify(example_manifest):
    hkp = generate_hybrid()
    block = HybridSigner(hkp).sign(example_manifest.unsigned_dict(), role="builder", signer="b")
    assert block["algorithm"] == "hybrid-Ed25519-ML-DSA-65"
    assert block["signature_value"] == ""
    HybridVerifier(hkp.ed25519.public_bytes, hkp.ml_dsa65.public_bytes).verify(
        example_manifest.unsigned_dict(), block["classical_signature"], block["pq_signature"]
    )


def test_hybrid_fails_if_classical_broken(example_manifest):
    hkp = generate_hybrid()
    block = HybridSigner(hkp).sign(example_manifest.unsigned_dict(), role="builder", signer="b")
    other = generate_ed25519()
    # Verify with the wrong classical key: classical component must fail.
    with pytest.raises(InvalidSignature):
        HybridVerifier(other.public_bytes, hkp.ml_dsa65.public_bytes).verify(
            example_manifest.unsigned_dict(),
            block["classical_signature"],
            block["pq_signature"],
        )


def test_hybrid_fails_if_pq_broken(example_manifest):
    hkp = generate_hybrid()
    block = HybridSigner(hkp).sign(example_manifest.unsigned_dict(), role="builder", signer="b")
    other = generate_ml_dsa65()
    with pytest.raises(InvalidSignature):
        HybridVerifier(hkp.ed25519.public_bytes, other.public_bytes).verify(
            example_manifest.unsigned_dict(),
            block["classical_signature"],
            block["pq_signature"],
        )


# -- manifest joint verification across profiles -------------------------------


def test_manifest_ml_dsa65_profile(example_manifest):
    b, c = generate_ml_dsa65(), generate_ml_dsa65()
    signed = example_manifest.with_signatures(
        [
            MlDsa65Signer(b).sign(example_manifest.unsigned_dict(), role="builder", signer="example-builder"),
            MlDsa65Signer(c).sign(example_manifest.unsigned_dict(), role="custodian", signer="opaque-systems"),
        ]
    )
    ctx = VerificationContext()
    ctx.add_ml_dsa65_key(b.public_bytes)
    ctx.add_ml_dsa65_key(c.public_bytes)
    assert verify_manifest(signed, ctx).ok


def test_manifest_hybrid_profile(example_manifest):
    b, c = generate_hybrid(), generate_hybrid()
    signed = example_manifest.with_signatures(
        [
            HybridSigner(b).sign(example_manifest.unsigned_dict(), role="builder", signer="example-builder"),
            HybridSigner(c).sign(example_manifest.unsigned_dict(), role="custodian", signer="opaque-systems"),
        ]
    )
    ctx = VerificationContext()
    ctx.add_hybrid_key(b.ed25519.public_bytes, b.ml_dsa65.public_bytes)
    ctx.add_hybrid_key(c.ed25519.public_bytes, c.ml_dsa65.public_bytes)
    assert verify_manifest(signed, ctx).ok


def test_manifest_mixed_profiles(example_manifest):
    b = generate_ed25519()
    c = generate_ml_dsa65()
    from wcm import Ed25519Signer

    signed = example_manifest.with_signatures(
        [
            Ed25519Signer(b).sign(example_manifest.unsigned_dict(), role="builder", signer="example-builder"),
            MlDsa65Signer(c).sign(example_manifest.unsigned_dict(), role="custodian", signer="opaque-systems"),
        ]
    )
    ctx = VerificationContext()
    ctx.add_key(b.public_bytes)
    ctx.add_ml_dsa65_key(c.public_bytes)
    assert verify_manifest(signed, ctx).ok


def test_algorithm_mismatch_rejected(example_manifest):
    # A key trusted as Ed25519, but a signature block claiming ML-DSA-65 with the
    # same key_id, must be rejected on the algorithm-mismatch path.
    b = generate_ed25519()
    c = generate_ed25519()
    ctx = VerificationContext()
    kid = ctx.add_key(b.public_bytes)
    ctx.add_key(c.public_bytes)
    from wcm import Ed25519Signer

    builder_block = {
        "role": "builder",
        "signer": "example-builder",
        "algorithm": "ML-DSA-65",  # lies about the algorithm
        "key_id": kid,
        "key_type": "software",
        "signature_value": "AA",
    }
    signed = example_manifest.with_signatures(
        [
            builder_block,
            Ed25519Signer(c).sign(example_manifest.unsigned_dict(), role="custodian", signer="opaque-systems"),
        ]
    )
    result = verify_manifest(signed, ctx)
    assert not result.ok
    assert any("algorithm mismatch" in (s.reason or "") for s in result.signatures)


def test_hybrid_missing_component_rejected(example_manifest):
    hkp = generate_hybrid()
    block = HybridSigner(hkp).sign(example_manifest.unsigned_dict(), role="builder", signer="example-builder")
    block["pq_signature"] = None  # drop a component
    c = generate_hybrid()
    signed = example_manifest.with_signatures(
        [
            block,
            HybridSigner(c).sign(example_manifest.unsigned_dict(), role="custodian", signer="opaque-systems"),
        ]
    )
    ctx = VerificationContext()
    ctx.add_hybrid_key(hkp.ed25519.public_bytes, hkp.ml_dsa65.public_bytes)
    ctx.add_hybrid_key(c.ed25519.public_bytes, c.ml_dsa65.public_bytes)
    result = verify_manifest(signed, ctx)
    assert not result.ok
