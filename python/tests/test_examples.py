"""The shipped example must always parse and round-trip. This is the gate that
catches spec/model/example drift (``extra="forbid"`` does the rest)."""
from __future__ import annotations

from wcm import (
    Ed25519Signer,
    VerificationContext,
    generate_ed25519,
    verify_manifest,
)


def test_example_starts_unsigned(example_manifest):
    assert example_manifest.signatures == []


def test_example_signs_and_verifies(example_manifest):
    builder, custodian = generate_ed25519(), generate_ed25519()
    signed = example_manifest.with_signatures(
        [
            Ed25519Signer(builder).sign(
                example_manifest.unsigned_dict(), role="builder", signer="example-builder"
            ),
            Ed25519Signer(custodian).sign(
                example_manifest.unsigned_dict(), role="custodian", signer="opaque-systems"
            ),
        ]
    )
    ctx = VerificationContext()
    ctx.add_key(builder.public_bytes)
    ctx.add_key(custodian.public_bytes)
    assert verify_manifest(signed, ctx).ok
