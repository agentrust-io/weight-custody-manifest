from __future__ import annotations

import pytest
from cryptography.exceptions import InvalidSignature

from wcm import (
    Ed25519Signer,
    Ed25519Verifier,
    WCM_SIGNED_FIELDS,
    ed25519_from_private_b64url,
    generate_ed25519,
    signing_pre_image,
)


def test_signed_fields_exclude_signatures():
    assert "signatures" not in WCM_SIGNED_FIELDS
    assert "weights_hash" in WCM_SIGNED_FIELDS
    assert "release_policy" in WCM_SIGNED_FIELDS


def test_pre_image_ignores_unsigned_fields(example_manifest):
    d = example_manifest.unsigned_dict()
    a = signing_pre_image(d)
    d2 = dict(d)
    d2["signatures"] = [{"role": "builder"}]
    d2["some_unknown"] = "x"
    assert signing_pre_image(d2) == a


def test_sign_and_verify_roundtrip(example_manifest):
    kp = generate_ed25519()
    block = Ed25519Signer(kp).sign(
        example_manifest.unsigned_dict(), role="builder", signer="example-builder"
    )
    assert block["role"] == "builder"
    assert block["algorithm"] == "Ed25519"
    assert block["key_id"] == kp.key_id
    Ed25519Verifier(kp.public_bytes).verify(
        example_manifest.unsigned_dict(), block["signature_value"]
    )


def test_verify_fails_on_tamper(example_manifest):
    kp = generate_ed25519()
    block = Ed25519Signer(kp).sign(
        example_manifest.unsigned_dict(), role="builder", signer="example-builder"
    )
    tampered = example_manifest.unsigned_dict()
    tampered["weights_hash"] = "sha256:" + "0" * 64
    with pytest.raises(InvalidSignature):
        Ed25519Verifier(kp.public_bytes).verify(tampered, block["signature_value"])


def test_verify_fails_wrong_key(example_manifest):
    kp = generate_ed25519()
    other = generate_ed25519()
    block = Ed25519Signer(kp).sign(
        example_manifest.unsigned_dict(), role="builder", signer="b"
    )
    with pytest.raises(InvalidSignature):
        Ed25519Verifier(other.public_bytes).verify(
            example_manifest.unsigned_dict(), block["signature_value"]
        )


def test_private_key_roundtrip_b64url(example_manifest):
    kp = generate_ed25519()
    restored = ed25519_from_private_b64url(kp.private_b64url())
    assert restored.key_id == kp.key_id


def test_reject_small_order_key():
    with pytest.raises(ValueError):
        Ed25519Verifier(bytes(32))  # all-zero is a torsion point


def test_reject_wrong_length_key():
    with pytest.raises(ValueError):
        Ed25519Verifier(b"tooshort")


def test_reject_non_urlsafe_signature(example_manifest):
    kp = generate_ed25519()
    with pytest.raises(ValueError):
        Ed25519Verifier(kp.public_bytes).verify(
            example_manifest.unsigned_dict(), "not+valid/base64"
        )


def test_keypair_repr_redacts_private():
    kp = generate_ed25519()
    assert "REDACTED" in repr(kp)
    assert kp.private_b64url() not in repr(kp)


@pytest.mark.parametrize(
    "bad_b64",
    ["AQAB\n", "A", "AB", "AC", "AD", "A" * 42 + "B", "A" * 85 + "B", "AA=", "not+valid/base64"],
)
def test_canonical_base64url_enforced_across_signing_runtime_renewal_and_sweep(bad_b64: str):
    from wcm._signing import _b64url_decode, _b64url_encode
    from wcm.memory_sweep import (
        BytearrayMemoryRange,
        memory_sweep_public_key,
        run_memory_sweep,
        verify_memory_sweep,
    )
    from wcm.renewal import _unb64url as renewal_unb64url
    from wcm.runtime_records import _unb64url as runtime_unb64url

    kp = generate_ed25519()
    assert _b64url_decode(kp.public_b64url()) == kp.public_bytes
    assert renewal_unb64url(kp.public_b64url()) == kp.public_bytes
    assert runtime_unb64url(kp.public_b64url()) == kp.public_bytes
    assert _b64url_encode(kp.public_bytes) == kp.public_b64url()

    with pytest.raises(ValueError):
        _b64url_decode(bad_b64)
    with pytest.raises(ValueError):
        renewal_unb64url(bad_b64)
    with pytest.raises(ValueError):
        runtime_unb64url(bad_b64)

    fp = run_memory_sweep(
        BytearrayMemoryRange(64, page_size=64),
        challenge_nonce="a" * 64,
        signing_key=kp.private_key,
        sweep_secret=b"s" * 32,
    )
    pub_b64 = memory_sweep_public_key(kp.private_key)
    assert verify_memory_sweep(fp, pub_b64)[0]
    tampered_sig = fp.model_copy(update={"signature_b64url": bad_b64})
    assert not verify_memory_sweep(tampered_sig, pub_b64)[0]
    tampered_pub = fp.model_copy(update={"public_key_b64url": bad_b64})
    assert not verify_memory_sweep(tampered_pub, bad_b64)[0]


