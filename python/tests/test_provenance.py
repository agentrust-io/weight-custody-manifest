"""OpenSSF model-signing provenance interop.

Two layers. The signed ``provenance`` field (schema, and that it is under the
joint signature) needs no external dependency. ``verify_provenance``
cryptographically checks a real model-signing signature; those tests are guarded
so they skip cleanly if the ``model-signing`` extra is absent, and run for real
when it is installed (it is in the dev extra).
"""
from __future__ import annotations

import copy

import pytest

from wcm import (
    Ed25519Signer,
    VerificationContext,
    WeightCustodyManifest,
    generate_ed25519,
    verify_manifest,
    verify_provenance,
)

try:
    import model_signing  # noqa: F401

    HAVE_MS = True
except ImportError:
    HAVE_MS = False

requires_ms = pytest.mark.skipif(not HAVE_MS, reason="model-signing extra not installed")

PROV = {
    "model_signing": {
        "method": "openssf-model-signing",
        "signed_digest": "sha256:" + "a" * 64,
        "transparency": "rekor:123456",
        "signer": "release@frontier-labs.example",
    }
}


def _sign(doc: dict):
    b, c = generate_ed25519(), generate_ed25519()
    m = WeightCustodyManifest.model_validate(doc)
    m = m.with_signatures([
        Ed25519Signer(b).sign(m.unsigned_dict(), role="builder", signer="builder"),
        Ed25519Signer(c).sign(m.unsigned_dict(), role="custodian", signer="custodian"),
    ])
    ctx = VerificationContext()
    ctx.add_key(b.public_bytes)
    ctx.add_key(c.public_bytes)
    return m, ctx


# -- the signed field, no external dependency ---------------------------------


def test_provenance_is_under_the_joint_signature(example_dict):
    doc = copy.deepcopy(example_dict)
    doc["provenance"] = PROV
    m, ctx = _sign(doc)
    assert verify_manifest(m, ctx).ok

    # Tamper the provenance after signing: the joint signature no longer covers it.
    tampered = m.model_dump(mode="json", exclude_none=True)
    tampered["provenance"]["model_signing"]["signed_digest"] = "sha256:" + "b" * 64
    tm = WeightCustodyManifest.model_validate(tampered)
    assert not verify_manifest(tm, ctx).ok


def test_verify_manifest_notes_the_provenance(example_dict):
    doc = copy.deepcopy(example_dict)
    doc["provenance"] = PROV
    m, ctx = _sign(doc)
    result = verify_manifest(m, ctx)
    assert result.ok
    assert any("model-signing" in n and "signed_digest" in n for n in result.notes)


def test_absent_provenance_is_backward_compatible(example_dict):
    m, ctx = _sign(copy.deepcopy(example_dict))
    result = verify_manifest(m, ctx)
    assert result.ok
    assert not any("provenance" in n for n in result.notes)


# -- verify_provenance against a real model-signing signature -----------------


def _write_ec_keys(tmp_path):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    priv = ec.generate_private_key(ec.SECP256R1())
    priv_p = tmp_path / "key.pem"
    priv_p.write_bytes(
        priv.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    pub_p = tmp_path / "key.pub"
    pub_p.write_bytes(
        priv.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )
    return priv_p, pub_p


def _sign_model(tmp_path, content=b"weights-v1"):
    priv_p, pub_p = _write_ec_keys(tmp_path)
    model = tmp_path / "model.bin"
    model.write_bytes(content)
    sig = tmp_path / "model.sig"
    model_signing.signing.Config().use_elliptic_key_signer(private_key=str(priv_p)).sign(
        str(model), str(sig)
    )
    return model, sig, pub_p


def _manifest_with_provenance(example_dict, signed_digest):
    doc = copy.deepcopy(example_dict)
    doc["provenance"] = {"model_signing": {"signed_digest": signed_digest}}
    m, _ = _sign(doc)
    return m


@requires_ms
def test_verify_provenance_round_trip(example_dict, tmp_path):
    from wcm import model_signing_digest

    model, sig, pub = _sign_model(tmp_path)
    digest = model_signing_digest(str(model))
    m = _manifest_with_provenance(example_dict, digest)

    result = verify_provenance(m, str(model), str(sig), public_key=str(pub))
    assert result.verified, result.reason


@requires_ms
def test_verify_provenance_rejects_wrong_digest(example_dict, tmp_path):
    model, sig, pub = _sign_model(tmp_path)
    # A valid signature, but the manifest records a digest for a different artifact.
    m = _manifest_with_provenance(example_dict, "sha256:" + "0" * 64)
    result = verify_provenance(m, str(model), str(sig), public_key=str(pub))
    assert not result.verified
    assert "signed_digest mismatch" in (result.reason or "")


@requires_ms
def test_verify_provenance_rejects_tampered_model(example_dict, tmp_path):
    from wcm import model_signing_digest

    model, sig, pub = _sign_model(tmp_path)
    digest = model_signing_digest(str(model))
    m = _manifest_with_provenance(example_dict, digest)
    # Tamper the model after signing: model-signing verification must fail first.
    model.write_bytes(b"weights-TAMPERED-after-signing")
    result = verify_provenance(m, str(model), str(sig), public_key=str(pub))
    assert not result.verified
    assert "did not verify" in (result.reason or "")


@requires_ms
def test_verify_provenance_requires_the_reference(example_dict, tmp_path):
    model, sig, pub = _sign_model(tmp_path)
    m, _ = _sign(copy.deepcopy(example_dict))  # no provenance field
    result = verify_provenance(m, str(model), str(sig), public_key=str(pub))
    assert not result.verified
    assert "no provenance" in (result.reason or "")
