"""Channel binding is the KBS default (GHSA-x3w3-7mvg-hxw5).

A caller that constructed ``KeyBrokerService`` without the flag used to get the
model key back in the clear, which a relayed quote could collect. These pin the
default and the custody start that consumes a sealed release.
"""
from __future__ import annotations

import pytest

from wcm import (
    EnclaveSession,
    KeyBrokerService,
    SoftwareProvider,
    generate_transport_keypair,
    manifest_identity,
)

KEY = b"a-released-decryption-key-32bytes"


def _kbs(manifest):
    # Deliberately no require_channel_binding argument: the default is under test.
    return KeyBrokerService(
        {manifest.weights_hash: KEY},
        trusted_manifest_identities={manifest_identity(manifest)},
    )


def _evidence(kbs, manifest, transport_public_key=None):
    ams = manifest.release_policy.required_serving_image.accepted_measurements
    current = next(m.measurement for m in ams if m.status.value == "current")
    rim = manifest.release_policy.required_gpu_measurement.rim_pin
    return SoftwareProvider().produce(
        kbs.issue_challenge(), serving_image_measurement=current, gpu_measurement=rim,
        transport_public_key=transport_public_key,
    )


def test_default_never_returns_the_key_in_the_clear(structural_manifest):
    kbs = _kbs(structural_manifest)
    _, pub = generate_transport_keypair()
    decision = kbs.verify_and_release(structural_manifest, _evidence(kbs, structural_manifest, pub))
    assert decision.released
    assert decision.key is None
    assert decision.sealed_key is not None


def test_default_refuses_evidence_without_a_transport_key(structural_manifest):
    kbs = _kbs(structural_manifest)
    decision = kbs.verify_and_release(structural_manifest, _evidence(kbs, structural_manifest))
    assert not decision.released
    assert decision.key is None and decision.sealed_key is None
    cb = next(c for c in decision.checks if c.name == "channel_binding")
    assert not cb.passed


def test_custody_starts_from_a_sealed_release_with_the_enclave_key(structural_manifest):
    kbs = _kbs(structural_manifest)
    priv, pub = generate_transport_keypair()
    decision = kbs.verify_and_release(structural_manifest, _evidence(kbs, structural_manifest, pub))
    session = EnclaveSession.from_release(
        structural_manifest, decision, transport_private_key=priv
    )
    assert session.use_key() == KEY


def test_custody_refuses_a_sealed_release_without_or_with_the_wrong_key(structural_manifest):
    kbs = _kbs(structural_manifest)
    _, pub = generate_transport_keypair()
    decision = kbs.verify_and_release(structural_manifest, _evidence(kbs, structural_manifest, pub))
    with pytest.raises(ValueError, match="no transport_private_key"):
        EnclaveSession.from_release(structural_manifest, decision)
    relay_priv, _ = generate_transport_keypair()
    with pytest.raises(ValueError, match="did not open"):
        EnclaveSession.from_release(
            structural_manifest, decision, transport_private_key=relay_priv
        )


def test_explicit_opt_out_still_returns_the_clear_key(structural_manifest):
    """The unsealed shape stays reachable, but only by asking for it."""
    kbs = KeyBrokerService(
        {structural_manifest.weights_hash: KEY},
        trusted_manifest_identities={manifest_identity(structural_manifest)},
        require_channel_binding=False,
    )
    decision = kbs.verify_and_release(structural_manifest, _evidence(kbs, structural_manifest))
    assert decision.released and decision.key == KEY
