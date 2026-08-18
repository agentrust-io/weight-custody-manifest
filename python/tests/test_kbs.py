from __future__ import annotations

import copy
from datetime import datetime, timezone

import pytest

from wcm import (
    KeyBrokerService,
    SealError,
    SoftwareProvider,
    WeightCustodyManifest,
    generate_transport_keypair,
    open_sealed,
)

KEY = b"decryption-key-for-these-weights"


def _now_before_retire():
    # 2026-07-15 is before the example's retire_after of 2026-07-16.
    return lambda: datetime(2026, 7, 15, 12, 0, 0, tzinfo=timezone.utc)


def _now_after_retire():
    return lambda: datetime(2026, 7, 19, 12, 0, 0, tzinfo=timezone.utc)


def _kbs(example_manifest, *, now=None, revoked=None, require_channel_binding=False):
    return KeyBrokerService(
        {example_manifest.weights_hash: KEY},
        now=now or _now_after_retire(),
        revoked_attestation_keys=revoked,
        require_channel_binding=require_channel_binding,
    )


def _measurements(example_manifest):
    ams = example_manifest.release_policy.required_serving_image.accepted_measurements
    current = next(m.measurement for m in ams if m.status.value == "current")
    retiring = next(m.measurement for m in ams if m.status.value == "retiring")
    revoked = next(m.measurement for m in ams if m.status.value == "revoked")
    rim = example_manifest.release_policy.required_gpu_measurement.rim_pin
    return current, retiring, revoked, rim


def test_happy_path_releases_key(example_manifest):
    kbs = _kbs(example_manifest)
    current, _, _, rim = _measurements(example_manifest)
    challenge = kbs.issue_challenge()
    evidence = SoftwareProvider().produce(
        challenge, serving_image_measurement=current, gpu_measurement=rim
    )
    decision = kbs.verify_and_release(example_manifest, evidence)
    assert decision.released
    assert decision.key == KEY
    assert not decision.failures


def test_replayed_nonce_denied(example_manifest):
    kbs = _kbs(example_manifest)
    current, _, _, rim = _measurements(example_manifest)
    challenge = kbs.issue_challenge()
    ev = SoftwareProvider().produce(
        challenge, serving_image_measurement=current, gpu_measurement=rim
    )
    assert kbs.verify_and_release(example_manifest, ev).released
    # Same evidence (same nonce) again: replay.
    second = kbs.verify_and_release(example_manifest, ev)
    assert not second.released
    assert second.failures[0].name == "nonce_fresh"


def test_wrong_platform_denied(example_manifest):
    kbs = _kbs(example_manifest)
    current, _, _, rim = _measurements(example_manifest)
    challenge = kbs.issue_challenge()
    ev = SoftwareProvider().produce(
        challenge,
        serving_image_measurement=current,
        gpu_measurement=rim,
        platform="intel-tdx",  # not in required_hw_platform
    )
    decision = kbs.verify_and_release(example_manifest, ev)
    assert not decision.released
    assert any(c.name == "cpu_platform_allowed" and not c.passed for c in decision.checks)


def test_unknown_serving_image_denied(example_manifest):
    kbs = _kbs(example_manifest)
    _, _, _, rim = _measurements(example_manifest)
    challenge = kbs.issue_challenge()
    ev = SoftwareProvider().produce(
        challenge,
        serving_image_measurement="sha256:" + "9" * 64,
        gpu_measurement=rim,
    )
    decision = kbs.verify_and_release(example_manifest, ev)
    assert not decision.released
    assert any(c.name == "serving_image" and not c.passed for c in decision.checks)


def test_revoked_serving_image_denied(example_manifest):
    kbs = _kbs(example_manifest)
    _, _, revoked, rim = _measurements(example_manifest)
    challenge = kbs.issue_challenge()
    ev = SoftwareProvider().produce(
        challenge, serving_image_measurement=revoked, gpu_measurement=rim
    )
    decision = kbs.verify_and_release(example_manifest, ev)
    assert not decision.released
    si = [c for c in decision.checks if c.name == "serving_image"][0]
    assert not si.passed and "revoked" in (si.detail or "")


def test_prefer_current_refuses_retiring(example_manifest):
    kbs = _kbs(example_manifest, now=_now_before_retire())
    _, retiring, _, rim = _measurements(example_manifest)
    challenge = kbs.issue_challenge()
    ev = SoftwareProvider().produce(
        challenge, serving_image_measurement=retiring, gpu_measurement=rim
    )
    decision = kbs.verify_and_release(example_manifest, ev)
    assert not decision.released
    si = [c for c in decision.checks if c.name == "serving_image"][0]
    assert "prefer-current" in (si.detail or "")


def test_retiring_past_retire_after_denied(example_manifest):
    kbs = _kbs(example_manifest, now=_now_after_retire())
    _, retiring, _, rim = _measurements(example_manifest)
    challenge = kbs.issue_challenge()
    ev = SoftwareProvider().produce(
        challenge, serving_image_measurement=retiring, gpu_measurement=rim
    )
    decision = kbs.verify_and_release(example_manifest, ev)
    assert not decision.released
    si = [c for c in decision.checks if c.name == "serving_image"][0]
    assert "retire_after" in (si.detail or "")


def test_gpu_absent_denied(example_manifest):
    kbs = _kbs(example_manifest)
    current, _, _, _ = _measurements(example_manifest)
    challenge = kbs.issue_challenge()
    ev = SoftwareProvider().produce(
        challenge, serving_image_measurement=current, include_gpu=False
    )
    decision = kbs.verify_and_release(example_manifest, ev)
    assert not decision.released
    assert any(c.name == "gpu" and not c.passed for c in decision.checks)


def test_gpu_binding_broken_denied(example_manifest):
    kbs = _kbs(example_manifest)
    current, _, _, rim = _measurements(example_manifest)
    challenge = kbs.issue_challenge()
    ev = SoftwareProvider().produce(
        challenge,
        serving_image_measurement=current,
        gpu_measurement=rim,
        break_gpu_binding=True,
    )
    decision = kbs.verify_and_release(example_manifest, ev)
    assert not decision.released
    gpu = [c for c in decision.checks if c.name == "gpu"][0]
    assert "nonce echo" in (gpu.detail or "")


def test_gpu_measurement_mismatch_denied(example_manifest):
    kbs = _kbs(example_manifest)
    current, _, _, _ = _measurements(example_manifest)
    challenge = kbs.issue_challenge()
    ev = SoftwareProvider().produce(
        challenge, serving_image_measurement=current, gpu_measurement="nvidia-rim:wrong"
    )
    decision = kbs.verify_and_release(example_manifest, ev)
    assert not decision.released
    assert any(c.name == "gpu" and not c.passed for c in decision.checks)


def test_attestation_key_revoked_denied(example_manifest):
    kbs = _kbs(example_manifest, revoked={"vcek-mock-0001"})
    current, _, _, rim = _measurements(example_manifest)
    challenge = kbs.issue_challenge()
    ev = SoftwareProvider().produce(
        challenge, serving_image_measurement=current, gpu_measurement=rim
    )
    decision = kbs.verify_and_release(example_manifest, ev)
    assert not decision.released
    assert any(c.name == "attestation_revocation" and not c.passed for c in decision.checks)


def test_stale_revocation_cache_denied(example_manifest):
    kbs = _kbs(example_manifest)
    current, _, _, rim = _measurements(example_manifest)
    challenge = kbs.issue_challenge()
    ev = SoftwareProvider().produce(
        challenge,
        serving_image_measurement=current,
        gpu_measurement=rim,
        cache_age_seconds=100_000,
    )
    decision = kbs.verify_and_release(example_manifest, ev)
    assert not decision.released
    assert any(c.name == "attestation_revocation" and not c.passed for c in decision.checks)


def test_no_key_for_weights_hash_denied(example_manifest):
    kbs = KeyBrokerService({}, now=_now_after_retire())  # empty keystore
    current, _, _, rim = _measurements(example_manifest)
    challenge = kbs.issue_challenge()
    ev = SoftwareProvider().produce(
        challenge, serving_image_measurement=current, gpu_measurement=rim
    )
    decision = kbs.verify_and_release(example_manifest, ev)
    assert not decision.released
    assert any(c.name == "key_available" and not c.passed for c in decision.checks)


# -- v0.8 memory-fingerprint challenge (hostile-owner posture) ----------------


def _hostile_manifest(example_dict) -> WeightCustodyManifest:
    example_dict["release_policy"]["memory_fingerprint_challenge"] = (
        "required-for-hostile-owner-posture"
    )
    example_dict["release_policy"]["physical_hardening"] = (
        "tamper-evident-enclosure+access-control+chain-of-custody"
    )
    return WeightCustodyManifest.model_validate(example_dict)


def test_memory_fingerprint_required_but_absent_denied(example_dict):
    manifest = _hostile_manifest(example_dict)
    kbs = _kbs(manifest)
    current, _, _, rim = _measurements(manifest)
    challenge = kbs.issue_challenge()
    ev = SoftwareProvider().produce(
        challenge, serving_image_measurement=current, gpu_measurement=rim
    )  # no memory fingerprint
    decision = kbs.verify_and_release(manifest, ev)
    assert not decision.released
    mf = [c for c in decision.checks if c.name == "memory_fingerprint"][0]
    assert "not present" in (mf.detail or "")


def test_memory_fingerprint_aliasing_denied(example_dict):
    manifest = _hostile_manifest(example_dict)
    kbs = _kbs(manifest)
    current, _, _, rim = _measurements(manifest)
    challenge = kbs.issue_challenge()
    ev = SoftwareProvider().produce(
        challenge,
        serving_image_measurement=current,
        gpu_measurement=rim,
        include_memory_fingerprint=True,
        aliasing_detected=True,
    )
    decision = kbs.verify_and_release(manifest, ev)
    assert not decision.released
    mf = [c for c in decision.checks if c.name == "memory_fingerprint"][0]
    assert "aliasing" in (mf.detail or "")


def test_memory_fingerprint_clean_releases(example_dict):
    manifest = _hostile_manifest(example_dict)
    kbs = _kbs(manifest)
    current, _, _, rim = _measurements(manifest)
    challenge = kbs.issue_challenge()
    ev = SoftwareProvider().produce(
        challenge,
        serving_image_measurement=current,
        gpu_measurement=rim,
        include_memory_fingerprint=True,
        aliasing_detected=False,
    )
    decision = kbs.verify_and_release(manifest, ev)
    assert decision.released
    assert decision.key == KEY


# -- the sweep the gate is checking (issue #79) --------------------------------
#
# The mechanism itself is tested in test_memory_sweep.py and the attestation
# binding end to end in test_quote_verify.py. These are the gate's decisions
# about a response: what it re-derives, what it refuses, and what it says when
# it is trusting structure rather than hardware.


def _hostile_evidence(kbs, manifest, **kwargs):
    current, _, _, rim = _measurements(manifest)
    challenge = kbs.issue_challenge()
    return SoftwareProvider().produce(
        challenge,
        serving_image_measurement=current,
        gpu_measurement=rim,
        include_memory_fingerprint=True,
        **kwargs,
    )


def _mf_check(decision):
    return [c for c in decision.checks if c.name == "memory_fingerprint"][0]


def test_memory_fingerprint_is_checked_against_a_re_derived_sweep(example_dict):
    """The clean path is not taken on trust: the gate recomputes the readback the
    challenge and the declared range imply, and the provider's real sweep matches
    it."""
    manifest = _hostile_manifest(example_dict)
    kbs = _kbs(manifest)
    ev = _hostile_evidence(kbs, manifest)
    from wcm.memory_sweep import ProtectedRange, expected_readback_hash

    declared = ProtectedRange(**ev.memory_fingerprint.declared_range.model_dump())
    assert str(ev.memory_fingerprint.readback_hash) == expected_readback_hash(
        ev.cpu.nonce_echo, declared
    )
    assert kbs.verify_and_release(manifest, ev).released


def test_memory_fingerprint_without_a_declared_range_denied(example_dict):
    manifest = _hostile_manifest(example_dict)
    kbs = _kbs(manifest)
    ev = _hostile_evidence(kbs, manifest)
    ev.memory_fingerprint.declared_range = None
    decision = kbs.verify_and_release(manifest, ev)
    assert not decision.released
    assert "no declared protected-memory range" in (_mf_check(decision).detail or "")


def test_memory_fingerprint_below_the_sweep_floor_denied(example_dict):
    """A range the enclave declares is a range the enclave chose. Without a floor
    a single granule satisfies the challenge."""
    manifest = _hostile_manifest(example_dict)
    kbs = KeyBrokerService(
        {manifest.weights_hash: KEY},
        now=_now_after_retire(),
        min_memory_sweep_bytes=1 << 30,
    )
    decision = kbs.verify_and_release(manifest, _hostile_evidence(kbs, manifest))
    assert not decision.released
    assert "below the" in (_mf_check(decision).detail or "")


def test_memory_fingerprint_readback_from_another_challenge_denied(example_dict):
    """A clean sweep run under an earlier nonce, relabelled with this one. The
    nonce field matches, so only re-deriving the readback catches it."""
    manifest = _hostile_manifest(example_dict)
    kbs = _kbs(manifest)
    stale = _hostile_evidence(kbs, manifest)
    ev = _hostile_evidence(kbs, manifest)
    ev.memory_fingerprint.readback_hash = stale.memory_fingerprint.readback_hash
    decision = kbs.verify_and_release(manifest, ev)
    assert not decision.released
    assert "readback does not match" in (_mf_check(decision).detail or "")


def test_memory_fingerprint_commitment_over_another_result_denied(example_dict):
    manifest = _hostile_manifest(example_dict)
    kbs = _kbs(manifest)
    other = _hostile_evidence(kbs, manifest)
    ev = _hostile_evidence(kbs, manifest)
    ev.memory_fingerprint.commitment = other.memory_fingerprint.commitment
    decision = kbs.verify_and_release(manifest, ev)
    assert not decision.released
    assert "commitment does not match" in (_mf_check(decision).detail or "")


def test_memory_fingerprint_malformed_commitment_denied(example_dict):
    manifest = _hostile_manifest(example_dict)
    kbs = _kbs(manifest)
    ev = _hostile_evidence(kbs, manifest)
    ev.memory_fingerprint.commitment = "not-hex"
    decision = kbs.verify_and_release(manifest, ev)
    assert not decision.released
    assert "not valid hex" in (_mf_check(decision).detail or "")


def test_unbound_fingerprint_passes_but_says_it_is_structural_only(example_dict):
    """A correct readback with nothing attesting it. The gate accepts it in the
    default posture and states the limit rather than reporting it as verified
    hardware evidence."""
    manifest = _hostile_manifest(example_dict)
    kbs = _kbs(manifest)
    ev = _hostile_evidence(kbs, manifest)
    ev.memory_fingerprint.commitment = None
    decision = kbs.verify_and_release(manifest, ev)
    assert decision.released
    assert "structural trust only" in (_mf_check(decision).detail or "")


def test_binding_required_rejects_a_result_nothing_attests(example_dict):
    """The host-authored case. The readback is arithmetic anyone can redo from
    the nonce and the range, so a KBS that requires the binding refuses a
    response that carries no commitment."""
    manifest = _hostile_manifest(example_dict)
    kbs = KeyBrokerService(
        {manifest.weights_hash: KEY},
        now=_now_after_retire(),
        require_memory_fingerprint_binding=True,
    )
    ev = _hostile_evidence(kbs, manifest)
    ev.memory_fingerprint.commitment = None
    decision = kbs.verify_and_release(manifest, ev)
    assert not decision.released
    assert "carries no commitment" in (_mf_check(decision).detail or "")


def test_binding_required_without_a_quote_verifier_fails_closed(example_dict):
    """A commitment nobody checks against a signed quote is not a binding. The
    gate refuses rather than reporting one it did not verify."""
    manifest = _hostile_manifest(example_dict)
    kbs = KeyBrokerService(
        {manifest.weights_hash: KEY},
        now=_now_after_retire(),
        require_memory_fingerprint_binding=True,
    )
    decision = kbs.verify_and_release(manifest, _hostile_evidence(kbs, manifest))
    assert not decision.released
    assert "no CPU quote verifier" in (_mf_check(decision).detail or "")


def test_a_real_aliased_sweep_is_what_trips_the_aliasing_denial(example_dict):
    """The provider does not set the flag; it sweeps a region that aliases and
    the sweep reports what it found."""
    manifest = _hostile_manifest(example_dict)
    kbs = _kbs(manifest)
    ev = _hostile_evidence(kbs, manifest, aliasing_detected=True)
    assert ev.memory_fingerprint.aliasing_detected is True
    decision = kbs.verify_and_release(manifest, ev)
    assert not decision.released
    assert "aliasing" in (_mf_check(decision).detail or "")


# -- channel binding (SPEC 3.2, CVE-2026-33697 relay defense) ------------------


def test_channel_binding_off_by_default_returns_raw_key(example_manifest):
    # Backward compatibility: no channel binding required, raw key as before.
    kbs = _kbs(example_manifest)
    current, _, _, rim = _measurements(example_manifest)
    challenge = kbs.issue_challenge()
    ev = SoftwareProvider().produce(
        challenge, serving_image_measurement=current, gpu_measurement=rim
    )
    decision = kbs.verify_and_release(example_manifest, ev)
    assert decision.released
    assert decision.key == KEY and decision.sealed_key is None


def test_channel_binding_required_seals_key_to_enclave(example_manifest):
    kbs = _kbs(example_manifest, require_channel_binding=True)
    current, _, _, rim = _measurements(example_manifest)
    challenge = kbs.issue_challenge()
    enclave_priv, enclave_pub = generate_transport_keypair()
    ev = SoftwareProvider().produce(
        challenge,
        serving_image_measurement=current,
        gpu_measurement=rim,
        transport_public_key=enclave_pub,
    )
    decision = kbs.verify_and_release(example_manifest, ev)
    assert decision.released
    # The raw key never crosses the channel; only the enclave transport key opens it.
    assert decision.key is None
    assert decision.sealed_key is not None
    assert open_sealed(decision.sealed_key, enclave_priv) == KEY
    # A relay holding a different channel key gets only ciphertext.
    attacker_priv, _ = generate_transport_keypair()
    with pytest.raises(SealError):
        open_sealed(decision.sealed_key, attacker_priv)


def test_channel_binding_required_but_absent_denied(example_manifest):
    kbs = _kbs(example_manifest, require_channel_binding=True)
    current, _, _, rim = _measurements(example_manifest)
    challenge = kbs.issue_challenge()
    ev = SoftwareProvider().produce(
        challenge, serving_image_measurement=current, gpu_measurement=rim
    )  # no transport_public_key
    decision = kbs.verify_and_release(example_manifest, ev)
    assert not decision.released
    assert decision.sealed_key is None
    cb = [c for c in decision.checks if c.name == "channel_binding"][0]
    assert not cb.passed and "transport_public_key" in (cb.detail or "")


def test_channel_binding_malformed_transport_key_denied(example_manifest):
    kbs = _kbs(example_manifest, require_channel_binding=True)
    current, _, _, rim = _measurements(example_manifest)
    challenge = kbs.issue_challenge()
    ev = SoftwareProvider().produce(
        challenge,
        serving_image_measurement=current,
        gpu_measurement=rim,
        transport_public_key="zz" * 32,  # not valid hex
    )
    decision = kbs.verify_and_release(example_manifest, ev)
    assert not decision.released
    cb = [c for c in decision.checks if c.name == "channel_binding"][0]
    assert not cb.passed


# ---------------------------------------------------------------------------
# retire_after parsing
#
# The value arrives in a manifest, so the gate cannot assume it is well formed.
# Found while building the L2 conformance vectors: a naive timestamp used to raise
# TypeError out of verify_and_release, aborting the release path on a manifest that
# had merely omitted a timezone offset.
# ---------------------------------------------------------------------------


def _retiring_only_manifest(example_dict, retire_after):
    """A manifest whose only accepted image is retiring, with *retire_after* verbatim."""
    doc = copy.deepcopy(example_dict)
    rsi = doc["release_policy"]["required_serving_image"]
    retiring = rsi["accepted_measurements"][1]["measurement"]
    rsi["accepted_measurements"] = [
        {"measurement": retiring, "status": "retiring", "retire_after": retire_after}
    ]
    return WeightCustodyManifest.model_validate(doc), retiring


def _decide(manifest, measurement, *, now):
    kbs = KeyBrokerService({str(manifest.weights_hash): b"k" * 32}, now=now)
    challenge = kbs.issue_challenge()
    rim = manifest.release_policy.required_gpu_measurement
    ev = SoftwareProvider().produce(
        challenge,
        serving_image_measurement=measurement,
        gpu_measurement=rim.rim_pin if rim else None,
    )
    decision = kbs.verify_and_release(manifest, ev)
    return decision, [c for c in decision.checks if c.name == "serving_image"][0]


def test_naive_retire_after_is_read_as_utc_and_does_not_raise(example_dict):
    """A timestamp with no offset must compare, not blow up."""
    manifest, measurement = _retiring_only_manifest(example_dict, "2026-07-16T00:00:00")
    decision, _ = _decide(
        manifest, measurement, now=lambda: datetime(2026, 1, 1, tzinfo=timezone.utc)
    )
    assert decision.released, [c for c in decision.checks if not c.passed]


def test_naive_retire_after_still_expires(example_dict):
    """Reading it as UTC must not turn the deadline off."""
    manifest, measurement = _retiring_only_manifest(example_dict, "2026-07-16T00:00:00")
    decision, check = _decide(
        manifest, measurement, now=lambda: datetime(2026, 8, 1, tzinfo=timezone.utc)
    )
    assert not decision.released
    assert "past retire_after" in (check.detail or "")


def test_aware_retire_after_keeps_its_offset(example_dict):
    """An explicit offset is honoured rather than overwritten with UTC.

    23:00 on 2026-07-15 at +02:00 is 21:00 UTC, so a 22:00 UTC clock is past it.
    Reading the value as UTC instead would put the deadline an hour in the future
    and wrongly release.
    """
    manifest, measurement = _retiring_only_manifest(
        example_dict, "2026-07-15T23:00:00+02:00"
    )
    decision, check = _decide(
        manifest, measurement, now=lambda: datetime(2026, 7, 15, 22, tzinfo=timezone.utc)
    )
    assert not decision.released
    assert "past retire_after" in (check.detail or "")


@pytest.mark.parametrize("bad", ["soon", "", "2026-13-45T99:99:99", "next tuesday"])
def test_unparseable_retire_after_fails_closed(example_dict, bad):
    """A deadline we cannot read is not a deadline that has not passed."""
    manifest, measurement = _retiring_only_manifest(example_dict, bad)
    decision, check = _decide(
        manifest, measurement, now=lambda: datetime(2026, 1, 1, tzinfo=timezone.utc)
    )
    assert not decision.released
    assert "not a parseable timestamp" in (check.detail or "")
