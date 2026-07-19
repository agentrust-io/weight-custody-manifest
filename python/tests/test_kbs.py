from __future__ import annotations

from datetime import datetime, timezone

import pytest

from wcm import (
    KeyBrokerService,
    SoftwareProvider,
    WeightCustodyManifest,
)

KEY = b"decryption-key-for-these-weights"


def _now_before_retire():
    # 2026-07-15 is before the example's retire_after of 2026-07-16.
    return lambda: datetime(2026, 7, 15, 12, 0, 0, tzinfo=timezone.utc)


def _now_after_retire():
    return lambda: datetime(2026, 7, 19, 12, 0, 0, tzinfo=timezone.utc)


def _kbs(example_manifest, *, now=None, revoked=None):
    return KeyBrokerService(
        {example_manifest.weights_hash: KEY},
        now=now or _now_after_retire(),
        revoked_attestation_keys=revoked,
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
