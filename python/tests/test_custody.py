from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from wcm.renewal import manifest_identity

from wcm import (
    EnclaveSession,
    KeyBrokerService,
    KeyWipedError,
    ReattestationRequired,
    SessionState,
    SoftwareProvider,
    TimeFloor,
    TrustedTimeSource,
    parse_cadence,
)

KEY = b"a-released-decryption-key-32bytes"


class Clock:
    def __init__(self, start: datetime) -> None:
        self.t = start

    def __call__(self) -> datetime:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t = self.t + timedelta(seconds=seconds)


def _clock() -> Clock:
    return Clock(datetime(2026, 7, 19, 12, 0, 0, tzinfo=timezone.utc))


# -- parse_cadence -------------------------------------------------------------


@pytest.mark.parametrize(
    "text,seconds",
    [("30s", 30), ("15m", 900), ("1h", 3600), ("24h", 86400), ("1d", 86400)],
)
def test_parse_cadence_valid(text, seconds):
    assert parse_cadence(text) == seconds


@pytest.mark.parametrize("text", ["", "24", "h", "0h", "1w", "-5m", "abc"])
def test_parse_cadence_invalid(text):
    with pytest.raises(ValueError):
        parse_cadence(text)


# -- lifecycle -----------------------------------------------------------------


def test_holding_serves_key():
    s = EnclaveSession(KEY, cadence_seconds=3600, now=_clock())
    assert s.state is SessionState.holding
    assert s.use_key() == KEY


def test_use_key_returns_independent_copy():
    s = EnclaveSession(KEY, cadence_seconds=3600, now=_clock())
    k = s.use_key()
    assert k == KEY and k is not None  # a bytes copy, not the internal buffer


def test_lapse_zeroizes_key():
    clock = _clock()
    s = EnclaveSession(KEY, cadence_seconds=3600, now=clock)
    clock.advance(3601)
    assert s.tick() is SessionState.wiped
    assert s.is_wiped
    with pytest.raises(KeyWipedError):
        s.use_key()


def test_use_key_within_window_ok():
    clock = _clock()
    s = EnclaveSession(KEY, cadence_seconds=3600, now=clock)
    clock.advance(3599)
    assert s.use_key() == KEY


def test_reattest_renews_window():
    clock = _clock()
    s = EnclaveSession(KEY, cadence_seconds=3600, now=clock)
    clock.advance(3000)
    s.reattest()  # renew; new deadline is now + 3600
    clock.advance(3000)  # 6000s from start, but only 3000s since renewal
    assert s.use_key() == KEY
    assert s.state is SessionState.holding


def test_reattest_after_lapse_raises():
    clock = _clock()
    s = EnclaveSession(KEY, cadence_seconds=3600, now=clock)
    clock.advance(3601)
    with pytest.raises(KeyWipedError):
        s.reattest()
    assert s.is_wiped


def test_zeroize_idempotent():
    s = EnclaveSession(KEY, cadence_seconds=3600, now=_clock())
    s.zeroize()
    s.zeroize()  # no raise
    assert s.is_wiped
    with pytest.raises(KeyWipedError):
        s.use_key()


def test_remaining_seconds():
    clock = _clock()
    s = EnclaveSession(KEY, cadence_seconds=3600, now=clock)
    clock.advance(600)
    assert s.remaining_seconds() == pytest.approx(3000.0)
    s.zeroize()
    assert s.remaining_seconds() == 0.0


def test_tick_on_wiped_is_noop():
    s = EnclaveSession(KEY, cadence_seconds=3600, now=_clock())
    s.zeroize()
    assert s.tick() is SessionState.wiped


# -- trusted-time honesty ------------------------------------------------------


@pytest.mark.parametrize(
    "tts,floor",
    [
        ("secure-tsc", TimeFloor.sound),
        ("lease-with-op-count-hybrid", TimeFloor.weaker),
        ("none-best-effort", TimeFloor.none),
    ],
)
def test_time_floor_reflects_trusted_time_source(tts, floor):
    from wcm import TrustedTimeSource

    s = EnclaveSession(
        KEY,
        cadence_seconds=3600,
        trusted_time_source=TrustedTimeSource(tts),
        now=_clock(),
    )
    assert s.time_floor is floor


# -- integration with the KBS release ------------------------------------------


def _released_decision(manifest, clock):
    kbs = KeyBrokerService(
        {manifest.weights_hash: KEY},
        now=clock,
        trusted_manifest_identities={manifest_identity(manifest)},
    )
    ams = manifest.release_policy.required_serving_image.accepted_measurements
    current = next(m.measurement for m in ams if m.status.value == "current")
    rim = manifest.release_policy.required_gpu_measurement.rim_pin
    ch = kbs.issue_challenge()
    ev = SoftwareProvider().produce(
        ch, serving_image_measurement=current, gpu_measurement=rim
    )
    return kbs.verify_and_release(manifest, ev)


def test_from_release_starts_custody(example_manifest):
    clock = _clock()
    decision = _released_decision(example_manifest, clock)
    assert decision.released

    session = EnclaveSession.from_release(example_manifest, decision, now=clock)
    assert session.use_key() == KEY
    # example cadence is 24h.
    assert session.remaining_seconds() == pytest.approx(86400.0)

    clock.advance(86401)
    with pytest.raises(KeyWipedError):
        session.use_key()


def test_from_release_rejects_unreleased(example_manifest):
    from wcm import ReleaseDecision

    denied = ReleaseDecision(released=False, key=None, checks=[])
    with pytest.raises(ValueError):
        EnclaveSession.from_release(example_manifest, denied)


# -- operation-count-anchored renewal (hybrid serving case) --------------------


def test_no_op_cap_is_unlimited():
    s = EnclaveSession(KEY, cadence_seconds=3600, now=_clock())
    for _ in range(1000):
        assert s.use_key() == KEY
    assert s.operations_remaining() is None
    assert s.operations_used == 1000


def test_op_budget_exhaustion_requires_reattest():
    s = EnclaveSession(
        KEY,
        cadence_seconds=3600,
        trusted_time_source=TrustedTimeSource.lease_with_op_count_hybrid,
        max_operations=3,
        now=_clock(),
    )
    for _ in range(3):
        assert s.use_key() == KEY
    assert s.operations_remaining() == 0
    with pytest.raises(ReattestationRequired):
        s.use_key()
    # The key is NOT wiped: this is a pause for re-attestation, not a lapse.
    assert s.state is SessionState.holding


def test_authorize_operation_counts_without_exporting_key():
    s = EnclaveSession(KEY, cadence_seconds=3600, max_operations=2, now=_clock())
    assert s.authorize_operation() is None
    assert s.operations_used == 1
    assert s.operations_remaining() == 1
    assert s.authorize_operation() is None
    with pytest.raises(ReattestationRequired):
        s.authorize_operation()
    assert s.state is SessionState.holding


def test_authorize_operation_lapse_zeroizes_key():
    clock = _clock()
    s = EnclaveSession(KEY, cadence_seconds=10, max_operations=100, now=clock)
    clock.advance(11)
    with pytest.raises(KeyWipedError):
        s.authorize_operation()
    assert s.is_wiped


def test_use_key_and_authorize_operation_share_one_budget():
    s = EnclaveSession(KEY, cadence_seconds=3600, max_operations=2, now=_clock())
    assert s.use_key() == KEY
    assert s.authorize_operation() is None
    with pytest.raises(ReattestationRequired):
        s.use_key()


def test_reattest_resets_op_budget():
    s = EnclaveSession(KEY, cadence_seconds=3600, max_operations=2, now=_clock())
    s.use_key()
    s.use_key()
    with pytest.raises(ReattestationRequired):
        s.use_key()
    s.reattest()
    assert s.operations_remaining() == 2
    assert s.use_key() == KEY


def test_op_budget_independent_of_wall_clock():
    clock = _clock()
    s = EnclaveSession(KEY, cadence_seconds=3600, max_operations=1, now=clock)
    s.use_key()
    clock.advance(10)  # still well within the wall-clock window
    with pytest.raises(ReattestationRequired):
        s.use_key()


def test_wall_clock_lapse_still_wipes_with_op_cap():
    clock = _clock()
    s = EnclaveSession(KEY, cadence_seconds=3600, max_operations=100, now=clock)
    clock.advance(3601)
    with pytest.raises(KeyWipedError):
        s.use_key()


def test_invalid_max_operations():
    with pytest.raises(ValueError):
        EnclaveSession(KEY, cadence_seconds=3600, max_operations=0)


def test_from_release_passes_max_operations(example_manifest):
    clock = _clock()
    decision = _released_decision(example_manifest, clock)
    session = EnclaveSession.from_release(
        example_manifest, decision, max_operations=1, now=clock
    )
    session.use_key()
    with pytest.raises(ReattestationRequired):
        session.use_key()


# -- signed evidence-bound renewal --------------------------------------------


def _session_and_kbs(
    manifest, clock, *, max_operations=1, renewal_ttl=60, renewal_signing_key=None,
):
    kbs = KeyBrokerService(
        {manifest.weights_hash: KEY}, now=clock,
        renewal_decision_ttl_seconds=renewal_ttl,
        renewal_signing_key=renewal_signing_key,
        trusted_manifest_identities={manifest_identity(manifest)},
    )
    current = next(
        item.measurement
        for item in manifest.release_policy.required_serving_image.accepted_measurements
        if item.status.value == "current"
    )
    rim = manifest.release_policy.required_gpu_measurement.rim_pin
    challenge = kbs.issue_challenge()
    evidence = SoftwareProvider().produce(
        challenge, serving_image_measurement=current, gpu_measurement=rim,
    )
    release = kbs.verify_and_release(manifest, evidence)
    session = EnclaveSession.from_release(
        manifest, release, max_operations=max_operations, now=clock,
    )
    return session, kbs, current, rim


def _renew(kbs, manifest, current, rim):
    challenge = kbs.issue_challenge()
    evidence = SoftwareProvider().produce(
        challenge, serving_image_measurement=current, gpu_measurement=rim,
    )
    return kbs.verify_for_renewal(manifest, evidence)


def test_signed_renewal_resets_budget_without_exporting_key(example_manifest):
    clock = _clock()
    session, kbs, current, rim = _session_and_kbs(example_manifest, clock)
    assert session.use_key() == KEY
    with pytest.raises(ReattestationRequired):
        session.authorize_operation()
    decision = _renew(kbs, example_manifest, current, rim)
    assert decision.renewed
    assert not hasattr(decision, "key")
    assert decision.verify(decision.public_key_b64url)
    session.apply_renewal(example_manifest, decision)
    assert session.operations_remaining() == 1
    session.authorize_operation()


def test_renewal_decision_is_single_use(example_manifest):
    clock = _clock()
    session, kbs, current, rim = _session_and_kbs(example_manifest, clock)
    decision = _renew(kbs, example_manifest, current, rim)
    session.apply_renewal(example_manifest, decision)
    with pytest.raises(ValueError, match="already applied"):
        session.apply_renewal(example_manifest, decision)


def test_kbs_nonce_replay_produces_signed_failed_renewal(example_manifest):
    clock = _clock()
    session, kbs, current, rim = _session_and_kbs(example_manifest, clock)
    challenge = kbs.issue_challenge()
    evidence = SoftwareProvider().produce(
        challenge, serving_image_measurement=current, gpu_measurement=rim,
    )
    first = kbs.verify_for_renewal(example_manifest, evidence)
    replay = kbs.verify_for_renewal(example_manifest, evidence)
    assert first.renewed
    assert not replay.renewed
    assert replay.verify(first.public_key_b64url)
    assert replay.checks[0]["name"] == "nonce_fresh"
    assert replay.checks[0]["passed"] is False
    with pytest.raises(ValueError, match="failed gate"):
        session.apply_renewal(example_manifest, replay)


def test_renewal_refuses_wrong_signer_and_tampering(example_manifest):
    from dataclasses import replace

    clock = _clock()
    session, kbs, current, rim = _session_and_kbs(example_manifest, clock)
    valid = _renew(kbs, example_manifest, current, rim)
    tampered = replace(
        valid,
        evidence_hash="sha256:" + "0" * 64,
    )
    with pytest.raises(ValueError, match="signature or signer"):
        session.apply_renewal(example_manifest, tampered)
    malformed = replace(valid, signature_b64url="***")
    assert not malformed.verify(malformed.public_key_b64url)
    wrong_kind = replace(valid, kind="another-protocol/v1")
    assert not wrong_kind.verify(wrong_kind.public_key_b64url)

    other = KeyBrokerService(
        {example_manifest.weights_hash: KEY},
        now=clock,
        trusted_manifest_identities={manifest_identity(example_manifest)},
    )
    wrong_signer = _renew(other, example_manifest, current, rim)
    with pytest.raises(ValueError, match="signature or signer"):
        session.apply_renewal(example_manifest, wrong_signer)


def test_renewal_refuses_signed_truncated_gate_list(example_manifest):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from wcm.renewal import sign_renewal_decision

    clock = _clock()
    signer = Ed25519PrivateKey.generate()
    session, kbs, current, rim = _session_and_kbs(
        example_manifest, clock, renewal_signing_key=signer,
    )
    valid = _renew(kbs, example_manifest, current, rim)
    challenge = kbs.issue_challenge()
    evidence = SoftwareProvider().produce(
        challenge, serving_image_measurement=current, gpu_measurement=rim,
    )
    truncated = sign_renewal_decision(
        signing_key=signer,
        renewed=True,
        manifest=example_manifest,
        evidence=evidence,
        issued_at=valid.issued_at,
        expires_at=valid.expires_at,
        checks=valid.checks[:-1],
    )
    assert truncated.verify(valid.public_key_b64url)
    with pytest.raises(ValueError, match="failed gate"):
        session.apply_renewal(example_manifest, truncated)


def test_renewal_refuses_cross_model_and_policy_drift(example_manifest, example_dict):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from wcm import WeightCustodyManifest

    clock = _clock()
    signer = Ed25519PrivateKey.generate()
    session, _, current, rim = _session_and_kbs(
        example_manifest, clock, renewal_signing_key=signer,
    )
    other_dict = dict(example_dict)
    other_dict["weights_hash"] = "sha256:" + "1" * 64
    other_manifest = WeightCustodyManifest.model_validate(other_dict)
    kbs = KeyBrokerService(
        {example_manifest.weights_hash: KEY, other_manifest.weights_hash: KEY}, now=clock,
        renewal_signing_key=signer,
        trusted_manifest_identities={
            manifest_identity(example_manifest), manifest_identity(other_manifest)
        },
    )
    other_decision = _renew(kbs, other_manifest, current, rim)
    with pytest.raises(ValueError, match="different model"):
        session.apply_renewal(example_manifest, other_decision)

    drifted_dict = dict(example_dict)
    drifted_dict["custody"] = dict(example_dict["custody"])
    drifted_dict["custody"]["attestation_cadence"] = "12h"
    drifted = WeightCustodyManifest.model_validate(drifted_dict)
    drift_kbs = KeyBrokerService(
        {drifted.weights_hash: KEY}, now=clock, renewal_signing_key=signer,
        trusted_manifest_identities={manifest_identity(drifted)},
    )
    drift_decision = _renew(drift_kbs, drifted, current, rim)
    with pytest.raises(ValueError, match="policy does not match"):
        session.apply_renewal(drifted, drift_decision)


def test_renewal_refuses_expired_failed_and_post_wipe_decisions(example_manifest):
    clock = _clock()
    session, kbs, current, rim = _session_and_kbs(
        example_manifest, clock, renewal_ttl=10,
    )
    expired = _renew(kbs, example_manifest, current, rim)
    clock.advance(11)
    with pytest.raises(ValueError, match="not currently valid"):
        session.apply_renewal(example_manifest, expired)

    challenge = kbs.issue_challenge()
    bad_evidence = SoftwareProvider().produce(
        challenge, serving_image_measurement=current, gpu_measurement="wrong-rim",
    )
    failed = kbs.verify_for_renewal(example_manifest, bad_evidence)
    assert not failed.renewed
    with pytest.raises(ValueError, match="failed gate"):
        session.apply_renewal(example_manifest, failed)

    fresh = _renew(kbs, example_manifest, current, rim)
    clock.advance(86401)
    with pytest.raises(KeyWipedError, match="already zeroized"):
        session.apply_renewal(example_manifest, fresh)
