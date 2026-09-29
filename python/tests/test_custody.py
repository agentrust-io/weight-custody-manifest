from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

import pytest
from wcm.renewal import manifest_identity

from wcm import (
    EnclaveSession,
    KeyBrokerService,
    KeyWipedError,
    ReattestationRequired,
    RenewalDenied,
    SessionState,
    ServingShutdown,
    SoftwareProvider,
    StopFloor,
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


def test_deadline_stops_serving_once_after_wiping():
    clock = _clock()
    stopped = []

    def stop():
        assert session.is_wiped
        assert session._key == bytearray()
        with pytest.raises(KeyWipedError):
            session.authorize_operation()
        stopped.append(True)

    session = EnclaveSession(KEY, cadence_seconds=10, now=clock, on_stop=stop)
    clock.advance(10)
    assert session.tick() is SessionState.wiped
    session.zeroize()
    assert stopped == [True]


def test_stop_error_cannot_restore_custody():
    def stop():
        raise RuntimeError("runtime cleanup failed")

    session = EnclaveSession(KEY, cadence_seconds=10, now=_clock(), on_stop=stop)
    with pytest.raises(RuntimeError, match="runtime cleanup failed"):
        session.zeroize()
    assert session.is_wiped
    assert session._key == bytearray()
    with pytest.raises(KeyWipedError):
        session.reattest()
    session.zeroize()


def test_from_release_passes_stop_hook(structural_manifest):
    clock = _clock()
    stopped = []
    session = EnclaveSession.from_release(
        structural_manifest, _released_decision(structural_manifest, clock),
        now=clock, on_stop=lambda: stopped.append(True),
    )
    session.zeroize()
    assert stopped == [True]


@pytest.mark.parametrize("failed_step", [None, "admission", "cancel", "unload", "terminate"])
def test_shutdown_order_and_failure_fallback(failed_step):
    steps = []

    def callback(name):
        def run():
            steps.append(name)
            if name == failed_step:
                raise RuntimeError(name)
        return run

    shutdown = ServingShutdown(
        stop_admission=callback("admission"),
        cancel_inflight=callback("cancel"),
        unload_weights=callback("unload"),
        terminate=callback("terminate"),
    )
    if failed_step is None:
        shutdown()
    else:
        with pytest.raises(ExceptionGroup) as caught:
            shutdown()
        assert str(caught.value.exceptions[0]) == failed_step
    shutdown()
    expected = ["admission", "cancel", "terminate"] if failed_step == "cancel" else [
        "admission", "cancel", "unload", "terminate",
    ]
    assert steps == expected


def test_monitor_stops_idle_session(monkeypatch):
    clock = _clock()
    stopped = []
    session = EnclaveSession(
        KEY, cadence_seconds=10, now=clock, on_stop=lambda: stopped.append(True),
    )

    async def advance(delay):
        clock.advance(delay)

    monkeypatch.setattr("wcm.custody.asyncio.sleep", advance)
    asyncio.run(session.monitor(poll_interval=3))
    assert clock() == session.deadline
    assert session.is_wiped
    assert stopped == [True]


def test_monitor_cancellation_stops_serving():
    stopped = []
    session = EnclaveSession(
        KEY, cadence_seconds=10, now=_clock(), on_stop=lambda: stopped.append(True),
    )

    async def run():
        task = asyncio.create_task(session.monitor())
        await asyncio.sleep(0)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(run())
    assert session.is_wiped
    assert stopped == [True]


def test_monitor_honors_successful_signed_renewal(structural_manifest, monkeypatch):
    clock = _clock()
    stopped = []
    session, kbs, current, rim = _session_and_kbs(
        structural_manifest, clock, on_stop=lambda: stopped.append(True),
    )
    original_deadline = session.deadline
    renewed = False

    async def advance(delay):
        nonlocal renewed
        clock.advance(delay)
        if not renewed:
            session.apply_renewal(structural_manifest, _renew(kbs, structural_manifest, current, rim))
            renewed = True

    monkeypatch.setattr("wcm.custody.asyncio.sleep", advance)
    asyncio.run(session.monitor(poll_interval=3600))
    assert session.deadline == original_deadline + timedelta(seconds=3600)
    assert clock() == session.deadline
    assert stopped == [True]


def test_monitor_clock_failure_stops_serving():
    stopped = []
    clock = _clock()
    fail = False

    def now():
        if fail:
            raise RuntimeError("clock unavailable")
        return clock()

    session = EnclaveSession(
        KEY, cadence_seconds=10, now=now, on_stop=lambda: stopped.append(True),
    )
    fail = True
    with pytest.raises(RuntimeError, match="clock unavailable"):
        asyncio.run(session.monitor())
    assert session.is_wiped
    assert stopped == [True]


@pytest.mark.parametrize("interval", [0, -1, float("nan"), float("inf")])
def test_monitor_rejects_invalid_interval(interval):
    session = EnclaveSession(KEY, cadence_seconds=10, now=_clock())
    with pytest.raises(ValueError, match="poll_interval"):
        asyncio.run(session.monitor(poll_interval=interval))


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


def test_from_release_starts_custody(structural_manifest):
    clock = _clock()
    decision = _released_decision(structural_manifest, clock)
    assert decision.released

    session = EnclaveSession.from_release(structural_manifest, decision, now=clock)
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


def test_from_release_passes_max_operations(structural_manifest):
    clock = _clock()
    decision = _released_decision(structural_manifest, clock)
    session = EnclaveSession.from_release(
        structural_manifest, decision, max_operations=1, now=clock
    )
    session.use_key()
    with pytest.raises(ReattestationRequired):
        session.use_key()


# -- signed evidence-bound renewal --------------------------------------------


def _session_and_kbs(
    manifest, clock, *, max_operations=1, renewal_ttl=60, renewal_signing_key=None,
    on_stop=None,
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
        on_stop=on_stop,
    )
    return session, kbs, current, rim


def _renew(kbs, manifest, current, rim):
    challenge = kbs.issue_challenge()
    evidence = SoftwareProvider().produce(
        challenge, serving_image_measurement=current, gpu_measurement=rim,
    )
    return kbs.verify_for_renewal(manifest, evidence)


def test_signed_renewal_resets_budget_without_exporting_key(structural_manifest):
    clock = _clock()
    session, kbs, current, rim = _session_and_kbs(structural_manifest, clock)
    assert session.use_key() == KEY
    with pytest.raises(ReattestationRequired):
        session.authorize_operation()
    decision = _renew(kbs, structural_manifest, current, rim)
    assert decision.renewed
    assert not hasattr(decision, "key")
    assert decision.verify(decision.public_key_b64url)
    session.apply_renewal(structural_manifest, decision)
    assert session.operations_remaining() == 1
    session.authorize_operation()


def test_renewal_decision_is_single_use(structural_manifest):
    clock = _clock()
    session, kbs, current, rim = _session_and_kbs(structural_manifest, clock)
    decision = _renew(kbs, structural_manifest, current, rim)
    session.apply_renewal(structural_manifest, decision)
    with pytest.raises(ValueError, match="already applied"):
        session.apply_renewal(structural_manifest, decision)


def test_kbs_nonce_replay_produces_signed_failed_renewal(structural_manifest):
    clock = _clock()
    session, kbs, current, rim = _session_and_kbs(structural_manifest, clock)
    challenge = kbs.issue_challenge()
    evidence = SoftwareProvider().produce(
        challenge, serving_image_measurement=current, gpu_measurement=rim,
    )
    first = kbs.verify_for_renewal(structural_manifest, evidence)
    replay = kbs.verify_for_renewal(structural_manifest, evidence)
    assert first.renewed
    assert not replay.renewed
    assert replay.verify(first.public_key_b64url)
    assert replay.checks[0]["name"] == "nonce_fresh"
    assert replay.checks[0]["passed"] is False
    # A short-circuited gate list is still the KBS's verdict, not a malformed decision.
    with pytest.raises(RenewalDenied) as denied:
        session.apply_renewal(structural_manifest, replay)
    assert denied.value.failed_check_names == {"nonce_fresh"}


def test_signed_denial_is_distinguishable_from_a_malformed_decision(structural_manifest):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from wcm.renewal import sign_renewal_decision

    clock = _clock()
    signer = Ed25519PrivateKey.generate()
    session, kbs, current, rim = _session_and_kbs(
        structural_manifest, clock, renewal_signing_key=signer,
    )
    deadline = session.deadline
    revoked = next(
        item.measurement
        for item in structural_manifest.release_policy.required_serving_image.accepted_measurements
        if item.status.value == "revoked"
    )

    verdict = _renew(kbs, structural_manifest, revoked, rim)
    assert verdict.verify(verdict.public_key_b64url) and not verdict.renewed
    with pytest.raises(RenewalDenied) as denied:
        session.apply_renewal(structural_manifest, verdict)
    assert "serving_image" in denied.value.failed_check_names
    assert denied.value.decision is verdict
    assert isinstance(denied.value, ValueError)  # back-compatible with ValueError callers

    valid = _renew(kbs, structural_manifest, current, rim)
    challenge = kbs.issue_challenge()
    evidence = SoftwareProvider().produce(
        challenge, serving_image_measurement=current, gpu_measurement=rim,
    )
    malformed = sign_renewal_decision(
        signing_key=signer,
        renewed=True,
        manifest=structural_manifest,
        evidence=evidence,
        issued_at=valid.issued_at,
        expires_at=valid.expires_at,
        checks=valid.checks[:-1],
    )
    assert malformed.verify(malformed.public_key_b64url)
    with pytest.raises(ValueError) as inconclusive:
        session.apply_renewal(structural_manifest, malformed)
    assert not isinstance(inconclusive.value, RenewalDenied)

    # Neither outcome moves the deadline, so exposure stays one cadence window.
    assert session.deadline == deadline
    assert session.state is SessionState.holding


def test_stop_floor_discloses_whether_a_teardown_adapter_exists():
    clock = _clock()
    undisclosed = EnclaveSession(KEY, cadence_seconds=10, now=clock)
    assert undisclosed.stop_floor is StopFloor.none
    assert EnclaveSession(
        KEY, cadence_seconds=10, now=clock, on_stop=lambda: None
    ).stop_floor is StopFloor.adapter

    # No adapter still ends custody; it just tears nothing down.
    clock.advance(10)
    assert undisclosed.tick() is SessionState.wiped


def test_failed_renewal_keeps_deadline_then_stops(structural_manifest):
    clock = _clock()
    stopped = []
    session, kbs, current, _ = _session_and_kbs(
        structural_manifest, clock, on_stop=lambda: stopped.append(True),
    )
    deadline = session.deadline
    clock.advance(10)
    failed = _renew(kbs, structural_manifest, current, "wrong-rim")
    with pytest.raises(RenewalDenied):
        session.apply_renewal(structural_manifest, failed)
    assert session.deadline == deadline
    assert not session.is_wiped
    assert stopped == []
    session.authorize_operation()
    clock.advance(session.remaining_seconds())
    with pytest.raises(KeyWipedError):
        session.authorize_operation()
    assert stopped == [True]


def test_renewal_refuses_wrong_signer_and_tampering(structural_manifest):
    from dataclasses import replace

    clock = _clock()
    session, kbs, current, rim = _session_and_kbs(structural_manifest, clock)
    valid = _renew(kbs, structural_manifest, current, rim)
    tampered = replace(
        valid,
        evidence_hash="sha256:" + "0" * 64,
    )
    with pytest.raises(ValueError, match="signature or signer"):
        session.apply_renewal(structural_manifest, tampered)
    malformed = replace(valid, signature_b64url="***")
    assert not malformed.verify(malformed.public_key_b64url)
    wrong_kind = replace(valid, kind="another-protocol/v1")
    assert not wrong_kind.verify(wrong_kind.public_key_b64url)

    other = KeyBrokerService(
        {structural_manifest.weights_hash: KEY},
        now=clock,
        trusted_manifest_identities={manifest_identity(structural_manifest)},
    )
    wrong_signer = _renew(other, structural_manifest, current, rim)
    with pytest.raises(ValueError, match="signature or signer"):
        session.apply_renewal(structural_manifest, wrong_signer)


def test_renewal_refuses_signed_truncated_gate_list(structural_manifest):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from wcm.renewal import sign_renewal_decision

    clock = _clock()
    signer = Ed25519PrivateKey.generate()
    session, kbs, current, rim = _session_and_kbs(
        structural_manifest, clock, renewal_signing_key=signer,
    )
    valid = _renew(kbs, structural_manifest, current, rim)
    challenge = kbs.issue_challenge()
    evidence = SoftwareProvider().produce(
        challenge, serving_image_measurement=current, gpu_measurement=rim,
    )
    truncated = sign_renewal_decision(
        signing_key=signer,
        renewed=True,
        manifest=structural_manifest,
        evidence=evidence,
        issued_at=valid.issued_at,
        expires_at=valid.expires_at,
        checks=valid.checks[:-1],
    )
    assert truncated.verify(valid.public_key_b64url)
    with pytest.raises(ValueError, match="omits required gates"):
        session.apply_renewal(structural_manifest, truncated)


def test_renewal_refuses_success_claimed_over_a_failed_gate(structural_manifest):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from wcm.renewal import sign_renewal_decision

    clock = _clock()
    signer = Ed25519PrivateKey.generate()
    session, kbs, current, rim = _session_and_kbs(
        structural_manifest, clock, renewal_signing_key=signer,
    )
    deadline = session.deadline
    valid = _renew(kbs, structural_manifest, current, rim)
    challenge = kbs.issue_challenge()
    evidence = SoftwareProvider().produce(
        challenge, serving_image_measurement=current, gpu_measurement=rim,
    )
    # Every required gate is present, one failed, and the issuer still claims success.
    checks = [dict(check) for check in valid.checks]
    checks[-1]["passed"] = False
    contradictory = sign_renewal_decision(
        signing_key=signer,
        renewed=True,
        manifest=structural_manifest,
        evidence=evidence,
        issued_at=valid.issued_at,
        expires_at=valid.expires_at,
        checks=checks,
    )
    assert contradictory.verify(contradictory.public_key_b64url)
    with pytest.raises(ValueError, match="claims success over a failed gate"):
        session.apply_renewal(structural_manifest, contradictory)
    assert session.deadline == deadline
    assert session.state is SessionState.holding


def test_renewal_refuses_cross_model_and_policy_drift(structural_manifest, example_dict):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from wcm import WeightCustodyManifest

    clock = _clock()
    signer = Ed25519PrivateKey.generate()
    session, _, current, rim = _session_and_kbs(
        structural_manifest, clock, renewal_signing_key=signer,
    )
    other_dict = dict(example_dict)
    other_dict["weights_hash"] = "sha256:" + "1" * 64
    other_manifest = WeightCustodyManifest.model_validate(other_dict)
    kbs = KeyBrokerService(
        {structural_manifest.weights_hash: KEY, other_manifest.weights_hash: KEY}, now=clock,
        renewal_signing_key=signer,
        trusted_manifest_identities={
            manifest_identity(structural_manifest), manifest_identity(other_manifest)
        },
    )
    other_decision = _renew(kbs, other_manifest, current, rim)
    with pytest.raises(ValueError, match="different model"):
        session.apply_renewal(structural_manifest, other_decision)

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


def test_renewal_refuses_expired_failed_and_post_wipe_decisions(structural_manifest):
    clock = _clock()
    session, kbs, current, rim = _session_and_kbs(
        structural_manifest, clock, renewal_ttl=10,
    )
    expired = _renew(kbs, structural_manifest, current, rim)
    clock.advance(11)
    with pytest.raises(ValueError, match="not currently valid"):
        session.apply_renewal(structural_manifest, expired)

    challenge = kbs.issue_challenge()
    bad_evidence = SoftwareProvider().produce(
        challenge, serving_image_measurement=current, gpu_measurement="wrong-rim",
    )
    failed = kbs.verify_for_renewal(structural_manifest, bad_evidence)
    assert not failed.renewed
    with pytest.raises(RenewalDenied):
        session.apply_renewal(structural_manifest, failed)

    fresh = _renew(kbs, structural_manifest, current, rim)
    clock.advance(86401)
    with pytest.raises(KeyWipedError, match="already zeroized"):
        session.apply_renewal(structural_manifest, fresh)


def test_from_release_rejects_a_manifest_other_than_the_released_one(structural_manifest):
    # Cadence and the time floor are read from the manifest handed in, so a
    # copy with a ten-year cadence must not ride on the pinned manifest's release.
    clock = _clock()
    decision = _released_decision(structural_manifest, clock)
    assert decision.released
    stretched = structural_manifest.model_copy(deep=True)
    stretched.custody.attestation_cadence = "3650d"
    with pytest.raises(ValueError, match="released against"):
        EnclaveSession.from_release(stretched, decision, now=clock)
