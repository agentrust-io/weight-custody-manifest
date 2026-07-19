from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from wcm import (
    EnclaveSession,
    KeyBrokerService,
    KeyWipedError,
    SessionState,
    SoftwareProvider,
    TimeFloor,
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
    kbs = KeyBrokerService({manifest.weights_hash: KEY}, now=clock)
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
