from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from wcm import ChallengeError, ChallengeStore


class Clock:
    def __init__(self, start: datetime) -> None:
        self.t = start

    def __call__(self) -> datetime:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t = self.t + timedelta(seconds=seconds)


def _clock() -> Clock:
    return Clock(datetime(2026, 7, 19, 12, 0, 0, tzinfo=timezone.utc))


def test_issue_unique_nonces():
    store = ChallengeStore(now=_clock())
    a, b = store.issue(), store.issue()
    assert a.nonce != b.nonce
    assert len(a.nonce) == 64  # 32 bytes hex


def test_consume_once_ok():
    store = ChallengeStore(now=_clock())
    c = store.issue()
    store.consume(c.nonce)  # no raise


def test_replay_rejected():
    store = ChallengeStore(now=_clock())
    c = store.issue()
    store.consume(c.nonce)
    with pytest.raises(ChallengeError, match="replay"):
        store.consume(c.nonce)


def test_unknown_nonce_rejected():
    store = ChallengeStore(now=_clock())
    with pytest.raises(ChallengeError, match="unknown"):
        store.consume("00" * 32)


def test_expiry_rejected():
    clock = _clock()
    store = ChallengeStore(ttl_seconds=60, now=clock)
    c = store.issue()
    clock.advance(61)
    with pytest.raises(ChallengeError, match="expired"):
        store.consume(c.nonce)


def test_expired_nonce_also_burned():
    clock = _clock()
    store = ChallengeStore(ttl_seconds=60, now=clock)
    c = store.issue()
    clock.advance(61)
    with pytest.raises(ChallengeError, match="expired"):
        store.consume(c.nonce)
    # Even rewinding, an expired-then-consumed nonce cannot be reused.
    clock.t = c.issued_at
    with pytest.raises(ChallengeError, match="replay"):
        store.consume(c.nonce)
