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


def test_concurrent_presentations_of_one_nonce_release_once():
    # The first consumer stalls inside the store (here, in the clock call);
    # without a lock the second consumer passed the replay check meanwhile and
    # both succeeded.
    import threading

    start = datetime(2026, 7, 19, 12, 0, 0, tzinfo=timezone.utc)
    second_arrived = threading.Event()
    calls = {"n": 0}
    stall = {"on": False}

    def clock() -> datetime:
        if stall["on"]:
            calls["n"] += 1
            if calls["n"] == 1:
                second_arrived.wait(timeout=1.0)
            else:
                second_arrived.set()
        return start

    store = ChallengeStore(now=clock)
    nonce = store.issue().nonce
    stall["on"] = True
    outcomes: list[str] = []

    def consume() -> None:
        try:
            store.consume(nonce)
            outcomes.append("ok")
        except ChallengeError:
            outcomes.append("refused")

    first = threading.Thread(target=consume)
    first.start()
    while calls["n"] == 0:
        pass
    second = threading.Thread(target=consume)
    second.start()
    first.join()
    second.join()
    assert sorted(outcomes) == ["ok", "refused"]


def test_expired_challenges_do_not_accumulate():
    clock = _clock()
    store = ChallengeStore(ttl_seconds=60, now=clock)
    old = [store.issue() for _ in range(1000)]
    store.consume(old[0].nonce)
    clock.advance(61)
    store.issue()
    assert len(store._issued) == 1
    assert len(store._consumed) == 0
    # Dropped nonces are still refused, as unknown.
    with pytest.raises(ChallengeError):
        store.consume(old[1].nonce)
