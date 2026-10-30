"""Bounded software state exploration; no trusted timer or erasure claim."""
import asyncio
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from itertools import product

import pytest
from wcm.custody import (
    EnclaveSession,
    KeyWipedError,
    ReattestationRequired,
    SessionState,
)


@dataclass
class Model:
    clock: int = 0
    deadline: int = 3
    operations: int = 0
    wiped: bool = False

    def step(self, action):
        if action == "advance":
            self.clock += 1
            return None
        if action == "stop":
            self.wiped = True
            return None
        if not self.wiped and self.clock >= self.deadline:
            self.wiped = True
        if action == "tick":
            return None
        if self.wiped:
            return KeyWipedError
        if action == "renew":
            self.deadline = self.clock + 3
            self.operations = 0
        elif action in {"use", "authorize"}:
            if self.operations == 2:
                return ReattestationRequired
            self.operations += 1
        return None


def exercise(sequence):
    model = Model()
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    stops = []
    session = EnclaveSession(b"test-key", cadence_seconds=3, max_operations=2,
                             now=lambda: start + timedelta(seconds=model.clock),
                             on_stop=lambda: stops.append("stopped"))
    for action in sequence:
        expected = model.step(action)
        call = {"tick": session.tick, "renew": session.reattest,
                "use": session.use_key, "authorize": session.authorize_operation,
                "stop": session.zeroize}.get(action)
        if call is not None:
            if expected:
                with pytest.raises(expected):
                    call()
            else:
                result = call()
                if action == "use":
                    assert result == b"test-key"
        assert session.is_wiped == model.wiped, sequence
        assert session.operations_used == model.operations, sequence
        assert session.deadline == start + timedelta(seconds=model.deadline), sequence
        assert len(stops) == int(model.wiped), sequence
    return model


def test_all_bounded_custody_sequences():
    actions = ("advance", "tick", "renew", "use", "authorize", "stop")
    # All length-five words include every shorter word as a prefix. The exact
    # search domain is deliberately small and reproducible: 6**5 sequences.
    for sequence in product(actions, repeat=5):
        exercise(sequence)
    # Longer targeted histories reach post-renewal budgets and exact expiry.
    exercise(("use", "use", "authorize", "renew", "use", "advance", "advance",
              "advance", "tick", "renew", "stop"))


def test_monitor_cancellation_is_terminal():
    async def scenario():
        start = datetime(2026, 1, 1, tzinfo=timezone.utc)
        stops = []
        entered_sleep = asyncio.Event()
        original_sleep = asyncio.sleep

        async def observe_sleep(delay):
            entered_sleep.set()
            await original_sleep(delay)

        session = EnclaveSession(b"test-key", cadence_seconds=3, now=lambda: start,
                                 on_stop=lambda: stops.append(1))
        # Observe entry into the real cooperative monitor without wall-clock
        # polling; restore the shared coroutine even when assertions fail.
        with pytest.MonkeyPatch.context() as patch:
            patch.setattr("wcm.custody.asyncio.sleep", observe_sleep)
            task = asyncio.create_task(session.monitor())
            await asyncio.wait_for(entered_sleep.wait(), 1)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
        assert session.state is SessionState.wiped
        assert stops == [1]
        with pytest.raises(KeyWipedError):
            session.use_key()
        with pytest.raises(KeyWipedError):
            session.reattest()
        session.zeroize()
        assert stops == [1]

    asyncio.run(scenario())
