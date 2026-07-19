"""Wipe-on-lapse: the runtime custody floor (SPEC.md sections 3.2, 3.3).

Once the KBS releases a key into the enclave, the enclave holds it only for the
``attestation_cadence`` window. Before the window lapses it must re-attest; if
it does not, it zeroizes the key from its own memory and stops serving. The key
is not "suspended pending renewal", it is gone, and a fresh release requires a
fresh successful attestation. This is what bounds worst-case exposure to one
cadence window against an operator who cannot forge attestation, whether or not
any revocation signal ever arrives.

Two honest limits, both from the spec:

  1. It assumes trusted time. The bound only holds if the clock the enclave
     checks the deadline against cannot be stalled by the host. That is what
     ``trusted_time_source`` names, and it is surfaced here as ``time_floor``:
     ``secure-tsc`` gives a sound bound, the lease/op-count hybrid a weaker but
     bounded one, ``none-best-effort`` no bound at all. This state machine
     enforces the deadline against whatever clock it is given; it cannot make an
     untrusted clock trustworthy, so it reports the floor rather than hiding it.
  2. It does not hold against a hardware owner who can forge attestation. Such
     an owner re-attests every window with a fresh forged quote and never
     zeroizes. That adversary is out of scope for this logic (open question 8.8);
     against it the bound comes from the quorum and physical hardening, not here.

Operation-count-anchored renewal for the hybrid's actively-serving case is not
implemented yet; this preview covers the wall-clock lapse.
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Callable, Optional

from .models import TrustedTimeSource, WeightCustodyManifest


class SessionState(str, Enum):
    holding = "holding"
    wiped = "wiped"


class TimeFloor(str, Enum):
    """How much the cadence bound is worth, given the trusted-time source."""

    sound = "sound"  # secure-tsc: worst-case exposure bounded by the cadence
    weaker = "weaker"  # hybrid: bounded, but by how long the host can lie to the KBS
    none = "none"  # none-best-effort: no bound; the host can stall time


_FLOOR: dict[TrustedTimeSource, TimeFloor] = {
    TrustedTimeSource.secure_tsc: TimeFloor.sound,
    TrustedTimeSource.lease_with_op_count_hybrid: TimeFloor.weaker,
    TrustedTimeSource.none_best_effort: TimeFloor.none,
}

_CADENCE_UNITS = {"d": 86400, "h": 3600, "m": 60, "s": 1}
_CADENCE_RE = re.compile(r"^\s*(\d+)\s*([dhms])\s*$")


class KeyWipedError(Exception):
    """The key has been zeroized; there is nothing to serve or renew."""


def parse_cadence(text: str) -> int:
    """Parse a cadence like ``"24h"`` / ``"15m"`` / ``"30s"`` / ``"1d"`` to seconds."""
    match = _CADENCE_RE.match(text)
    if not match:
        raise ValueError(
            f"invalid cadence {text!r}; expected an integer with unit d/h/m/s, e.g. '24h'"
        )
    value, unit = int(match.group(1)), match.group(2)
    if value == 0:
        raise ValueError("cadence must be greater than zero")
    return value * _CADENCE_UNITS[unit]


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class EnclaveSession:
    """An enclave's custody of one released key, enforcing wipe-on-lapse.

    Construct one from a successful release (``from_release``) or directly. Call
    ``reattest`` before the window closes to renew; ``use_key`` returns the key
    only while holding; a lapsed window zeroizes the key on the next interaction.
    """

    def __init__(
        self,
        key: bytes,
        *,
        cadence_seconds: int,
        trusted_time_source: TrustedTimeSource = TrustedTimeSource.none_best_effort,
        weights_hash: Optional[str] = None,
        now: Optional[Callable[[], datetime]] = None,
    ) -> None:
        if cadence_seconds <= 0:
            raise ValueError("cadence_seconds must be greater than zero")
        self._key = bytearray(key)
        self._cadence = cadence_seconds
        self._tts = trusted_time_source
        self.weights_hash = weights_hash
        self._now = now or _utcnow
        self._state = SessionState.holding
        self._deadline: datetime = self._now() + timedelta(seconds=cadence_seconds)

    @classmethod
    def from_release(
        cls,
        manifest: WeightCustodyManifest,
        decision: "object",
        *,
        now: Optional[Callable[[], datetime]] = None,
    ) -> "EnclaveSession":
        """Start custody from a KBS ``ReleaseDecision`` that released a key.

        Reads the cadence from ``custody.attestation_cadence`` and the floor from
        ``release_policy.trusted_time_source``.
        """
        released = getattr(decision, "released", False)
        key = getattr(decision, "key", None)
        if not released or key is None:
            raise ValueError("cannot start custody: the release decision has no key")
        return cls(
            key,
            cadence_seconds=parse_cadence(manifest.custody.attestation_cadence),
            trusted_time_source=manifest.release_policy.trusted_time_source,
            weights_hash=manifest.weights_hash,
            now=now,
        )

    # -- properties ------------------------------------------------------------

    @property
    def state(self) -> SessionState:
        return self._state

    @property
    def is_wiped(self) -> bool:
        return self._state is SessionState.wiped

    @property
    def deadline(self) -> datetime:
        return self._deadline

    @property
    def time_floor(self) -> TimeFloor:
        """How much the cadence bound is worth for this session's trusted time."""
        return _FLOOR[self._tts]

    def remaining_seconds(self, now: Optional[datetime] = None) -> float:
        if self._state is SessionState.wiped:
            return 0.0
        current = now if now is not None else self._now()
        return max(0.0, (self._deadline - current).total_seconds())

    # -- state transitions -----------------------------------------------------

    def tick(self, now: Optional[datetime] = None) -> SessionState:
        """Evaluate the deadline; zeroize the key if the window has lapsed."""
        if self._state is SessionState.wiped:
            return self._state
        current = now if now is not None else self._now()
        if current > self._deadline:
            self.zeroize()
        return self._state

    def reattest(self, now: Optional[datetime] = None) -> None:
        """Record a successful re-attestation and renew the window.

        The caller is responsible for having actually completed a fresh KBS
        round-trip; this renews the lease on that basis. Re-attestation must
        happen before the window closes: once the key is wiped it is gone, and a
        fresh release (a new session) is required.

        Raises:
            KeyWipedError: the window already lapsed and the key was zeroized.
        """
        current = now if now is not None else self._now()
        if self.tick(current) is SessionState.wiped:
            raise KeyWipedError(
                "re-attestation too late: the cadence window lapsed and the key was "
                "zeroized; request a fresh release"
            )
        self._deadline = current + timedelta(seconds=self._cadence)

    def use_key(self, now: Optional[datetime] = None) -> bytes:
        """Return the key for serving, only while holding.

        Raises:
            KeyWipedError: the window lapsed; the key is gone, not suspended.
        """
        if self.tick(now) is SessionState.wiped:
            raise KeyWipedError("key has been zeroized (cadence lapsed)")
        return bytes(self._key)

    def zeroize(self) -> None:
        """Overwrite the key in memory and mark the session wiped (idempotent).

        Best-effort in a managed runtime: Python may have copied the bytes
        elsewhere. A production enclave zeroizes the real key material; this is
        the reference semantics.
        """
        for i in range(len(self._key)):
            self._key[i] = 0
        self._key = bytearray()
        self._state = SessionState.wiped
