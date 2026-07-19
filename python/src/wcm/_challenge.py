"""KBS challenge issuance and single-use nonce tracking (SPEC.md section 3.2).

The key release service issues a fresh, single-use nonce before every release.
The enclave attests over that nonce, binding its quote to this exchange and
this instant, so a quote captured on the wire cannot be replayed later. This
is the ``replay_protection: kbs-nonce-required`` control.

Time is injectable (``now``) so expiry is testable without real waiting; the
KBS uses its own clock here, never a guest-supplied one.
"""
from __future__ import annotations

import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Callable, Optional


class ChallengeError(Exception):
    """A presented nonce is unknown, expired, or already used."""


@dataclass(frozen=True)
class Challenge:
    nonce: str  # 256-bit hex
    issued_at: datetime
    expires_at: datetime


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class ChallengeStore:
    """Issues nonces and enforces single use within a TTL."""

    def __init__(
        self,
        *,
        ttl_seconds: int = 300,
        now: Optional[Callable[[], datetime]] = None,
    ) -> None:
        self._ttl = ttl_seconds
        self._now = now or _utcnow
        self._issued: dict[str, Challenge] = {}
        self._consumed: set[str] = set()

    def issue(self) -> Challenge:
        now = self._now()
        challenge = Challenge(
            nonce=secrets.token_hex(32),
            issued_at=now,
            expires_at=now + timedelta(seconds=self._ttl),
        )
        self._issued[challenge.nonce] = challenge
        return challenge

    def consume(self, nonce: str) -> None:
        """Validate *nonce* and mark it used. Idempotency is intentionally not
        offered: a second presentation of the same nonce is a replay and fails.

        Raises:
            ChallengeError: unknown, expired, or already-consumed nonce.
        """
        if nonce in self._consumed:
            raise ChallengeError("nonce already used (replay)")
        challenge = self._issued.get(nonce)
        if challenge is None:
            raise ChallengeError("unknown nonce (not issued by this KBS)")
        if self._now() > challenge.expires_at:
            self._consumed.add(nonce)
            raise ChallengeError("nonce expired")
        self._consumed.add(nonce)
