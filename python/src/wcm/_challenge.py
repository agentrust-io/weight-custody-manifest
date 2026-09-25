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
import threading
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
    """Issues nonces and enforces single use within a TTL.

    Thread-safe: the reference server runs sync handlers on a thread pool, and
    an unlocked check-then-add let two concurrent presentations of one nonce
    both pass. Memory is bounded by the TTL window: expired challenges are
    dropped on every issue, since an unauthenticated caller can request as
    many as it likes. A dropped nonce reads as unknown, which still refuses it.
    """

    def __init__(
        self,
        *,
        ttl_seconds: int = 300,
        now: Optional[Callable[[], datetime]] = None,
    ) -> None:
        self._ttl = ttl_seconds
        self._now = now or _utcnow
        self._issued: dict[str, Challenge] = {}
        # nonce -> its challenge's expiry, kept only until that expiry passes.
        self._consumed: dict[str, datetime] = {}
        self._lock = threading.Lock()

    def _prune(self, now: datetime) -> None:
        # Insertion order is issue order, so with a steady clock the oldest
        # entries sit at the front; stop at the first one still live.
        for table in (self._issued, self._consumed):
            while table:
                nonce = next(iter(table))
                entry = table[nonce]
                expires = entry.expires_at if isinstance(entry, Challenge) else entry
                if now <= expires:
                    break
                del table[nonce]

    def issue(self) -> Challenge:
        with self._lock:
            now = self._now()
            self._prune(now)
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
        with self._lock:
            if nonce in self._consumed:
                raise ChallengeError("nonce already used (replay)")
            challenge = self._issued.pop(nonce, None)
            if challenge is None:
                raise ChallengeError("unknown nonce (not issued by this KBS)")
            self._consumed[nonce] = challenge.expires_at
            if self._now() > challenge.expires_at:
                raise ChallengeError("nonce expired")
