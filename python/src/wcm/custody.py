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

For ``lease-with-op-count-hybrid``, the wall-clock lease bounds the idle case
here, and ``max_operations`` anchors the actively-serving case: after N serving
operations the session raises ``ReattestationRequired`` until it re-attests, a
count the enclave's own execution increments that a host cannot advance without
also doing the inference work. N is a deployment parameter (SPEC.md open
question 8.9 residual), not a manifest field, so it is passed in explicitly.
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Callable, Optional

from .models import TrustedTimeSource, WeightCustodyManifest
from .renewal import REQUIRED_RENEWAL_CHECKS, RenewalDecision, manifest_identity


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


class ReattestationRequired(Exception):
    """The operation-count budget is exhausted; re-attest to keep serving.

    Distinct from ``KeyWipedError``: the key is NOT gone here. This is the
    op-count anchor for the ``lease-with-op-count-hybrid`` serving case
    (SPEC.md 3.1, Patch 1): after N operations the enclave must re-attest, a
    count its own execution increments that a host cannot advance without also
    doing the inference work. The wall-clock lease still bounds the idle case
    and zeroizes independently.
    """


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
        max_operations: Optional[int] = None,
        weights_hash: Optional[str] = None,
        manifest_hash: Optional[str] = None,
        renewal_public_key_b64url: Optional[str] = None,
        now: Optional[Callable[[], datetime]] = None,
    ) -> None:
        if cadence_seconds <= 0:
            raise ValueError("cadence_seconds must be greater than zero")
        if max_operations is not None and max_operations <= 0:
            raise ValueError("max_operations must be greater than zero when set")
        self._key = bytearray(key)
        self._cadence = cadence_seconds
        self._tts = trusted_time_source
        # The op-count anchor for the hybrid serving case. None means no op
        # ceiling (secure-tsc and best-effort rely on the wall clock alone).
        self._max_ops = max_operations
        self._ops = 0
        self.weights_hash = weights_hash
        self._manifest_hash = manifest_hash
        self._renewal_public_key = renewal_public_key_b64url
        self._used_renewals: set[str] = set()
        self._now = now or _utcnow
        self._state = SessionState.holding
        self._deadline: datetime = self._now() + timedelta(seconds=cadence_seconds)

    @classmethod
    def from_release(
        cls,
        manifest: WeightCustodyManifest,
        decision: "object",
        *,
        max_operations: Optional[int] = None,
        now: Optional[Callable[[], datetime]] = None,
    ) -> "EnclaveSession":
        """Start custody from a KBS ``ReleaseDecision`` that released a key.

        Reads the cadence from ``custody.attestation_cadence`` and the floor from
        ``release_policy.trusted_time_source``. ``max_operations`` (the op-count
        anchor N) is a deployment parameter, not a manifest field yet (SPEC.md
        open question 8.9 residual), so it is passed in explicitly.
        """
        released = getattr(decision, "released", False)
        key = getattr(decision, "key", None)
        if not released or key is None:
            raise ValueError("cannot start custody: the release decision has no key")
        return cls(
            key,
            cadence_seconds=parse_cadence(manifest.custody.attestation_cadence),
            trusted_time_source=manifest.release_policy.trusted_time_source,
            max_operations=max_operations,
            weights_hash=manifest.weights_hash,
            manifest_hash=getattr(decision, "manifest_hash", None),
            renewal_public_key_b64url=getattr(
                decision, "renewal_public_key_b64url", None
            ),
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

    @property
    def operations_used(self) -> int:
        return self._ops

    def operations_remaining(self) -> Optional[int]:
        """Operations left before re-attestation is required, or None if uncapped."""
        if self._max_ops is None:
            return None
        return max(0, self._max_ops - self._ops)

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
        self._ops = 0  # the op-count budget resets on a fresh attestation

    def apply_renewal(
        self,
        manifest: WeightCustodyManifest,
        decision: RenewalDecision,
        now: Optional[datetime] = None,
    ) -> None:
        """Apply one fresh signed KBS renewal decision to this custody session."""
        current = now if now is not None else self._now()
        if self.tick(current) is SessionState.wiped:
            raise KeyWipedError("renewal too late: custody was already zeroized")
        if self._manifest_hash is None or self._renewal_public_key is None:
            raise ValueError("session was not created from a renewal-capable release")
        if not decision.verify(self._renewal_public_key):
            raise ValueError("renewal decision signature or signer is invalid")
        check_names = [check.get("name") for check in decision.checks]
        checks_complete = (
            all(isinstance(name, str) for name in check_names)
            and len(check_names) == len(set(check_names))
            and REQUIRED_RENEWAL_CHECKS.issubset(check_names)
        )
        if (not decision.renewed or not checks_complete
                or not all(check.get("passed") is True for check in decision.checks)):
            raise ValueError("renewal decision contains a failed gate")
        if decision.weights_hash != self.weights_hash:
            raise ValueError("renewal decision is for different model weights")
        expected_manifest = manifest_identity(manifest)
        if expected_manifest != self._manifest_hash or decision.manifest_hash != self._manifest_hash:
            raise ValueError("renewal decision or manifest policy does not match this session")
        if parse_cadence(manifest.custody.attestation_cadence) != self._cadence:
            raise ValueError("renewal cadence does not match this session")
        if manifest.release_policy.trusted_time_source is not self._tts:
            raise ValueError("renewal trusted-time source does not match this session")
        try:
            if not decision.issued_at.endswith("Z") or not decision.expires_at.endswith("Z"):
                raise ValueError
            issued = datetime.fromisoformat(decision.issued_at.replace("Z", "+00:00"))
            expires = datetime.fromisoformat(decision.expires_at.replace("Z", "+00:00"))
            if issued.tzinfo is None or expires.tzinfo is None:
                raise ValueError
        except (TypeError, ValueError) as exc:
            raise ValueError("renewal decision timestamps are invalid") from exc
        if issued > current or current > expires or expires <= issued:
            raise ValueError("renewal decision is not currently valid")
        renewal_id = decision.renewal_id
        if renewal_id in self._used_renewals:
            raise ValueError("renewal decision was already applied")
        self._used_renewals.add(renewal_id)
        self._deadline = current + timedelta(seconds=self._cadence)
        self._ops = 0

    def use_key(self, now: Optional[datetime] = None) -> bytes:
        """Return the key for one serving operation, counting it against the budget.

        Each call is one operation. When an op-count anchor is set and the budget
        is exhausted, serving must pause for a re-attestation (the key is not
        wiped). The wall-clock lease is enforced first and zeroizes independently.

        Raises:
            KeyWipedError: the wall-clock window lapsed; the key is gone.
            ReattestationRequired: the op-count budget is exhausted; re-attest.
        """
        self.authorize_operation(now)
        return bytes(self._key)

    def authorize_operation(self, now: Optional[datetime] = None) -> None:
        """Authorize one serving operation without returning another key copy.

        This is the long-lived runtime path after the key has been opened inside
        the admitted boundary. It enforces exactly the same wall-clock lease and
        operation-count budget as :meth:`use_key`, including incrementing the
        operation counter on success, but it does not export key bytes.

        Raises:
            KeyWipedError: the wall-clock window lapsed; the key is gone.
            ReattestationRequired: the op-count budget is exhausted; re-attest.
        """
        if self.tick(now) is SessionState.wiped:
            raise KeyWipedError("key has been zeroized (cadence lapsed)")
        if self._max_ops is not None and self._ops >= self._max_ops:
            raise ReattestationRequired(
                f"op-count budget of {self._max_ops} exhausted; re-attest to continue serving"
            )
        self._ops += 1

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
