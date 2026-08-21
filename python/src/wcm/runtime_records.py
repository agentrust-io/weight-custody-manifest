"""Signed, hash-chained custody runtime records for protected controllers."""
from __future__ import annotations

import base64
import binascii
from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any, Iterable, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from ._canonicalize import canonical_hash, canonicalize


class RuntimeEvent(str, Enum):
    lease_started = "lease_started"
    renewal_succeeded = "renewal_succeeded"
    lapse_detected = "lapse_detected"
    revocation_detected = "revocation_detected"
    wipe_requested = "wipe_requested"
    wipe_completed = "wipe_completed"
    process_terminated = "process_terminated"


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _unb64url(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def runtime_public_key(signing_key: Ed25519PrivateKey) -> str:
    return _b64url(
        signing_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
    )


@dataclass(frozen=True)
class RuntimeRecord:
    kind: str
    algorithm: str
    sequence: int
    event: str
    occurred_at: str
    weights_hash: str
    manifest_hash: str
    lease_id: str
    previous_record_hash: Optional[str]
    detail: dict[str, Any]
    public_key_b64url: str
    signature_b64url: str

    def signing_payload(self) -> dict[str, Any]:
        value = asdict(self)
        value.pop("signature_b64url")
        return value

    @property
    def record_hash(self) -> str:
        return canonical_hash(asdict(self))

    def verify(self, expected_public_key_b64url: str) -> bool:
        if (
            self.kind != "wcm-runtime-record/v1"
            or self.algorithm != "Ed25519"
            or self.sequence < 0
            or self.public_key_b64url != expected_public_key_b64url
        ):
            return False
        try:
            key = Ed25519PublicKey.from_public_bytes(_unb64url(self.public_key_b64url))
            key.verify(
                _unb64url(self.signature_b64url), canonicalize(self.signing_payload())
            )
        except (binascii.Error, ValueError, InvalidSignature):
            return False
        return True


def sign_runtime_record(
    *,
    signing_key: Ed25519PrivateKey,
    sequence: int,
    event: RuntimeEvent,
    occurred_at: str,
    weights_hash: str,
    manifest_hash: str,
    lease_id: str,
    previous: Optional[RuntimeRecord] = None,
    detail: Optional[dict[str, Any]] = None,
) -> RuntimeRecord:
    if sequence < 0 or (previous is None) != (sequence == 0):
        raise ValueError("sequence 0 must be the first record; later records require previous")
    if previous is not None and previous.sequence + 1 != sequence:
        raise ValueError("runtime record sequence is not contiguous")
    if not occurred_at.endswith("Z"):
        raise ValueError("runtime record timestamp must be UTC with a Z suffix")
    public_key = runtime_public_key(signing_key)
    unsigned = RuntimeRecord(
        kind="wcm-runtime-record/v1",
        algorithm="Ed25519",
        sequence=sequence,
        event=event.value,
        occurred_at=occurred_at,
        weights_hash=weights_hash,
        manifest_hash=manifest_hash,
        lease_id=lease_id,
        previous_record_hash=previous.record_hash if previous else None,
        detail=dict(detail or {}),
        public_key_b64url=public_key,
        signature_b64url="",
    )
    signature = signing_key.sign(canonicalize(unsigned.signing_payload()))
    return RuntimeRecord(
        **{**asdict(unsigned), "signature_b64url": _b64url(signature)}
    )


def verify_runtime_record_chain(
    records: Iterable[RuntimeRecord],
    expected_public_key_b64url: str,
    *,
    require_terminal_sequence: bool = True,
) -> tuple[bool, str]:
    values = list(records)
    if not values:
        return False, "runtime record chain is empty"
    identity = (values[0].weights_hash, values[0].manifest_hash, values[0].lease_id)
    previous: Optional[RuntimeRecord] = None
    for index, record in enumerate(values):
        if record.sequence != index:
            return False, "runtime record sequence is not contiguous"
        if not record.verify(expected_public_key_b64url):
            return False, f"runtime record {index} signature or format is invalid"
        if (record.weights_hash, record.manifest_hash, record.lease_id) != identity:
            return False, "runtime record identity changed within the chain"
        expected_previous = previous.record_hash if previous else None
        if record.previous_record_hash != expected_previous:
            return False, "runtime record previous hash does not match"
        previous = record
    if not require_terminal_sequence:
        return True, "valid partial runtime record chain"
    events = [record.event for record in values]
    boundaries = {RuntimeEvent.lapse_detected.value, RuntimeEvent.revocation_detected.value}
    boundary_positions = [i for i, event in enumerate(events) if event in boundaries]
    if events[0] != RuntimeEvent.lease_started.value or len(boundary_positions) != 1:
        return False, "chain requires one lease start and one lapse or revocation boundary"
    boundary = boundary_positions[0]
    terminal = [
        RuntimeEvent.wipe_requested.value,
        RuntimeEvent.wipe_completed.value,
        RuntimeEvent.process_terminated.value,
    ]
    if events[boundary + 1 :] != terminal:
        return False, "boundary must be followed by wipe requested, wipe completed, and termination"
    if any(event != RuntimeEvent.renewal_succeeded.value for event in events[1:boundary]):
        return False, "only successful renewals may occur before the terminal boundary"
    return True, "valid terminal runtime record chain"
