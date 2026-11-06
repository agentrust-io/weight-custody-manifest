"""Experimental, opt-in checks of loaded model buffers, not hardware attestation.

A trusted loader/observer supplies the *actual serving buffers*. The caller must
quiesce the engine and synchronize device writes while measuring. A signature
authenticates that observer's report; it cannot establish that a dishonest reader
reported the right memory, or prevent writes after a sample. See
docs/model-memory-integrity.md before integrating this with a serving runtime.

This module does not alter the manifest, CompositeEvidence, KBS or custody
protocol. In particular, decrypt/load precedes this check; a runtime must check
before enabling serving and continue to enforce its separate custody lease.
"""
from __future__ import annotations

import hashlib
import threading
from collections.abc import Callable, Mapping
from typing import Annotated, Literal, Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from pydantic import BaseModel, ConfigDict, Field, model_validator

from ._canonicalize import canonical_hash, canonicalize
from ._challenge import Challenge, ChallengeError, ChallengeStore
from ._signing import _SMALL_ORDER_POINTS, _b64url_decode, _b64url_encode
from ._types import HashValue

Name = Annotated[str, Field(strict=True, min_length=1, max_length=160,
                           pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:/-]*$")]
Hex32 = Annotated[str, Field(strict=True, min_length=64, max_length=64,
                            pattern=r"^[0-9a-f]{64}$")]
ByteCount = Annotated[int, Field(strict=True, gt=0, le=2**53 - 1)]
_CHUNK_BYTES = 1024 * 1024
_MAX_BUFFERS = 4096


class _Frozen(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True,
                              revalidate_instances="always")


class BufferDigest(_Frozen):
    name: Name
    nbytes: ByteCount
    sha256: Hex32


class _Inventory(_Frozen):
    buffers: Annotated[tuple[BufferDigest, ...],
                       Field(min_length=1, max_length=_MAX_BUFFERS)]

    @model_validator(mode="after")
    def ordered_unique_names(self) -> _Inventory:
        names = [entry.name for entry in self.buffers]
        if names != sorted(set(names)):
            raise ValueError("buffer names must be unique and sorted")
        return self


class ModelMemoryBaseline(_Inventory):
    """Pinned by the approver, from a separately trusted preparation process.

    Artifact bytes and loaded tensor bytes need not have the same hash. Pin the
    exact loader/layout as well as its expected immutable buffer inventory.
    """

    kind: Literal["wcm-model-memory-baseline-v1"] = "wcm-model-memory-baseline-v1"
    manifest_hash: HashValue
    weights_hash: HashValue
    serving_image_measurement: HashValue
    layout_id: Name


class ModelMemoryObservation(_Inventory):
    kind: Literal["wcm-model-memory-observation-v1"] = "wcm-model-memory-observation-v1"
    baseline_hash: HashValue
    challenge_nonce: Hex32
    transport_public_key: Hex32
    signature_b64url: Annotated[str, Field(strict=True, min_length=86, max_length=86)]


class ModelMemoryError(ValueError):
    """A loaded-model check failed; this is not permission to continue serving."""


class ModelBuffer(Protocol):
    @property
    def nbytes(self) -> int: ...

    def read(self, offset: int, length: int) -> bytes: ...


class BufferMemoryReader:
    """Read a contiguous live CPU buffer without modifying it.

    Device adapters must read device memory, synchronize it, and account for all
    immutable weights/adapters. Hashing the file or an old CPU mirror is not an
    implementation of that contract.
    """

    def __init__(self, buffer: bytes | bytearray | memoryview) -> None:
        self._view = memoryview(buffer).cast("B")

    @property
    def nbytes(self) -> int:
        return self._view.nbytes

    def read(self, offset: int, length: int) -> bytes:
        if offset < 0 or length < 0 or offset + length > self.nbytes:
            raise ValueError("read outside buffer")
        return self._view[offset:offset + length].tobytes()


def measure_model_buffers(buffers: Mapping[str, ModelBuffer]) -> tuple[BufferDigest, ...]:
    """Read every byte in the declared inventory using bounded read chunks.

    Enumerating *all* serving buffers and holding a stable snapshot are the
    adapter's responsibility. The mapping must not be modified during this call.
    """
    if not 1 <= len(buffers) <= _MAX_BUFFERS:
        raise ModelMemoryError("invalid number of model buffers")
    result: list[BufferDigest] = []
    for name, reader in sorted(buffers.items()):
        size = reader.nbytes
        # Validate before looping or calling an adapter with unbounded offsets.
        BufferDigest(name=name, nbytes=size, sha256="0" * 64)
        digest = hashlib.sha256()
        for offset in range(0, size, _CHUNK_BYTES):
            length = min(_CHUNK_BYTES, size - offset)
            block = reader.read(offset, length)
            if not isinstance(block, bytes) or len(block) != length:
                raise ModelMemoryError("reader did not return the requested bytes")
            digest.update(block)
        if reader.nbytes != size:
            raise ModelMemoryError("buffer size changed while measuring")
        result.append(BufferDigest(name=name, nbytes=size, sha256=digest.hexdigest()))
    return tuple(result)


def _baseline_copy(baseline: ModelMemoryBaseline) -> ModelMemoryBaseline:
    # model_copy(update=...) and model_construct can bypass Pydantic validation.
    return ModelMemoryBaseline.model_validate_json(baseline.model_dump_json(warnings=False))


def model_memory_baseline_hash(baseline: ModelMemoryBaseline) -> str:
    return canonical_hash(_baseline_copy(baseline).model_dump(mode="json"))


def observe_model_memory(
    buffers: Mapping[str, ModelBuffer],
    *,
    baseline: ModelMemoryBaseline,
    challenge_nonce: str,
    transport_public_key: str,
    signing_key: Ed25519PrivateKey,
) -> ModelMemoryObservation:
    """Sign actual measurements, including mismatches, for the named baseline.

    The signer key must be provisioned to the trusted observer, not the host
    operator. A verifier pins its public key out of band. This function does not
    create or approve a baseline from potentially compromised live bytes.
    """
    unsigned = ModelMemoryObservation(
        baseline_hash=HashValue(model_memory_baseline_hash(baseline)),
        challenge_nonce=challenge_nonce,
        transport_public_key=transport_public_key,
        buffers=measure_model_buffers(buffers),
        signature_b64url="A" * 86,
    )
    payload = unsigned.model_dump(mode="json", exclude={"signature_b64url"})
    return ModelMemoryObservation(
        **payload,
        signature_b64url=_b64url_encode(signing_key.sign(canonicalize(payload))),
    )


class ModelMemoryVerifier:
    """Opt-in observer verification, with fresh, single-use challenges.

    This verdict must be combined with hardware evidence binding the same
    transport key, approved runtime and observer identity. It is not a KBS grant,
    an attestation quote, a serving lease, or a remote proof of shutdown.
    """

    def __init__(
        self,
        *,
        baseline: ModelMemoryBaseline,
        observer_public_key_b64url: str,
        transport_public_key: str,
        challenge_store: ChallengeStore | None = None,
    ) -> None:
        self._baseline = _baseline_copy(baseline)
        self._baseline_hash = model_memory_baseline_hash(self._baseline)
        # Reuse the wire model's canonical binding validation.
        ModelMemoryObservation(
            baseline_hash=HashValue(self._baseline_hash), challenge_nonce="0" * 64,
            transport_public_key=transport_public_key, buffers=self._baseline.buffers,
            signature_b64url="A" * 86,
        )
        raw = _b64url_decode(observer_public_key_b64url)
        if raw in _SMALL_ORDER_POINTS:
            raise ValueError("invalid observer public key")
        self._key = Ed25519PublicKey.from_public_bytes(raw)
        self._transport_key = transport_public_key
        self._challenges = challenge_store or ChallengeStore(ttl_seconds=30)

    def issue_challenge(self) -> Challenge:
        return self._challenges.issue()

    def verify(
        self, observation: ModelMemoryObservation, *, challenge_nonce: str,
    ) -> tuple[bool, str]:
        # Consume the caller's expected challenge, not an attacker-selected one.
        # A failed attempt also consumes it; retry requires fresh observation.
        try:
            self._challenges.consume(challenge_nonce)
            report = ModelMemoryObservation.model_validate_json(observation.model_dump_json(warnings=False))
            if report.challenge_nonce != challenge_nonce:
                return False, "model memory observation belongs to a different challenge"
            if report.baseline_hash != self._baseline_hash:
                return False, "model memory baseline binding mismatch"
            if report.transport_public_key != self._transport_key:
                return False, "model memory transport binding mismatch"
            payload = report.model_dump(mode="json", exclude={"signature_b64url"})
            self._key.verify(_b64url_decode(report.signature_b64url), canonicalize(payload))
            if report.buffers != self._baseline.buffers:
                return False, "loaded model buffer inventory or bytes differ from baseline"
            return True, "observer signature, bindings and model buffer measurements verified"
        except (ChallengeError, ValueError, TypeError, AttributeError, InvalidSignature):
            return False, "invalid, expired, replayed or unauthenticated model memory observation"


class ModelMemoryGuard:
    """Check before each operation; latch closed and invoke teardown on failure.

    Call *after* the existing custody authorization check and *before* dispatch to
    the serving worker. This does not authorize an operation by itself. It has no
    background thread and cannot detect a change during a running operation.
    The caller must quiesce/synchronize the real serving buffers for each scan.
    """

    def __init__(
        self, baseline: ModelMemoryBaseline, *, on_failure: Callable[[], None],
    ) -> None:
        if not callable(on_failure):
            raise TypeError("on_failure must be a teardown callback")
        self._baseline = _baseline_copy(baseline)
        self._on_failure = on_failure
        self._failed = False
        self._lock = threading.Lock()

    def check_before_operation(self, buffers: Mapping[str, ModelBuffer]) -> None:
        with self._lock:
            if self._failed:
                raise ModelMemoryError("model memory guard is latched closed")
            try:
                if measure_model_buffers(buffers) != self._baseline.buffers:
                    raise ModelMemoryError("loaded model buffers differ from approved baseline")
            except Exception as exc:
                # Adapter failures are denials too. Latch before teardown, which
                # can itself fail. Never resume just because bytes are restored.
                self._failed = True
                failure = exc
            else:
                return
        try:
            self._on_failure()
        except Exception as exc:
            raise ModelMemoryError("integrity failed; teardown callback also failed") from exc
        raise ModelMemoryError("model memory check failed; serving must remain disabled") from failure
