"""Protected-memory write/read sweep and signed release-attempt transcript."""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import math
from collections.abc import Iterator
from typing import Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from ._canonicalize import canonicalize
from ._types import HashValue
from .attestation import MemoryFingerprint


class ProtectedMemoryRange(Protocol):
    """Page-addressable memory owned by the protected runtime."""

    @property
    def page_size(self) -> int: ...

    @property
    def page_count(self) -> int: ...

    def write_page(self, index: int, value: bytes) -> None: ...

    def read_page(self, index: int) -> bytes: ...


class BytearrayMemoryRange:
    """Concrete in-process range; production adapters wrap protected pages."""

    def __init__(self, size: int, *, page_size: int = 4096) -> None:
        if size <= 0 or page_size <= 0 or size % page_size:
            raise ValueError("memory range must contain whole, non-empty pages")
        self._memory = bytearray(size)
        self._page_size = page_size

    @property
    def page_size(self) -> int:
        return self._page_size

    @property
    def page_count(self) -> int:
        return len(self._memory) // self._page_size

    def write_page(self, index: int, value: bytes) -> None:
        if len(value) != self._page_size or not 0 <= index < self.page_count:
            raise ValueError("invalid protected-memory page write")
        start = index * self._page_size
        self._memory[start : start + self._page_size] = value

    def read_page(self, index: int) -> bytes:
        if not 0 <= index < self.page_count:
            raise ValueError("invalid protected-memory page read")
        start = index * self._page_size
        return bytes(self._memory[start : start + self._page_size])


def memory_sweep_public_key(signing_key: Ed25519PrivateKey) -> str:
    raw = signing_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _page_value(secret: bytes, nonce: str, index: int, page_size: int) -> bytes:
    seed = hmac.new(
        secret, nonce.encode("utf-8") + index.to_bytes(8, "big"), hashlib.sha256
    ).digest()
    return hashlib.shake_256(seed).digest(page_size)


def _order(secret: bytes, nonce: str, count: int, label: bytes) -> Iterator[int]:
    """Yield a nonce-derived full permutation in constant auxiliary memory."""
    material = hmac.new(secret, label + nonce.encode("utf-8"), hashlib.sha256).digest()
    start = int.from_bytes(material[:16], "big") % count
    step = int.from_bytes(material[16:], "big") % count or 1
    while math.gcd(step, count) != 1:
        step = (step + 1) % count or 1
    for offset in range(count):
        yield (start + offset * step) % count


def run_memory_sweep(
    memory: ProtectedMemoryRange,
    *,
    challenge_nonce: str,
    signing_key: Ed25519PrivateKey,
    sweep_secret: bytes,
    range_start: int = 0,
) -> MemoryFingerprint:
    """Write then read every declared page and sign the complete transcript."""
    if len(sweep_secret) < 32:
        raise ValueError("sweep_secret must contain at least 32 unpredictable bytes")
    if memory.page_count <= 0 or memory.page_size <= 0 or range_start < 0:
        raise ValueError("declared protected-memory range is invalid")
    write_order = _order(sweep_secret, challenge_nonce, memory.page_count, b"write")
    read_order = _order(sweep_secret, challenge_nonce, memory.page_count, b"read")
    for index in write_order:
        memory.write_page(
            index, _page_value(sweep_secret, challenge_nonce, index, memory.page_size)
        )
    aliasing = False
    readback = hashlib.sha256()
    for index in read_order:
        actual = memory.read_page(index)
        expected = _page_value(sweep_secret, challenge_nonce, index, memory.page_size)
        aliasing |= not hmac.compare_digest(actual, expected)
        readback.update(index.to_bytes(8, "big"))
        readback.update(hashlib.sha256(actual).digest())
    unsigned = MemoryFingerprint(
        challenge_nonce=challenge_nonce,
        algorithm="wcm-full-range-v1",
        range_start=range_start,
        range_length=memory.page_count * memory.page_size,
        page_size=memory.page_size,
        pages_written=memory.page_count,
        pages_read=memory.page_count,
        aliasing_detected=aliasing,
        readback_hash=HashValue("sha256:" + readback.hexdigest()),
        public_key_b64url=memory_sweep_public_key(signing_key),
        signature_b64url="",
    )
    signature = signing_key.sign(canonicalize(unsigned.signing_payload()))
    return MemoryFingerprint(
        **{
            **unsigned.model_dump(),
            "signature_b64url": base64.urlsafe_b64encode(signature)
            .rstrip(b"=")
            .decode("ascii"),
        }
    )


def verify_memory_sweep(
    result: MemoryFingerprint, expected_public_key_b64url: str
) -> tuple[bool, str]:
    if result.algorithm != "wcm-full-range-v1":
        return False, "unsupported memory sweep algorithm"
    if (
        result.range_start < 0
        or result.range_length <= 0
        or result.page_size <= 0
        or result.range_length % result.page_size
        or result.pages_written != result.range_length // result.page_size
        or result.pages_read != result.pages_written
    ):
        return False, "memory sweep did not cover the complete declared range"
    if (
        result.public_key_b64url != expected_public_key_b64url
        or not result.signature_b64url
    ):
        return False, "memory sweep signer is not the policy-pinned protected key"
    try:
        public = base64.urlsafe_b64decode(
            result.public_key_b64url + "=" * (-len(result.public_key_b64url) % 4)
        )
        signature = base64.urlsafe_b64decode(
            result.signature_b64url + "=" * (-len(result.signature_b64url) % 4)
        )
        Ed25519PublicKey.from_public_bytes(public).verify(
            signature, canonicalize(result.signing_payload())
        )
    except (binascii.Error, ValueError, InvalidSignature):
        return False, "memory sweep signature is invalid"
    return True, "memory sweep transcript is complete and signed"
