from __future__ import annotations

from dataclasses import replace

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from wcm import (
    BytearrayMemoryRange,
    memory_sweep_public_key,
    run_memory_sweep,
    verify_memory_sweep,
)


class AliasedMemoryRange:
    """Controlled defect: logical pages 0 and 2 share physical storage."""

    page_size = 64
    page_count = 4

    def __init__(self) -> None:
        self._pages = [bytearray(self.page_size) for _ in range(4)]

    def _physical(self, index: int) -> int:
        return 0 if index == 2 else index

    def write_page(self, index: int, value: bytes) -> None:
        self._pages[self._physical(index)][:] = value

    def read_page(self, index: int) -> bytes:
        return bytes(self._pages[self._physical(index)])


def _run(memory=None):
    key = Ed25519PrivateKey.generate()
    result = run_memory_sweep(
        memory or BytearrayMemoryRange(4 * 64, page_size=64),
        challenge_nonce="ab" * 32,
        signing_key=key,
        sweep_secret=b"protected unpredictable sweep key",
        range_start=0x1000,
    )
    return key, result


def test_real_full_range_write_read_transcript_verifies():
    key, result = _run()
    assert result.pages_written == result.pages_read == 4
    assert result.range_length == 256
    assert not result.aliasing_detected
    assert verify_memory_sweep(result, memory_sweep_public_key(key))[0]


def test_controlled_aliased_mapping_is_detected():
    key, result = _run(AliasedMemoryRange())
    assert result.aliasing_detected
    assert verify_memory_sweep(result, memory_sweep_public_key(key))[0]


def test_omitted_range_and_host_tampering_are_rejected():
    key, result = _run()
    public = memory_sweep_public_key(key)
    incomplete = result.model_copy(update={"pages_read": result.pages_read - 1})
    assert not verify_memory_sweep(incomplete, public)[0]
    forged = result.model_copy(update={"aliasing_detected": True})
    assert not verify_memory_sweep(forged, public)[0]


def test_host_authored_result_signed_by_wrong_key_is_rejected():
    _, result = _run()
    trusted = Ed25519PrivateKey.generate()
    assert not verify_memory_sweep(result, memory_sweep_public_key(trusted))[0]


def test_short_secret_and_invalid_range_fail_closed():
    key = Ed25519PrivateKey.generate()
    try:
        run_memory_sweep(
            BytearrayMemoryRange(64, page_size=64),
            challenge_nonce="nonce",
            signing_key=key,
            sweep_secret=b"short",
        )
    except ValueError as exc:
        assert "unpredictable" in str(exc)
    else:
        raise AssertionError("short sweep secret was accepted")
