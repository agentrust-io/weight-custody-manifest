"""Attestation providers for the Layer 2 gate.

A provider turns a KBS challenge into ``CompositeEvidence``. Only a software
mock is implemented in this preview; real TEE providers (AMD SEV-SNP, Intel
TDX, NVIDIA CC) are a later PR and can reuse the agent-manifest hardware
providers.

The provider interface intentionally mirrors agent-manifest's so the family
stays consistent.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Optional

from ._challenge import Challenge
from ._types import HashValue
from .attestation import (
    CompositeEvidence,
    CpuQuote,
    DeclaredMemoryRange,
    GpuReport,
    MemoryFingerprint,
)
from .memory_sweep import (
    AliasedRegion,
    BufferRegion,
    MemoryRegion,
    ProtectedRange,
    fingerprint_commitment,
    run_sweep,
)

#: The mock's default protected range: 1 MiB of real allocation at a plausible
#: guest-physical base. Small enough to sweep inside a unit test, large enough
#: that the probe set spans 256 granules and an alias has somewhere to fold.
_MOCK_RANGE_BASE = 0x4000_0000
_MOCK_RANGE_BYTES = 1 << 20
_MOCK_PROBE_COUNT = 64


class AttestationUnavailableError(RuntimeError):
    """Raised when a provider cannot produce hardware attestation.

    Callers MUST NOT treat this as success: an enclave that cannot attest is
    not entitled to a key.
    """


class AttestationProvider(ABC):
    """Interface every provider implements."""

    @abstractmethod
    def produce(
        self,
        challenge: Challenge,
        *,
        serving_image_measurement: str,
        transport_public_key: Optional[str] = None,
    ) -> CompositeEvidence:
        """Produce composite evidence bound to *challenge*'s nonce.

        ``transport_public_key`` (hex X25519) is the enclave transport key the
        KBS seals the released key to; when set it is bound into the quote for
        channel binding (SPEC 3.2). Optional so the pre-channel-binding flow is
        unchanged.
        """
        raise NotImplementedError


class SoftwareProvider(AttestationProvider):
    """Mock provider for tests and local development.

    It assembles well-formed evidence over a challenge nonce, but it does NOT
    talk to any TEE and its evidence therefore carries no hardware root of
    trust. A production KBS MUST use a hardware provider; this exists so the
    gate logic can be exercised end to end without hardware. Its knobs
    (``aliasing_detected``, a wrong ``nonce_echo`` via ``break_gpu_binding``,
    a stale cache age) let tests drive each failure path.
    """

    def produce(
        self,
        challenge: Challenge,
        *,
        serving_image_measurement: str,
        platform: str = "amd-sev-snp",
        assurance_tier: str = "hardware-attested",
        gpu_platform: str = "nvidia-cc-gpu",
        gpu_measurement: Optional[str] = None,
        include_gpu: bool = True,
        break_gpu_binding: bool = False,
        include_memory_fingerprint: bool = False,
        aliasing_detected: bool = False,
        memory_range: Optional[ProtectedRange] = None,
        region: Optional[MemoryRegion] = None,
        attestation_key_id: str = "vcek-mock-0001",
        cache_age_seconds: int = 0,
        transport_public_key: Optional[str] = None,
    ) -> CompositeEvidence:
        nonce = challenge.nonce

        cpu = CpuQuote(
            platform=platform,
            assurance_tier=assurance_tier,
            serving_image_measurement=HashValue(serving_image_measurement),
            nonce_echo=nonce,
            attestation_key_id=attestation_key_id,
            attestation_key_cache_age_seconds=cache_age_seconds,
            # The mock carries no raw quote, so nothing binds this into hardware;
            # it is here so the gate can seal to it and the relay path is testable.
            transport_public_key=transport_public_key,
        )

        gpu: Optional[GpuReport] = None
        if include_gpu and gpu_measurement is not None:
            gpu = GpuReport(
                platform=gpu_platform,
                measurement=gpu_measurement,
                nonce_echo=("tampered-" + nonce if break_gpu_binding else nonce),
            )

        mf: Optional[MemoryFingerprint] = None
        if include_memory_fingerprint:
            declared = memory_range or ProtectedRange(
                base_address=_MOCK_RANGE_BASE,
                size_bytes=_MOCK_RANGE_BYTES,
                probe_count=_MOCK_PROBE_COUNT,
            )
            # An actual sweep, over an actual allocation. ``aliasing_detected``
            # is not a field this sets: it selects the region and the sweep
            # reports what it found, so a test asking for aliasing gets the
            # detection exercised rather than the flag asserted.
            if region is None:
                region = (
                    AliasedRegion(declared, declared.size_bytes // 2)
                    if aliasing_detected
                    else BufferRegion(declared)
                )
            result = run_sweep(nonce, declared, region)
            mf = MemoryFingerprint(
                challenge_nonce=nonce,
                aliasing_detected=result.aliasing_detected,
                readback_hash=HashValue(result.readback_hash),
                declared_range=DeclaredMemoryRange(**declared.as_dict()),
                commitment=fingerprint_commitment(
                    nonce, declared, result.readback_hash, result.aliasing_detected
                ).hex(),
            )

        return CompositeEvidence(cpu=cpu, gpu=gpu, memory_fingerprint=mf)
