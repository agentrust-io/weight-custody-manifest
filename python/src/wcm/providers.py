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

from ._canonicalize import canonical_hash
from ._challenge import Challenge
from ._types import HashValue
from .attestation import CompositeEvidence, CpuQuote, GpuReport, MemoryFingerprint


class AttestationUnavailableError(RuntimeError):
    """Raised when a provider cannot produce hardware attestation.

    Callers MUST NOT treat this as success: an enclave that cannot attest is
    not entitled to a key.
    """


class AttestationProvider(ABC):
    """Interface every provider implements."""

    @abstractmethod
    def produce(self, challenge: Challenge, *, serving_image_measurement: str) -> CompositeEvidence:
        """Produce composite evidence bound to *challenge*'s nonce."""
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
        attestation_key_id: str = "vcek-mock-0001",
        cache_age_seconds: int = 0,
    ) -> CompositeEvidence:
        nonce = challenge.nonce

        cpu = CpuQuote(
            platform=platform,
            assurance_tier=assurance_tier,
            serving_image_measurement=HashValue(serving_image_measurement),
            nonce_echo=nonce,
            attestation_key_id=attestation_key_id,
            attestation_key_cache_age_seconds=cache_age_seconds,
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
            mf = MemoryFingerprint(
                challenge_nonce=nonce,
                aliasing_detected=aliasing_detected,
                readback_hash=HashValue(canonical_hash({"nonce": nonce})),
            )

        return CompositeEvidence(cpu=cpu, gpu=gpu, memory_fingerprint=mf)
