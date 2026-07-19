"""Attestation evidence models for the Layer 2 gate (SPEC.md section 3.2).

The enclave's evidence is TWO chains, not one: a CPU CVM quote and a SEPARATE
GPU attestation report, both echoing the same KBS nonce. The KBS performs
composite verification and, crucially, checks that the two are bound to each
other by the shared nonce echo (a valid CPU quote paired with an unattested or
mismatched GPU is rejected).

These are the shapes the KBS verifies; they are not the manifest schema. A
provider (see ``providers``) produces a ``CompositeEvidence``; the software
provider fills these with well-formed but hardware-unrooted values for testing.
"""
from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, ConfigDict

from ._types import HashValue


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class CpuQuote(_Strict):
    """CPU confidential-VM quote (SEV-SNP / TDX class)."""

    platform: str  # e.g. "amd-sev-snp"
    assurance_tier: str  # e.g. "hardware-attested"
    serving_image_measurement: HashValue
    nonce_echo: str  # the KBS nonce this quote was produced over
    attestation_key_id: str  # VCEK id (AMD) or equivalent
    attestation_key_cache_age_seconds: int = 0


class GpuReport(_Strict):
    """GPU attestation report, a separate evidence chain from the CPU quote."""

    platform: str  # e.g. "nvidia-cc-gpu"
    measurement: str  # matches release_policy.required_gpu_measurement.rim_pin
    cc_mode: bool = True
    nonce_echo: str  # MUST equal the CPU quote's nonce_echo (composite binding)


class MemoryFingerprint(_Strict):
    """v0.8 memory-fingerprint challenge response (SPEC.md 3.1, 3.6).

    The enclave writes KBS-supplied random values across its full declared DRAM
    range and returns a hash of the readback. ``aliasing_detected`` is true when
    the readback shows the address collisions a BadRAM-class aliasing attack
    produces. Required in the hostile-owner posture.
    """

    challenge_nonce: str
    aliasing_detected: bool
    readback_hash: HashValue


class CompositeEvidence(_Strict):
    cpu: CpuQuote
    gpu: Optional[GpuReport] = None
    memory_fingerprint: Optional[MemoryFingerprint] = None
