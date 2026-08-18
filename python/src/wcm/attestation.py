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

from pydantic import BaseModel, ConfigDict, Field

from ._types import HashValue
from .memory_sweep import GRANULE_BYTES


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class CpuQuote(_Strict):
    """CPU confidential-VM quote (SEV-SNP / TDX class).

    ``quote_b64`` optionally carries a raw hardware report or a platform-specific
    evidence bundle (base64) for verifier-side cryptographic checks.
    """

    platform: str  # e.g. "amd-sev-snp"
    assurance_tier: str  # e.g. "hardware-attested"
    serving_image_measurement: HashValue
    nonce_echo: str  # the KBS nonce this quote was produced over
    attestation_key_id: str  # VCEK id (AMD) or equivalent
    attestation_key_cache_age_seconds: int = 0
    quote_b64: Optional[str] = None
    # Hex X25519 public key the enclave vouches for, folded into REPORT_DATA
    # under the nonce (see _seal, _hw_providers). When present the KBS seals the
    # released key to it, so a relayed quote yields only ciphertext (SPEC 3.2
    # channel binding). Absent on the pre-channel-binding evidence shape.
    transport_public_key: Optional[str] = None


class GpuReport(_Strict):
    """GPU attestation report, a separate evidence chain from the CPU quote."""

    platform: str  # e.g. "nvidia-cc-gpu"
    measurement: str  # matches release_policy.required_gpu_measurement.rim_pin
    cc_mode: bool = True
    nonce_echo: str  # MUST equal the CPU quote's nonce_echo (composite binding)
    quote_b64: Optional[str] = None


class DeclaredMemoryRange(_Strict):
    """The protected-memory range a fingerprint response says it swept.

    Without it the readback hash is unverifiable and the sweep is unbounded: a
    single page and the whole DRAM installation would present identically. The
    gate re-derives the probe plan from this range and the challenge nonce, so
    the range is part of what the evidence commits to, not a label on it.

    Mirrors ``memory_sweep.ProtectedRange``; kept as its own model because this
    is the wire shape the gate validates, and the sweep's own type carries
    behaviour the wire does not.
    """

    base_address: int = Field(ge=0)
    size_bytes: int = Field(gt=0)
    granule_bytes: int = Field(default=GRANULE_BYTES, gt=0)
    probe_count: int = Field(gt=0)


class MemoryFingerprint(_Strict):
    """v0.8 memory-fingerprint challenge response (SPEC.md 3.1, 3.6).

    The enclave writes nonce-derived values across its declared protected-memory
    range, reads them back in a different nonce-derived order, and returns a hash
    of the readback. ``aliasing_detected`` is true when the readback shows the
    address collisions a BadRAM-class aliasing attack produces. Required in the
    hostile-owner posture.

    ``declared_range`` is what the gate needs to check the response rather than
    file it: with the range and the nonce it re-derives the probe plan and the
    readback an honest sweep must have produced. It is optional on the model only
    so a pre-sweep evidence bundle still parses; the gate denies when the
    challenge is required and the range is absent.

    ``commitment`` is ``memory_sweep.fingerprint_commitment`` hex: the 32 bytes
    the enclave folds into the quote's REPORT_DATA. It is what separates a result
    the enclave produced from one the host wrote, and the gate can only enforce
    that separation when a quote verifier is wired (see ``kbs`` and
    ``docs/memory-fingerprint.md``).
    """

    challenge_nonce: str
    aliasing_detected: bool
    readback_hash: HashValue
    declared_range: Optional[DeclaredMemoryRange] = None
    commitment: Optional[str] = None


class CompositeEvidence(_Strict):
    cpu: CpuQuote
    gpu: Optional[GpuReport] = None
    memory_fingerprint: Optional[MemoryFingerprint] = None
