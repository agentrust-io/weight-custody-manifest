"""Hardware attestation providers for the Layer 2 producer side.

These are the enclave-side adapters that fetch a real, nonce-bound attestation
quote and package it as WCM ``CompositeEvidence`` for the KBS to verify:

  SevSnpProvider   — AMD SEV-SNP CPU quote via /dev/sev-guest (Linux 5.19+)
  TdxProvider      — Intel TDX CPU quote via /dev/tdx-guest (Linux 6.2+)
  NvidiaCcProvider — NVIDIA CC GPU report via an external attestation command
  HardwareCompositeProvider — pairs a CPU provider with a GPU provider
  select_provider  — auto-select the best available, else software fallback

⚠️ NOT VALIDATED AGAINST REAL SILICON. The ioctl request layouts and the
report byte offsets below mirror the documented ABI and the agentrust-io
agent-manifest implementation (Apache-2.0), but they have not been checked
against a live SEV-SNP / TDX / NVIDIA machine. Treat every raw-report offset
as provisional until validated on hardware. What IS exercised in CI is the
availability detection, the software fallback, and the report *parsing* (against
synthetic fixtures) — never a real hardware root of trust.

Honesty note that outlives the offsets: even a perfectly-parsed, signature-valid
quote does not defeat a physically-extracted attestation key (TEE.fail-class,
open question 8.8). These providers get evidence to the gate; they do not close
that hole.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
# subprocess is used only for the NVIDIA attestation command (trusted env var).
import subprocess  # nosec B404
from abc import ABC, abstractmethod
from typing import Any, Optional

from ._challenge import Challenge
from ._types import HashValue
from .attestation import CompositeEvidence, CpuQuote, GpuReport
from .providers import AttestationProvider, AttestationUnavailableError, SoftwareProvider


def _report_data_for(nonce_hex: str) -> bytes:
    """64-byte REPORT_DATA binding the KBS nonce: sha256(nonce) zero-padded."""
    return hashlib.sha256(bytes.fromhex(nonce_hex)).digest() + bytes(32)


# ---------------------------------------------------------------------------
# CPU quote providers
# ---------------------------------------------------------------------------


class CpuQuoteProvider(ABC):
    """Produces a single-platform CPU CVM quote bound to a challenge nonce."""

    platform: str

    @staticmethod
    @abstractmethod
    def is_available() -> bool:
        """True if this platform's attestation interface is present locally."""
        raise NotImplementedError

    @abstractmethod
    def cpu_quote(
        self,
        challenge: Challenge,
        *,
        serving_image_measurement: str,
        assurance_tier: str = "hardware-attested",
    ) -> CpuQuote:
        raise NotImplementedError


class SevSnpProvider(CpuQuoteProvider):
    """AMD SEV-SNP CPU quote via /dev/sev-guest.

    Offsets (PROVISIONAL, per snp_attestation_report, kernel 6.x):
      REPORT_DATA  at 0x50 (64 bytes)   — the guest-controlled binding field
      MEASUREMENT  at 0x90 (48 bytes)   — launch measurement (SHA-384)
      CHIP_ID      at 0x1A0 (64 bytes)  — identifies the VCEK
    """

    platform = "amd-sev-snp"
    _DEV = "/dev/sev-guest"
    _IOCTL = 0xC0A00300  # SNP_GET_REPORT, _IOWR('S', 0, struct snp_guest_req_ioctl)

    @staticmethod
    def is_available() -> bool:
        return os.path.exists(SevSnpProvider._DEV)

    def _fetch_report(self, report_data: bytes) -> bytes:
        """Fetch a raw SNP report with the given REPORT_DATA. Overridable in tests."""
        buf = bytearray(4096)
        buf[:64] = report_data
        try:
            import fcntl  # Linux-only; absent off-Linux, which means no SEV-SNP here

            with open(self._DEV, "rb") as dev:
                fcntl.ioctl(dev, self._IOCTL, buf)  # type: ignore[attr-defined]
        except (OSError, ImportError) as exc:
            raise AttestationUnavailableError(
                f"SEV-SNP report request failed ({self._DEV}): {exc}"
            ) from exc
        return bytes(buf)

    def cpu_quote(
        self,
        challenge: Challenge,
        *,
        serving_image_measurement: str,
        assurance_tier: str = "hardware-attested",
    ) -> CpuQuote:
        raw = self._fetch_report(_report_data_for(challenge.nonce))
        chip_id = raw[0x1A0 : 0x1A0 + 64]
        return CpuQuote(
            platform=self.platform,
            assurance_tier=assurance_tier,
            serving_image_measurement=HashValue(serving_image_measurement),
            nonce_echo=challenge.nonce,
            attestation_key_id="vcek:" + chip_id[:8].hex(),
            attestation_key_cache_age_seconds=0,
            quote_b64=base64.b64encode(raw).decode(),
        )


class TdxProvider(CpuQuoteProvider):
    """Intel TDX CPU quote via /dev/tdx-guest.

    Offsets (PROVISIONAL): the request places REPORTDATA at buf[0:64]; the TD
    report's reportdata lands at 104 within the returned structure.
    """

    platform = "intel-tdx"
    _DEV = "/dev/tdx-guest"
    _IOCTL = 0xC4405401  # TDX_CMD_GET_REPORT0, _IOWR('T', 1, struct tdx_report_req)

    @staticmethod
    def is_available() -> bool:
        return os.path.exists(TdxProvider._DEV)

    def _fetch_report(self, report_data: bytes) -> bytes:
        buf = bytearray(1088)
        buf[:64] = report_data
        try:
            import fcntl  # Linux-only; absent off-Linux, which means no TDX here

            with open(self._DEV, "rb") as dev:
                fcntl.ioctl(dev, self._IOCTL, buf)  # type: ignore[attr-defined]
        except (OSError, ImportError) as exc:
            raise AttestationUnavailableError(
                f"TDX report request failed ({self._DEV}): {exc}"
            ) from exc
        return bytes(buf)

    def cpu_quote(
        self,
        challenge: Challenge,
        *,
        serving_image_measurement: str,
        assurance_tier: str = "hardware-attested",
    ) -> CpuQuote:
        raw = self._fetch_report(_report_data_for(challenge.nonce))
        return CpuQuote(
            platform=self.platform,
            assurance_tier=assurance_tier,
            serving_image_measurement=HashValue(serving_image_measurement),
            nonce_echo=challenge.nonce,
            # TDX has no VCEK; the quoting enclave's cert identifies the key.
            attestation_key_id="tdx-quote:" + raw[64:72].hex(),
            attestation_key_cache_age_seconds=0,
            quote_b64=base64.b64encode(raw).decode(),
        )


# ---------------------------------------------------------------------------
# GPU report provider
# ---------------------------------------------------------------------------


class NvidiaCcProvider:
    """NVIDIA Confidential Computing GPU report via an external attestation tool.

    Real NVIDIA CC attestation runs through NVIDIA's local GPU verifier / NRAS
    and is not a simple device ioctl, so this shells out to a command that emits
    a JSON object ``{"measurement": "...", "cc_mode": true, "report_b64": "..."}``.
    Configure it with ``WCM_NVIDIA_ATTESTATION_CMD``; absent that, this provider
    reports unavailable. The integration is PROVISIONAL and unvalidated.
    """

    platform = "nvidia-cc-gpu"
    _ENV = "WCM_NVIDIA_ATTESTATION_CMD"

    @staticmethod
    def is_available() -> bool:
        cmd = os.environ.get(NvidiaCcProvider._ENV)
        if not cmd:
            return False
        return shutil.which(cmd.split()[0]) is not None

    def _run_tool(self, nonce_hex: str) -> dict[str, Any]:
        cmd = os.environ.get(self._ENV)
        if not cmd:
            raise AttestationUnavailableError(
                f"{self._ENV} is not set; no NVIDIA CC attestation command configured"
            )
        try:
            # Command comes from a trusted operator env var, not user input.
            out = subprocess.run(  # nosec B603
                [*cmd.split(), "--nonce", nonce_hex],
                capture_output=True,
                text=True,
                timeout=30,
                check=True,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise AttestationUnavailableError(
                f"NVIDIA CC attestation command failed: {exc}"
            ) from exc
        try:
            data = json.loads(out.stdout)
        except json.JSONDecodeError as exc:
            raise AttestationUnavailableError(
                f"NVIDIA CC attestation command returned non-JSON output: {exc}"
            ) from exc
        if not isinstance(data, dict) or "measurement" not in data:
            raise AttestationUnavailableError(
                "NVIDIA CC attestation output missing 'measurement'"
            )
        return data

    def gpu_report(self, challenge: Challenge) -> GpuReport:
        data = self._run_tool(challenge.nonce)
        return GpuReport(
            platform=self.platform,
            measurement=str(data["measurement"]),
            cc_mode=bool(data.get("cc_mode", True)),
            nonce_echo=challenge.nonce,
            quote_b64=data.get("report_b64"),
        )


# ---------------------------------------------------------------------------
# Composite provider and auto-selection
# ---------------------------------------------------------------------------


class HardwareCompositeProvider(AttestationProvider):
    """Pairs a CPU quote provider with an optional GPU report provider.

    Both evidence chains are bound to the same challenge nonce, which is what
    the KBS's composite check requires (SPEC.md 3.2).
    """

    def __init__(
        self,
        cpu: CpuQuoteProvider,
        gpu: Optional[NvidiaCcProvider] = None,
    ) -> None:
        self._cpu = cpu
        self._gpu = gpu

    def produce(
        self, challenge: Challenge, *, serving_image_measurement: str
    ) -> CompositeEvidence:
        cpu_quote = self._cpu.cpu_quote(
            challenge, serving_image_measurement=serving_image_measurement
        )
        gpu_report = self._gpu.gpu_report(challenge) if self._gpu is not None else None
        return CompositeEvidence(cpu=cpu_quote, gpu=gpu_report)


def select_cpu_provider() -> Optional[CpuQuoteProvider]:
    """Return the best available CPU quote provider, or None if none is present."""
    if SevSnpProvider.is_available():
        return SevSnpProvider()
    if TdxProvider.is_available():
        return TdxProvider()
    return None


def select_provider(*, require_hardware: bool = False) -> AttestationProvider:
    """Select an attestation provider.

    Picks a hardware CPU provider (plus NVIDIA GPU if configured) when available.
    With ``require_hardware=True`` and no CPU hardware present, raises rather than
    silently downgrading; otherwise falls back to the software mock (which has no
    hardware root of trust and must not back a real custody claim).
    """
    cpu = select_cpu_provider()
    if cpu is None:
        if require_hardware:
            raise AttestationUnavailableError(
                "no hardware CPU attestation available (/dev/sev-guest, /dev/tdx-guest); "
                "set require_hardware=False only for development"
            )
        return SoftwareProvider()
    gpu = NvidiaCcProvider() if NvidiaCcProvider.is_available() else None
    return HardwareCompositeProvider(cpu, gpu)
