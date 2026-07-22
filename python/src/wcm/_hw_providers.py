"""Hardware attestation providers for the Layer 2 producer side.

These are the enclave-side adapters that fetch a real, nonce-bound attestation
quote and package it as WCM ``CompositeEvidence`` for the KBS to verify:

  SevSnpProvider    - AMD SEV-SNP CPU quote via /dev/sev-guest (Linux 5.19+)
  TdxProvider       - Intel TDX CPU quote via /dev/tdx-guest (Linux 6.2+)
  AzureSnpVtpmProvider - AMD SEV-SNP on an Azure CVM via the vTPM paravisor path
  AzureTdxVtpmProvider - Intel TDX on an Azure CVM (vTPM TD report + IMDS quote)
  NvidiaCcProvider  - NVIDIA CC GPU report via an external attestation command
  HardwareCompositeProvider - pairs a CPU provider with a GPU provider
  select_provider   - auto-select the best available, else software fallback

Validation status: the two Azure vTPM providers ARE validated against live Azure
hosts (SEV-SNP on DC2as_v5, TDX on DCes_v6 westeurope; their captured quotes
verify through snp.py / tdx.py against the real AMD and Intel roots). The
bare-metal ioctl paths (SevSnpProvider, TdxProvider) and NvidiaCcProvider are
still PROVISIONAL: their request layouts mirror the documented ABI and the
agentrust-io agent-manifest implementation (Apache-2.0) but are unchecked on
that hardware. What CI exercises everywhere is availability detection, the
software fallback, and report *parsing* against synthetic fixtures.

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
import urllib.request
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
      REPORT_DATA  at 0x50 (64 bytes)   - the guest-controlled binding field
      MEASUREMENT  at 0x90 (48 bytes)   - launch measurement (SHA-384)
      CHIP_ID      at 0x1A0 (64 bytes)  - identifies the VCEK
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


class AzureSnpVtpmProvider(CpuQuoteProvider):
    """AMD SEV-SNP CPU quote on an Azure confidential VM (vTPM path).

    Azure CVMs have no /dev/sev-guest; the paravisor publishes the SNP report in
    the vTPM NV index 0x01400001, wrapped in an HCL header (validated against a
    live Azure host - see the repo history). This provider reads that index via
    ``tpm2_nvread`` and extracts the raw SNP report.

    Caveat carried from that validation: Azure binds the report's REPORT_DATA to
    the vTPM runtime-data hash, not a caller nonce, so ``nonce_echo`` here is the
    structural challenge pointer while the raw report (``quote_b64``) carries the
    Azure binding. Cryptographic quote verification (VCEK signature + AMD chain)
    works; the KBS nonce-binding check does not apply on Azure.
    """

    platform = "amd-sev-snp"
    _NV_INDEX = "0x01400001"
    _TPM_DEV = "/dev/tpmrm0"

    @staticmethod
    def is_available() -> bool:
        return os.path.exists(AzureSnpVtpmProvider._TPM_DEV) and (
            shutil.which("tpm2_nvread") is not None
        )

    def _fetch_hcl(self) -> bytes:
        """Read the HCL report blob from the vTPM. Overridable in tests."""
        if shutil.which("tpm2_nvread") is None:
            raise AttestationUnavailableError("tpm2_nvread not found (Azure CVM tooling)")
        try:
            # NV index + tool are fixed constants (tpm2_nvread from the guest's
            # PATH), not user input.
            out = subprocess.run(  # nosec B603 B607
                ["tpm2_nvread", "-C", "o", self._NV_INDEX],
                capture_output=True,
                timeout=30,
                check=True,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise AttestationUnavailableError(
                f"reading vTPM NV {self._NV_INDEX} failed: {exc}"
            ) from exc
        return out.stdout

    def cpu_quote(
        self,
        challenge: Challenge,
        *,
        serving_image_measurement: str,
        assurance_tier: str = "hardware-attested",
    ) -> CpuQuote:
        from .snp import extract_snp_report_from_hcl, parse_snp_report

        report = extract_snp_report_from_hcl(self._fetch_hcl())
        parsed = parse_snp_report(report)
        return CpuQuote(
            platform=self.platform,
            assurance_tier=assurance_tier,
            serving_image_measurement=HashValue(serving_image_measurement),
            nonce_echo=challenge.nonce,
            attestation_key_id="vcek:" + parsed.chip_id[:8].hex(),
            attestation_key_cache_age_seconds=0,
            quote_b64=base64.b64encode(report).decode(),
        )


class AzureTdxVtpmProvider(CpuQuoteProvider):
    """Intel TDX CPU quote on an Azure confidential VM (vTPM paravisor path).

    Azure TDX CVMs have no /dev/tdx-guest. The paravisor publishes a TD report in
    the same vTPM NV index SNP uses (0x01400001, HCL-wrapped). Unlike an SNP
    report, a TD report is NOT self-verifiable: it carries no PCK signature. So
    this provider extracts the TD report and exchanges it for a full DCAP quote at
    the Azure IMDS quote service (/acc/tdquote); that quote (VCEK-free, QE + PCK
    chain to the Intel SGX Root CA) is what ``tdx.py`` verifies. Validated on a
    live Azure DCes_v6 host in westeurope.

    Caveat (mirrors ``AzureSnpVtpmProvider``): Azure binds the TD report's
    REPORT_DATA to the vTPM runtime-data/AK hash, not a caller nonce, so
    ``verify_tdx_quote`` must be called with ``expected_nonce=None`` here and
    freshness comes from the enclosing vTPM quote, not the TD report field.
    """

    platform = "intel-tdx"
    _NV_INDEX = "0x01400001"
    _TPM_DEV = "/dev/tpmrm0"
    _HCL_TDREPORT_OFFSET = 32
    _TDREPORT_LEN = 1024
    _TDQUOTE_URL = "http://169.254.169.254/acc/tdquote"  # fixed Azure IMDS link-local host

    @staticmethod
    def is_available() -> bool:
        # Requires the Azure vTPM tooling AND an HCL whose embedded report is a
        # TDX TD report (REPORTMACSTRUCT TYPE byte == 0x81). That byte is what
        # distinguishes a TDX CVM from an Azure SEV-SNP CVM sharing this NV index.
        if not (
            os.path.exists(AzureTdxVtpmProvider._TPM_DEV) and shutil.which("tpm2_nvread")
        ):
            return False
        try:
            hcl = AzureTdxVtpmProvider()._fetch_hcl()
        except AttestationUnavailableError:
            return False
        off = AzureTdxVtpmProvider._HCL_TDREPORT_OFFSET
        return hcl[:4] == b"HCLA" and len(hcl) > off and hcl[off] == 0x81

    def _fetch_hcl(self) -> bytes:
        """Read the HCL report blob from the vTPM (owner hierarchy). Overridable in tests."""
        if shutil.which("tpm2_nvread") is None:
            raise AttestationUnavailableError("tpm2_nvread not found (Azure CVM tooling)")
        try:
            out = subprocess.run(  # nosec B603 B607
                ["tpm2_nvread", "-C", "o", self._NV_INDEX],
                capture_output=True,
                timeout=30,
                check=True,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise AttestationUnavailableError(
                f"reading vTPM NV {self._NV_INDEX} failed: {exc}"
            ) from exc
        return out.stdout

    def _fetch_quote(self, tdreport: bytes) -> bytes:
        """Exchange a TD report for a DCAP quote at the Azure IMDS service. Overridable in tests."""
        report_b64u = base64.urlsafe_b64encode(tdreport).rstrip(b"=").decode()
        body = json.dumps({"report": report_b64u}).encode()
        req = urllib.request.Request(
            self._TDQUOTE_URL, data=body, headers={"Content-Type": "application/json"}
        )
        try:
            # Fixed Azure IMDS link-local host; not attacker-controlled.
            resp = json.loads(
                urllib.request.urlopen(req, timeout=30).read().decode()  # nosec B310
            )
        except (OSError, ValueError) as exc:
            raise AttestationUnavailableError(f"Azure /acc/tdquote failed: {exc}") from exc
        q = resp.get("quote") or resp.get("Quote")
        if not q:
            raise AttestationUnavailableError("no quote in /acc/tdquote response")
        return base64.urlsafe_b64decode(q + "=" * (-len(q) % 4))

    def cpu_quote(
        self,
        challenge: Challenge,
        *,
        serving_image_measurement: str,
        assurance_tier: str = "hardware-attested",
    ) -> CpuQuote:
        hcl = self._fetch_hcl()
        tdreport = hcl[self._HCL_TDREPORT_OFFSET : self._HCL_TDREPORT_OFFSET + self._TDREPORT_LEN]
        quote = self._fetch_quote(tdreport)
        return CpuQuote(
            platform=self.platform,
            assurance_tier=assurance_tier,
            serving_image_measurement=HashValue(serving_image_measurement),
            nonce_echo=challenge.nonce,
            # REPORT_DATA is Azure-vTPM-bound, not nonce-bound (see class docstring).
            attestation_key_id="tdx-quote:azure-vtpm",
            attestation_key_cache_age_seconds=0,
            quote_b64=base64.b64encode(quote).decode(),
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
        return SevSnpProvider()  # bare-metal / KVM SEV-SNP (guest controls REPORT_DATA)
    if TdxProvider.is_available():
        return TdxProvider()  # bare-metal / KVM Intel TDX (guest controls REPORT_DATA)
    # Azure TDX is checked before the Azure SNP catch-all: its is_available reads
    # the HCL and only matches a TDX TD report, so an Azure SNP CVM falls through.
    if AzureTdxVtpmProvider.is_available():
        return AzureTdxVtpmProvider()  # Azure CVM Intel TDX via vTPM + IMDS /acc/tdquote
    if AzureSnpVtpmProvider.is_available():
        return AzureSnpVtpmProvider()  # Azure CVM SEV-SNP via the vTPM paravisor path
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
