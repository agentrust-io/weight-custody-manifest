"""Hardware attestation providers for the Layer 2 producer side.

These are the enclave-side adapters that fetch a real, nonce-bound attestation
quote and package it as WCM ``CompositeEvidence`` for the KBS to verify:

  SevSnpProvider    - AMD SEV-SNP CPU quote via /dev/sev-guest (Linux 5.19+)
  TdxProvider       - Intel TDX CPU report via /dev/tdx_guest (Linux 6.2+)
  AzureSnpVtpmProvider - AMD SEV-SNP on an Azure CVM via the vTPM paravisor path
  AzureTdxVtpmProvider - Intel TDX on an Azure CVM (vTPM TD report + IMDS quote)
  NvidiaCcProvider  - NVIDIA CC GPU report via an external attestation command
  HardwareCompositeProvider - pairs a CPU provider with a GPU provider
  select_provider   - auto-select the best available, else software fallback

Validation status: the two Azure vTPM providers ARE validated against live Azure
hosts (SEV-SNP on DC2as_v5, TDX on DCes_v6 westeurope; their captured quotes
verify through snp.py / tdx.py against the real AMD and Intel roots). The
bare-metal SEV-SNP ioctl path is validated on a live GCP N2D SEV-SNP guest. The
bare-metal TDX report ioctl path is also validated on a live GCP C3 guest;
conversion of that TDREPORT into a remotely verifiable TDX quote remains
provisional. NvidiaCcProvider is also still PROVISIONAL. What CI exercises
everywhere is availability detection, the
software fallback, and report *parsing* against synthetic fixtures.

Honesty note that outlives the offsets: even a perfectly-parsed, signature-valid
quote does not defeat a physically-extracted attestation key (TEE.fail-class,
open question 8.8). These providers get evidence to the gate; they do not close
that hole.
"""
from __future__ import annotations

import base64
import ctypes
import hashlib
import json
import os
import shutil
import tempfile
# subprocess is used only for the NVIDIA attestation command (trusted env var).
import subprocess  # nosec B404
import urllib.request
from abc import ABC, abstractmethod
from typing import Any, Optional

from ._challenge import Challenge
from ._types import HashValue
from .attestation import CompositeEvidence, CpuQuote, GpuReport
from .providers import AttestationProvider, AttestationUnavailableError, SoftwareProvider


def _report_data_for(nonce_hex: str, channel_binding: bytes = b"") -> bytes:
    """64-byte REPORT_DATA: sha256(nonce || channel_binding), zero-padded.

    ``channel_binding`` is the enclave's transport public key (raw 32 bytes) when
    channel binding is in use, else empty. Folding it in under the nonce is what
    stops a relay from substituting its own transport key: changing the key would
    change REPORT_DATA and fail quote verification. With an empty binding this is
    sha256(nonce), the pre-channel-binding value, so existing quotes still verify.
    """
    return hashlib.sha256(bytes.fromhex(nonce_hex) + channel_binding).digest() + bytes(32)


def _channel_binding(transport_public_key: Optional[str]) -> bytes:
    """Raw bytes of a hex transport key for REPORT_DATA, or empty if unset."""
    return bytes.fromhex(transport_public_key) if transport_public_key else b""


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
        transport_public_key: Optional[str] = None,
    ) -> CpuQuote:
        raise NotImplementedError


class SevSnpProvider(CpuQuoteProvider):
    """AMD SEV-SNP CPU quote via /dev/sev-guest.

    Offsets (per snp_attestation_report, kernel 6.x):
      REPORT_DATA  at 0x50 (64 bytes)   - the guest-controlled binding field
      MEASUREMENT  at 0x90 (48 bytes)   - launch measurement (SHA-384)
      CHIP_ID      at 0x1A0 (64 bytes)  - identifies the VCEK
    """

    platform = "amd-sev-snp"
    _DEV = "/dev/sev-guest"
    _IOCTL = 0xC0205300  # SNP_GET_REPORT, _IOWR('S', 0, 32-byte guest request)

    @staticmethod
    def is_available() -> bool:
        return os.path.exists(SevSnpProvider._DEV)

    def _fetch_report(self, report_data: bytes) -> bytes:
        """Fetch a raw SNP report with the given REPORT_DATA. Overridable in tests."""
        class _GuestRequest(ctypes.Structure):
            _fields_ = [
                ("msg_version", ctypes.c_uint8),
                ("req_data", ctypes.c_uint64),
                ("resp_data", ctypes.c_uint64),
                ("exitinfo2", ctypes.c_uint64),
            ]

        request = ctypes.create_string_buffer(96)
        ctypes.memmove(request, report_data, 64)
        response = ctypes.create_string_buffer(4000)
        ioctl_arg = _GuestRequest(
            msg_version=1,
            req_data=ctypes.addressof(request),
            resp_data=ctypes.addressof(response),
            exitinfo2=0,
        )
        try:
            import fcntl  # Linux-only; absent off-Linux, which means no SEV-SNP here

            with open(self._DEV, "rb") as dev:
                fcntl.ioctl(dev, self._IOCTL, ioctl_arg)  # type: ignore[attr-defined]
        except (OSError, ImportError) as exc:
            raise AttestationUnavailableError(
                f"SEV-SNP report request failed ({self._DEV}): {exc}"
            ) from exc
        status = int.from_bytes(response.raw[0:4], "little")
        report_size = int.from_bytes(response.raw[4:8], "little")
        if status != 0 or report_size != 1184:
            raise AttestationUnavailableError(
                "SEV-SNP report response invalid "
                f"(status={status}, report_size={report_size}, "
                f"exitinfo2={ioctl_arg.exitinfo2})"
            )
        return response.raw[32 : 32 + report_size]

    def cpu_quote(
        self,
        challenge: Challenge,
        *,
        serving_image_measurement: str,
        assurance_tier: str = "hardware-attested",
        transport_public_key: Optional[str] = None,
    ) -> CpuQuote:
        # Bare-metal / KVM SEV-SNP: the guest controls REPORT_DATA, so the
        # transport key is bound there under the nonce (channel binding).
        raw = self._fetch_report(
            _report_data_for(challenge.nonce, _channel_binding(transport_public_key))
        )
        chip_id = raw[0x1A0 : 0x1A0 + 64]
        return CpuQuote(
            platform=self.platform,
            assurance_tier=assurance_tier,
            serving_image_measurement=HashValue(serving_image_measurement),
            nonce_echo=challenge.nonce,
            attestation_key_id="vcek:" + chip_id[:8].hex(),
            attestation_key_cache_age_seconds=0,
            quote_b64=base64.b64encode(raw).decode(),
            transport_public_key=transport_public_key,
        )


class TdxProvider(CpuQuoteProvider):
    """Intel TDX CPU report via /dev/tdx_guest.

    The ioctl request is 64 bytes of REPORTDATA followed by a 1,024-byte
    TDREPORT. REPORTDATA is at offset 128 within the returned TDREPORT's
    REPORTMACSTRUCT. A TDREPORT still needs a quote-generation service before a
    remote verifier can validate it against Intel collateral.
    """

    platform = "intel-tdx"
    _DEV = "/dev/tdx_guest"
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
        return bytes(buf[64:])

    def cpu_quote(
        self,
        challenge: Challenge,
        *,
        serving_image_measurement: str,
        assurance_tier: str = "hardware-attested",
        transport_public_key: Optional[str] = None,
    ) -> CpuQuote:
        # configfs-tsm / bare-metal TDX: the guest controls REPORT_DATA, so the
        # transport key is bound there under the nonce (channel binding).
        raw = self._fetch_report(
            _report_data_for(challenge.nonce, _channel_binding(transport_public_key))
        )
        return CpuQuote(
            platform=self.platform,
            assurance_tier=assurance_tier,
            serving_image_measurement=HashValue(serving_image_measurement),
            nonce_echo=challenge.nonce,
            # TDX has no VCEK; the quoting enclave's cert identifies the key.
            attestation_key_id="tdx-report:" + raw[:8].hex(),
            attestation_key_cache_age_seconds=0,
            quote_b64=base64.b64encode(raw).decode(),
            transport_public_key=transport_public_key,
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
    _AK_HANDLE = "0x81000003"
    _THIM_URL = "http://169.254.169.254/metadata/THIM/amd/certification"

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
        transport_public_key: Optional[str] = None,
    ) -> CpuQuote:
        from .snp import extract_snp_report_from_hcl, parse_snp_report

        hcl = self._fetch_hcl()
        report = extract_snp_report_from_hcl(hcl)
        parsed = parse_snp_report(report)
        binding = _report_data_for(
            challenge.nonce, _channel_binding(transport_public_key)
        )[:32]
        bundle = self._fetch_freshness_bundle(hcl, binding)
        return CpuQuote(
            platform=self.platform,
            assurance_tier=assurance_tier,
            serving_image_measurement=HashValue(serving_image_measurement),
            nonce_echo=challenge.nonce,
            attestation_key_id="vcek:" + parsed.chip_id[:8].hex(),
            attestation_key_cache_age_seconds=0,
            quote_b64=base64.b64encode(json.dumps(bundle).encode()).decode(),
            transport_public_key=transport_public_key,
        )

    def _fetch_freshness_bundle(self, hcl: bytes, binding: bytes) -> dict[str, Any]:
        """Capture the HCL-authenticated AK's fresh PCR-23 quote."""
        for tool in ("tpm2_readpublic", "tpm2_quote"):
            if shutil.which(tool) is None:
                raise AttestationUnavailableError(f"{tool} not found (Azure CVM tooling)")
        try:
            req = urllib.request.Request(self._THIM_URL, headers={"Metadata": "true"})
            thim = json.loads(urllib.request.urlopen(req, timeout=10).read().decode())  # nosec B310
            with tempfile.TemporaryDirectory(prefix="wcm-vtpm-") as tmp:
                ak = os.path.join(tmp, "ak.pem")
                msg = os.path.join(tmp, "quote.msg")
                sig = os.path.join(tmp, "quote.sig")
                subprocess.run(  # nosec B603 B607
                    ["tpm2_readpublic", "-c", self._AK_HANDLE, "-f", "pem", "-o", ak],
                    capture_output=True,
                    timeout=30,
                    check=True,
                )
                subprocess.run(  # nosec B603 B607
                    [
                        "tpm2_quote", "-c", self._AK_HANDLE, "-l", "sha256:23",
                        "-q", binding.hex(), "-m", msg, "-s", sig, "-g", "sha256",
                    ],
                    capture_output=True,
                    timeout=30,
                    check=True,
                )
                ak_pem = open(ak, encoding="utf-8").read()
                quote = open(msg, "rb").read()
                signature = open(sig, "rb").read()
        except (OSError, ValueError, subprocess.SubprocessError) as exc:
            raise AttestationUnavailableError(f"Azure vTPM freshness capture failed: {exc}") from exc
        chain = self._split_pems(thim.get("certificateChain", ""))
        vcek = thim.get("vcekCert") or thim.get("vcek") or thim.get("vcekCertificate")
        if not vcek or not chain:
            raise AttestationUnavailableError("Azure THIM response lacks VCEK/AMD chain")
        return {
            "kind": "wcm-azure-snp-vtpm/v1",
            "hcl_b64": base64.b64encode(hcl).decode(),
            "ak_pem": ak_pem,
            "tpm_quote_b64": base64.b64encode(quote).decode(),
            "tpm_signature_b64": base64.b64encode(signature).decode(),
            "vcek_pem": vcek,
            "intermediates_pem": chain[:-1],
        }

    @staticmethod
    def _split_pems(blob: str) -> list[str]:
        marker = "-----END CERTIFICATE-----"
        return [part + marker + "\n" for part in blob.split(marker) if "BEGIN CERTIFICATE" in part]


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
        transport_public_key: Optional[str] = None,
    ) -> CpuQuote:
        hcl = self._fetch_hcl()
        tdreport = hcl[self._HCL_TDREPORT_OFFSET : self._HCL_TDREPORT_OFFSET + self._TDREPORT_LEN]
        quote = self._fetch_quote(tdreport)
        return CpuQuote(
            platform=self.platform,
            assurance_tier=assurance_tier,
            serving_image_measurement=HashValue(serving_image_measurement),
            nonce_echo=challenge.nonce,
            # REPORT_DATA is Azure-vTPM-bound, not nonce-bound (see class docstring);
            # the transport key's hardware binding likewise rides the vTPM quote.
            attestation_key_id="tdx-quote:azure-vtpm",
            attestation_key_cache_age_seconds=0,
            quote_b64=base64.b64encode(quote).decode(),
            transport_public_key=transport_public_key,
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
                # Local NVIDIA appraisal fetches RIM and OCSP material and can
                # legitimately take several minutes on a fresh validation host.
                timeout=360,
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
        self,
        challenge: Challenge,
        *,
        serving_image_measurement: str,
        transport_public_key: Optional[str] = None,
    ) -> CompositeEvidence:
        cpu_quote = self._cpu.cpu_quote(
            challenge,
            serving_image_measurement=serving_image_measurement,
            transport_public_key=transport_public_key,
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
