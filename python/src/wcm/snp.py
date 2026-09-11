"""AMD SEV-SNP attestation report parsing and verification (SPEC.md section 3.2).

The vendor-specific half of quote verification for AMD, grounded in a real
report captured from a live Azure SEV-SNP confidential VM (see the hardware
validation in the repo history):

  - parse the SNP attestation report (ABI v2/v3) into its fields,
  - verify the report's VCEK signature (ECDSA P-384 over the report body, with
    AMD's little-endian r||s encoding), and
  - extract the report from Azure's vTPM HCL wrapper (the paravisor path used by
    Azure CVMs, which have no /dev/sev-guest).

``SnpQuoteParser`` plugs a report + its VCEK/ASK/ARK chain into the generic
``QuoteVerifier`` (see ``_quote_verify``), so the SNP flow reuses the tested
cert-chain + nonce-binding machinery. The VCEK->ASK->ARK chain is RSA-PSS, which
the verifier handles (validated against real AMD certs).

REPORT_DATA note: a bare-metal/KVM guest sets REPORT_DATA to its own value (WCM
uses sha256(nonce)), so the nonce binding holds. Azure CVMs bind REPORT_DATA to
the vTPM runtime-data hash instead, so there the nonce check does not apply and
verification is chain + signature only.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

from ._quote_verify import ParsedQuote, QuoteFormatError

# SNP attestation report field offsets (AMD ABI). Report body signed by the
# VCEK is bytes [0 : _SIG_OFFSET]; the signature occupies the trailing block.
_REPORT_LEN = 0x4A0  # 1184 bytes
_OFF_VERSION = 0x00
_OFF_POLICY = 0x08
_OFF_VMPL = 0x30
_OFF_PLATFORM_INFO = 0x40  # 8 bytes, see PlatformInfo
_OFF_REPORT_DATA = 0x50  # 64 bytes
_OFF_MEASUREMENT = 0x90  # 48 bytes (SHA-384 launch measurement)
_OFF_HOST_DATA = 0xC0  # 32 bytes
_OFF_REPORTED_TCB = 0x180  # 8 bytes
_OFF_CHIP_ID = 0x1A0  # 64 bytes
_SIG_OFFSET = 0x2A0  # signature block (512 bytes): r (72 LE) || s (72 LE) || rsvd
_ECDSA_COMPONENT = 48  # P-384 r/s are 48 bytes, stored in 72-byte little-endian slots

_HCL_SIGNATURE = b"HCLA"
_HCL_SNP_OFFSET = 32  # SNP report starts after the 32-byte Azure HCL header


# PLATFORM_INFO bit positions within the 8-byte field at _OFF_PLATFORM_INFO.
_PI_SMT_EN = 0
_PI_TSME_EN = 1
_PI_ECC_EN = 2
_PI_RAPL_DIS = 3
_PI_CIPHERTEXT_HIDING_EN = 4
_PI_ALIAS_CHECK_COMPLETE = 5
_PI_SEV_TIO_EN = 7

# Report version in which a PLATFORM_INFO bit acquired meaning. Below it the bit
# is reserved, so a verifier must report "unknown", never "false" (see below).
_MIN_VERSION_ALIAS_CHECK = 3
_MIN_VERSION_SEV_TIO = 5


@dataclass(frozen=True)
class PlatformInfo:
    """The PLATFORM_INFO field of an SNP attestation report (offset 0x40).

    Two of these bits are the only statements about *physical* platform state
    that any production attestation report carries today, which is why they are
    parsed rather than skipped:

    ``alias_check_complete`` is AMD's mitigation for BadRAM (CVE-2024-21944,
    AMD-SB-3015): the Secure Boot loader measures DRAM's response to address
    bits at boot and sets this bit only when no aliasing addresses were found.
    It requires the Oct 2024 firmware floor (Milan/Milan-X: PI 1.0.0.D + SEV FW
    1.55.22, SPL 0x17; Genoa/Genoa-X/Bergamo/Siena: PI 1.0.0.D + SEV FW 1.55.38,
    SPL 0x16). Its limit is documented in SPEC.md section 3.6: a boot-time scan
    is a time-of-check/time-of-use control, and Battering RAM (IEEE S&P 2026)
    defeats it by passing the command/address lines through untouched during
    POST and enabling aliasing at runtime. Requiring it raises the floor from
    "any $10 SPD spoof" to "an interposer"; it does not close the class.

    ``ciphertext_hiding_en`` reports whether the host's read path to SNP guest
    private memory returns constant values instead of ciphertext. It is the
    precondition SPEC.md section 3.6 attaches to the semi-trusted-operator
    custody claim, because without it a *malicious hypervisor* extracts keys via
    ciphertext side channels (CipherLeaks, USENIX Security 2021; Heracles, CCS
    2025) with no physical access at all. It does not bear on a physical
    adversary: TEE.fail extracted an ECDSA key from a SEV-SNP CVM on an EPYC
    9015 with ciphertext hiding verified enabled.

    Version gating is deliberate. ``ALIAS_CHECK_COMPLETE`` was added in report
    version 3 and ``SEV-TIO`` in version 5; below those the bits are reserved
    and read zero. Reporting a reserved zero as ``False`` would turn "this
    platform predates the field" into "this platform failed its alias check",
    so those two are ``None`` when the report version cannot carry them.
    """

    raw: int
    smt_en: bool
    tsme_en: bool
    ecc_en: bool
    rapl_dis: bool
    ciphertext_hiding_en: bool
    alias_check_complete: bool | None
    sev_tio_en: bool | None


def _parse_platform_info(value: int, version: int) -> PlatformInfo:
    def bit(pos: int) -> bool:
        return bool((value >> pos) & 1)

    return PlatformInfo(
        raw=value,
        smt_en=bit(_PI_SMT_EN),
        tsme_en=bit(_PI_TSME_EN),
        ecc_en=bit(_PI_ECC_EN),
        rapl_dis=bit(_PI_RAPL_DIS),
        ciphertext_hiding_en=bit(_PI_CIPHERTEXT_HIDING_EN),
        alias_check_complete=(
            bit(_PI_ALIAS_CHECK_COMPLETE) if version >= _MIN_VERSION_ALIAS_CHECK else None
        ),
        sev_tio_en=bit(_PI_SEV_TIO_EN) if version >= _MIN_VERSION_SEV_TIO else None,
    )


@dataclass(frozen=True)
class SnpReport:
    version: int
    policy: int
    vmpl: int
    platform_info: PlatformInfo
    report_data: bytes  # 64 bytes
    measurement: bytes  # 48 bytes
    host_data: bytes  # 32 bytes
    reported_tcb: int
    chip_id: bytes  # 64 bytes
    raw: bytes  # the full report bytes

    @property
    def body(self) -> bytes:
        """The bytes the VCEK signs (everything before the signature block)."""
        return self.raw[:_SIG_OFFSET]


def parse_snp_report(report: bytes) -> SnpReport:
    """Parse an AMD SEV-SNP attestation report into its fields."""
    if len(report) < _REPORT_LEN:
        raise QuoteFormatError(
            f"SNP report too short: {len(report)} bytes, need >= {_REPORT_LEN}"
        )

    def u(off: int, size: int = 8) -> int:
        return int.from_bytes(report[off : off + size], "little")

    version = u(_OFF_VERSION, 4)
    return SnpReport(
        version=version,
        policy=u(_OFF_POLICY, 8),
        vmpl=u(_OFF_VMPL, 4),
        platform_info=_parse_platform_info(u(_OFF_PLATFORM_INFO, 8), version),
        report_data=report[_OFF_REPORT_DATA : _OFF_REPORT_DATA + 64],
        measurement=report[_OFF_MEASUREMENT : _OFF_MEASUREMENT + 48],
        host_data=report[_OFF_HOST_DATA : _OFF_HOST_DATA + 32],
        reported_tcb=u(_OFF_REPORTED_TCB, 8),
        chip_id=report[_OFF_CHIP_ID : _OFF_CHIP_ID + 64],
        raw=bytes(report[:_REPORT_LEN]),
    )


def snp_signature_der(report: bytes) -> bytes:
    """Convert the SNP report's AMD-encoded signature to DER (for ECDSA verify).

    The signature block holds P-384 (r, s) as little-endian integers in 72-byte
    slots; ECDSA verification needs a DER-encoded (r, s).
    """
    sig = report[_SIG_OFFSET : _SIG_OFFSET + 512]
    r = int.from_bytes(sig[0:_ECDSA_COMPONENT], "little")
    s = int.from_bytes(sig[72 : 72 + _ECDSA_COMPONENT], "little")
    return utils.encode_dss_signature(r, s)


def verify_snp_report_signature(report: bytes, vcek: x509.Certificate) -> bool:
    """True if *report* is signed by *vcek* (ECDSA P-384 / SHA-384 over the body)."""
    from cryptography.exceptions import InvalidSignature

    pub = vcek.public_key()
    if not isinstance(pub, ec.EllipticCurvePublicKey):
        return False
    try:
        pub.verify(snp_signature_der(report), report[:_SIG_OFFSET], ec.ECDSA(hashes.SHA384()))
        return True
    except InvalidSignature:
        return False


def extract_snp_report_from_hcl(hcl: bytes) -> bytes:
    """Extract the SNP report from an Azure vTPM HCL wrapper (NV index 0x01400001)."""
    if hcl[:4] != _HCL_SIGNATURE:
        raise QuoteFormatError(
            f"not an Azure HCL report (signature {hcl[:4]!r}, expected {_HCL_SIGNATURE!r})"
        )
    return hcl[_HCL_SNP_OFFSET : _HCL_SNP_OFFSET + _REPORT_LEN]


class SnpQuoteParser:
    """Adapts a raw SNP report + its VCEK/ASK/ARK chain to a ``ParsedQuote``.

    On Azure the cert chain is fetched separately (THIM/IMDS), so it is supplied
    at construction rather than embedded in the quote. ``quote_b64`` is the
    base64 of the raw SNP report.
    """

    def __init__(
        self, vcek: x509.Certificate, intermediates: list[x509.Certificate]
    ) -> None:
        self._vcek = vcek
        self._intermediates = intermediates

    def parse(self, quote_b64: str) -> ParsedQuote:
        try:
            report = base64.b64decode(quote_b64)
        except (ValueError, TypeError) as exc:
            raise QuoteFormatError(f"undecodable SNP quote: {exc}") from exc
        if len(report) < _REPORT_LEN:
            raise QuoteFormatError("SNP report too short")
        return ParsedQuote(
            report_body=report[:_SIG_OFFSET],
            signature=snp_signature_der(report),
            leaf=self._vcek,
            intermediates=self._intermediates,
            report_data_offset=_OFF_REPORT_DATA,
            report_signature_algorithm="ecdsa-p384-sha384",
        )
