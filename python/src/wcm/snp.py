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
_OFF_REPORT_DATA = 0x50  # 64 bytes
_OFF_MEASUREMENT = 0x90  # 48 bytes (SHA-384 launch measurement)
_OFF_HOST_DATA = 0xC0  # 32 bytes
_OFF_REPORTED_TCB = 0x180  # 8 bytes
_OFF_CHIP_ID = 0x1A0  # 64 bytes
_SIG_OFFSET = 0x2A0  # signature block (512 bytes): r (72 LE) || s (72 LE) || rsvd
_ECDSA_COMPONENT = 48  # P-384 r/s are 48 bytes, stored in 72-byte little-endian slots

_HCL_SIGNATURE = b"HCLA"
_HCL_SNP_OFFSET = 32  # SNP report starts after the 32-byte Azure HCL header


@dataclass(frozen=True)
class SnpReport:
    version: int
    policy: int
    vmpl: int
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

    return SnpReport(
        version=u(_OFF_VERSION, 4),
        policy=u(_OFF_POLICY, 8),
        vmpl=u(_OFF_VMPL, 4),
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
        )
