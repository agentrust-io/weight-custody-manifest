"""Intel TDX DCAP quote parsing and verification (SPEC.md section 3.2).

The Intel counterpart to ``snp.py``. A TDX ECDSA quote (attestation key type 2,
DCAP v4) is a two-level structure, unlike SEV-SNP's single VCEK signature:

  1. an **attestation key** (ECDSA P-256) signs the quote header + TD report;
  2. that attestation key is bound into the **QE report** (its SHA-256 sits in
     the QE report's REPORT_DATA);
  3. the QE report is signed by the **PCK** leaf certificate; and
  4. the PCK chains PCK -> Intel SGX Processor/Platform CA -> Intel SGX Root CA.

``verify_tdx_quote`` checks all four plus the nonce binding and returns the same
``QuoteVerification`` type the rest of the SDK uses. The generic
``QuoteVerifier``/``ParsedQuote`` path models a single leaf signature, which does
not fit this two-level shape, so TDX has its own entry point rather than a
``QuoteParser`` adapter.

REPORT_DATA note: on platforms where the guest controls the TD report's
REPORT_DATA (Linux ``configfs-tsm``, the path GCP C3 TDX exposes), WCM sets it to
sha256(nonce), so the nonce binding holds directly, unlike the Azure SEV-SNP vTPM
path. Offsets follow the Intel DCAP v4 spec; treat them as validate-against-real-
hardware until a captured GCP quote confirms them (mirrors ``snp.py``).
"""
from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

from ._quote_verify import (
    QuoteFormatError,
    QuoteVerification,
    TrustStore,
    _utcnow,
    verify_cert_chain,
)

# -- quote layout (DCAP v4, little-endian) ------------------------------------
_HEADER_LEN = 48
_OFF_VERSION = 0x00           # u16
_OFF_ATT_KEY_TYPE = 0x02      # u16 (2 = ECDSA-P256)
_OFF_TEE_TYPE = 0x04          # u32 (0x81 = TDX)

_TD_REPORT_LEN = 584          # TD10 report body
_OFF_TD_REPORT_DATA = 520     # 64 bytes, within the TD report body
_OFF_TD_MRTD = 136            # 48 bytes, within the TD report body

_SIGNED_LEN = _HEADER_LEN + _TD_REPORT_LEN  # bytes the attestation key signs

# SGX QE report (384 bytes)
_QE_REPORT_LEN = 384
_OFF_QE_REPORT_DATA = 320     # 64 bytes, within the QE report

_ECDSA_SIG_LEN = 64           # r(32) || s(32)
_ECDSA_PUBKEY_LEN = 64        # x(32) || y(32)

_TEE_TYPE_TDX = 0x81
_ATT_KEY_TYPE_ECDSA_P256 = 2
_CERT_TYPE_PCK_CHAIN = 5      # QE cert-data inner type: PEM PCK chain


@dataclass(frozen=True)
class TdxReport:
    """The parsed TD report body fields verification and policy care about."""

    report_data: bytes   # 64 bytes (guest-set to sha256(nonce) on configfs-tsm)
    mrtd: bytes          # 48 bytes, the TD measurement
    raw: bytes           # the full 584-byte report body


@dataclass(frozen=True)
class TdxQuote:
    """A decomposed TDX ECDSA (DCAP v4) quote."""

    version: int
    tee_type: int
    signed_body: bytes            # header || TD report (what the att key signs)
    report: TdxReport
    quote_signature: bytes        # 64-byte r||s by the attestation key
    attestation_pubkey: bytes     # 64-byte x||y P-256 attestation key
    qe_report: bytes              # 384-byte SGX QE report
    qe_report_signature: bytes    # 64-byte r||s by the PCK leaf
    qe_auth_data: bytes
    pck_leaf: x509.Certificate
    pck_intermediates: list[x509.Certificate]


def _u16(b: bytes, off: int) -> int:
    return int(struct.unpack_from("<H", b, off)[0])


def _u32(b: bytes, off: int) -> int:
    return int(struct.unpack_from("<I", b, off)[0])


def _raw_ecdsa_to_der(sig64: bytes) -> bytes:
    """DCAP stores ECDSA (r, s) as two big-endian 32-byte ints; DER-encode them."""
    r = int.from_bytes(sig64[:32], "big")
    s = int.from_bytes(sig64[32:64], "big")
    return utils.encode_dss_signature(r, s)


def _p256_from_raw(xy: bytes) -> ec.EllipticCurvePublicKey:
    x = int.from_bytes(xy[:32], "big")
    y = int.from_bytes(xy[32:64], "big")
    return ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()


def parse_tdx_quote(quote: bytes) -> TdxQuote:
    """Parse a DCAP v4 TDX ECDSA quote into its verifiable pieces.

    Raises ``QuoteFormatError`` on any structural problem.
    """
    if len(quote) < _SIGNED_LEN + 4:
        raise QuoteFormatError("TDX quote too short for header + TD report")
    version = _u16(quote, _OFF_VERSION)
    att_key_type = _u16(quote, _OFF_ATT_KEY_TYPE)
    tee_type = _u32(quote, _OFF_TEE_TYPE)
    if tee_type != _TEE_TYPE_TDX:
        raise QuoteFormatError(f"not a TDX quote (tee_type {tee_type:#x})")
    if att_key_type != _ATT_KEY_TYPE_ECDSA_P256:
        raise QuoteFormatError(f"unsupported attestation key type {att_key_type}")

    signed_body = quote[:_SIGNED_LEN]
    td_body = quote[_HEADER_LEN:_SIGNED_LEN]
    report = TdxReport(
        report_data=td_body[_OFF_TD_REPORT_DATA:_OFF_TD_REPORT_DATA + 64],
        mrtd=td_body[_OFF_TD_MRTD:_OFF_TD_MRTD + 48],
        raw=td_body,
    )

    sig_len = _u32(quote, _SIGNED_LEN)
    sig = quote[_SIGNED_LEN + 4:]
    if len(sig) < sig_len or sig_len < _ECDSA_SIG_LEN + _ECDSA_PUBKEY_LEN + 6:
        raise QuoteFormatError("TDX signature section truncated")

    quote_signature = sig[0:_ECDSA_SIG_LEN]
    attestation_pubkey = sig[_ECDSA_SIG_LEN:_ECDSA_SIG_LEN + _ECDSA_PUBKEY_LEN]

    # QE certification data (outer): type u16, size u32, then the cert-data blob.
    off = _ECDSA_SIG_LEN + _ECDSA_PUBKEY_LEN
    _qe_cd_type = _u16(sig, off)
    qe_cd_size = _u32(sig, off + 2)
    off += 6
    cd = sig[off:off + qe_cd_size]
    if len(cd) < _QE_REPORT_LEN + _ECDSA_SIG_LEN + 2:
        raise QuoteFormatError("QE certification data truncated")

    qe_report = cd[0:_QE_REPORT_LEN]
    qe_report_sig = cd[_QE_REPORT_LEN:_QE_REPORT_LEN + _ECDSA_SIG_LEN]
    p = _QE_REPORT_LEN + _ECDSA_SIG_LEN
    qe_auth_size = _u16(cd, p)
    p += 2
    qe_auth = cd[p:p + qe_auth_size]
    p += qe_auth_size

    pck_type = _u16(cd, p)
    pck_size = _u32(cd, p + 2)
    p += 6
    pck_blob = cd[p:p + pck_size]
    if pck_type != _CERT_TYPE_PCK_CHAIN:
        raise QuoteFormatError(f"unexpected PCK cert-data type {pck_type} (want {_CERT_TYPE_PCK_CHAIN})")
    try:
        certs = x509.load_pem_x509_certificates(pck_blob)
    except ValueError as exc:
        raise QuoteFormatError(f"unparseable PCK cert chain: {exc}") from exc
    if not certs:
        raise QuoteFormatError("empty PCK cert chain")

    return TdxQuote(
        version=version,
        tee_type=tee_type,
        signed_body=signed_body,
        report=report,
        quote_signature=quote_signature,
        attestation_pubkey=attestation_pubkey,
        qe_report=qe_report,
        qe_report_signature=qe_report_sig,
        qe_auth_data=qe_auth,
        pck_leaf=certs[0],
        pck_intermediates=certs[1:],
    )


def verify_tdx_quote(
    quote: bytes,
    trust_store: TrustStore,
    *,
    expected_nonce: Optional[str] = None,
    channel_binding: bytes = b"",
    now: Optional[datetime] = None,
) -> QuoteVerification:
    """Verify a TDX DCAP v4 quote end to end.

    Checks, in order: the attestation-key signature over header+TD report; the
    attestation key's binding into the QE report; the QE report signature by the
    PCK leaf; the PCK chain to a trusted Intel SGX root; and, when
    *expected_nonce* is given, that the TD report's REPORT_DATA binds it.

    Pass ``expected_nonce=None`` on platforms where REPORT_DATA is not
    guest-controlled: on the Azure vTPM path the paravisor binds it to the vTPM
    attestation key, so freshness comes from the enclosing vTPM quote, not this
    field, and checking it here would always fail. Bare-metal / configfs-tsm
    guests do control REPORT_DATA, so pass the nonce there.

    ``channel_binding`` is the enclave's attested transport public key (raw
    bytes) when channel binding is in use, else empty; REPORT_DATA must then bind
    ``sha256(nonce || channel_binding)``, so a relay cannot swap in its own
    transport key (SPEC 3.2). Only meaningful with a guest-controlled
    REPORT_DATA, i.e. alongside a non-None *expected_nonce*.
    """
    current = now if now is not None else _utcnow()
    try:
        q = parse_tdx_quote(quote)
    except QuoteFormatError as exc:
        return QuoteVerification(False, str(exc))

    # 1. Attestation key signs (header || TD report).
    try:
        _p256_from_raw(q.attestation_pubkey).verify(
            _raw_ecdsa_to_der(q.quote_signature), q.signed_body, ec.ECDSA(hashes.SHA256())
        )
    except (InvalidSignature, ValueError):
        return QuoteVerification(False, "quote signature does not verify under the attestation key")

    # 2. Attestation key is the one the QE vouched for: its hash sits in the QE
    #    report's REPORT_DATA (sha256(att_pubkey || qe_auth), zero-padded).
    expect_binding = hashlib.sha256(q.attestation_pubkey + q.qe_auth_data).digest()
    qe_report_data = q.qe_report[_OFF_QE_REPORT_DATA:_OFF_QE_REPORT_DATA + 64]
    if qe_report_data[:32] != expect_binding:
        return QuoteVerification(False, "attestation key not bound in the QE report")

    # 3. PCK leaf signs the QE report.
    pck_pub = q.pck_leaf.public_key()
    if not isinstance(pck_pub, ec.EllipticCurvePublicKey):
        return QuoteVerification(False, "PCK leaf is not an ECDSA certificate")
    try:
        pck_pub.verify(
            _raw_ecdsa_to_der(q.qe_report_signature), q.qe_report, ec.ECDSA(hashes.SHA256())
        )
    except (InvalidSignature, ValueError):
        return QuoteVerification(False, "QE report signature does not verify under the PCK leaf")

    # 4. PCK chains to a trusted Intel SGX root.
    chain_error = verify_cert_chain(q.pck_leaf, q.pck_intermediates, trust_store, current)
    if chain_error is not None:
        return QuoteVerification(False, chain_error)

    # 5. Nonce binding (guest-controlled REPORT_DATA, e.g. bare-metal / configfs-tsm).
    #    Skipped when expected_nonce is None: on the Azure vTPM path REPORT_DATA is
    #    paravisor-bound to the vTPM AK, so freshness lives in the enclosing vTPM
    #    quote, not here (see the docstring).
    if expected_nonce is not None:
        expected = hashlib.sha256(bytes.fromhex(expected_nonce) + channel_binding).digest()
        if q.report.report_data[:32] != expected:
            reason = (
                "REPORT_DATA does not bind the challenge nonce and transport key (possible relay)"
                if channel_binding
                else "REPORT_DATA does not bind the challenge nonce (possible replay)"
            )
            return QuoteVerification(False, reason)

    return QuoteVerification(True, leaf_subject=q.pck_leaf.subject.rfc4514_string())
