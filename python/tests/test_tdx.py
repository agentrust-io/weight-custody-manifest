"""Intel TDX DCAP quote parsing + verification, against a synthetic quote.

Hermetic: synthetic P-256 keys stand in for the attestation key, the PCK, and
the Intel SGX Root CA, assembled into a DCAP v4 quote so the two-level verifier
(att-key signature -> QE-report binding -> PCK signature -> PCK chain -> nonce)
is exercised end to end with no hardware. A real GCP TDX capture validates the
byte offsets against silicon later.
"""
from __future__ import annotations

import datetime
import hashlib
import struct

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.x509.oid import NameOID

from wcm import TrustStore, parse_tdx_quote, verify_tdx_quote
from wcm._quote_verify import QuoteFormatError

NOW = datetime.datetime(2026, 7, 21, 12, 0, 0, tzinfo=datetime.timezone.utc)
NONCE = "ab" * 32


def _p256():
    return ec.generate_private_key(ec.SECP256R1())


def _raw_sig(key, message: bytes) -> bytes:
    der = key.sign(message, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def _raw_pub(key) -> bytes:
    nums = key.public_key().public_numbers()
    return nums.x.to_bytes(32, "big") + nums.y.to_bytes(32, "big")


def _cert(subject, issuer_name, subj_key, issuer_key, *, ca=False):
    b = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_name)]))
        .public_key(subj_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - datetime.timedelta(days=1))
        .not_valid_after(NOW + datetime.timedelta(days=365))
    )
    if ca:
        b = b.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    return b.sign(issuer_key, hashes.SHA256())


def _pem(cert) -> bytes:
    from cryptography.hazmat.primitives import serialization

    return cert.public_bytes(serialization.Encoding.PEM)


def build_quote(*, nonce_hex=NONCE, mrtd=b"\x33" * 48):
    """Assemble a valid synthetic TDX DCAP v4 quote and its trust root."""
    root_k = _p256()
    root = _cert("Intel SGX Root CA (synthetic)", "Intel SGX Root CA (synthetic)", root_k, root_k, ca=True)
    pck_k = _p256()
    pck = _cert("Intel SGX PCK (synthetic)", "Intel SGX Root CA (synthetic)", pck_k, root_k)
    att_k = _p256()

    # Header (48 bytes): version 4, att_key_type 2, tee_type 0x81 (TDX).
    header = bytearray(48)
    struct.pack_into("<H", header, 0x00, 4)
    struct.pack_into("<H", header, 0x02, 2)
    struct.pack_into("<I", header, 0x04, 0x81)

    # TD report body (584 bytes): mrtd at 136, report_data at 520.
    td = bytearray(584)
    td[136:136 + 48] = mrtd
    td[520:520 + 32] = hashlib.sha256(bytes.fromhex(nonce_hex)).digest()

    signed_body = bytes(header) + bytes(td)
    quote_sig = _raw_sig(att_k, signed_body)
    att_pub = _raw_pub(att_k)

    # QE report (384 bytes): report_data at 320 binds the attestation key.
    qe_auth = b"qe-auth"
    qe_report = bytearray(384)
    qe_report[320:320 + 32] = hashlib.sha256(att_pub + qe_auth).digest()
    qe_report_sig = _raw_sig(pck_k, bytes(qe_report))

    pck_blob = _pem(pck) + _pem(root)
    cert_data = (
        bytes(qe_report)
        + qe_report_sig
        + struct.pack("<H", len(qe_auth)) + qe_auth
        + struct.pack("<H", 5) + struct.pack("<I", len(pck_blob)) + pck_blob
    )
    sig_data = (
        quote_sig + att_pub
        + struct.pack("<H", 6) + struct.pack("<I", len(cert_data)) + cert_data
    )
    quote = signed_body + struct.pack("<I", len(sig_data)) + sig_data
    return bytes(quote), root


def _trust(root):
    ts = TrustStore()
    ts.add_root(root)
    return ts


# -- parse --------------------------------------------------------------------


def test_parse_fields():
    quote, _ = build_quote()
    q = parse_tdx_quote(quote)
    assert q.version == 4 and q.tee_type == 0x81
    assert q.report.mrtd == b"\x33" * 48
    assert q.report.report_data[:32] == hashlib.sha256(bytes.fromhex(NONCE)).digest()


def test_parse_rejects_non_tdx():
    quote, _ = build_quote()
    bad = bytearray(quote)
    struct.pack_into("<I", bad, 0x04, 0x00)  # tee_type SGX, not TDX
    with pytest.raises(QuoteFormatError):
        parse_tdx_quote(bytes(bad))


def test_parse_rejects_short():
    with pytest.raises(QuoteFormatError):
        parse_tdx_quote(b"\x00" * 100)


# -- verify -------------------------------------------------------------------


def test_verify_end_to_end():
    quote, root = build_quote()
    result = verify_tdx_quote(quote, _trust(root), expected_nonce=NONCE, now=NOW)
    assert result.verified, result.reason


def test_wrong_nonce_fails():
    quote, root = build_quote()
    result = verify_tdx_quote(quote, _trust(root), expected_nonce="cd" * 32, now=NOW)
    assert not result.verified and "REPORT_DATA" in (result.reason or "")


def test_untrusted_root_fails():
    quote, _ = build_quote()
    other = TrustStore()
    other.add_root(_cert("x", "x", _p256(), _p256(), ca=True))
    result = verify_tdx_quote(quote, other, expected_nonce=NONCE, now=NOW)
    assert not result.verified and "trusted root" in (result.reason or "")


def test_tampered_td_report_fails():
    quote, root = build_quote()
    bad = bytearray(quote)
    bad[136] ^= 0xFF  # flip an MRTD byte inside the signed body
    result = verify_tdx_quote(bytes(bad), _trust(root), expected_nonce=NONCE, now=NOW)
    assert not result.verified and "quote signature" in (result.reason or "")


def test_broken_qe_binding_fails():
    # Rebuild with a QE report that binds the wrong attestation key.
    quote, root = build_quote()
    q = parse_tdx_quote(quote)
    # Corrupt the QE report's REPORT_DATA binding by rebuilding the quote with a
    # mismatched qe_auth is complex; instead flip a byte in the binding region.
    idx = quote.find(q.qe_report)
    bad = bytearray(quote)
    bad[idx + 320] ^= 0xFF  # first byte of the QE REPORT_DATA binding
    result = verify_tdx_quote(bytes(bad), _trust(root), expected_nonce=NONCE, now=NOW)
    assert not result.verified
