"""AMD SEV-SNP report parsing + verification.

Two layers:
  1. Hermetic synthetic SNP report (a P-384 'VCEK' signs a crafted report),
     exercising the parser, the AMD LE r||s signature encoding, HCL extraction,
     and the SnpQuoteParser -> QuoteVerifier integration.
  2. The REAL public AMD Milan ASK/ARK chain (committed fixture, fetched from a
     live Azure host's THIM during hardware validation) verified through
     verify_cert_chain -- real RSA-PSS AMD certs, no host-specific data.
"""
from __future__ import annotations

import base64
import datetime
import hashlib
import pathlib
import struct

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.x509.oid import NameOID

from wcm import (
    QuoteVerifier,
    SnpQuoteParser,
    TrustStore,
    extract_snp_report_from_hcl,
    parse_snp_report,
    verify_cert_chain,
    verify_snp_report_signature,
)
from wcm._quote_verify import QuoteFormatError

NOW = datetime.datetime(2026, 7, 20, 12, 0, 0, tzinfo=datetime.timezone.utc)
NONCE = "ab" * 32
FIXTURES = pathlib.Path(__file__).parent / "fixtures"


def _p384():
    return ec.generate_private_key(ec.SECP384R1())


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
    return b.sign(issuer_key, hashes.SHA384())


def _synth_report(vcek_key, nonce_hex: str, *, measurement=b"\x11" * 48, chip=b"\x22" * 64) -> bytes:
    body = bytearray(0x2A0)
    struct.pack_into("<I", body, 0x00, 3)  # version 3
    body[0x50 : 0x50 + 32] = hashlib.sha256(bytes.fromhex(nonce_hex)).digest()  # REPORT_DATA
    body[0x90 : 0x90 + 48] = measurement
    body[0x1A0 : 0x1A0 + 64] = chip
    der = vcek_key.sign(bytes(body), ec.ECDSA(hashes.SHA384()))
    r, s = decode_dss_signature(der)
    sig = bytearray(512)
    sig[0:48] = r.to_bytes(48, "little")
    sig[72 : 72 + 48] = s.to_bytes(48, "little")
    return bytes(body) + bytes(sig)


# -- parser + signature --------------------------------------------------------


def test_parse_fields():
    report = _synth_report(_p384(), NONCE)
    r = parse_snp_report(report)
    assert r.version == 3
    assert r.measurement == b"\x11" * 48
    assert r.chip_id == b"\x22" * 64
    assert r.report_data[:32] == hashlib.sha256(bytes.fromhex(NONCE)).digest()


def test_parse_rejects_short():
    with pytest.raises(QuoteFormatError):
        parse_snp_report(b"\x00" * 100)


def test_signature_verifies_and_tamper_fails():
    k = _p384()
    vcek = _cert("SEV-VCEK", "root", k, _p384())  # cert issuer irrelevant to report sig
    report = _synth_report(k, NONCE)
    assert verify_snp_report_signature(report, vcek) is True
    tampered = bytearray(report)
    tampered[0x90] ^= 0xFF  # flip a measurement byte
    assert verify_snp_report_signature(bytes(tampered), vcek) is False


def test_hcl_extraction():
    report = _synth_report(_p384(), NONCE)
    hcl = b"HCLA" + b"\x00" * 28 + report + b"trailing-runtime-data"
    assert extract_snp_report_from_hcl(hcl) == report
    with pytest.raises(QuoteFormatError):
        extract_snp_report_from_hcl(b"XXXX" + b"\x00" * 1200)


# -- SnpQuoteParser -> QuoteVerifier integration -------------------------------


def _vcek_chain():
    root_k = _p384()
    root = _cert("snp-root", "snp-root", root_k, root_k, ca=True)
    vcek_k = _p384()
    vcek = _cert("SEV-VCEK", "snp-root", vcek_k, root_k)
    return root, vcek, vcek_k


def test_snp_quote_verifier_end_to_end():
    root, vcek, vcek_k = _vcek_chain()
    report = _synth_report(vcek_k, NONCE)
    ts = TrustStore(); ts.add_root(root)
    verifier = QuoteVerifier(SnpQuoteParser(vcek, []), ts)
    result = verifier.verify(base64.b64encode(report).decode(), expected_nonce=NONCE, now=NOW)
    assert result.verified


def test_snp_quote_verifier_wrong_nonce_fails():
    root, vcek, vcek_k = _vcek_chain()
    report = _synth_report(vcek_k, NONCE)
    ts = TrustStore(); ts.add_root(root)
    verifier = QuoteVerifier(SnpQuoteParser(vcek, []), ts)
    result = verifier.verify(base64.b64encode(report).decode(), expected_nonce="cd" * 32, now=NOW)
    assert not result.verified and "REPORT_DATA" in (result.reason or "")


def test_snp_quote_verifier_untrusted_root_fails():
    _, vcek, vcek_k = _vcek_chain()
    report = _synth_report(vcek_k, NONCE)
    other = TrustStore(); other.add_root(_cert("x", "x", _p384(), _p384(), ca=True))
    verifier = QuoteVerifier(SnpQuoteParser(vcek, []), other)
    assert not verifier.verify(base64.b64encode(report).decode(), expected_nonce=NONCE, now=NOW).verified


# -- REAL public AMD Milan chain (committed fixture) ---------------------------


def test_real_amd_milan_chain_verifies():
    """ASK->ARK from a live Azure host's THIM (public generic Milan roots, RSA-PSS)."""
    certs = x509.load_pem_x509_certificates((FIXTURES / "amd_milan_cert_chain.pem").read_bytes())
    ask = next(c for c in certs if c.subject != c.issuer)
    ark = next(c for c in certs if c.subject == c.issuer)
    ts = TrustStore(); ts.add_root(ark)
    now = datetime.datetime.now(datetime.timezone.utc)
    assert verify_cert_chain(ask, [], ts, now) is None  # ASK is signed by ARK (RSA-PSS)


@pytest.fixture(params=["rsa-pss", "ecdsa-sha256"])
def mixed_issuer_snp(request):
    """Synthetic cert/report algorithm separation; no host identifiers."""
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    issuer = (rsa.generate_private_key(public_exponent=65537, key_size=2048)
              if request.param == "rsa-pss" else _p384())
    leaf_key = _p384()

    def certificate(name, subject_key, ca):
        builder = (x509.CertificateBuilder()
                   .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
                   .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test-root")]))
                   .public_key(subject_key.public_key()).serial_number(x509.random_serial_number())
                   .not_valid_before(NOW-datetime.timedelta(days=1))
                   .not_valid_after(NOW+datetime.timedelta(days=365))
                   .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
        kwargs = ({"rsa_padding": padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)}
                  if request.param == "rsa-pss" else {})
        return builder.sign(issuer, hashes.SHA256(), **kwargs)

    root = certificate("test-root", issuer, True)
    leaf = certificate("test-vcek", leaf_key, False)
    trust = TrustStore(); trust.add_root(root)
    return leaf, trust, _synth_report(leaf_key, NONCE)


def test_snp_report_algorithm_independent_of_certificate(mixed_issuer_snp):
    leaf, trust, report = mixed_issuer_snp
    assert verify_snp_report_signature(report, leaf)
    result = QuoteVerifier(SnpQuoteParser(leaf, []), trust).verify(
        base64.b64encode(report).decode(), expected_nonce=NONCE, now=NOW)
    assert result.verified, result.reason


@pytest.mark.parametrize("fault", ["body", "signature", "nonce", "channel", "untrusted"])
def test_mixed_issuer_snp_rejects_invalid_evidence(mixed_issuer_snp, fault):
    leaf, trust, report = mixed_issuer_snp
    data = bytearray(report)
    if fault == "body": data[0x90] ^= 1
    if fault == "signature": data[0x2A0] ^= 1
    if fault == "untrusted":
        trust = TrustStore()
        other = _p384()
        trust.add_root(_cert("untrusted", "untrusted", other, other, ca=True))
    result = QuoteVerifier(SnpQuoteParser(leaf, []), trust).verify(
        base64.b64encode(data).decode(), expected_nonce="cd"*32 if fault == "nonce" else NONCE,
        channel_binding=b"substituted-key" if fault == "channel" else b"", now=NOW)
    assert not result.verified
    expected = "signature" if fault in ("body", "signature") else (
        "trusted root" if fault == "untrusted" else "REPORT_DATA")
    assert expected in result.reason
