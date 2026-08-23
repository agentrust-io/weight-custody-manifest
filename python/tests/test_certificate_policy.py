from __future__ import annotations

import base64
import warnings
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.utils import CryptographyDeprecationWarning
from cryptography.x509.oid import NameOID

from wcm._certificates import CertificatePolicyError, load_pem_certificate


def _non_positive_serial_pem() -> bytes:
    """Construct sanitized DER with serial 0 without retaining provider data."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "sanitized.invalid")])
    now = datetime.now(timezone.utc)
    der = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(minutes=1))
        .sign(key, hashes.SHA256())
        .public_bytes(serialization.Encoding.DER)
    )
    # Serial 1 is the first DER INTEGER 01 in TBSCertificate. Changing only its
    # value preserves the encoding and recreates the dependency warning/error.
    marker = b"\x02\x01\x01"
    offset = der.find(marker)
    assert offset >= 0
    invalid = der[: offset + 2] + b"\x00" + der[offset + 3 :]
    encoded = base64.b64encode(invalid)
    lines = [encoded[i : i + 64] for i in range(0, len(encoded), 64)]
    return b"-----BEGIN CERTIFICATE-----\n" + b"\n".join(lines) + b"\n-----END CERTIFICATE-----\n"


def test_non_positive_serial_has_stable_fail_closed_policy() -> None:
    with pytest.raises(CertificatePolicyError, match="certificate"):
        load_pem_certificate(_non_positive_serial_pem())


def test_provider_specific_non_positive_serial_exception_is_explicit() -> None:
    certificate = load_pem_certificate(
        _non_positive_serial_pem(), allow_non_positive_serial=True
    )
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", CryptographyDeprecationWarning)
        assert certificate.serial_number == 0


def test_future_parser_exception_has_same_non_sensitive_policy(monkeypatch) -> None:
    """Model cryptography 51's documented load-time rejection until it ships."""
    def reject_non_positive_serial(data: bytes) -> x509.Certificate:
        del data
        raise ValueError("future dependency-specific parser detail")

    monkeypatch.setattr(x509, "load_pem_x509_certificate", reject_non_positive_serial)
    with pytest.raises(
        CertificatePolicyError, match="provider certificate is not accepted X.509"
    ) as caught:
        load_pem_certificate(b"sanitized certificate bytes")
    assert "dependency-specific" not in str(caught.value)


def test_positive_serial_is_supported() -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "sanitized.example")])
    now = datetime.now(timezone.utc)
    pem = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(minutes=1))
        .sign(key, hashes.SHA256())
        .public_bytes(serialization.Encoding.PEM)
    )
    assert load_pem_certificate(pem).serial_number == 1
