"""Certificate loading with a stable fail-closed provider policy.

cryptography 50 warns for X.509 serial numbers <= 0 and cryptography 51 rejects
them while parsing. WCM explicitly rejects those certificates on every
supported version. This adapter turns both dependency behaviours into the same
non-sensitive error without changing signature, chain, validity, or revocation
verification.
"""
from __future__ import annotations

import warnings

from cryptography import x509
from cryptography.utils import CryptographyDeprecationWarning


class CertificatePolicyError(ValueError):
    """Provider certificate encoding or WCM certificate policy was rejected."""


def load_pem_certificate(data: bytes) -> x509.Certificate:
    try:
        with warnings.catch_warnings():
            # cryptography 50 warns and 51 raises. WCM has already chosen a
            # stable rejection policy, so keep the transition warning out of
            # provider logs and apply the explicit serial check below.
            warnings.simplefilter("ignore", CryptographyDeprecationWarning)
            certificate = x509.load_pem_x509_certificate(data)
            serial = certificate.serial_number
    except ValueError as exc:
        raise CertificatePolicyError("provider certificate is not accepted X.509") from exc
    if serial <= 0:
        raise CertificatePolicyError("provider certificate serial number must be positive")
    return certificate


def load_pem_certificates(data: bytes) -> list[x509.Certificate]:
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", CryptographyDeprecationWarning)
            certificates = x509.load_pem_x509_certificates(data)
            serials = [certificate.serial_number for certificate in certificates]
    except ValueError as exc:
        raise CertificatePolicyError("provider certificate chain is not accepted X.509") from exc
    if any(serial <= 0 for serial in serials):
        raise CertificatePolicyError("provider certificate serial number must be positive")
    return certificates
