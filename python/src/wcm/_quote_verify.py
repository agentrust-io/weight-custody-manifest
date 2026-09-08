"""Verifier-side quote verification: the security-critical trust decision.

Getting structured evidence to the gate (Layers 1-2, the hardware providers) is
not the trust decision. The trust decision is here: does the raw attestation
quote actually carry a valid hardware signature, does that signing key chain to
a root the verifier trusts, and is the quote cryptographically bound to *this*
KBS challenge? A structural check on ``nonce_echo`` proves none of that.

This module implements that machinery for real and tests it against a synthetic
PKI:

  - X.509 cert-chain validation (leaf -> intermediates -> a trusted root),
    including validity periods and per-link signature checks;
  - report-body signature verification by the leaf key (ECDSA / RSA / Ed25519);
  - cryptographic nonce binding: REPORT_DATA must equal sha256(challenge nonce).

Vendor-specific binary parsing lives in the platform modules. This verifier
checks certificate signatures, report signatures and nonce binding under the
supplied trust policy. It does not establish resistance to physical key extraction
or extend the assurance supplied by the underlying hardware.
"""
from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional, Protocol

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa

from ._certificates import load_pem_certificate


@dataclass(frozen=True)
class ParsedQuote:
    """A quote decomposed into the pieces verification needs."""

    report_body: bytes  # the signed bytes (contains REPORT_DATA)
    signature: bytes  # signature over report_body by the leaf key
    leaf: x509.Certificate  # the attestation-key cert (e.g. VCEK)
    intermediates: list[x509.Certificate] = field(default_factory=list)
    report_data_offset: int = 0  # where the 32-byte nonce digest sits in report_body
    report_signature_algorithm: str = "ecdsa-sha256"  # selected by the format parser


class QuoteParser(Protocol):
    """Turns a base64 quote blob into a ``ParsedQuote``.

    Vendor parsers (AMD SEV-SNP, Intel TDX, NVIDIA) implement this against their
    real binary layouts. ``JsonQuoteParser`` is the tested reference container.
    """

    def parse(self, quote_b64: str) -> ParsedQuote: ...


class JsonQuoteParser:
    """Reference parser: quote_b64 is base64(JSON) with report/signature/certs.

    Container shape::

        {"report_b64": ..., "signature_b64": ...,
         "leaf_pem": ..., "intermediates_pem": [...],
         "report_data_offset": 0}

    The default report profile is ECDSA/SHA-256. Configure
    ``report_signature_algorithm`` for another supported profile:
    ``ecdsa-p384-sha384``, ``rsa-pss-sha256`` (32-byte salt),
    ``rsa-pkcs1-sha256``, or ``ed25519``. The input container cannot override it.
    Vendor parsers select the algorithm required by their report format.
    """

    def __init__(self, *, report_signature_algorithm: str = "ecdsa-sha256") -> None:
        # Configuration belongs to the verifier's parser, not the input JSON.
        self._report_signature_algorithm = report_signature_algorithm

    def parse(self, quote_b64: str) -> ParsedQuote:
        try:
            doc = json.loads(base64.b64decode(quote_b64))
            leaf = load_pem_certificate(doc["leaf_pem"].encode())
            inters = [
                load_pem_certificate(p.encode())
                for p in doc.get("intermediates_pem", [])
            ]
            return ParsedQuote(
                report_body=base64.b64decode(doc["report_b64"]),
                signature=base64.b64decode(doc["signature_b64"]),
                leaf=leaf,
                intermediates=inters,
                report_data_offset=int(doc.get("report_data_offset", 0)),
                report_signature_algorithm=self._report_signature_algorithm,
            )
        except (KeyError, ValueError, TypeError) as exc:
            raise QuoteFormatError(f"unparseable quote container: {exc}") from exc


class QuoteFormatError(Exception):
    """The quote blob could not be parsed into a ParsedQuote."""


class TrustStore:
    """The set of root certificates the verifier will chain to."""

    def __init__(self) -> None:
        self._roots: list[x509.Certificate] = []

    def add_root(self, cert: x509.Certificate) -> None:
        self._roots.append(cert)

    def add_root_pem(self, pem: str) -> None:
        self._roots.append(load_pem_certificate(pem.encode()))

    @property
    def roots(self) -> list[x509.Certificate]:
        return list(self._roots)


@dataclass(frozen=True)
class QuoteVerification:
    verified: bool
    reason: Optional[str] = None
    leaf_subject: Optional[str] = None


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _pubkey_verify(pub: object, signature: bytes, message: bytes, cert: x509.Certificate) -> None:
    """Verify an X.509 certificate signature using its issuer parameters.

    These parameters describe the certificate signature only. Attestation report
    signatures use the independently selected report-format profile below.
    """
    params = cert.signature_algorithm_parameters
    if isinstance(pub, ec.EllipticCurvePublicKey):
        pub.verify(signature, message, params)  # type: ignore[arg-type]
    elif isinstance(pub, rsa.RSAPublicKey):
        pub.verify(signature, message, params, cert.signature_hash_algorithm)  # type: ignore[arg-type]
    elif isinstance(pub, ed25519.Ed25519PublicKey):
        pub.verify(signature, message)
    else:
        raise InvalidSignature(f"unsupported issuer key type {type(pub).__name__}")


def _verify_report_signature(q: ParsedQuote) -> None:
    """Verify the report using format-defined parameters, never issuer metadata."""
    pub = q.leaf.public_key()
    algorithm = q.report_signature_algorithm
    if algorithm == "ecdsa-sha256" and isinstance(pub, ec.EllipticCurvePublicKey):
        pub.verify(q.signature, q.report_body, ec.ECDSA(hashes.SHA256()))
    elif algorithm == "ecdsa-p384-sha384" and isinstance(pub, ec.EllipticCurvePublicKey):
        if not isinstance(pub.curve, ec.SECP384R1):
            raise InvalidSignature("SNP report requires a P-384 key")
        pub.verify(q.signature, q.report_body, ec.ECDSA(hashes.SHA384()))
    elif algorithm == "rsa-pss-sha256" and isinstance(pub, rsa.RSAPublicKey):
        pub.verify(q.signature, q.report_body,
                   padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32), hashes.SHA256())
    elif algorithm == "rsa-pkcs1-sha256" and isinstance(pub, rsa.RSAPublicKey):
        pub.verify(q.signature, q.report_body, padding.PKCS1v15(), hashes.SHA256())
    elif algorithm == "ed25519" and isinstance(pub, ed25519.Ed25519PublicKey):
        pub.verify(q.signature, q.report_body)
    else:
        raise InvalidSignature("unsupported report signature profile or key type")


def _signed_by(cert: x509.Certificate, issuer: x509.Certificate) -> bool:
    try:
        _pubkey_verify(issuer.public_key(), cert.signature, cert.tbs_certificate_bytes, cert)
        return True
    except (InvalidSignature, UnsupportedAlgorithm, TypeError, ValueError):
        return False


def _valid_at(cert: x509.Certificate, now: datetime) -> bool:
    return cert.not_valid_before_utc <= now <= cert.not_valid_after_utc


def verify_cert_chain(
    leaf: x509.Certificate,
    intermediates: list[x509.Certificate],
    trust_store: TrustStore,
    now: datetime,
) -> Optional[str]:
    """Return None if *leaf* chains to a trusted root, else a failure reason."""
    chain = [leaf, *intermediates]
    for i in range(len(chain) - 1):
        if not _valid_at(chain[i], now):
            return f"certificate outside validity window: {chain[i].subject.rfc4514_string()}"
        if not _signed_by(chain[i], chain[i + 1]):
            return "broken certificate chain (a link is not signed by the next)"
    top = chain[-1]
    if not _valid_at(top, now):
        return f"certificate outside validity window: {top.subject.rfc4514_string()}"
    for root in trust_store.roots:
        if not _valid_at(root, now):
            continue
        if top == root or _signed_by(top, root):
            return None
    return "does not chain to a trusted root"


class QuoteVerifier:
    """Verifies a quote: cert chain, report signature, and nonce binding."""

    def __init__(self, parser: QuoteParser, trust_store: TrustStore) -> None:
        self._parser = parser
        self._trust = trust_store

    def verify(
        self,
        quote_b64: str,
        *,
        expected_nonce: str,
        channel_binding: bytes = b"",
        expected_workload_measurement: Optional[str] = None,
        now: Optional[datetime] = None,
    ) -> QuoteVerification:
        """Verify a quote's chain, signature, and REPORT_DATA binding.

        REPORT_DATA must equal ``sha256(nonce || channel_binding)``.
        ``channel_binding`` is the enclave's attested transport public key (raw
        bytes) when channel binding is in use, else empty. Folding it in is what
        stops quote *relay*: a relay cannot swap in its own transport key without
        breaking this check. Empty binding reduces to sha256(nonce), the
        replay-only value, so pre-channel-binding quotes still verify.
        """
        # Generic quote formats do not expose a TPM PCR digest. Platform
        # verifiers (notably AzureSnpVtpmVerifier) consume this policy-derived
        # value. Keeping it on the common call shape lets the KBS pass the
        # manifest value without trusting an evidence-side assertion.
        del expected_workload_measurement
        current = now if now is not None else _utcnow()
        try:
            q = self._parser.parse(quote_b64)
        except QuoteFormatError as exc:
            return QuoteVerification(False, str(exc))

        chain_error = verify_cert_chain(q.leaf, q.intermediates, self._trust, current)
        if chain_error is not None:
            return QuoteVerification(False, chain_error)

        try:
            _verify_report_signature(q)
        except (InvalidSignature, UnsupportedAlgorithm, TypeError, ValueError):
            return QuoteVerification(False, "report signature does not verify under the leaf key")

        expected = hashlib.sha256(bytes.fromhex(expected_nonce) + channel_binding).digest()
        actual = q.report_body[q.report_data_offset : q.report_data_offset + 32]
        if actual != expected:
            reason = (
                "REPORT_DATA does not bind the challenge nonce and transport key (possible relay)"
                if channel_binding
                else "REPORT_DATA does not bind the challenge nonce (possible replay)"
            )
            return QuoteVerification(False, reason)

        return QuoteVerification(True, leaf_subject=q.leaf.subject.rfc4514_string())
