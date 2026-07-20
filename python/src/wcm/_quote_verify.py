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

What it does NOT do, deliberately: it ships no AMD or NVIDIA root certificates
and no vendor binary-report parser. Those are the parts that cannot be validated
without real captured quotes, and shipping them unvalidated would be exactly the
false confidence WCM refuses. A vendor plugs in a ``QuoteParser`` (real binary
offsets) and a ``TrustStore`` (real roots); the verification machinery below is
what is tested and reused. And none of this closes the key-extraction hole
(open question 8.8): a physically-extracted key produces a signature that is
genuinely valid, so it passes every check here. This raises the bar to a real
hardware signature; it does not defeat a hardware owner who lifted the key.
"""
from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional, Protocol

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa


@dataclass(frozen=True)
class ParsedQuote:
    """A quote decomposed into the pieces verification needs."""

    report_body: bytes  # the signed bytes (contains REPORT_DATA)
    signature: bytes  # signature over report_body by the leaf key
    leaf: x509.Certificate  # the attestation-key cert (e.g. VCEK)
    intermediates: list[x509.Certificate] = field(default_factory=list)
    report_data_offset: int = 0  # where the 32-byte nonce digest sits in report_body


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

    This is what the framework is tested against; a vendor parser produces the
    same ``ParsedQuote`` from real binary bytes.
    """

    def parse(self, quote_b64: str) -> ParsedQuote:
        try:
            doc = json.loads(base64.b64decode(quote_b64))
            leaf = x509.load_pem_x509_certificate(doc["leaf_pem"].encode())
            inters = [
                x509.load_pem_x509_certificate(p.encode())
                for p in doc.get("intermediates_pem", [])
            ]
            return ParsedQuote(
                report_body=base64.b64decode(doc["report_b64"]),
                signature=base64.b64decode(doc["signature_b64"]),
                leaf=leaf,
                intermediates=inters,
                report_data_offset=int(doc.get("report_data_offset", 0)),
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
        self._roots.append(x509.load_pem_x509_certificate(pem.encode()))

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
    """Verify *signature* over *message* with *pub*; raises InvalidSignature.

    Uses the certificate's own signature-algorithm parameters, so RSASSA-PSS is
    handled as well as PKCS#1 v1.5 and ECDSA. This matters for real vendor chains:
    AMD's VCEK/ASK/ARK certs are RSA-PSS (validated against a live SEV-SNP host),
    which a PKCS#1-v1.5-only verifier wrongly rejects.
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


def _signed_by(cert: x509.Certificate, issuer: x509.Certificate) -> bool:
    try:
        _pubkey_verify(issuer.public_key(), cert.signature, cert.tbs_certificate_bytes, cert)
        return True
    except InvalidSignature:
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
        self, quote_b64: str, *, expected_nonce: str, now: Optional[datetime] = None
    ) -> QuoteVerification:
        current = now if now is not None else _utcnow()
        try:
            q = self._parser.parse(quote_b64)
        except QuoteFormatError as exc:
            return QuoteVerification(False, str(exc))

        chain_error = verify_cert_chain(q.leaf, q.intermediates, self._trust, current)
        if chain_error is not None:
            return QuoteVerification(False, chain_error)

        try:
            _pubkey_verify(q.leaf.public_key(), q.signature, q.report_body, q.leaf)
        except InvalidSignature:
            return QuoteVerification(False, "report signature does not verify under the leaf key")

        expected = hashlib.sha256(bytes.fromhex(expected_nonce)).digest()
        actual = q.report_body[q.report_data_offset : q.report_data_offset + 32]
        if actual != expected:
            return QuoteVerification(
                False, "REPORT_DATA does not bind the challenge nonce (possible replay)"
            )

        return QuoteVerification(True, leaf_subject=q.leaf.subject.rfc4514_string())
