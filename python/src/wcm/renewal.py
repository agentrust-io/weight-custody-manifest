"""Signed, keyless renewal decisions for long-lived WCM custody sessions."""
from __future__ import annotations

import base64
import binascii
import hashlib
from dataclasses import asdict, dataclass
from typing import Any, Iterable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from ._canonicalize import canonical_hash, canonicalize
from ._signing import signing_pre_image
from .attestation import CompositeEvidence
from .models import WeightCustodyManifest

REQUIRED_RENEWAL_CHECKS = frozenset({
    "nonce_fresh",
    "manifest_authorized",
    "channel_binding",
    "cpu_platform_allowed",
    "assurance_tier",
    "serving_image",
    "gpu",
    "memory_fingerprint",
    "attestation_revocation",
    "cpu_quote_verified",
    "gpu_report_verified",
    "key_available",
})


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _unb64url(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def manifest_identity(manifest: WeightCustodyManifest) -> str:
    material = signing_pre_image(manifest.model_dump(mode="json", exclude_none=True))
    return "sha256:" + hashlib.sha256(material).hexdigest()


def evidence_identity(evidence: CompositeEvidence) -> str:
    return canonical_hash(evidence.model_dump(mode="json", exclude_none=True))


@dataclass(frozen=True)
class RenewalDecision:
    kind: str
    algorithm: str
    renewed: bool
    weights_hash: str
    manifest_hash: str
    challenge_nonce_hash: str
    evidence_hash: str
    issued_at: str
    expires_at: str
    checks: tuple[dict[str, Any], ...]
    public_key_b64url: str
    signature_b64url: str

    def signing_payload(self) -> dict[str, Any]:
        value = asdict(self)
        value.pop("signature_b64url")
        return value

    @property
    def renewal_id(self) -> str:
        return canonical_hash(self.signing_payload())

    def verify(self, expected_public_key_b64url: str) -> bool:
        if (self.kind != "wcm-renewal/v1" or self.algorithm != "Ed25519"
                or self.public_key_b64url != expected_public_key_b64url):
            return False
        try:
            key = Ed25519PublicKey.from_public_bytes(_unb64url(self.public_key_b64url))
            key.verify(_unb64url(self.signature_b64url), canonicalize(self.signing_payload()))
        except (binascii.Error, ValueError, InvalidSignature):
            return False
        return True


def renewal_public_key(signing_key: Ed25519PrivateKey) -> str:
    raw = signing_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw,
    )
    return _b64url(raw)


def sign_renewal_decision(
    *,
    signing_key: Ed25519PrivateKey,
    renewed: bool,
    manifest: WeightCustodyManifest,
    evidence: CompositeEvidence,
    issued_at: str,
    expires_at: str,
    checks: Iterable[dict[str, Any]],
) -> RenewalDecision:
    unsigned = RenewalDecision(
        kind="wcm-renewal/v1",
        algorithm="Ed25519",
        renewed=renewed,
        weights_hash=str(manifest.weights_hash),
        manifest_hash=manifest_identity(manifest),
        challenge_nonce_hash="sha256:" + hashlib.sha256(
            evidence.cpu.nonce_echo.encode("utf-8")
        ).hexdigest(),
        evidence_hash=evidence_identity(evidence),
        issued_at=issued_at,
        expires_at=expires_at,
        checks=tuple(dict(check) for check in checks),
        public_key_b64url=renewal_public_key(signing_key),
        signature_b64url="",
    )
    signature = signing_key.sign(canonicalize(unsigned.signing_payload()))
    return RenewalDecision(
        **{**asdict(unsigned), "signature_b64url": _b64url(signature)}
    )
