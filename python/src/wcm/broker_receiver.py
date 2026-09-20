"""Provision-once broker lifecycle using locally hashed effective configuration.

This library path does not measure Python, isolate memory, or securely erase it.
Run it in the approved immutable broker image; the host must not be able to alter
the code, configuration, clock, or private state. Native-SNP workloads use a
pinned VCEK chain and SHA256 of the raw signed launch measurement as their WCM
measurement. The existing HTTP server's environment keystore path is unchanged.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from ._challenge import Challenge
from ._quote_verify import QuoteVerification, QuoteVerifier, TrustStore
from ._seal import generate_transport_keypair
from .attestation import CompositeEvidence
from .kbs import KeyBrokerService, ReleaseDecision
from .models import WeightCustodyManifest
from .nvidia import build_gpu_verifier
from .provisioning import (
    BrokerProvisioningPolicy, ProvisioningEnvelope, open_provisioned_key,
    provisioning_binding,
)
from .snp import SnpQuoteParser, parse_snp_report


@dataclass(frozen=True)
class BrokerEffectiveConfiguration:
    """Actual immutable constructor inputs; certificate encodings are normalized.

    All runtime choices are fixed by the versioned profile except these inputs.
    Updating any input requires a new receiver and owner approval of its digest.
    """

    cpu_root_der: bytes
    cpu_vcek_der: bytes
    cpu_intermediate_ders: tuple[bytes, ...]
    trusted_manifest_identities: frozenset[str]
    owner_public_key: bytes
    gpu_root_der: bytes | None = None

    def __post_init__(self) -> None:
        for field in ("cpu_root_der", "cpu_vcek_der", "gpu_root_der"):
            value = getattr(self, field)
            if value is not None:
                cert = x509.load_der_x509_certificate(bytes(value))
                object.__setattr__(self, field, cert.public_bytes(serialization.Encoding.DER))
        intermediates = tuple(
            x509.load_der_x509_certificate(bytes(value)).public_bytes(serialization.Encoding.DER)
            for value in self.cpu_intermediate_ders
        )
        object.__setattr__(self, "cpu_intermediate_ders", intermediates)
        identities = frozenset(self.trusted_manifest_identities)
        if not identities or any(
            not isinstance(value, str) or re.fullmatch(r"sha256:[0-9a-f]{64}", value) is None
            for value in identities
        ):
            raise ValueError("an exact nonempty manifest identity allowlist is required")
        object.__setattr__(self, "trusted_manifest_identities", identities)
        owner = bytes(self.owner_public_key)
        Ed25519PublicKey.from_public_bytes(owner)
        object.__setattr__(self, "owner_public_key", owner)

    def digest(self) -> str:
        """Hash the exact inputs used below, including fixed security controls."""
        value = {
            "profile": "wcm/native-snp-broker-receiver/v1",
            "cpu_verifier": "native-snp-sha256-launch/v1",
            "workload_vmpl": 0,
            "workload_debug_allowed": False,
            "cpu_root_der": self.cpu_root_der.hex(),
            "cpu_vcek_der": self.cpu_vcek_der.hex(),
            "cpu_intermediate_ders": [cert.hex() for cert in self.cpu_intermediate_ders],
            "gpu_root_der": self.gpu_root_der.hex() if self.gpu_root_der is not None else None,
            "trusted_manifest_identities": sorted(self.trusted_manifest_identities),
            "owner_public_key": self.owner_public_key.hex(),
            "require_channel_binding": True,
            "require_cpu_quote_verification": True,
            "require_gpu_report_verification": True,
            "allow_legacy_memory_fingerprint": False,
            "clock": "system-utc",
            "challenge_ttl_seconds": 300,
            "max_attestation_cache_age_seconds": 600,
            "renewal_decision_ttl_seconds": 60,
            "provisioning_request_ttl_seconds": 60,
        }
        return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


class _NativeWorkloadVerifier(QuoteVerifier):
    def verify(
        self, quote_b64: str, *, expected_nonce: str, channel_binding: bytes = b"",
        expected_workload_measurement: str | None = None, now: datetime | None = None,
    ) -> QuoteVerification:
        # Decode once so the verified bytes and the appraised measurement agree.
        try:
            raw = base64.b64decode(quote_b64, validate=True)
        except (binascii.Error, ValueError):
            return QuoteVerification(False, "invalid native SNP quote encoding")
        result = super().verify(
            base64.b64encode(raw).decode(), expected_nonce=expected_nonce,
            channel_binding=channel_binding, now=now,
        )
        if not result.verified:
            return result
        report = parse_snp_report(raw)
        measurement = "sha256:" + hashlib.sha256(report.measurement).hexdigest()
        if report.version < 2 or measurement != expected_workload_measurement:
            return QuoteVerification(False, "signed workload launch measurement mismatch")
        if report.policy & (1 << 19):
            return QuoteVerification(False, "debug-enabled workload is forbidden")
        if report.vmpl != 0:
            return QuoteVerification(False, "workload report must be at VMPL 0")
        return result


class BrokerReceiver:
    """Fresh boot -> attestation request -> provision once -> release -> retire.

    No method returns the provisioning private key, raw model key, or mutable
    KBS. These API boundaries do not protect against code running in this process.
    """

    def __init__(self, configuration: BrokerEffectiveConfiguration, policy: BrokerProvisioningPolicy):
        if configuration.digest() != policy.configuration_sha256:
            raise ValueError("effective broker configuration does not match owner policy")
        self._configuration = configuration
        self._policy = policy
        private, self._public = generate_transport_keypair()
        self._private: X25519PrivateKey | None = private
        self._pending: Challenge | None = None
        self._seen_provisioning_nonces: set[str] = set()
        self._kbs: KeyBrokerService | None = None
        self._retired = False
        self._lock = threading.Lock()

    @property
    def transport_public_key(self) -> str:
        return self._public

    def provisioning_report_data(self, challenge: Challenge) -> bytes:
        """Return native SNP REPORT_DATA computed from this receiver's inputs.

        Pass this to SevSnpProvider.provisioning_report(); the owner verifies the
        returned hardware report before it produces a ProvisioningEnvelope.
        """
        with self._lock:
            if self._retired or self._kbs is not None:
                raise RuntimeError("broker is not awaiting provisioning")
            if len(bytes.fromhex(challenge.nonce)) != 32 or bytes.fromhex(challenge.nonce).hex() != challenge.nonce:
                raise ValueError("owner challenge must be a 32-byte nonce")
            now = datetime.now(timezone.utc)
            if now > challenge.expires_at:
                raise ValueError("owner challenge expired")
            if challenge.nonce in self._seen_provisioning_nonces:
                raise ValueError("owner challenge already requested during this boot")
            self._seen_provisioning_nonces.add(challenge.nonce)
            # Challenge timestamps are not owner-signed; enforce a local bound
            # and never allow a repeated nonce to extend the installation window.
            self._pending = Challenge(challenge.nonce, now, min(challenge.expires_at, now + timedelta(seconds=60)))
            binding = provisioning_binding(self._policy, self._public)
            return hashlib.sha256(bytes.fromhex(challenge.nonce) + binding).digest() + bytes(32)

    def install(self, envelope: ProvisioningEnvelope) -> None:
        """Authenticate and install once; any attempt consumes the pending request."""
        with self._lock:
            if self._retired or self._kbs is not None or self._pending is None:
                raise RuntimeError("broker is not awaiting a provisioning envelope")
            pending = self._pending
            self._pending = None
            if envelope.nonce != pending.nonce or datetime.now(timezone.utc) > pending.expires_at:
                raise ValueError("provisioning envelope is stale or for another request")
            if self._private is None:
                raise RuntimeError("broker provisioning key is unavailable")
            key = open_provisioned_key(
                envelope, policy=self._policy, transport_private_key=self._private,
                trusted_owner=Ed25519PublicKey.from_public_bytes(self._configuration.owner_public_key),
            )
            if len(key) not in (16, 24, 32):
                raise ValueError("provisioned key must have an AES key length")
            config = self._configuration
            trust = TrustStore()
            trust.add_root(x509.load_der_x509_certificate(config.cpu_root_der))
            verifier = _NativeWorkloadVerifier(SnpQuoteParser(
                x509.load_der_x509_certificate(config.cpu_vcek_der),
                [x509.load_der_x509_certificate(cert) for cert in config.cpu_intermediate_ders],
            ), trust)
            gpu = None
            if config.gpu_root_der is not None:
                gpu = build_gpu_verifier(x509.load_der_x509_certificate(config.gpu_root_der).public_bytes(
                    serialization.Encoding.PEM
                ))
            self._kbs = KeyBrokerService(
                {self._policy.weights_hash: key}, cpu_quote_verifier=verifier,
                gpu_report_verifier=gpu, require_channel_binding=True,
                require_cpu_quote_verification=True, require_gpu_report_verification=True,
                trusted_manifest_identities=config.trusted_manifest_identities,
                challenge_ttl_seconds=300, max_attestation_cache_age_seconds=600,
                renewal_decision_ttl_seconds=60, allow_legacy_memory_fingerprint=False,
            )
            self._private = None

    def issue_challenge(self) -> Challenge:
        with self._lock:
            if self._retired or self._kbs is None:
                raise RuntimeError("broker is not provisioned or has retired")
            return self._kbs.issue_challenge()

    def verify_and_release(self, manifest: WeightCustodyManifest, evidence: CompositeEvidence) -> ReleaseDecision:
        with self._lock:
            if self._retired or self._kbs is None:
                raise RuntimeError("broker is not provisioned or has retired")
            return self._kbs.verify_and_release(manifest.model_copy(deep=True), evidence.model_copy(deep=True))

    def retire(self) -> None:
        """Permanently deny this receiver's API; dropping references is not erasure."""
        with self._lock:
            self._retired = True
            self._pending = None
            self._private = None
            self._kbs = None
