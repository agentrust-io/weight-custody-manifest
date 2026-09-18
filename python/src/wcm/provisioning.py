"""Owner-side, native-SNP broker provisioning reference protocol.

This module does not isolate a process or measure its configuration. A measured
broker must compute its own configuration digest and generate its transport key
inside the protected boundary. The owner runs this verifier outside the hostile
host. No HTTP endpoint or production broker boot path is installed here.
"""
from __future__ import annotations

import hashlib
import json
import threading
from contextlib import nullcontext
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Callable, ContextManager

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from ._challenge import Challenge, ChallengeStore
from ._quote_verify import QuoteVerifier, TrustStore
from ._seal import open_sealed, seal_to_public_key
from .snp import SnpQuoteParser, parse_snp_report
from .provisioning_state import OwnerEpochStore
if TYPE_CHECKING:
    from .deployment_identity import DeploymentApproval

_DOMAIN = b"wcm/broker-provisioning/v1\x00"


@dataclass(frozen=True)
class BrokerProvisioningPolicy:
    """Owner-approved identity, exact configuration, key label and update epoch.

    configuration_sha256 covers the complete effective configuration: roots,
    verifier selection, accepted manifests, platform policy and override paths.
    The owner supplies these values; the request cannot change them.
    """

    measurement_hex: str
    configuration_sha256: str
    weights_hash: str
    epoch: int
    guest_policy: int
    minimum_tcb_le_hex: str
    required_platform_fields: frozenset[str]
    forbidden_platform_fields: frozenset[str]

    def __post_init__(self) -> None:
        for name, size in (("measurement_hex", 48), ("configuration_sha256", 32),
                           ("minimum_tcb_le_hex", 8)):
            value = getattr(self, name)
            if not isinstance(value, str) or len(value) != size * 2:
                raise ValueError(f"{name} must be {size}-byte lowercase hex")
            try:
                valid = bytes.fromhex(value).hex() == value
            except ValueError:
                valid = False
            if not valid:
                raise ValueError(f"{name} must be {size}-byte lowercase hex")
        if not isinstance(self.weights_hash, str) or not self.weights_hash:
            raise ValueError("weights_hash must be nonempty")
        if type(self.epoch) is not int or self.epoch < 0:
            raise ValueError("epoch must be a nonnegative integer")
        if type(self.guest_policy) is not int or not 0 <= self.guest_policy < 2**64:
            raise ValueError("guest_policy must be an unsigned 64-bit word")
        if self.guest_policy & (1 << 19):
            raise ValueError("debug-enabled broker policy is forbidden")
        fields = {"smt_en", "tsme_en", "ecc_en", "rapl_dis", "ciphertext_hiding_en",
                  "alias_check_complete", "sev_tio_en"}
        for name in ("required_platform_fields", "forbidden_platform_fields"):
            value = getattr(self, name)
            if not isinstance(value, (set, frozenset)) or not value <= fields:
                raise ValueError(f"{name} must contain known SNP platform fields")
            object.__setattr__(self, name, frozenset(value))
        if self.required_platform_fields & self.forbidden_platform_fields:
            raise ValueError("contradictory platform requirements")

    def context(self) -> bytes:
        return _DOMAIN + json.dumps(
            {
                "measurement_hex": self.measurement_hex,
                "configuration_sha256": self.configuration_sha256,
                "weights_hash": self.weights_hash,
                "epoch": self.epoch,
                "guest_policy": self.guest_policy,
                "minimum_tcb_le_hex": self.minimum_tcb_le_hex,
                "required_platform_fields": sorted(self.required_platform_fields),
                "forbidden_platform_fields": sorted(self.forbidden_platform_fields),
            }, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        ).encode("ascii")


def provisioning_binding(policy: BrokerProvisioningPolicy, public_key_hex: str) -> bytes:
    """Channel binding for REPORT_DATA = SHA256(nonce || binding), zero padded.

    The protected broker computes policy.configuration_sha256 from the config
    it actually enforces. Echoing an owner's digest without checking the local
    configuration does not satisfy the protocol's trust assumption.
    """
    public_key = bytes.fromhex(public_key_hex)
    if len(public_key) != 32 or public_key.hex() != public_key_hex:
        raise ValueError("transport public key must be canonical 32-byte lowercase hex")
    return _DOMAIN + public_key + hashlib.sha256(policy.context()).digest()


@dataclass(frozen=True)
class ProvisioningEnvelope:
    nonce: str
    ciphertext: bytes
    owner_signature: bytes


def _aad(policy: BrokerProvisioningPolicy, nonce: str, public_key_hex: str) -> bytes:
    return policy.context() + bytes.fromhex(nonce) + bytes.fromhex(public_key_hex)


class OwnerProvisioner:
    """Provision only to an authenticated native-SNP broker instance.

    Owner state and signing key must be protected from the customer. Updates
    revoke outstanding challenges and advance the epoch. An optional owner-side
    epoch store enforces restart floors and rejects stale live owner processes.
    Protecting that database from deletion and snapshot rollback remains required.
    """

    def __init__(
        self, policy: BrokerProvisioningPolicy, *,
        owner_signing_key: Ed25519PrivateKey,
        trusted_root: x509.Certificate,
        now: Callable[[], datetime] | None = None,
        challenge_ttl_seconds: int = 60,
        epoch_store: OwnerEpochStore | None = None,
        deployment_approval: DeploymentApproval | None = None,
    ) -> None:
        if type(challenge_ttl_seconds) is not int or challenge_ttl_seconds <= 0:
            raise ValueError("challenge TTL must be a positive integer")
        if deployment_approval is not None:
            deployment_approval.require_policy(policy)
        self._deployment_approval = deployment_approval
        self._policy = policy
        self._signer = owner_signing_key
        self._trust = TrustStore()
        self._trust.add_root(trusted_root)
        self._now = now or (lambda: datetime.now(timezone.utc))
        self._ttl = challenge_ttl_seconds
        self._challenges = ChallengeStore(ttl_seconds=self._ttl, now=self._now)
        self._lock = threading.Lock()
        self._epoch_store = epoch_store
        with self._epoch_guard(policy, admit=True):
            pass

    def _epoch_guard(
        self, policy: BrokerProvisioningPolicy, *, admit: bool = False,
    ) -> ContextManager[None]:
        return (self._epoch_store.guard(policy.epoch, policy.context(), admit=admit)
                if self._epoch_store is not None else nullcontext())

    def issue_challenge(self) -> Challenge:
        with self._lock:
            with self._epoch_guard(self._policy):
                return self._challenges.issue()

    def update_policy(self, policy: BrokerProvisioningPolicy) -> None:
        with self._lock:
            if policy.epoch <= self._policy.epoch:
                raise ValueError("policy update must advance epoch")
            if self._deployment_approval is not None:
                self._deployment_approval.require_policy(policy)
            with self._epoch_guard(policy, admit=True):
                self._policy = policy
                self._challenges = ChallengeStore(ttl_seconds=self._ttl, now=self._now)

    def provision(
        self, *, nonce: str, report: bytes, vcek: x509.Certificate,
        intermediates: list[x509.Certificate], transport_public_key: str,
        model_key: bytes,
    ) -> ProvisioningEnvelope:
        """Authenticate signed measurement/config/channel before any key leaves.

        model_key is supplied by the owner-side key store, never by the broker.
        Certificate material can be supplied by the broker; only the pinned
        owner root is authoritative. All attempts consume their challenge.
        """
        import base64

        # Parse exactly the bytes authenticated below, even if a caller supplies
        # a mutable buffer despite the bytes annotation.
        report = bytes(report)
        intermediates = list(intermediates)
        with self._lock, self._epoch_guard(self._policy):
            self._challenges.consume(nonce)
            if not isinstance(model_key, bytes) or len(model_key) not in (16, 24, 32):
                raise ValueError("model key must be a 16, 24 or 32-byte AES key")
            policy = self._policy
            if self._deployment_approval is not None:
                self._deployment_approval.require_policy(policy)
            verifier = QuoteVerifier(SnpQuoteParser(vcek, intermediates), self._trust)
            result = verifier.verify(
                base64.b64encode(report).decode("ascii"), expected_nonce=nonce,
                channel_binding=provisioning_binding(policy, transport_public_key),
                now=self._now(),
            )
            if not result.verified:
                raise ValueError(f"broker attestation rejected: {result.reason}")
            parsed = parse_snp_report(report)
            if parsed.version < 2 or parsed.measurement.hex() != policy.measurement_hex:
                raise ValueError("broker image measurement rejected")
            if parsed.policy != policy.guest_policy or parsed.policy & (1 << 19):
                raise ValueError("broker guest policy rejected")
            if parsed.vmpl != 0:
                raise ValueError("broker must run at VMPL 0")
            # Each byte is a component SVN (or reserved), never a scalar TCB
            # ordering. The owner pins the floor's CPU-generation-specific ABI.
            if any(actual < floor for actual, floor in zip(
                parsed.reported_tcb.to_bytes(8, "little"), bytes.fromhex(policy.minimum_tcb_le_hex)
            )):
                raise ValueError("broker reported TCB below owner floor")
            for field in policy.required_platform_fields:
                if getattr(parsed.platform_info, field) is not True:
                    raise ValueError(f"broker platform requires {field}")
            for field in policy.forbidden_platform_fields:
                if getattr(parsed.platform_info, field) is not False:
                    raise ValueError(f"broker platform forbids {field}")
            aad = _aad(policy, nonce, transport_public_key)
            ciphertext = seal_to_public_key(transport_public_key, model_key, aad=aad)
            return ProvisioningEnvelope(nonce, ciphertext, self._signer.sign(aad + ciphertext))


def open_provisioned_key(
    envelope: ProvisioningEnvelope, *, policy: BrokerProvisioningPolicy,
    transport_private_key: X25519PrivateKey, trusted_owner: Ed25519PublicKey,
) -> bytes:
    """Authenticate owner and exact policy before opening in the protected broker.

    This is an envelope decoder, not a key installation or anti-rollback store.
    A broker must use a fresh in-boundary key per boot and install an envelope
    once; protecting state, key erasure and lifetime are deployment obligations.
    """
    ciphertext = bytes(envelope.ciphertext)
    signature = bytes(envelope.owner_signature)
    public_key = transport_private_key.public_key().public_bytes_raw().hex()
    aad = _aad(policy, envelope.nonce, public_key)
    trusted_owner.verify(signature, aad + ciphertext)
    return open_sealed(ciphertext, transport_private_key, aad=aad)
