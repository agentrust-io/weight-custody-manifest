"""Pydantic v2 data models for the Weight Custody Manifest (SPEC.md section 3.1).

This models the Layer 1 manifest: the signed artifact a builder issues to
describe exactly which weights are released, under what terms, and against
which release policy. It is the executable form of the JSON in SPEC.md
section 3.1, including the v0.8 additions (``trusted_time_source``,
``memory_fingerprint_challenge``, ``attestation_revocation_check``).

Unknown fields are rejected (``extra="forbid"``): the spec defines exhaustive
field sets, so an unrecognized key is structural drift, not an extension point.
That is what lets the example-validation test catch spec/model divergence.

Layer 2 (attestation-gated key release), the KBS, and runtime custody are not
modeled here; this package is the manifest and its joint signatures only.
"""
from __future__ import annotations

from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field, model_validator

from ._types import HashValue


# ---------------------------------------------------------------------------
# Enums (allowed value sets per SPEC.md section 3.1)
# ---------------------------------------------------------------------------


class AssuranceTier(str, Enum):
    """The single baseline for anything above a pilot is hardware-attested;
    claim-only assurance is not offered for frontier weights (SPEC.md 3.1)."""

    hardware_attested = "hardware-attested"


class PhysicalHardening(str, Enum):
    not_required = "not-required"
    tamper_evident = "tamper-evident-enclosure+access-control+chain-of-custody"


class TrustedTimeSource(str, Enum):
    """v0.8, resolves former open question 8.9. Names the clock the
    wipe-on-lapse floor trusts, per deployment, rather than assuming one."""

    secure_tsc = "secure-tsc"
    lease_with_op_count_hybrid = "lease-with-op-count-hybrid"
    none_best_effort = "none-best-effort"


class MemoryFingerprintChallenge(str, Enum):
    """v0.8, the measurement-forgery (BadRAM-class) defense from open
    question 8.8. Required in the hostile-owner posture."""

    required_for_hostile_owner_posture = "required-for-hostile-owner-posture"
    not_required = "not-required"


class Tenancy(str, Enum):
    shared = "shared"
    dedicated = "dedicated"


class KeyReleaseMode(str, Enum):
    attestation_gated = "attestation-gated"


class ReplayProtection(str, Enum):
    kbs_nonce_required = "kbs-nonce-required"


class ServingImageStatus(str, Enum):
    current = "current"
    retiring = "retiring"
    revoked = "revoked"


class RevocationAuthority(str, Enum):
    builder_and_custodian_joint = "builder-and-opaque-joint"
    quorum = "quorum"


class CustodianType(str, Enum):
    hosted = "opaque-hosted"
    customer_self_custody = "customer-self-custody"


class SignatureRole(str, Enum):
    builder = "builder"
    custodian = "custodian"
    sovereign = "sovereign"
    additional = "additional"


class SignatureAlgorithm(str, Enum):
    ed25519 = "Ed25519"


class KeyType(str, Enum):
    software = "software"
    hardware = "hardware"


# ---------------------------------------------------------------------------
# Sub-objects
# ---------------------------------------------------------------------------


class DerivativePolicy(str, Enum):
    """Machine-checkable derivative permission (SPEC.md section 3.4).

    The freeform ``permitted_derivatives`` string carries the legal terms; this
    enum is the part a lineage verifier can enforce. ``none`` forbids any
    derivative; ``fine-tune-only`` and ``unrestricted`` both permit a derivative
    to exist (the SDK does not police the *kind* of derivative structurally).
    """

    none = "none"
    fine_tune_only = "fine-tune-only"
    unrestricted = "unrestricted"


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Builder(_Strict):
    identity: str
    signing_key: str


class ReleaseTerms(_Strict):
    license: str
    permitted_derivatives: str
    permitted_environments: list[str] = Field(min_length=1)
    jurisdiction_restriction: Optional[str] = None
    # Machine-checkable form of permitted_derivatives; None means unspecified
    # (a lineage verifier reports it as not machine-enforceable).
    derivatives: Optional[DerivativePolicy] = None


class RightsHolder(_Strict):
    """Who holds IP over the base weights vs the fine-tune (SPEC.md 3.4)."""

    base: str  # holder of the base-weights IP (commonly the builder)
    derivative: Optional[str] = None  # holder of the fine-tune IP (e.g. the customer)


class RequiredGpuMeasurement(_Strict):
    rim_pin: str
    note: Optional[str] = None


class AcceptedMeasurement(_Strict):
    measurement: HashValue
    status: ServingImageStatus
    # Required iff status is 'retiring' (see RequiredServingImage validator).
    retire_after: Optional[str] = None


class RequiredServingImage(_Strict):
    signer: str
    release_rule: str
    accepted_measurements: list[AcceptedMeasurement] = Field(min_length=1)
    note: Optional[str] = None

    @model_validator(mode="after")
    def _retire_after_only_when_retiring(self) -> "RequiredServingImage":
        for m in self.accepted_measurements:
            if m.status is ServingImageStatus.retiring and m.retire_after is None:
                raise ValueError(
                    "a 'retiring' accepted_measurement requires 'retire_after'"
                )
            if m.status is not ServingImageStatus.retiring and m.retire_after is not None:
                raise ValueError(
                    "'retire_after' is only valid on a 'retiring' accepted_measurement"
                )
        return self


class SovereignProfile(_Strict):
    enabled: bool = False
    revocation_authority: RevocationAuthority = RevocationAuthority.quorum
    sovereign_signer: Optional[str] = None
    additional_signers: Optional[list[str]] = None
    note: Optional[str] = None

    @model_validator(mode="after")
    def _enabled_requires_quorum(self) -> "SovereignProfile":
        if self.enabled:
            if self.revocation_authority is not RevocationAuthority.quorum:
                raise ValueError(
                    "sovereign_profile.enabled requires revocation_authority='quorum'"
                )
            if not self.sovereign_signer:
                raise ValueError(
                    "sovereign_profile.enabled requires 'sovereign_signer'"
                )
        return self


class ReleasePolicy(_Strict):
    required_assurance_tier: AssuranceTier
    physical_hardening: PhysicalHardening = PhysicalHardening.not_required
    trusted_time_source: TrustedTimeSource = TrustedTimeSource.none_best_effort
    memory_fingerprint_challenge: MemoryFingerprintChallenge = (
        MemoryFingerprintChallenge.not_required
    )
    required_hw_platform: list[str] = Field(min_length=1)
    required_gpu_measurement: Optional[RequiredGpuMeasurement] = None
    tenancy: Tenancy = Tenancy.shared
    required_serving_image: RequiredServingImage
    key_release_mode: KeyReleaseMode = KeyReleaseMode.attestation_gated
    replay_protection: ReplayProtection = ReplayProtection.kbs_nonce_required
    attestation_revocation_check: Optional[str] = None
    revocation_authority: RevocationAuthority = (
        RevocationAuthority.builder_and_custodian_joint
    )
    sovereign_profile: SovereignProfile = Field(default_factory=SovereignProfile)


class KbsImage(_Strict):
    measurement: HashValue
    signer: str
    note: Optional[str] = None


class Custody(_Strict):
    custodian: str
    custodian_type: CustodianType
    kbs_image: KbsImage
    enclave_id: str
    attestation_cadence: str
    kbs_attestation_cadence: Optional[str] = None


class ManifestSignature(_Strict):
    role: SignatureRole
    signer: str
    algorithm: SignatureAlgorithm = SignatureAlgorithm.ed25519
    key_id: str
    key_type: KeyType = KeyType.software
    signed_at: Optional[str] = None
    signature_value: str
    signed_fields: Optional[list[str]] = None


# ---------------------------------------------------------------------------
# Top-level manifest
# ---------------------------------------------------------------------------


class WeightCustodyManifest(_Strict):
    """A Layer 1 Weight Custody Manifest (SPEC.md section 3.1)."""

    manifest_version: str
    weights_hash: HashValue
    builder: Builder
    release_terms: ReleaseTerms
    release_policy: ReleasePolicy
    custody: Custody
    # Layer 4 (SPEC.md 3.4): a derivative points at its parent's weights_hash and
    # records the IP split. Both are signed (see WCM_SIGNED_FIELDS). Absent on a
    # root manifest.
    derived_from: Optional[HashValue] = None
    rights_holder: Optional[RightsHolder] = None
    signatures: list[ManifestSignature] = Field(default_factory=list)

    @model_validator(mode="after")
    def _derived_from_not_self(self) -> "WeightCustodyManifest":
        if self.derived_from is not None and self.derived_from == self.weights_hash:
            raise ValueError("derived_from must not equal the manifest's own weights_hash")
        return self

    @model_validator(mode="after")
    def _sovereign_consistency(self) -> "WeightCustodyManifest":
        # When the sovereign profile is on, top-level revocation is quorum-based
        # and the unilateral path is gone (SPEC.md 3.1, 3.2).
        if self.release_policy.sovereign_profile.enabled:
            if self.release_policy.revocation_authority is not RevocationAuthority.quorum:
                raise ValueError(
                    "with sovereign_profile.enabled, release_policy.revocation_authority "
                    "must be 'quorum'"
                )
        return self

    def unsigned_dict(self) -> dict[str, Any]:
        """Manifest as a plain dict WITHOUT the signatures array.

        This is what a signer is handed: the ``signatures`` array is excluded
        from the pre-image (``WCM_SIGNED_FIELDS``), so passing it or not makes
        no cryptographic difference, but excluding it keeps intent clear.
        """
        return self.model_dump(mode="json", exclude_none=True, exclude={"signatures"})

    def signed_roles(self) -> set[SignatureRole]:
        return {s.role for s in self.signatures}

    def with_signatures(self, blocks: list[dict[str, Any]]) -> "WeightCustodyManifest":
        """Return a copy with *blocks* as the signatures array, re-validated.

        *blocks* are signature-block dicts as produced by ``Ed25519Signer.sign``.
        Re-validation turns them into ``ManifestSignature`` objects so the
        result is ready for ``verify_manifest``.
        """
        doc = self.model_dump(mode="json", exclude_none=True)
        doc["signatures"] = blocks
        return WeightCustodyManifest.model_validate(doc)
