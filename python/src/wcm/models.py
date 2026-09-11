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
from typing import Any, Literal, Optional

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


class PlatformIntegrityRequirement(str, Enum):
    required = "required"
    not_required = "not-required"


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
    ed25519 = "Ed25519"  # standard profile
    ml_dsa_65 = "ML-DSA-65"  # post-quantum profile (NIST FIPS 204)
    hybrid = "hybrid-Ed25519-ML-DSA-65"  # both required, both must verify


class KeyType(str, Enum):
    software = "software"
    hardware = "hardware"


class BaseConfidentiality(str, Enum):
    """Whether the BASE weights are actually secret (SPEC.md section 3.1).

    Made explicit rather than assumed, so a reader is not misled about what a
    manifest protects:

    - ``confidential``: base weights are secret (the frontier-model case).
      Attestation-gated release protects their secrecy. This is the default and
      the posture the rest of the spec was written around.
    - ``gated-open``: base weights are obtainable under a gated license
      (e.g. a community license). Secrecy is license-gated, not cryptographic.
    - ``open``: base weights are fully public. Encrypting them protects nothing;
      the manifest's value is integrity/provenance, license enforcement,
      derivative custody, and the kill switch, not secrecy.

    The verifier does not block on this field; it reports consistency notes
    (see ``verify_manifest``) so an ``open`` manifest is not read as promising a
    secrecy guarantee it cannot deliver.
    """

    confidential = "confidential"
    gated_open = "gated-open"
    open = "open"


class DeploymentModel(str, Enum):
    """Which direction the trust runs (SPEC.md section 2, principle 4).

    - ``builder-to-customer``: a builder places a model into a customer's
      environment; the vulnerable party is the builder. This is the default and
      the primary walk-through in the spec.
    - ``byom-symmetric``: one organization holds both the builder and custodian
      roles, bringing its own model into confidential infrastructure it also
      custodies. The same platform and primitives, roles collapsed onto one
      party. Requires ``customer-self-custody`` (the org custodies its own
      model).
    """

    builder_to_customer = "builder-to-customer"
    byom_symmetric = "byom-symmetric"


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


class ModelSigningProvenance(_Strict):
    """A reference to an OpenSSF model-signing signature (SPEC.md section 3.9).

    WCM does not re-sign the model files; it records a pointer to the signature
    that already attests them, so a verifier can cross-check that the custody
    manifest and the model-signing signature cover the same artifact. WCM is the
    custody-and-release layer; model-signing is the provenance layer beneath it.

    ``signed_digest`` is the stable digest WCM derives from the model-signing
    manifest (``provenance.model_signing_digest``); ``verify_provenance`` verifies
    the signature and re-derives this digest from the model files to bind the two.
    """

    method: Literal["openssf-model-signing"] = "openssf-model-signing"
    signed_digest: str
    transparency: Optional[str] = None  # e.g. a Sigstore/Rekor locator or URI
    signer: Optional[str] = None  # the model-signing identity, if disclosed


class Provenance(_Strict):
    """Where the base weights came from, referenced not re-derived (SPEC.md 3.9).

    Optional and extensible: today it carries an OpenSSF model-signing reference;
    other provenance systems can be added as sibling fields without changing the
    custody or release semantics.
    """

    model_signing: Optional[ModelSigningProvenance] = None


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


class PlatformIntegrity(_Strict):
    """Requirements on hardware-reported platform state (SPEC.md section 3.6).

    These are the only two statements about *physical* platform state that a
    production attestation report carries today, so the manifest can require
    them rather than leaving them unread.

    ``alias_check_complete`` requires SEV-SNP PLATFORM_INFO bit 5: AMD's
    boot-time DRAM alias scan (the BadRAM mitigation, CVE-2024-21944 /
    AMD-SB-3015) completed and found no aliasing addresses. Requiring it lifts
    the floor from a ~$10 SPD spoof to an interposer. It does not close the
    class: a boot-time scan is time-of-check/time-of-use, and Battering RAM
    (IEEE S&P 2026) passes the command/address lines through untouched during
    POST and enables aliasing afterwards.

    ``ciphertext_hiding`` requires PLATFORM_INFO bit 4. This is the precondition
    section 3.6 attaches to the semi-trusted-operator custody claim: without it
    a malicious *hypervisor* extracts keys through ciphertext side channels
    (CipherLeaks, Heracles) with no physical access. It says nothing about a
    physical adversary.

    Both default to ``not-required`` *within* this object, but the object itself
    is optional on ``ReleasePolicy`` and absent by default, so adding it does not
    perturb the signing pre-image of manifests written before it existed.
    """

    alias_check_complete: PlatformIntegrityRequirement = (
        PlatformIntegrityRequirement.not_required
    )
    ciphertext_hiding: PlatformIntegrityRequirement = (
        PlatformIntegrityRequirement.not_required
    )
    note: Optional[str] = None


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
    platform_integrity: Optional[PlatformIntegrity] = None
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
    signature_value: str  # the single signature; empty string in hybrid mode
    # Hybrid mode carries both component signatures (SPEC.md post-quantum profile).
    classical_signature: Optional[str] = None
    pq_signature: Optional[str] = None
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
    # Whether the base weights are actually secret, and which trust direction the
    # deployment runs (SPEC.md 3.1, section 2). Both are signed (WCM_SIGNED_FIELDS)
    # and both carry a backward-compatible default: a manifest that omits them is
    # read as a confidential, builder-to-customer release (the original posture).
    base_confidentiality: BaseConfidentiality = BaseConfidentiality.confidential
    deployment_model: DeploymentModel = DeploymentModel.builder_to_customer
    # Layer 4 (SPEC.md 3.4): a derivative points at its parent's weights_hash and
    # records the IP split. Both are signed (see WCM_SIGNED_FIELDS). Absent on a
    # root manifest.
    derived_from: Optional[HashValue] = None
    rights_holder: Optional[RightsHolder] = None
    # Provenance interop (SPEC.md 3.9): an optional signed reference to an OpenSSF
    # model-signing signature for the base weights. Signed (WCM_SIGNED_FIELDS);
    # absent on a manifest that does not cross-reference a model-signing bundle.
    provenance: Optional[Provenance] = None
    signatures: list[ManifestSignature] = Field(default_factory=list)

    @model_validator(mode="after")
    def _derived_from_not_self(self) -> "WeightCustodyManifest":
        if self.derived_from is not None and self.derived_from == self.weights_hash:
            raise ValueError("derived_from must not equal the manifest's own weights_hash")
        return self

    @model_validator(mode="after")
    def _byom_symmetric_is_self_custody(self) -> "WeightCustodyManifest":
        # Symmetric BYOM means one org brings its own model into infrastructure it
        # also custodies, so a hosted custodian is contradictory (SPEC.md 3.1).
        if self.deployment_model is DeploymentModel.byom_symmetric:
            if self.custody.custodian_type is not CustodianType.customer_self_custody:
                raise ValueError(
                    "deployment_model 'byom-symmetric' requires "
                    "custody.custodian_type 'customer-self-custody'"
                )
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
