"""Verification of a Weight Custody Manifest's joint signatures.

A manifest is valid only when the REQUIRED roles have signed and every
signature verifies cryptographically over the same pre-image the signer used
(``WCM_SIGNED_FIELDS``, section 3.1). The required roles are:

  - ``builder`` and ``custodian`` always (joint signature, never the customer);
  - additionally ``sovereign`` (matching ``sovereign_profile.sovereign_signer``)
    when ``sovereign_profile.enabled`` is true.

This is Layer 1 only: it proves who authorized the manifest and that it was
not altered after signing. It does NOT attest the runtime environment or
release any key, which is Layer 2 (SPEC.md section 3.2) and not in this
package. Verifying an authority-layer signature says nothing about whether
adversary-owned silicon forged an attestation quote (open question 8.8).
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Optional, cast

from cryptography.exceptions import InvalidSignature

from ._signing import (
    Ed25519Verifier,
    HybridVerifier,
    MlDsa65Verifier,
    _b64url_decode,
)
from .models import (
    BaseConfidentiality,
    DeploymentModel,
    MemoryFingerprintChallenge,
    PhysicalHardening,
    SignatureAlgorithm,
    SignatureRole,
    Tenancy,
    WeightCustodyManifest,
)


class VerificationContext:
    """Holds the set of trusted public keys, indexed by key_id.

    A verifier supplies the keys it is willing to trust for the builder and
    custodian (and sovereign, if applicable). A signature whose ``key_id`` is
    not in this set is treated as untrusted, not merely unverified. Each key is
    trusted for exactly one algorithm; a signature whose algorithm does not match
    the trusted key's is rejected.
    """

    def __init__(self) -> None:
        # key_id -> (algorithm value, material). Material is raw public bytes for
        # Ed25519 / ML-DSA-65, or (ed25519_pub, ml_dsa65_pub) for hybrid.
        self._keys: dict[str, tuple[str, object]] = {}

    def add_key(self, public_key_bytes: bytes) -> str:
        """Trust a raw Ed25519 public key (standard profile). Returns its key_id."""
        verifier = Ed25519Verifier(public_key_bytes)  # validates the key
        self._keys[verifier.key_id] = (SignatureAlgorithm.ed25519.value, public_key_bytes)
        return verifier.key_id

    def add_key_b64url(self, s: str) -> str:
        return self.add_key(_b64url_decode(s))

    def add_ml_dsa65_key(self, public_key_bytes: bytes) -> str:
        """Trust a raw ML-DSA-65 public key (post-quantum profile)."""
        verifier = MlDsa65Verifier(public_key_bytes)  # validates the key
        self._keys[verifier.key_id] = (SignatureAlgorithm.ml_dsa_65.value, public_key_bytes)
        return verifier.key_id

    def add_hybrid_key(self, ed25519_public_bytes: bytes, ml_dsa65_public_bytes: bytes) -> str:
        """Trust a combined Ed25519 + ML-DSA-65 key (hybrid profile)."""
        key_id = hashlib.sha256(ed25519_public_bytes + ml_dsa65_public_bytes).hexdigest()
        self._keys[key_id] = (
            SignatureAlgorithm.hybrid.value,
            (ed25519_public_bytes, ml_dsa65_public_bytes),
        )
        return key_id

    def _lookup(self, key_id: str) -> Optional[tuple[str, object]]:
        return self._keys.get(key_id)

    def get(self, key_id: str) -> Optional[bytes]:
        """Back-compat: return the raw Ed25519 public bytes for *key_id*, else None."""
        entry = self._keys.get(key_id)
        if entry is not None and entry[0] == SignatureAlgorithm.ed25519.value:
            return entry[1]  # type: ignore[return-value]
        return None


@dataclass(frozen=True)
class SignatureResult:
    role: SignatureRole
    signer: str
    key_id: str
    valid: bool
    reason: Optional[str] = None


@dataclass(frozen=True)
class VerificationResult:
    ok: bool
    signatures: list[SignatureResult] = field(default_factory=list)
    missing_roles: list[SignatureRole] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    # Non-blocking advisories about what the manifest actually protects, e.g. an
    # 'open' base whose secrecy is not the thing being guarded, or a symmetric
    # BYOM posture. These never change ``ok``; they exist so a manifest is not
    # read as promising more than it delivers (see ``_consistency_notes``).
    notes: list[str] = field(default_factory=list)


def _required_roles(manifest: WeightCustodyManifest) -> list[SignatureRole]:
    roles = [SignatureRole.builder, SignatureRole.custodian]
    if manifest.release_policy.sovereign_profile.enabled:
        roles.append(SignatureRole.sovereign)
    return roles


def _verify_one(algo: str, material: object, unsigned: dict[str, Any], sig: Any) -> None:
    """Verify one signature by algorithm; raises InvalidSignature/ValueError on failure."""
    if algo == SignatureAlgorithm.ed25519.value:
        Ed25519Verifier(cast(bytes, material)).verify(unsigned, sig.signature_value)
    elif algo == SignatureAlgorithm.ml_dsa_65.value:
        MlDsa65Verifier(cast(bytes, material)).verify(unsigned, sig.signature_value)
    elif algo == SignatureAlgorithm.hybrid.value:
        if not sig.classical_signature or not sig.pq_signature:
            raise InvalidSignature("hybrid signature is missing a component")
        ed_pub, pq_pub = cast("tuple[bytes, bytes]", material)
        HybridVerifier(ed_pub, pq_pub).verify(
            unsigned, sig.classical_signature, sig.pq_signature
        )
    else:
        raise InvalidSignature(f"unsupported signature algorithm {algo!r}")


def _consistency_notes(manifest: WeightCustodyManifest) -> list[str]:
    """Non-blocking advisories: does the manifest promise what it can deliver?

    This is the 'consistency check' half of the base-confidentiality design: the
    field is declarative, but where a declaration and a control point in
    different directions we say so, rather than let the manifest imply a secrecy
    guarantee it does not hold.
    """
    notes: list[str] = []
    bc = manifest.base_confidentiality
    rp = manifest.release_policy

    if bc is BaseConfidentiality.open:
        notes.append(
            "base_confidentiality 'open': attestation-gated release here protects the "
            "integrity and provenance of the served stack and enforces the license, "
            "derivative, and revocation terms. It does NOT protect the secrecy of the "
            "base weights, which are public."
        )
        secrecy_controls: list[str] = []
        if (
            rp.memory_fingerprint_challenge
            is MemoryFingerprintChallenge.required_for_hostile_owner_posture
        ):
            secrecy_controls.append("memory_fingerprint_challenge")
        if rp.physical_hardening is PhysicalHardening.tamper_evident:
            secrecy_controls.append("physical_hardening")
        if rp.tenancy is Tenancy.dedicated:
            secrecy_controls.append("tenancy=dedicated")
        if secrecy_controls:
            notes.append(
                "these controls defend base-weight secrecy and add little for an open "
                "base (consider dropping the cost): " + ", ".join(secrecy_controls)
            )
    elif bc is BaseConfidentiality.gated_open:
        notes.append(
            "base_confidentiality 'gated-open': the base's secrecy is license-gated, "
            "not cryptographic; key release adds integrity and provenance and enforces "
            "the gate's terms."
        )

    if manifest.deployment_model is DeploymentModel.byom_symmetric:
        if manifest.builder.identity == manifest.custody.custodian:
            notes.append(
                "deployment_model 'byom-symmetric': builder and custodian are one "
                f"identity ('{manifest.builder.identity}') holding both roles (self-custody)."
            )
        else:
            notes.append(
                "deployment_model 'byom-symmetric' declared, but builder "
                f"('{manifest.builder.identity}') and custodian "
                f"('{manifest.custody.custodian}') differ; confirm both belong to the "
                "same governing org."
            )

    if manifest.provenance is not None and manifest.provenance.model_signing is not None:
        ms = manifest.provenance.model_signing
        loc = f", transparency={ms.transparency}" if ms.transparency else ""
        notes.append(
            f"provenance: references an OpenSSF model-signing signature (method "
            f"'{ms.method}', signed_digest {ms.signed_digest}{loc}). The reference "
            "is under the joint signature; call verify_provenance to cryptographically "
            "check that model-signing signature against the model files."
        )

    return notes


def verify_manifest(
    manifest: WeightCustodyManifest, context: VerificationContext
) -> VerificationResult:
    """Verify a manifest's joint signatures against *context*'s trusted keys.

    Returns a ``VerificationResult``; ``ok`` is true only when every required
    role is present, every signature verifies, and no signature in the
    manifest is invalid or from an untrusted key.
    """
    unsigned = manifest.unsigned_dict()
    results: list[SignatureResult] = []
    errors: list[str] = []

    for sig in manifest.signatures:
        entry = context._lookup(sig.key_id)
        if entry is None:
            results.append(
                SignatureResult(
                    role=sig.role,
                    signer=sig.signer,
                    key_id=sig.key_id,
                    valid=False,
                    reason="untrusted key_id (not in verification context)",
                )
            )
            continue
        trusted_algo, material = entry
        want = sig.algorithm.value
        if trusted_algo != want:
            results.append(
                SignatureResult(
                    role=sig.role,
                    signer=sig.signer,
                    key_id=sig.key_id,
                    valid=False,
                    reason=f"algorithm mismatch: key trusted for {trusted_algo}, signature is {want}",
                )
            )
            continue
        try:
            _verify_one(want, material, unsigned, sig)
            results.append(
                SignatureResult(
                    role=sig.role, signer=sig.signer, key_id=sig.key_id, valid=True
                )
            )
        except (InvalidSignature, ValueError) as exc:
            results.append(
                SignatureResult(
                    role=sig.role,
                    signer=sig.signer,
                    key_id=sig.key_id,
                    valid=False,
                    reason=f"signature verification failed: {exc}",
                )
            )

    valid_roles = {r.role for r in results if r.valid}

    # Sovereign role must be the declared sovereign_signer, not just anyone
    # presenting a 'sovereign'-tagged block.
    sp = manifest.release_policy.sovereign_profile
    if sp.enabled:
        sovereign_ok = any(
            r.valid and r.role is SignatureRole.sovereign and r.signer == sp.sovereign_signer
            for r in results
        )
        if not sovereign_ok:
            valid_roles.discard(SignatureRole.sovereign)
            errors.append(
                "sovereign_profile.enabled but no valid signature from "
                f"sovereign_signer '{sp.sovereign_signer}'"
            )

    required = _required_roles(manifest)
    missing = [role for role in required if role not in valid_roles]

    any_invalid = [r for r in results if not r.valid]
    ok = not missing and not any_invalid

    return VerificationResult(
        ok=ok,
        signatures=results,
        missing_roles=missing,
        errors=errors,
        notes=_consistency_notes(manifest),
    )
