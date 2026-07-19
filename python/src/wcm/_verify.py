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

from dataclasses import dataclass, field
from typing import Optional

from cryptography.exceptions import InvalidSignature

from ._signing import Ed25519Verifier, _b64url_decode
from .models import SignatureRole, WeightCustodyManifest


class VerificationContext:
    """Holds the set of trusted public keys, indexed by key_id.

    A verifier supplies the keys it is willing to trust for the builder and
    custodian (and sovereign, if applicable). A signature whose ``key_id`` is
    not in this set is treated as untrusted, not merely unverified.
    """

    def __init__(self) -> None:
        self._keys: dict[str, bytes] = {}

    def add_key(self, public_key_bytes: bytes) -> str:
        """Trust a raw Ed25519 public key. Returns its key_id."""
        verifier = Ed25519Verifier(public_key_bytes)  # validates the key
        self._keys[verifier.key_id] = public_key_bytes
        return verifier.key_id

    def add_key_b64url(self, s: str) -> str:
        return self.add_key(_b64url_decode(s))

    def get(self, key_id: str) -> Optional[bytes]:
        return self._keys.get(key_id)


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


def _required_roles(manifest: WeightCustodyManifest) -> list[SignatureRole]:
    roles = [SignatureRole.builder, SignatureRole.custodian]
    if manifest.release_policy.sovereign_profile.enabled:
        roles.append(SignatureRole.sovereign)
    return roles


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
        pub = context.get(sig.key_id)
        if pub is None:
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
        try:
            Ed25519Verifier(pub).verify(unsigned, sig.signature_value)
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
    )
