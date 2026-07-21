"""Sovereign self-custody with threshold split-key release (SPEC 3.5, decision 15).

    python examples/sovereign_self_custody.py

Everything here is real WCM code with a software (mock) attestation provider, so
it runs anywhere with no hardware.

The problem this solves
-----------------------
A sovereign runs the model in its own jurisdiction, on hardware it owns, and
operates the key release service (KBS) itself. That is the hostile-owner
posture: the owner can forge its own KBS attestation quote (open question 8.8,
key-extraction half). Single-key self-custody is therefore unsound for a
sovereign, because one forged quote would self-release the key.

Decision 15's answer is threshold split-key release: the key is split so that no
single party, the sovereign included, holds it. The attested KBS enclave
reconstructs the key only from a quorum of shares contributed by independent
parties. One forged quote is then not enough, because it still yields only one
share. This demo shows that end to end with a 2-of-3 split across the builder,
the sovereign, and the custodian.

What is real vs modelled here: the split, the reconstruction, the attestation
gate, and the manifest's sovereign quorum are all real SDK code. The share
contribution "into the attested enclave" is narrated, not sandboxed; a real
deployment runs the combine inside the measured KBS enclave so no party sees the
assembled key.
"""
from __future__ import annotations

import hashlib

from wcm import (
    Ed25519Signer,
    KeyBrokerService,
    SoftwareProvider,
    VerificationContext,
    WeightCustodyManifest,
    combine_shares,
    generate_ed25519,
    split_secret,
    verify_manifest,
)


def rule(title: str) -> None:
    print(f"\n{'=' * 70}\n{title}\n{'=' * 70}")


def sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def main() -> int:
    # Three independent parties. In a sovereign deployment none of them may hold
    # the whole key on its own.
    builder_kp, custodian_kp, sovereign_kp = (
        generate_ed25519(),
        generate_ed25519(),
        generate_ed25519(),
    )
    serving = sha256(b"builder-signed serving stack, measured")
    weights_hash = sha256(b"the frontier weights")

    # ---- Step 0: the sovereign self-custody manifest ------------------------
    rule("Step 0 - Sovereign manifest (quorum revocation, self-custody, hardened)")
    doc = {
        "manifest_version": "0.1",
        "weights_hash": weights_hash,
        "builder": {"identity": "frontier-lab", "signing_key": "ed25519:builder"},
        "release_terms": {
            "license": "sovereign-deployment-agreement",
            "permitted_derivatives": "none",
            "permitted_environments": ["sovereign-attested-enclave"],
        },
        "release_policy": {
            "required_assurance_tier": "hardware-attested",
            # Hostile-owner posture: physical hardening and the memory-fingerprint
            # challenge are mandatory here (SPEC 3.5, 3.6).
            "physical_hardening": "tamper-evident-enclosure+access-control+chain-of-custody",
            "memory_fingerprint_challenge": "required-for-hostile-owner-posture",
            "trusted_time_source": "secure-tsc",
            "required_hw_platform": ["amd-sev-snp", "nvidia-cc-gpu"],
            "required_gpu_measurement": {"rim_pin": "nvidia-rim:demo-golden"},
            "required_serving_image": {
                "signer": "ed25519:builder",
                "release_rule": "prefer-current",
                "accepted_measurements": [{"measurement": serving, "status": "current"}],
            },
            "attestation_revocation_check": "live-per-release, max-cache-age: short-window",
            # Sovereign profile: revocation is quorum-only, no unilateral kill.
            "revocation_authority": "quorum",
            "sovereign_profile": {
                "enabled": True,
                "revocation_authority": "quorum",
                "sovereign_signer": "sovereign-security-team",
            },
        },
        "custody": {
            "custodian": "sovereign-national-ai",
            "custodian_type": "customer-self-custody",
            "kbs_image": {"measurement": sha256(b"builder-signed KBS image"), "signer": "ed25519:builder"},
            "enclave_id": "did:sovereign:kbs-enclave-01",
            "attestation_cadence": "1h",
        },
    }
    manifest = WeightCustodyManifest.model_validate(doc)
    manifest = manifest.with_signatures([
        Ed25519Signer(builder_kp).sign(manifest.unsigned_dict(), role="builder", signer="frontier-lab"),
        Ed25519Signer(custodian_kp).sign(manifest.unsigned_dict(), role="custodian", signer="sovereign-national-ai"),
        Ed25519Signer(sovereign_kp).sign(manifest.unsigned_dict(), role="sovereign", signer="sovereign-security-team"),
    ])
    print("sovereign_profile.enabled :", manifest.release_policy.sovereign_profile.enabled)
    print("custodian_type            :", manifest.custody.custodian_type.value)
    print("signed by                 : builder + custodian + sovereign (quorum)")

    # ---- Step 1: verify the manifest (the sovereign quorum must be present) --
    rule("Step 1 - Verify the manifest (sovereign quorum required)")
    ctx = VerificationContext()
    for kp in (builder_kp, custodian_kp, sovereign_kp):
        ctx.add_key(kp.public_bytes)
    result = verify_manifest(manifest, ctx)
    print("manifest valid            :", result.ok)
    if not result.ok:
        print("errors:", result.errors, "missing:", result.missing_roles)
        return 1

    # ---- Step 2: split the key so no single party holds it ------------------
    rule("Step 2 - Split the decryption key 2-of-3 (builder, sovereign, custodian)")
    key = hashlib.sha256(b"the weights decryption key").digest()
    shares = split_secret(key, threshold=2, shares=3)
    builder_share, sovereign_share, custodian_share = shares
    print("key split into            : 3 shares, any 2 reconstruct")
    print("no single party holds the key. Each holds one share.")

    # ---- Step 3: the attested self-custody KBS authorizes release -----------
    rule("Step 3 - Attested KBS gate (parties verify the enclave before sharing)")
    # The self-custody KBS holds NO weight key (empty entry): the gate proves the
    # enclave is the builder-measured release coordinator; the key comes from the
    # quorum, not from the KBS.
    kbs = KeyBrokerService({weights_hash: b""})
    challenge = kbs.issue_challenge()
    evidence = SoftwareProvider().produce(
        challenge,
        serving_image_measurement=serving,
        gpu_measurement="nvidia-rim:demo-golden",
        include_memory_fingerprint=True,  # mandatory in the hostile-owner posture
    )
    decision = kbs.verify_and_release(manifest, evidence)
    print("attestation gate passed   :", decision.released)
    if not decision.released:
        for c in decision.failures():
            print("  failed:", c.name, "-", c.detail)
        return 1
    print("each party checks this attestation before contributing its share.")

    # ---- Step 4: a quorum reconstructs the key inside the enclave -----------
    rule("Step 4 - Quorum contributes shares; enclave reconstructs the key")
    reconstructed = combine_shares([builder_share, sovereign_share])
    print("builder + sovereign -> key matches :", reconstructed == key)
    # Any two shares work (fault tolerance): losing one party does not lose the key.
    print("builder + custodian -> key matches :", combine_shares([builder_share, custodian_share]) == key)

    # ---- Step 5: one party (and one forged quote) is not enough -------------
    rule("Step 5 - The decision-15 property: a single forged quote cannot release")
    sovereign_alone = combine_shares([sovereign_share])
    print("sovereign's single share -> key    :", sovereign_alone == key, " (cannot reconstruct)")
    print("even if the sovereign forges its own KBS quote (open 8.8), it still holds")
    print("only one share, so one forged quote does not assemble the key. It needs a")
    print("quorum that includes an independent party. That is why threshold is a")
    print("PREREQUISITE for sovereign self-custody, not an optional hardening.")

    # ---- Step 6: what carries the guarantee here ----------------------------
    rule("What carries the guarantee (and what does not)")
    print("carries it : threshold (no single party assembles the key), the sovereign")
    print("             revocation quorum, mandatory physical hardening, transparency log.")
    print("does NOT   : wipe-on-lapse is not an independent floor against a hardware")
    print("             owner who can forge attestation (SPEC 3.5). The bound is the")
    print("             quorum and the hardening, not enclave-resident timing.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
