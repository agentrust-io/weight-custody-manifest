"""End-to-end Weight Custody Manifest flow on an OPEN-weight model.

Run it:

    python examples/open_model_e2e.py

Everything here is real WCM code with a **software (mock) attestation provider**,
so it runs anywhere with no hardware. The point is to show how the whole flow
fits together, and to be honest about what each step is actually doing when the
base model is public.

The reframe that drives this demo
---------------------------------
For a closed frontier model the job is secrecy: don't let the weights leak. For
an OPEN-weight model (Llama, Mistral, SmolLM, ...) the base weights are already
downloadable, so encrypting them and gating decryption behind attestation
protects nothing - anyone can just download the same checkpoint. Saying that
plainly matters. What the same six-step machinery still does, and why you'd run
it anyway:

  * Integrity / provenance - prove you are running exactly the certified
    checkpoint and serving stack, unmodified, not a silently tampered fork.
  * License / field-of-use - make the model's license a technical release
    condition, not just contract text.
  * Derivative custody - the fine-tune trained on your proprietary data is real,
    novel IP that never existed publicly. THIS is what you're protecting.
  * A kill switch - now triggered by a safety recall or license violation, not
    by "we detected theft".

For a fully-public base, the base's own confidentiality is theater; this demo
labels it as such and puts the derivative at the center.
"""
from __future__ import annotations

import hashlib

from wcm import (
    EnclaveSession,
    KeyBrokerService,
    KeyWipedError,
    SoftwareProvider,
    VerificationContext,
    WeightCustodyManifest,
    generate_ed25519,
    Ed25519Signer,
    is_root,
    verify_lineage,
    verify_manifest,
)


def rule(title: str) -> None:
    print(f"\n{'=' * 70}\n{title}\n{'=' * 70}")


def sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def build_manifest(
    *,
    weights_hash: str,
    license_text: str,
    serving_measurement: str,
    builder_id: str,
    custodian_id: str,
    derivatives: str,
    derived_from: str | None = None,
    rights_holder: dict | None = None,
) -> dict:
    """Assemble a manifest document (the Layer 1 artifact)."""
    m: dict = {
        "manifest_version": "0.1",
        "weights_hash": weights_hash,
        "builder": {"identity": builder_id, "signing_key": "ed25519:demo"},
        "release_terms": {
            "license": license_text,
            "permitted_derivatives": "fine-tune-only",
            "derivatives": derivatives,  # machine-checkable (none|fine-tune-only|unrestricted)
            "permitted_environments": ["enterprise-governed-enclave"],
        },
        "release_policy": {
            "required_assurance_tier": "hardware-attested",
            "trusted_time_source": "secure-tsc",
            "required_hw_platform": ["amd-sev-snp", "nvidia-cc-gpu"],
            "required_gpu_measurement": {"rim_pin": "nvidia-rim:demo-golden"},
            "required_serving_image": {
                "signer": "ed25519:demo",
                "release_rule": "prefer-current",
                "accepted_measurements": [
                    {"measurement": serving_measurement, "status": "current"}
                ],
            },
            "attestation_revocation_check": "live-per-release, max-cache-age: short-window",
            "revocation_authority": "builder-and-opaque-joint",
        },
        "custody": {
            "custodian": custodian_id,
            "custodian_type": "customer-self-custody",
            "kbs_image": {"measurement": sha256(b"reference-kbs-image"), "signer": "ed25519:demo"},
            "enclave_id": "did:example:enterprise-enclave-01",
            "attestation_cadence": "1h",
        },
    }
    if derived_from is not None:
        m["derived_from"] = derived_from
    if rights_holder is not None:
        m["rights_holder"] = rights_holder
    return m


def sign(manifest: WeightCustodyManifest, keypair, role: str, signer: str) -> dict:
    return Ed25519Signer(keypair).sign(manifest.unsigned_dict(), role=role, signer=signer)


def main() -> None:
    # In the open-weight case the "builder" and "custodian" collapse into the
    # enterprise's own model-governance function (the symmetric BYOM case,
    # design principle 4). It certifies which checkpoint + serving stack are
    # approved internally, and it runs them. We model that with two keys held by
    # the same governance org.
    gov_builder = generate_ed25519()
    gov_custodian = generate_ed25519()

    rule("Open-weight model: base weights are PUBLIC")
    # Pretend this blob is a downloaded checkpoint (in reality: your
    # Llama-3.1 / Mistral / SmolLM safetensors). We hash the real bytes.
    checkpoint = b"<the bytes of a public open-weight checkpoint>"
    base_hash = sha256(checkpoint)
    serving = sha256(b"vllm-0.6.3 + policy-bundle-v2 (the certified serving stack)")
    print("base weights_hash :", base_hash)
    print("license           : Llama-3.1-Community (usage + scale restrictions)")
    print("NOTE: encrypting a *public* base protects nothing. The mechanism below")
    print("      does INTEGRITY + LICENSE work here, not secrecy.")

    # ---- Step 0: certify the base checkpoint (integrity + license) ----------
    rule("Step 0 - Certify the base: manifest (integrity + license), jointly signed")
    base_doc = build_manifest(
        weights_hash=base_hash,
        license_text="Llama-3.1-Community",
        serving_measurement=serving,
        builder_id="acme-model-governance",
        custodian_id="acme-model-governance",
        derivatives="fine-tune-only",
    )
    base = WeightCustodyManifest.model_validate(base_doc)
    base = base.with_signatures([
        sign(base, gov_builder, "builder", "acme-model-governance"),
        sign(base, gov_custodian, "custodian", "acme-model-governance"),
    ])
    print("manifest binds: weights_hash, the certified serving image, and the license.")
    print("signed jointly by the governance function as builder + custodian.")

    # ---- Step 1: verify the manifest (provenance) ---------------------------
    rule("Step 1 - Verify the manifest (is this the certified checkpoint?)")
    ctx = VerificationContext()
    ctx.add_key(gov_builder.public_bytes)
    ctx.add_key(gov_custodian.public_bytes)
    result = verify_manifest(base, ctx)
    print("manifest signature valid:", result.ok, "  (integrity, not secrecy)")

    # ---- Step 2: attestation-gated load -------------------------------------
    rule("Step 2 - Attestation gate: only load the CERTIFIED serving stack")
    kbs = KeyBrokerService({base.weights_hash: b"loading-key-protects-no-secret-here"})
    challenge = kbs.issue_challenge()
    evidence = SoftwareProvider().produce(  # a REAL enclave would produce a hardware quote
        challenge,
        serving_image_measurement=serving,
        gpu_measurement="nvidia-rim:demo-golden",
    )
    decision = kbs.verify_and_release(base, evidence)
    print("gate released:", decision.released)
    print("what the gate enforced: genuine attestation nonce, the approved platform,")
    print("and a serving-image measurement matching what governance signed - so a")
    print("silently modified fork of the public weights would NOT load.")

    # ---- Step 3: runtime custody (the kill switch) --------------------------
    rule("Step 3 - Wipe-on-lapse custody (kill switch: recall / license violation)")
    session = EnclaveSession.from_release(base, decision)
    session.use_key()
    print("serving under a 1h cadence; time_floor =", session.time_floor.value)
    print("kill-switch reason has shifted: not 'theft detected' but a safety recall,")
    print("a license breach, or governance pulling a misbehaving checkpoint.")

    # ---- Step 4: license / field-of-use (technical checkpoint) --------------
    rule("Step 4 - License is a technical release condition, not just contract text")
    print("release_terms.license =", base.release_terms.license)
    print("the environment is only marked releasable under the disclosed,")
    print("license-conforming configuration bound into the signed manifest.")

    # ---- Step 5: fine-tune -> the DERIVATIVE is the real asset ---------------
    rule("Step 5 - Fine-tune on proprietary data: the derivative is novel IP")
    derivative_weights = checkpoint + b"<+ acme proprietary trading-desk fine-tune>"
    deriv_hash = sha256(derivative_weights)
    deriv_doc = build_manifest(
        weights_hash=deriv_hash,
        license_text="Llama-3.1-Community + Acme-proprietary-derivative",
        serving_measurement=serving,
        builder_id="acme-model-governance",
        custodian_id="acme-model-governance",
        derivatives="none",  # Acme does not permit derivatives OF its derivative
        derived_from=base.weights_hash,
        rights_holder={"base": "meta", "derivative": "acme"},
    )
    deriv = WeightCustodyManifest.model_validate(deriv_doc)
    deriv = deriv.with_signatures([
        sign(deriv, gov_builder, "builder", "acme-model-governance"),
        sign(deriv, gov_custodian, "custodian", "acme-model-governance"),
    ])
    print("derivative weights_hash:", deriv_hash)
    print("derived_from           :", deriv.derived_from)
    print("rights_holder          :", {"base": deriv.rights_holder.base, "derivative": deriv.rights_holder.derivative})
    print("THIS never existed publicly. It is the whole reason to run the stack.")

    # ---- Step 6: lineage + revocation on the derivative ---------------------
    rule("Step 6 - Verify lineage (derivative -> public base root)")
    manifests = {base.weights_hash: base, deriv.weights_hash: deriv}
    lineage = verify_lineage(manifests, deriv.weights_hash)
    print("lineage ok :", lineage.ok)
    print("chain      :", " -> ".join(h.split(':')[1][:12] + '...' for h in lineage.chain))
    print("depth      :", lineage.depth, " root is a base manifest:", is_root(base))

    rule("What was doing real work")
    print("moot for a public base : encrypt-at-rest secrecy of the base weights")
    print("real work              : integrity/provenance (0,1,2), license (0,4),")
    print("                         derivative custody + lineage (5,6), kill switch (3)")
    print("\nSame six steps as the closed-model flow; the purpose of half of them flipped.")


if __name__ == "__main__":
    main()
