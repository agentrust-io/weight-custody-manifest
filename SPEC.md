# Weight Custody Manifest (WCM)
### An Open Specification for Protecting Model Weights in Customer-Controlled Infrastructure
*Working draft, v0.5. Open specification, pre-1.0. Subject to change and NOT ready to build against yet; read the open questions (section 8) before relying on anything here. The operated custody service and enclave implementation are separate and proprietary; this repository is the open protocol layer only.*

> Renamed from "Model Manifest" in v0.2. The artifact governs weight release and custody, not model identity or capability, so the name now says that. "Model Passport" and the "Model *" naming space are left to Harbor. See section 4.

---

## 1. The Setup: The Trust Direction Nobody Solved

Opaque's platform, as of 3.0, solves a specific and well-understood problem: protecting a customer's data from the operator of the model that touches it. Confidential computing, verifiable agent identity, and the cMCP gateway all point the same direction. The enterprise is the vulnerable party, the model operator is the party being constrained, and the customer needs proof the constraint is real.

Deploy a frontier model into a customer's own infrastructure, on prem, inside a sovereign cloud, behind an air gap, and the vulnerable party flips. Now it is the model builder whose IP is exposed. Once weights leave the builder's boundary, the builder has to trust the customer's hardware, hypervisor, and operations staff not to extract the weights, copy them, fine tune and leak a derivative, or reverse engineer proprietary architecture choices out of the artifact itself. Today there is no attestation gated mechanism that says "release these weights only into this specific verified enclave, under this specific policy," and no way to revoke that release if the environment is later found compromised.

This is a forward-looking design. It targets the builder-into-customer-infrastructure case: a frontier lab whose weights need protecting the moment a custodian's infrastructure sits between those weights and a customer's own hardware. It is written ahead of that need, not against any specific deployment.

**This is where Opaque 3.0 stops, and where this document starts.**

Weight Custody Manifest is the second half of the trust boundary Opaque already owns one side of. Where the existing platform proves to the customer what the model operator did, Weight Custody Manifest proves to the model builder what the customer's infrastructure will and will not do with the weights it is trusted with.

---

## 2. Design Principles

Five principles, and unlike an open federated protocol, all five are allowed to be opinionated in Opaque's favor, because this is commercial infrastructure, not a public standard.

1. **Custody, not just visibility.** A guarantee that only observes misuse after the fact is not sufficient for an asset as valuable as frontier weights. Against every *software* adversary the weights are never in a form the customer's infrastructure can act on outside the enclave: encrypted at rest, decrypted only inside attested memory, and inaccessible to the host OS, hypervisor, or a software-privileged operator by construction. Against a *physical* operator who owns the hardware, current confidential-GPU silicon does not deliver this by construction (the honest scope is in section 3.6); there, custody degrades to raising the cost of extraction, detecting and attributing it, containing the window through revocation, and legal recourse, with a physical-hardening tier that is mandatory when the operator itself is the adversary (section 3.6).
2. **Enforced at the point of release, not the point of detection.** The strongest control is the one exercised before the key is handed over, not the one that notices theft afterward. Attestation gated key release is the anchor primitive everything else in this document hangs off.
3. **Revocable, always.** Every grant of access has a corresponding way to take it back, and the ability to revoke cannot depend on the customer's cooperation. If an environment's attestation posture changes, degrades, or is later found compromised, decrypt access stops without needing the customer's infrastructure to agree.
4. **Symmetric with the platform, not bolted onto it.** Opaque already runs a confidential compute control plane for the customer facing direction. Weight Custody Manifest is the same control plane, same enclave primitives, same cMCP gateway, exercised for the opposite party. A customer bringing their own model into that environment (BYOM) and a builder placing a model into that environment should be the same underlying mechanism with the roles reversed, not two separate products.
5. **Custodian is a role, not necessarily Opaque.** Opaque is the default and reference custodian, but the architecture leaves room for a customer's own infrastructure to act as custodian without Opaque in the loop, provided it meets the same attestation bar. This matters for sovereign customers who will not accept a third party, even a trusted one, sitting permanently in the key release path. The protocol, not the operator, is the thing being trusted.

---

## 3. Reference Architecture

Four layers, deliberately mirroring the shape of the platform's existing customer facing side, because the same primitives, run in the other direction, are the whole point.

```
+-----------------------------------------------------------+
|  Layer 4 - Derivative Lineage & Compliance Mapping         |
|  (fine-tune tracking, IP chain of custody, RATS/EAT, NIST) |
+-------------------------------------------------------------+
|  Layer 3 - Runtime Custody & Extraction Defense            |
|  (kill switch, exfiltration monitoring, resource ceilings)  |
+-------------------------------------------------------------+
|  Layer 2 - Attestation-Gated Key Release                    |
|  (enclave verification, policy co-governance, revocation)   |
+-------------------------------------------------------------+
|  Layer 1 - Weight Custody Manifest                                   |
|  (signed weight identity, license terms, release policy)    |
+-------------------------------------------------------------+
              ^                                    ^
        Model builder                       Customer enclave
    (any frontier lab or vendor)       (any sovereign or enterprise env)
```

### 3.1 Layer 1: The Weight Custody Manifest

Before any weights move, the builder issues a signed manifest describing exactly what is being released and under what terms. This is the artifact this document is named for, and it is the one piece of this architecture built to also serve as the customer facing evidence of what was released, in case of audit or dispute.

```json
{
  "manifest_version": "0.1",
  "weights_hash": "sha256:4a1c...9b02",
  "builder": {
    "identity": "example-builder",
    "signing_key": "ed25519:builder-key..."
  },
  "release_terms": {
    "license": "customer-deployment-agreement-ref:CDA-2026-0091",
    "permitted_derivatives": "fine-tune-only, no re-export of base weights",
    "permitted_environments": ["opaque-cmcp-attested-enclave"],
    "jurisdiction_restriction": "US, EU"
  },
  "release_policy": {
    "required_assurance_tier": "hardware-attested",
    "physical_hardening": "not-required | tamper-evident-enclosure+access-control+chain-of-custody",
    "required_hw_platform": ["amd-sev-snp", "nvidia-cc-gpu"],
    "tenancy": "shared",
    "required_serving_image": {
      "signer": "ed25519:builder-key...",
      "accepted_measurements": [
        { "measurement": "sha256:serving-stack-v2...", "status": "current" },
        { "measurement": "sha256:serving-stack-v1...", "status": "retiring", "retire_after": "2026-07-16T00:00:00Z" }
      ],
      "note": "key decrypts only under a builder-signed serving stack whose measurement is in this set; a patch adds a measurement and retires the prior one on a window, so patching does not re-issue every live manifest"
    },
    "key_release_mode": "attestation-gated",
    "replay_protection": "kbs-nonce-required",
    "revocation_authority": "builder-and-opaque-joint",
    "sovereign_profile": {
      "enabled": false,
      "revocation_authority": "quorum",
      "sovereign_signer": "required",
      "note": "when enabled, no single party (builder included) can revoke or dark the model unilaterally"
    }
  },
  "custody": {
    "custodian": "opaque-systems",
    "custodian_type": "opaque-hosted | customer-self-custody",
    "kbs_image": {
      "measurement": "sha256:kbs-release-logic...",
      "signer": "ed25519:opaque-key...",
      "note": "the key release service runs in an attested enclave in EVERY profile, Opaque-hosted included, so even an Opaque insider cannot alter release logic without failing this measurement"
    },
    "enclave_id": "did:opaque:example-enclave-04",
    "attestation_cadence": "24h",
    "kbs_attestation_cadence": "24h (anchor: >= inference cadence; short-inference sovereign deployments set this much longer than their inference cadence, see 3.5)"
  },
  "signatures": [
    { "role": "builder", "signer": "example-builder", "sig": "base64:..." },
    { "role": "custodian", "signer": "opaque-systems", "sig": "base64:..." }
  ]
}
```

Key design choices:

- **The manifest is signed jointly by the builder and the custodian, never by the customer alone.** The customer is the party being constrained by this document. Letting the constrained party co-sign its own constraint defeats the purpose. Opaque, as custodian, stands in the position TLS certificate authorities occupy for the web: a party both sides can point to.
- **`release_terms` is a legal artifact wearing a technical wrapper.** License, permitted derivatives, and jurisdiction restriction map directly onto the deployment agreement's actual contract language, so the manifest is the enforceable, machine checkable version of terms legal already negotiated, not a parallel policy invented by engineering.
- **`required_assurance_tier` is not optional the way it is in an open protocol.** Weight Custody Manifest has exactly one baseline tier for anything above a pilot: hardware attested. Claim-only assurance, sufficient for Harbor's hobbyist self-hoster, is not sufficient for frontier weights. There is no lower tier to fall back to. Above the baseline, the `physical_hardening` tier adds tamper-evident or tamper-responsive enclosure, physical access control, and supply-chain chain-of-custody. It is optional in the semi-trusted default posture, where the silicon holds in practice, and mandatory in the hostile-owner posture, where it is the only technical defense against the memory-bus attack class that defeats the CPU CVM and forges attestation (section 3.6).
- **`revocation_authority` is joint by default, with a unilateral emergency override.** The builder alone should not be able to revoke mid contract without recourse, and the custodian alone should not be able to keep serving weights the builder has flagged. Joint authority is the standard path. Either party can also trigger an immediate unilateral emergency revocation outside that path, with mandatory joint reconciliation afterward. See section 3.2 for how that works in practice.
- **`custodian_type` is not locked to Opaque.** The default and reference implementation is Opaque hosted, but a customer's own infrastructure can act as custodian if it meets the same hardware attestation bar as `required_assurance_tier`. Opaque is trusted as the reference implementation and, in the Opaque-hosted case, as the operator of the key release service. It is not architecturally required to be a permanent third party in every deployment. Independent of who hosts it, the key release service itself runs inside an attested enclave in every profile (`custody.kbs_image`), so the release logic is measured and cannot be altered even by an Opaque insider with infrastructure access. Self-custody differs only in who operates that attested enclave, not in whether it is attested (section 3.5).
- **`required_serving_image` is the control that actually protects the weights, and it is builder-signed.** Attestation-gated release protects the decryption *key*. The asset is the decrypted weights in enclave memory, and whoever supplies the code running inside the enclave can read them. So the party that gets to read the weights is the party that signs the serving stack, and in this architecture that party is the builder, not the customer and not Opaque. The key decrypts only under a serving image whose measurement matches the builder's signature, which is why "no raw weight export path" (Layer 3) can be a real property rather than a policy promise. The consequence is deliberate and worth stating plainly: the customer, including a sovereign customer, runs builder-signed code inside its own environment. The customer's leverage is not authorship of that code but the ability to read its measurement out of the attestation quote and refuse the deployment if it does not match what was disclosed, plus the revocation veto below. This is the one place the architecture asks the customer to accept opacity, and it is the price of the guarantee being enforceable in silicon instead of on paper. Patching is handled by `accepted_measurements`: the builder keeps a small set of currently-valid serving-image measurements and retires old ones on a window, so a security patch to the serving stack adds a measurement rather than invalidating every live manifest and forcing a fleet-wide re-issuance.
- **`tenancy` is an opt-in dedicated-hardware control.** The default is `shared`. A high-value deployment can set `dedicated`, forbidding co-located workloads on the same physical host. This is the operational mitigation for the side-channel residual (cache, timing, and contention attacks on shared silicon) that hardware confidentiality does not fully close, documented as ADV-6 in the threat model. It is opt-in because it trades cost and hardware flexibility for that margin, and not every deployment needs it.
- **`sovereign_profile` binds revocation to a quorum.** In the default (non-sovereign) profile, either party can trigger a unilateral emergency revocation (see section 3.2). That is unacceptable in a sovereign deployment: a foreign builder holding an own-signature kill switch over a model running inside a sovereign jurisdiction is exactly the dependency sovereign programs exist to remove. With `sovereign_profile.enabled`, revocation requires a quorum that includes the sovereign signer, so no single foreign party can dark the model. The tradeoff is that emergency revocation is slower, which is why the wipe-on-lapse behavior in section 3.2 matters most in this profile: even without a fast kill switch, the key zeroizes on its own if attestation cannot be renewed.

### 3.2 Layer 2: Attestation-Gated Key Release

This is the handshake, run in the opposite direction from Harbor's. Harbor has a caller verifying a model before sending it data. Here, the builder (or Opaque acting on the builder's behalf) verifies the customer's enclave before releasing a decryption key.

**Flow:**

1. The enclave requests release. The key release service replies with a fresh, single-use challenge (nonce). This binds the coming quote to this exchange and this instant, so a quote captured on the wire cannot be replayed later to obtain a key.
2. The customer's enclave produces a hardware attestation quote (RATS/EAT format) over that nonce, proving its own integrity: the exact firmware, kernel, confidential VM measurements, and running serving-image measurement.
3. The key release service verifies the quote: the nonce is the one it issued and is unexpired, the hardware is genuine, and the measurements satisfy `required_hw_platform`, `required_assurance_tier`, and `required_serving_image.accepted_measurements`. The release service itself runs in an attested enclave (`custody.kbs_image`), in every profile, so this verification logic is measured and cannot be quietly altered by whoever operates the KBS.
4. If verification passes, the decryption key for that specific `weights_hash` is released into the enclave and never persists outside it. The host OS, hypervisor, and any Opaque staff with infrastructure access cannot observe the key or the decrypted weights.
5. The enclave holds the key only for the attestation cadence window declared in the manifest (mirroring a session TTL). Before that window lapses, the enclave must re-attest, the same as Layer 1's re-signing. If re-attestation does not succeed before the window closes, the enclave zeroizes the key from its own memory and halts inference (see wipe-on-lapse below). The key is not "suspended pending renewal"; it is gone, and a fresh release requires a fresh successful attestation.

**The gate is only as sound as attestation is unforgeable.** Every step above assumes the quote the KBS verifies is genuine. That assumption holds against a remote or software adversary and, in practice, against a semi-trusted operator. It does *not* hold against a hostile hardware owner: TEE.fail / BadRAM-class attacks forge quotes that pass verification at the highest trust level (section 3.6), so in that posture the KBS cannot distinguish a forged environment from a real one by verification alone. This is why the hostile-owner posture requires the physical-hardening tier, and why detecting a forged quote at the gate is called out as an unresolved residual (open question 8.8). In the semi-trusted default posture, the gate is sound.

**Failure paths:**

| Failure | Default behavior |
|---|---|
| No attestation quote produced | Hard fail. No manifest speaks to an unattested environment, no exceptions. |
| Quote does not carry the current challenge nonce, or the nonce is expired or reused | Hard fail. Blocks a network adversary from replaying a previously valid quote to obtain a key. |
| Quote fails hardware measurement check | Hard fail. Key is never released. |
| Quote valid, but platform not in `required_hw_platform` | Hard fail. This is a policy the builder set, not one Opaque can override on the customer's behalf. |
| Quote valid, but serving-image measurement not in `required_serving_image.accepted_measurements` (or past its `retire_after`) | Hard fail. Key is never released. This stops the customer from swapping in a stack that could read weights out of memory, while the accepted set lets the builder roll a patched image without re-issuing every live manifest. |
| Attestation cadence lapses without re-attestation | Key is zeroized from inside the enclave and inference halts. Not "suspended," gone. A fresh successful attestation re-releases a new key; there is nothing to reinstate. |
| Revocation entry issued (default profile, builder+custodian joint signature) | Hard fail, immediate, no grace period, no policy override. |
| Unilateral emergency revocation triggered by either party alone (default profile only) | Hard fail, immediate. Access is suspended on the single signature without waiting for the other party's co-signature. Disabled under `sovereign_profile`. |
| Revocation under `sovereign_profile` | Requires the quorum defined in the profile, including the sovereign signer. No single party, builder included, can revoke alone. The wipe-on-lapse path still applies independently of quorum. |
| Customer's infrastructure changes underlying hardware or region | Manifest's `enclave_id` no longer matches. Treated as a new environment, requiring a fresh manifest issuance and fresh attestation, not an automatic transfer. |

**Wipe-on-lapse is the revocation floor.** The two revocation paths below depend on a signal reaching the enclave, and a customer who has compromised the host can try to keep serving by partitioning the enclave from the key release service so no revocation ever arrives. Wipe-on-lapse removes that as an option. The enclave will not serve past its cadence window without a fresh successful attestation, and if that attestation does not happen, the enclave zeroizes the key from its own memory. So the worst-case time from a decision to cut off weights to weights actually being unusable is bounded by the cadence window, whether or not any revocation signal gets through, and whether or not the customer cooperates. This is what makes Principle 3 ("revocable, always") true against a hostile host rather than only against a cooperative one. It also makes `attestation_cadence` a security parameter, not a convenience setting: a 24 hour cadence means a 24 hour worst-case exposure window, and a high-risk deployment should set it in minutes and accept that a network partition then becomes an outage by design.

**Unilateral emergency revocation (default profile only).** Joint signature revocation assumes both parties can be reached and agree, which is a reasonable assumption for a planned wind down and a bad one for an active incident. In the default (non-sovereign) profile, either the builder or the custodian can trigger an immediate unilateral revocation on their own signature alone. Key access stops the moment that single signature is verified, no waiting on the other party. The revocation is provisional: within a fixed reconciliation window (24 hours, see open question 8.1), both parties review the incident and either confirm the revocation as permanent or, if it turns out to have been a false alarm, jointly reinstate access under a fresh manifest. The unilateral path exists specifically so that "can we reach each other fast enough" is never the bottleneck between a discovered compromise and weights actually going dark. This path is disabled under `sovereign_profile`; there, the quorum is the only fast path, and wipe-on-lapse is the backstop when the quorum cannot be assembled in time.

**Multi-party policy co-governance and the sovereign profile.** For deployments where more than one stakeholder needs to sign off (a regulator, the customer's own security team, and the builder, for example in a sovereign deployment), the `release_policy` object supports an `additional_signers` array requiring a quorum before the manifest is valid. The `sovereign_profile` extends that quorum to revocation, not just release: with it enabled, the sovereign signer is required for any revocation, so no single foreign party can dark a model running in the sovereign's jurisdiction. This is the mechanism that lets a regulated sovereign deployment satisfy "no single party unilaterally controls the release or the kill decision" without inventing a separate approval workflow outside the manifest. The cost is that the builder gives up its own-signature kill switch in exchange for the sovereign deal, which is the right trade in that context precisely because wipe-on-lapse still guarantees the weights go dark on their own if attestation cannot be renewed.

### 3.3 Layer 3: Runtime Custody & Extraction Defense

Once weights are live inside the enclave, custody is an ongoing obligation, not a one time check.

- **Kill switch.** A revocation entry suspends key access for a `weights_hash`, and the enclave stops serving as soon as it receives the entry or, failing that, on its next cadence lapse. This is the same mechanism as Layer 2's revocation path, exercised at any point during the deployment's life, not only at re-attestation time. In the default profile either party can trigger it unilaterally; under `sovereign_profile` it needs the quorum. Either way the effective worst case is bounded by the cadence window through wipe-on-lapse, so "the customer partitioned the enclave so the revocation never arrived" does not buy the customer more than one cadence window of continued serving.
- **Extraction and distillation defense, and its honest limit.** The enclave boundary enforces resource and rate ceilings on inference calls, and every call produces a signed, hash-chained audit receipt (reusing TRACE's receipt format rather than inventing a second one). Anomalous call patterns, high volume probing consistent with model stealing, are visible in the receipt stream without Opaque or the builder needing to see call content, the same privacy preserving pattern Harbor's Layer 3 uses for its own audit trail. What this does not fully solve is distillation by a customer whose legitimate production traffic is already high volume: a determined customer can train a student model from outputs generated entirely within its permitted rate envelope, and no ceiling that keeps production usable will stop that. Rate ceilings and receipts raise the cost and make gross theft visible; they do not make in-envelope distillation impossible, and this draft should not claim they do. Stronger distillation resistance (output watermarking, per-tenant response perturbation) is out of scope here and noted as follow up.
- **No raw weight *software* export path, and an honest limit against a physical operator.** Against every software adversary, the host OS, the hypervisor, a privileged operator with software access, and an Opaque insider, the enclave design makes it structurally impossible, not merely against policy, for decrypted weights to be written to customer storage, copied to another process, or transmitted off the enclave, provided `required_serving_image` is builder-signed and measured so the customer cannot substitute a stack that dumps memory (section 3.1). That much is real and enforced in silicon. The honest limit: current confidential-GPU hardware protects GPU-resident weights by *access-control firewalling*, not memory encryption, so weights sit in plaintext in HBM during compute, and NVIDIA explicitly excludes sophisticated physical attacks (decapsulation, on-package probing) from its threat model. A determined operator who owns the hardware is therefore not stopped by the silicon. Against that adversary WCM does not claim structural impossibility; it raises the cost and skill bar, makes extraction detectable and attributable through attestation and receipts, limits the value window through wipe-on-lapse and revocation, backs it with the manifest's legal terms, and offers the optional physical-hardening tier. The full scope statement is section 3.6. A software-policy violation here is unrecoverable the moment it happens, which is why the software path is closed in silicon rather than in policy.
- **Cost and resource governance.** Rate ceilings enforced at the serving boundary double as a defense against resource exhaustion and as an early signal for extraction attempts, reusing the same enforcement point as the ceiling above.

### 3.4 Layer 4: Derivative Lineage & Compliance Mapping

If the customer is permitted to fine tune inside the enclave (per `permitted_derivatives` in Layer 1), the resulting derivative weights need their own chain of custody back to the original manifest.

- **Derivative manifests.** A fine tune produces a new `weights_hash` with a `derived_from` field pointing at the parent manifest. The builder's IP claim over the base weights does not disappear because a derivative exists; `rights_holder` on the derivative manifest reflects whatever the deployment agreement specifies, commonly a split between builder IP in the base and customer IP in the fine tune data.
- **Compliance mapping.** Rather than inventing new audit language, Weight Custody Manifest artifacts map onto frameworks auditors already recognize:

| Weight Custody Manifest Artifact | Maps to |
|---|---|
| Layer 1 manifest | ML-BOM, NIST AI RMF "Map" function |
| Layer 2 attestation | IETF RATS (RFC 9334), EAT (RFC 9711) |
| Layer 3 audit receipts | SLSA-style provenance, applied to inference custody rather than build |
| Layer 4 derivative lineage | NIST AI RMF "Govern," export control and IP chain of custody documentation |

### 3.5 Self-Custody: The Attested Key Release Service

The default deployment has Opaque operating the key release service (KBS). A sovereign customer will often refuse a third party, even a trusted one, sitting permanently in the release path. The naive answer, "let the customer run the KBS," breaks the whole model: a customer who controls the KBS can release the key to itself and ignore the manifest. The builder would be trusting the customer's word, which is exactly the thing this architecture exists to replace.

First, a point that is broader than self-custody: **the KBS runs inside an attested enclave in every deployment, Opaque-hosted included.** Its release logic (`custody.kbs_image`) is measured and builder-verified, which closes the insider threat uniformly, an Opaque operator cannot alter release behavior without failing that measurement (threat model ADV-3). Self-custody then changes only *who operates* the attested enclave, not whether it is attested.

The reference design for self-custody applies the same primitive one level up, with the customer as the operator: **the customer runs the attested KBS enclave itself.**

- **Recursion that terminates at the builder's root of trust.** The KBS enclave image, the release logic and policy engine, is signed by the builder and has a known measurement. The builder verifies the KBS enclave's attestation quote the same way the KBS verifies the inference enclave's quote. So the chain is: the builder trusts hardware attestation, verifies the KBS measurement against a value it signed, and the KBS in turn verifies the inference enclave. It bottoms out at the hardware root of trust, not at anyone's promise. Two attested enclaves, both measured up to the builder.
- **What the customer gets.** It hosts the KBS on its own hardware, in its own jurisdiction. Opaque is not a permanent operator in the release path. Opaque's role narrows to authoring the reference KBS image and, optionally, co-signing the manifest, not running the service.
- **What the customer cannot do.** It cannot alter the measured release logic, cannot release the key against manifest policy, and cannot self-release, because any of those changes the KBS measurement and fails the builder's verification. The customer runs the service without controlling its behavior. This is the same verify-by-measurement-not-authorship bargain the serving image makes in section 3.1, now applied to the release path too.
- **Single key first, threshold as v2.** v1 is a single key: the attested KBS enclave is the sole release authority, chosen to get self-custody to market. The cost is honest, a vulnerability in the measured, builder-signed KBS logic is a single point of failure for release in v1. The mitigation is the same as for any enclave here, the release logic is deliberately small, measured, and revocable. Threshold split-key release (no single party, customer included, can assemble the key alone) is the planned v2 hardening, not built here and explicitly not a prerequisite for the first sovereign self-custody offer.
- **The KBS is the stable anchor, not the flakiest link.** The KBS re-attests on its own cadence, set deliberately longer and more conservative than the inference enclaves it feeds (illustratively 6h for the KBS against 15m for inference), so its normal re-attestation blips do not cascade into the fleet that depends on it. A degraded KBS still loses its own trust standing, and the inference enclaves still enforce their own short cadence and wipe-on-lapse independently, so the anchor being slower does not weaken the floor. See the cadence coupling note in section 8 for the reasoning.
- **Composes with the sovereign profile.** An attested self-custody KBS plus `sovereign_profile` gives the sovereign both properties it actually wants: no foreign party operates its release path, and no single foreign party can dark the model. Revocation still has to reach the KBS, and wipe-on-lapse in the inference enclave remains the floor underneath both, unchanged by who runs the KBS.

Two lighter alternatives were considered and rejected as standalone answers. An Opaque-authored appliance the customer hosts keeps Opaque as the logical release authority, so it does not actually satisfy the no-third-party-in-path requirement; it is at most a pragmatic interim offering before the attested KBS is built. A reproducibly-built KBS with a tamper-evident audit log is detect-not-prevent (a forked binary can still self-release, you just learn about it afterward), which contradicts Principle 1, so it is useful only as an audit supplement layered on top of attestation, never on its own.

### 3.6 Guarantee Scope: What the Silicon Does and Does Not Cover

This section states plainly what the hardware WCM runs on actually guarantees, so no downstream reader over-reads the custody claim. It is grounded in an adversarial assessment of NVIDIA Confidential Computing (H100/H200/Blackwell) and closes former open question 8.4.

**Custody-grade, silicon-enforced, against software and remote adversaries.** A host OS, hypervisor, cloud or software-privileged operator, remote attacker, or Opaque insider cannot read the decryption key or the decrypted weights. This holds by construction: SEV-SNP/TDX for the CPU CVM, NVIDIA CC firewalling for the GPU, an attested serving image, and an encrypted, replay-protected CPU-to-GPU channel (AES-GCM-256). This is the common commercial case, a managed or enterprise operator who will not physically attack the hardware, and for it the custody claim is true.

**Not custody-grade against a physical operator who owns the hardware.** NVIDIA CC protects GPU memory by access-control firewalling of a Compute Protected Region, not by encrypting HBM, so weights are plaintext in HBM during compute, and NVIDIA scopes sophisticated physical attacks out of its threat model. Confidentiality against a physical adversary rests on the assumption that on-package HBM resists common interposer tools, which is a design assumption, not a proof. For the on-prem and sovereign deployments WCM targets, where the customer owns the box, this is the adversary that matters most, and the silicon does not stop them.

**What WCM offers against the physical operator, in order:**
1. **Cost.** Extraction requires decapsulation or on-package probing, sophisticated-lab or nation-state effort, not a curious admin with software access.
2. **Detection and attribution.** Attestation state and hash-chained receipts make tampering and anomalous use visible and attributable.
3. **Containment.** Wipe-on-lapse and revocation cap the window in which extracted material stays useful and stop future release.
4. **Legal recourse.** The manifest is the machine-checkable expression of contract terms, so physical extraction is a provable breach.
5. **Optional physical hardening.** The `physical_hardening` tier requires tamper-evident or tamper-responsive enclosure, physical access control, and supply-chain custody, pushing the residual onto operational controls the deployment must meet and be audited against.

**The correction, stated honestly.** This is not a defeat of the architecture, it is a correction to the claim. Everything WCM does above the silicon (revocation, wipe-on-lapse, receipts, legal binding, physical hardening) matters *more* given the silicon floor is software-grade, not less. The dishonest version of this document would say "physically impossible." The honest version says: cryptographic custody against software theft, cost plus detection plus containment plus recourse against physical theft, with a hardening tier for those who need to narrow the gap.

**Two dependencies this assessment also surfaced:**
- **Attestation phone-home.** NVIDIA attestation depends on NVIDIA-signed RIM golden measurements and, by default, the NVIDIA-operated NRAS service. Air-gapped verification is feasible but requires pre-staged RIM/OCSP data and accepts possible staleness of revocation data. A sovereign deployment that tolerates no NVIDIA online dependency must provision this deliberately; treat it as a deployment requirement, not an afterthought.
- **CPU-CVM physical surface (assessed, and worse than the GPU case).** The follow-on assessment is in: physical memory-bus attacks defeat SEV-SNP and TDX today. TEE.fail (2025) is a sub-$1000, briefcase-portable DDR5 interposer that extracts keys from live SEV-SNP/TDX memory, including attestation keys, and forges attestation quotes that pass Intel's verifier at its highest trust level. BadRAM does the same to SEV-SNP attestation for about $10 plus one-time SPD access. The root cause is structural, deterministic unauthenticated full-DRAM encryption without freshness, so it is not fixable without new silicon. Two consequences for WCM, both severe against the operator-owns-the-box adversary WCM targets: (1) the decryption key in the CPU CVM is physically extractable, more cheaply than the GPU weights; (2) attestation itself can be forged, which undermines the anchor primitive, attestation-gated release (Principle 2), not just confidentiality. Software-only variants (CipherLeaks, Heracles) extract keys via ciphertext side channels from a malicious hypervisor with no physical access at all. This reaches the foundation of the scheme, so the positioning response is decisive, and it is resolved next.

**Positioning (resolved): custody is scoped to the operator-trust model.** WCM makes its custody claim against two clearly separated operator postures, not one, and never blends them:

- **Semi-trusted operator (default).** Opaque-hosted, reputable-cloud, or contract-bound enterprise deployments, where a briefcase bus-interposer attack on the operator's own datacenter is impractical, detectable, attributable, and a provable breach. Here the silicon guarantee holds in practice, and WCM is custody-grade against every adversary short of the operator physically attacking hardware they control. This is the default posture and the near-term commercial surface.
- **Hostile-owner operator (sovereign or on-prem bare metal), physical hardening mandatory.** Where the operator owns the bare metal and is themselves the adversary, the silicon does not hold, so this posture is supported **only** with the `physical_hardening` tier required, not optional: tamper-responsive memory enclosure that zeroizes on bus tamper, locked SPD, physical access control, and supply-chain custody. Hardening is the only concrete technical defense against the TEE.fail / BadRAM class, and even with it the honest claim is raise-cost plus detect plus contain plus legal, backed by hardening, not silicon-absolute custody. A hostile-owner deployment without the hardening tier is not offered.

The claim WCM never makes is silicon-enforced custody against a bare-metal owner with no physical hardening. That configuration is out of scope, deliberately.

---

## 4. Relationship to Adjacent Work

**Naming.** This document is the Weight Custody Manifest: it governs weight release and custody, not model identity, so the name says that. The "Model *" naming space, including how Harbor's Model Passport family evolves, is left to the Harbor and agentrust-io teams, with no dependency on this document.

**Relationship to Harbor.** Harbor's Model Passport answers "what is this model and is it safe to call." This document's manifest answers "who is allowed to hold a decryption key for this model and under what proof." They are not competitors; a Harbor passport could reference a Weight Custody Manifest as one of its attested inputs, the same way Harbor's own section 4 describes TRACE and Harbor cross referencing each other. WCM is open-core (next paragraph), so its spec layer is intended to sit alongside the agentrust-io open specs, not opposite them.

**Open-core, deliberately.** A custody guarantee that a frontier lab cannot audit is not trustworthy. A builder and a sovereign must be able to read exactly what is and is not claimed (section 3.6), and the 8.3 posture (reproducible builds plus independent third-party audit, trust the auditor not the vendor's word) cannot coexist with a secret spec. WCM is therefore open-core:
- **Open (destined for agentrust-io):** the protocol and manifest schema, the attestation and revocation semantics, the threat model, and the reproducibly-built reference KBS image that section 8.3 already requires to be independently auditable.
- **Proprietary (Opaque):** the operated custodian service and its key-release operation, the cMCP integration, and the enclave engineering on confidential-compute silicon.

The open layer is the protocol; the value of an implementation lies in operating a trustworthy attested custodian and in the quality of the enclave implementation, not in keeping the format secret. This mirrors the rest of the family (TRACE, cMCP, Agent Manifest, cA2A): open spec, independent implementations. **Publication is staged:** this specification is pre-1.0 and published for review and comment, not for production use, until the hostile-owner posture stabilizes (open question 8.8).

**Relationship to TRACE and cMCP.** Layer 3's audit receipt format reuses TRACE's hash chained receipt design rather than inventing a second one. Layer 2's attestation gated key release is the same enclave and attestation infrastructure cMCP already runs for the customer facing gateway, exercised in the opposite direction. This document is not a new product surface; it is the second face of infrastructure Opaque already operates.

---

## 5. Worked Example: End-to-End

A frontier lab (referred to here generically as "the builder") is deploying a model into a customer's confidential environment. The primary walk-through is the default profile. The sovereign delta follows.

**5.1 Default profile**

1. **Manifest issuance.** The builder signs a Layer 1 manifest for the specific fine tune being deployed: `weights_hash`, `release_terms` matching the signed deployment agreement, `required_assurance_tier` set to hardware attested, `required_serving_image` set to the builder's signed serving stack, `revocation_authority` joint, `attestation_cadence` at the 24 hour default. Opaque, as custodian, co-signs.
2. **Enclave provisioning.** The customer's confidential environment boots, produces its hardware attestation quote, and requests key release against the manifest's `weights_hash`.
3. **Key release.** Opaque's key release service verifies the quote against the manifest's policy, including that the running serving image is the builder-signed one. It passes. The decryption key is released directly into the attested enclave memory, never touching customer visible storage or Opaque's own operational staff.
4. **Normal operation.** Inference proceeds. Every call produces a signed audit receipt. On the 24 hour cadence the enclave re-attests automatically and access continues; if any re-attestation failed, the enclave would zeroize the key on its own within that window.
5. **Something goes wrong.** A security review finds a misconfiguration that could allow host level access to enclave memory under specific conditions. The builder does not wait to reach Opaque for a joint signature. It triggers a unilateral emergency revocation against the `weights_hash` on its own signature.
6. **Propagation, with a floor underneath it.** Key access is cut the moment that single signature verifies. If the compromised host tries to buy time by partitioning the enclave so the revocation never lands, it gains at most one cadence window: the key zeroizes on the next failed re-attestation regardless. Within the 24 hour reconciliation window, the builder and Opaque jointly confirm the revocation as permanent.
7. **Recovery.** The misconfiguration is fixed, the environment is re-attested from scratch, and a new manifest is issued referencing the revoked one for audit continuity. The prior key grant does not carry forward, matching Layer 2's design.

**5.2 Sovereign delta**

Same flow, three changes. The rest is identical.

- **Issuance.** `sovereign_profile.enabled` is true, with the sovereign's security team as a required quorum signer. `attestation_cadence` is set short, worked here at 1 hour, because in this profile the cadence is the revocation floor and the fast unilateral path is gone.
- **Provisioning.** Before allowing the enclave to come up, the sovereign's security team reads the `required_serving_image` measurement out of the manifest and confirms it matches the builder-disclosed stack. It cannot author that code, but it can verify the measurement and refuse the deployment. This is the whole of the sovereign's leverage over the runtime, and it is deliberately just verify-and-refuse, not authorship (section 3.1).
- **Revocation.** Step 5 changes: the builder cannot dark the model on its own signature. It raises the incident and the quorum (builder, Opaque, sovereign security team) assembles to sign. The floor in step 6 is unchanged and matters more here: even though the quorum is slower to assemble than a single signature, the 1 hour cadence caps worst-case exposure regardless of how long the quorum takes.

---

## 6. What Weight Custody Manifest Deliberately Does Not Do

- It does not evaluate model quality or capability. A manifest describes custody terms, not whether the model is good at its job.
- It is not a federated, host agnostic protocol. Unlike Harbor, it assumes a custodian and enforcement point, Opaque by default and reference implementation, with room for customer self-custody where the deployment requires it. That default is a deliberate commercial choice, not an oversight.
- It does not replace the deployment agreement's legal terms. The manifest is the machine checkable expression of terms legal has already negotiated, not a substitute for that negotiation.
- It does not attempt to solve BYOM symmetry in this draft, beyond the principle in section 2. The customer bringing their own model into the same confidential infrastructure is a real and related capability, but this document is scoped to the builder-to-customer direction only.

---

## 7. Resolved Design Decisions

1. **Naming.** This document is the Weight Custody Manifest, renamed from "Model Manifest" in v0.2 because it governs release and custody, not model identity. The "Model *" naming space is left to Harbor and agentrust-io as a cross-team decision with no dependency on this document. Section 4.
2. **Runtime control (the crux).** The party that can read decrypted weights is the party that signs the in-enclave serving stack. In this architecture that party is the builder: `required_serving_image` is builder-signed, and the key decrypts only under that measured stack. The customer, sovereign included, runs builder-signed code and verifies it by measurement rather than authoring it. This is what lets "no raw weight export path" be a real property instead of a promise. Section 3.1, 3.3.
3. **Custodian exclusivity.** Opaque is the default and reference custodian, not the only possible one. Customer self-custody of the *key release service* is achieved by running the KBS inside its own attested enclave with a builder-verified measurement (section 3.5), which is what lets Opaque leave the runtime release path without the builder having to trust the customer's word. Note this is separate from runtime control: even a self-custody customer still runs the builder-signed serving image. Sections 3.1, 3.5, section 2. Detail still open, question 8.2.
4. **Buildability and the GPU reality (assessed).** Layer 2 (attestation-gated key release) is buildable today on the cMCP and enclave stack. The confidential-GPU dependency was assessed (former open question 8.4): NVIDIA CC is GA on H100/H200 and rolling out on Blackwell, is custody-grade against software and remote adversaries with low inference overhead (under 7%), but protects GPU memory by access-control firewalling rather than encryption and explicitly excludes sophisticated physical attacks. So the core guarantee is silicon-enforced against software theft and cost-plus-detection-plus-containment-plus-recourse against a physical operator (section 3.6). The product is buildable; the claim is reframed, not withdrawn.
5. **Applicability.** This is a forward-looking design for the builder-into-customer-infrastructure case (a builder's weights deployed into a customer's own or sovereign environment). It is not tied to any specific deployment.
6. **Revocation.** Default profile: joint signature is standard, either party can trigger a unilateral emergency revocation with mandatory reconciliation within 24 hours. Sovereign profile: revocation requires a quorum including the sovereign signer, no unilateral path. Underneath both, wipe-on-lapse zeroizes the key from inside the enclave on any cadence lapse, bounding worst-case exposure to one cadence window regardless of profile or customer cooperation. This makes `attestation_cadence` a security parameter. Sections 3.1, 3.2.
7. **Scope of this draft.** Four layers is the right level of resolution for now. Multi-party co-governance and BYOM pipeline compatibility are named where relevant (sections 3.2 and 2) but deliberately not fully specified here. In-envelope distillation resistance beyond rate ceilings (watermarking, response perturbation) is explicitly out of scope, section 3.3.
8. **Replay protection.** The Layer 2 release handshake is nonce-bound: the KBS issues a fresh single-use challenge, the enclave attests over it, and a stale or reused nonce hard-fails. Closes the quote-replay threat (threat model T4.1). Section 3.2, `release_policy.replay_protection`.
9. **KBS attestation is universal.** The key release service runs in an attested enclave in every profile, not only self-custody, so the release logic is measured and an Opaque insider cannot alter it (threat model ADV-3). Self-custody changes the operator, not whether the KBS is attested. Sections 3.1, 3.2, 3.5, `custody.kbs_image`.
10. **Serving-image measurement rotation.** `required_serving_image.accepted_measurements` carries a small set of currently-valid measurements with a retire window, so a serving-stack patch adds a measurement rather than invalidating every live manifest. Sections 3.1, 3.2.
11. **Dedicated tenancy is an opt-in profile.** `tenancy: dedicated` forbids co-located workloads, the operational mitigation for the side-channel residual (threat model ADV-6). Default is `shared`; the control is opt-in for high-value deployments. Section 3.1.
12. **Custody is scoped to the operator-trust model.** The GPU and CPU-CVM assessments established that no current confidential-computing silicon delivers custody against an operator who owns the hardware: the key is extractable and attestation is forgeable with cheap published attacks. WCM therefore claims custody in two separated postures, semi-trusted operator (default, silicon holds in practice) and hostile-owner (physical hardening mandatory, claim is deterrence plus detection plus containment plus legal). It never claims silicon-enforced custody against an unhardened hardware owner. Sections 1, 3.1, 3.6. This is the central honesty of the specification.
13. **Open-core, with agentrust-io as the spec's home.** The spec, threat model, and reproducible reference KBS image are open and destined for agentrust-io, alongside TRACE/cMCP/Agent Manifest/cA2A; the operated custodian service, cMCP integration, and enclave engineering stay proprietary to Opaque. The value is operation and implementation, not a secret format, and an auditable spec is a trust requirement for builders and sovereigns. Publication is staged behind 8.8 stabilizing. Section 4.

## 8. Open Questions Still Standing

1. **Reconciliation window, set to 24h.** The window for a unilateral revocation to be confirmed or reversed is set to 24 hours, down from the 72h placeholder. Wipe-on-lapse already bounds the security exposure independently of this window, so 24h is about the human confirm-or-reverse process and about not letting a wrongful revocation stand long, not about containing weight exposure. Residual: validate 24h against an actual incident response timeline at a large regulated customer, and confirm it survives a weekend or cross-timezone review without forcing a rushed confirmation. If it does not, the fallback is a tiered window (shorter default, documented extension on mutual request) rather than a blanket return to 72h. Sections 3.2, 5.1.
2. **Self-custody attestation parity.** Resolved in direction, one detail left. The reference design is an attested KBS: the customer's key release service runs inside its own attested enclave whose builder-signed measurement the builder verifies (section 3.5). Two former sub-questions are now closed: threshold hardening is a v2 follow-up and not a prerequisite for the first offer, and the cadence coupling is settled in 8.5. What still needs specifying: the KBS enclave image contents and its threat model, written to implementable detail. Self-custody remains "described, not yet offered" until that is done.
3. **Will the sovereign accept builder-signed in-enclave code, in two places?** The v0.2 decision has the sovereign customer running a builder-signed, customer-unauditable serving image inside its own jurisdiction, with verification limited to matching a disclosed measurement. If the sovereign also self-custodies (section 3.5), that is now *two* such enclaves in-environment, the serving image and the KBS image, not one. Both are verify-by-measurement, neither is customer-authored. That is the correct security choice but an untested commercial and political one, and the surface it asks the sovereign to accept is larger than a single opaque component. It needs a real conversation with a sovereign buyer before it is assumed acceptable, because a sovereign that rejects opaque foreign code in-environment rejects the whole architecture, not just a parameter. The opening posture into that conversation is reproducible builds plus independent third-party audit for both images: neither image's source is handed to the customer, but both are built reproducibly and an agreed independent auditor certifies that the running measurement corresponds to certified source. That gives the sovereign verifiable assurance about what the foreign code does without the builder surrendering the weights-serving IP, and it moves the trust from the vendor's word to the auditor. This is distinct from, and not in tension with, the reproducible-build option rejected in section 3.5: there it was rejected as a *custody* mechanism, because an audit log does not stop a forked KBS from self-releasing, whereas here it is a *disclosure and verification* mechanism for accepting builder-signed image contents, layered on top of attestation rather than replacing it.
4. **Confidential GPU maturity (assessed, closed).** Resolved by the deep-research assessment folded into section 3.6 and resolved decision 4. NVIDIA CC is custody-grade against software and remote adversaries but not against a physical operator (access-control firewalling, not HBM encryption; sophisticated physical attacks out of scope). The guarantee is reframed in 3.6 rather than asserted. Attestation phone-home (NRAS/RIM dependency) is now a documented deployment requirement for sovereign/air-gapped cases (3.6).
5. **KBS-to-inference cadence coupling (self-custody only). Resolved: KBS runs longer.** When the customer self-custodies, every inference enclave depends on the KBS for key renewal, so a KBS that lapses and wipes darks its dependents at their next cadence by cascade. That cascade is a feature (a degraded release service should drop its dependents rather than serve keys it can no longer stand behind), but it makes a short-cadence fleet only as available as its KBS. Resolution: the KBS runs a deliberately longer, more conservative cadence than the inference enclaves it serves (illustratively 6h KBS against 15m inference), so the release service is the stable anchor and its normal re-attestation blips do not cascade into the fleet. The security cost, that the KBS's own trust standing is refreshed less often, is acceptable because the KBS attack surface is small and measured, and the inference enclaves enforce their own short cadence and wipe-on-lapse independently of the KBS. Residual: pick the concrete ratio per deployment; the 6h:15m figures are illustrative, not fixed.
6. **Does the physical-operator gap extend to the CPU CVM? Assessed: yes, and to attestation.** Physical bus-interposer attacks (TEE.fail, sub-$1000; BadRAM, ~$10) defeat SEV-SNP/TDX today: they extract keys from live CVM memory and forge attestation quotes at the highest trust level, and the root cause (deterministic unauthenticated full-DRAM encryption without freshness) needs new silicon to fix (3.6). Software-only variants (CipherLeaks, Heracles) do it from a malicious hypervisor. So against the operator-owns-the-box adversary the CPU CVM protects neither the key nor attestation integrity, which reaches the anchor primitive (Principle 2). What remains open is not technical but strategic: how WCM positions given the anchor does not hold against a hardware owner. That decision is 8.7.
7. **Positioning given the anchor does not hold against a hardware owner. Resolved: scope custody to the operator-trust model.** WCM claims two postures, never blended (section 3.6): semi-trusted operator (default; silicon holds in practice) and hostile-owner (sovereign / on-prem bare metal), where physical hardening is mandatory and the honest claim is raise-cost plus detect plus contain plus legal, backed by hardening, not silicon-absolute custody. Silicon-enforced custody against a bare-metal owner with no hardening is explicitly out of scope. Residual: validate that the mandatory hardening tier (tamper-responsive enclosure, locked SPD, access control, chain-of-custody) is procurable and auditable for a real sovereign deployment, and price it.
8. **Can anything detect a forged attestation quote at the Layer 2 gate?** Open, and it is the sharpest technical residual. TEE.fail / BadRAM forge quotes that pass vendor verification at the highest trust level (3.6), so the KBS cannot distinguish a forged quote from a genuine one by verification alone. The question is whether any signal outside the quote helps: hardware-bound freshness the interposer cannot replay, out-of-band platform health, physical-hardening attestation as a second independent factor, or rate/behaviour anomalies at the gate. In the semi-trusted posture this is bounded by the same detectability that bounds the physical attack; in the hostile-owner posture it is a real hole that mandatory hardening narrows but does not provably close. Needs dedicated design work before Layer 2 is specced for the hostile-owner posture.

---

*v0.5, pre-1.0 open specification. Companion: `THREAT-MODEL.md`. Sections 3 and 5 are load-bearing.*

*Version history: v0.1 initial draft. v0.2 established the runtime-control crux (builder-signed serving image), wipe-on-lapse, the sovereign revocation profile, and the attested-KBS self-custody design. v0.3 folded in a confidential-GPU assessment and reframed the guarantee as silicon-enforced against software theft but cost-plus-detection against a physical operator (section 3.6). v0.4 folded in a CPU-CVM assessment (TEE.fail / BadRAM defeat SEV-SNP/TDX and forge attestation), scoped custody to the operator-trust model, and made physical hardening mandatory for the hostile-owner posture. v0.5 set the open-core model: this spec, the threat model, and the reference KBS image are open; the operated custody service and enclave implementation are separate. Pre-1.0 and not ready to build against.*
