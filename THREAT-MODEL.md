# Weight Custody Manifest: Threat Model

*Working draft, v0.4, pre-1.0. Companion to `SPEC.md`. v0.4 applied an external panel assessment: precise per-vendor attribution of TEE.fail (Intel forgery / AMD key extraction) and BadRAM (SEV-SNP forgery); added TCB item 8 (trusted monotonic time) and T1.8 (clock-stall defeats wipe-on-lapse); the malicious-hypervisor ciphertext-side-channel path is now reflected in the spec's commercial-posture claim.*

*Prior companion note to `SPEC.md`. This is the foundation the implementation spec hangs off: it fixes what is being protected, from whom, what is trusted, and what is explicitly not defended. Section references (3.1, 3.2, ...) point into the spec. It folds in two hardware assessments: NVIDIA GPU CC and the SEV-SNP/TDX CPU CVM are both custody-grade against software adversaries but not against an operator who owns the hardware (TEE.fail / BadRAM extract keys and forge attestation), so custody is scoped to the operator-trust model, semi-trusted default vs hostile-owner with mandatory physical hardening (SPEC 3.6). The sharpest open residual is detecting a forged attestation quote at the Layer 2 gate (SPEC open question 8.8).*

---

## 0. How to read this

Every guarantee in the WCM design is a claim of the form "adversary X cannot do Y because mechanism Z." This document enumerates the X's (section 3), states exactly what is trusted so the Z's can work (section 2, the TCB), and then walks each adversary against each asset and records the mechanism and the residual risk (section 4). A guarantee whose residual risk is unacceptable is a spec bug found before it was written, which is the point of doing this first.

The single most important section is 2, the TCB. Everything WCM promises is conditional on that list being true. If any item in it is false, the corresponding guarantees fail silently.

---

## 1. Assets

Ordered by value. The whole architecture exists for A1.

| ID | Asset | Why it matters | Where it lives |
|---|---|---|---|
| A1 | Decrypted model weights | The builder's core IP. Theft, copying, or distillation of these is the loss the whole system exists to prevent. | Inference enclave memory (CPU CVM + confidential GPU memory) during inference only |
| A2 | Weight decryption key | Whoever holds it can decrypt A1 at rest. | Released into inference enclave memory; held by the KBS otherwise |
| A3 | Manifest integrity | The manifest is the enforceable expression of the deployment agreement. A forged or altered manifest defeats every downstream control. | Signed artifact, at rest and in transit |
| A4 | Attestation quotes | The evidence key release is gated on. A forgeable quote makes attestation-gated release meaningless. | Produced by enclave hardware, verified by KBS |
| A5 | Audit receipts | The tamper-evident record of inference usage; the basis for extraction detection and dispute. | Hash-chained stream, TRACE format |
| A6 | Derivative weights | Fine-tunes carry the builder's base-weight IP forward (3.4). | Inference/training enclave memory; new manifest |
| A7 | Signing keys (builder, custodian, sovereign) | Compromise of any collapses the authority model. | Out of band; ideally in HSM / their own enclaves |

---

## 2. Trusted Computing Base (the load-bearing assumptions)

WCM's guarantees hold **if and only if** every item below holds. This is the honest core of the threat model. Each item is a thing we are choosing to trust rather than defend, and each is a place the whole system fails silently if the assumption is wrong.

1. **SEV-SNP / TDX confidentiality is real against a remote attacker, partial against a malicious hypervisor, and broken against a physical operator. (Assessed, design-doc 3.6 / 8.6.)** Against a remote software attacker with neither hypervisor control nor physical access, the CVM protects the key and memory. But two adversaries WCM actually faces are not covered: (a) a *malicious hypervisor* can extract keys via ciphertext side channels (CipherLeaks, USENIX Security 2021; Heracles, CCS 2025) with no physical access, because full-DRAM memory encryption is deterministic and unauthenticated; and (b) a *physical operator* can, with cheap published tools, read the key from live memory **and forge attestation**, though which result on which platform matters: on Intel TDX/SGX, TEE.fail (a sub-$1000 DDR5 bus interposer of hand-soldered commodity parts) forges attestation quotes that pass verification at the highest trust level, while on AMD SEV-SNP its demonstrated result is key/confidential-data extraction; BadRAM (CVE-2024-21944, ~$10 plus one-time SPD access) is the attack that forges SEV-SNP attestation. Between them, on the platforms WCM pins, both key extraction and attestation forgery are achievable. The root cause is structural, deterministic unauthenticated encryption without freshness, adopted to scale encryption to full DRAM, and not fixable without new silicon. For WCM this is severe: the target adversary owns the box, so both (a) and (b) are in scope, the decryption key is extractable, and attestation itself is forgeable (which also breaks item 3 below). See T3.3 and the new T1.7.
2. **NVIDIA Confidential Computing isolates GPU-resident weights from *software* adversaries, not from a physical operator.** Assessed (design-doc 3.6). Weights in GPU memory are protected from the host, hypervisor, and other tenants by access-control firewalling, and the CPU-to-GPU channel is encrypted and replay-protected. But the mechanism is *not* memory encryption: weights are plaintext in HBM during compute, and NVIDIA explicitly excludes sophisticated physical attacks (decapsulation, on-package probing) from scope. So this item holds against software and remote adversaries and does NOT hold against a physical operator who owns the hardware, which is exactly ADV-1/ADV-2. The A1 guarantee against those adversaries is therefore not custody-grade; see the revised T1.2.
3. **The hardware roots of trust and their attestation services are sound.** The AMD and NVIDIA attestation verification paths, including the vendors' own attestation/endorsement services, are trusted to certify genuine hardware and correct measurements. **Caveat (assessed):** this does NOT hold against an operator who can mount TEE.fail / BadRAM-class attacks, which forge attestation quotes that pass verification at the highest trust level. Against WCM's target adversary, attestation soundness is not assumable, and this is the single most damaging finding because Layer 2 release gating (Principle 2) depends entirely on it.
4. **Measured code is the only code that runs in the enclave.** The measurement in an attestation quote fully and faithfully captures the firmware, kernel, CVM config, and serving image. There is no unmeasured code path (no unmeasured init, no runtime code load) that could exfiltrate A1.
5. **Signing keys (A7) are secret and their holders are who the manifest says.** The builder's, custodian's, and (sovereign profile) sovereign's private keys are not compromised.
6. **The builder-signed serving image does not itself exfiltrate weights.** Since the customer runs builder-signed code and verifies it only by measurement, the builder is trusted (backed by reproducible builds + independent audit per 8.3) not to ship a serving image that leaks A1.
7. **Cryptographic primitives are sound.** Signatures, the hash chain, and the at-rest weight encryption are not broken.
8. **Trusted monotonic time is available to the enclave. (Assessed, being designed.)** Wipe-on-lapse enforces a cadence TTL, which requires a clock the host cannot stall. SEV-SNP does not provide this by default, so the deployment must supply SecureTSC or an equivalent, or use a KBS-issued signed lease (design-doc 3.2, open question 8.9). If this item fails, a host-privileged operator stalls the enclave's perceived time and serves indefinitely on a stale key, defeating the revocation floor with no physical access at all. Treat it as a required build property, not a free assumption.

Anything not on this list is an adversary in section 3, not an assumption.

---

## 3. Adversaries

Each adversary is defined by capability and goal. "Privileged" means root/hypervisor-level control of the named component.

| ID | Adversary | Capability | Primary goal |
|---|---|---|---|
| ADV-1 | **Malicious customer operator** | Privileged on the host OS and hypervisor of the customer's own infrastructure. Can run arbitrary code outside the enclave, inspect host memory, control networking, restart hardware. Cannot break the TCB. | Extract, copy, or distill A1; retain access after revocation |
| ADV-2 | **Compromised host** | Same capabilities as ADV-1 but the actor is a third party who has breached the customer, possibly without the customer's knowledge. Behaviorally identical to ADV-1; separated because the customer is a victim, not the attacker, which changes the response (revocation, not breach of contract). | Extract A1; persist |
| ADV-3 | **Malicious Opaque insider** | Infrastructure access to the Opaque-operated KBS and control plane (default profile). Cannot break the TCB, does not hold the builder's signing key. | Release A1 to an unauthorized environment; suppress a revocation |
| ADV-4 | **Network adversary** | Full control of the network between enclave and KBS, and between builder, custodian, and customer. Can drop, delay, replay, and MITM. | Force a stale key to persist; replay a quote; block a revocation |
| ADV-5 | **Malicious or coerced builder** | Holds the builder signing key; can issue and revoke manifests. Relevant chiefly in the sovereign profile, where the customer does not want a foreign builder holding unilateral power. | Dark a model in a sovereign jurisdiction unilaterally; issue a manifest that over-collects |
| ADV-6 | **Co-located tenant / side-channel attacker** | Runs a workload on the same physical hardware as the enclave. Cannot break SEV-SNP/CC directly but probes timing, cache, power, contention. | Recover fragments of A1 or A2 via side channel |
| ADV-7 | **Supply-chain attacker** | Compromises the serving image or KBS image before it is signed and measured. | Ship a measured-and-trusted image that exfiltrates A1 |

---

## 4. Threats, mitigations, residual risk

Format: threat -> mechanism (design-doc reference) -> residual risk. Residual risk is where the spec work and the honesty live.

### 4.1 ADV-1 / ADV-2 (malicious or compromised host) against A1 (weights)

- **T1.1 Read weights out of enclave memory from the host.** Mitigation: SEV-SNP memory encryption/isolation, TCB item 1 (3.1, Principle 1). Residual: none above the TCB; fails only if item 1 is false.
- **T1.2 Read weights out of GPU memory.** Against a *software* ADV-1/ADV-2 (privileged host or hypervisor, no physical access): mitigated by NVIDIA CC access-control firewalling (TCB item 2, design 3.6). Against a *physical* ADV-1/ADV-2 (operator willing to mount on-package attacks): **NOT mitigated cryptographically.** Weights are plaintext in HBM and NVIDIA scopes sophisticated physical attacks out. Residual is handled by the design-3.6 stack, not by silicon: raise cost (decapsulation, on-package probing), detect and attribute (attestation plus receipts), contain (wipe-on-lapse, revocation), legal recourse, and the optional `physical_hardening` tier. This is the honest downgrade from custody to cost-plus-detection against the physical operator, and it is the single most important correction the GPU assessment forced. **A parallel question is open (8.6): if TEE.fail-class attacks also defeat the CPU CVM (TCB item 1), the same downgrade applies to T3.3 and to the key, not only to weights.**
- **T1.3 Substitute a serving image that dumps weights to host storage.** Mitigation: `required_serving_image`, key decrypts only under the builder-signed measured stack; a swapped image changes the measurement and fails release (3.1, 3.3). Residual: depends on TCB items 4 and 6.
- **T1.4 Keep serving after revocation by partitioning the enclave from the KBS (ADV-1/ADV-2/ADV-4 combined).** Mitigation: wipe-on-lapse, the enclave zeroizes the key from inside on cadence lapse regardless of whether any signal arrives (3.2). Residual: bounded exposure of one cadence window. This is the designed floor, not a defect; the residual shrinks as cadence shortens (security parameter).
- **T1.5 Distill a student model from inference outputs within the permitted rate envelope.** Mitigation: partial only, rate ceilings + receipts raise cost and surface gross theft (3.3). Residual: **acknowledged and unsolved.** In-envelope distillation by a legitimate high-volume customer is not prevented. Out of scope for now; watermarking/perturbation noted as follow-up.
- **T1.6 Snapshot enclave memory (cold-boot / live migration abuse).** Mitigation: SEV-SNP protects memory at rest in DRAM and blocks unauthorized migration; key exists only in enclave memory (3.2). Residual: depends on TCB item 1; physical DRAM attacks below the SEV-SNP guarantee are out of scope (section 5).
- **T1.7 Physically extract the key from the CPU CVM, or forge attestation, via a memory-bus attack. (Assessed, the most serious finding.)** A physical operator running TEE.fail (sub-$1000 DDR5 interposer) reads the key out of live AMD SEV-SNP memory and, on Intel TDX/SGX, forges quotes that pass verification at the highest trust level; BadRAM (~$10 + SPD access) is the attack that forges AMD SEV-SNP attestation. On the platforms WCM pins, both key extraction and attestation forgery are within reach of the box's owner. Mitigation against WCM's target adversary (operator owns the box): **none at the silicon level today.** The structural fix (authenticated memory encryption with integrity and freshness) needs new hardware. What remains is the design-3.6 stack (cost, detection, containment, legal) plus the `physical_hardening` tier (tamper-responsive memory enclosure that zeroizes on bus tamper, locked SPD, physical access control, supply-chain custody), which is the only concrete technical defense against this specific class and is now mandatory, not optional, for a hostile-owner deployment (design-doc 3.6, resolved decision 12). This threat is worse than T1.2 in two ways: it is cheaper than GPU decapsulation, and it defeats attestation (Principle 2), not just confidentiality. Software-only variants (CipherLeaks, Heracles) achieve key extraction from a malicious hypervisor with no physical access at all.
- **T1.8 Stall the enclave's clock so wipe-on-lapse never fires. (Assessed.)** A host-privileged operator (no physical access needed) freezes or slows the enclave's perceived time, so the cadence deadline never elapses, the enclave never demands re-attestation, and it serves indefinitely on a stale key. Distinct from a network attacker who *blocks* re-attestation (that path fails safe by wiping); this one silently keeps the key alive. Mitigation: trusted monotonic time (TCB item 8), SecureTSC or a KBS-issued signed lease (design-doc 3.2, open question 8.9). Until that is specified and built, the revocation floor is defeatable by software, which is why R2/8.9 gate Layer 2 implementation.

### 4.2 ADV-3 (malicious Opaque insider) against A2 (key) / A1

- **T3.1 Release the key to an environment that should not have it.** Mitigation: release is gated on an attestation quote matching manifest policy, which the insider cannot forge (TCB 3, 4); and in the default profile the manifest is builder+custodian co-signed, so the insider cannot unilaterally author policy (3.1). Residual: an insider who could alter the KBS verification logic. Resolved: the KBS runs in an attested enclave in every profile (design 3.1/3.5, `custody.kbs_image`), Opaque-hosted included, so the verification logic is measured and an insider cannot alter it undetectably. The residual narrows to a bug in the measured KBS logic itself, which is the v1 single-key single-point-of-failure that threshold split-key hardens in v2.
- **T3.2 Suppress or delay a revocation.** Mitigation: wipe-on-lapse does not depend on the KBS actively pushing anything; absence of renewal is itself the kill (3.2). An insider suppressing a revocation still cannot extend access past a cadence window without also forging fresh quotes. Residual: within one cadence window, an insider colluding with the host could sustain access; shortens with cadence.
- **T3.3 Observe the decrypted weights via infra access.** Mitigation: TCB item 1, Opaque staff have infra access but not enclave-memory access (3.2 step 3). Residual: none above TCB.

### 4.3 ADV-4 (network) against A2 / A4

- **T4.1 Replay an old valid attestation quote to obtain a key.** Mitigation: the release handshake is nonce-bound and the quote is tied to the specific enclave instance. Now specified in design 3.2, the KBS issues a single-use challenge and a stale or reused nonce hard-fails (`release_policy.replay_protection`). Residual: none if freshness is enforced.
- **T4.2 Block re-attestation to deny renewal.** Mitigation: this is availability loss, not a confidentiality breach; wipe-on-lapse means blocked renewal darks the model rather than exposing it (3.2). Residual: availability only, accepted.
- **T4.3 MITM the manifest or revocation in transit.** Mitigation: both are signed (A3, TCB 5); tampering is detected. Residual: a dropped revocation, covered by T1.4/wipe-on-lapse.

### 4.4 ADV-5 (malicious/coerced builder) against the customer

- **T5.1 Unilaterally dark a model running in a sovereign jurisdiction.** Mitigation: `sovereign_profile` removes the builder's unilateral revocation and requires a quorum including the sovereign signer (3.1, 3.2). Residual: the sovereign trades this for a slower revocation path; wipe-on-lapse still provides the floor. In the default (non-sovereign) profile, unilateral builder revocation is by design and not treated as a threat.
- **T5.2 Issue a manifest that over-collects or misrepresents terms.** Mitigation: `release_terms` maps to the negotiated deployment agreement and the customer sees the manifest; the customer verifies before provisioning (3.1, 5.2). Residual: relies on the customer actually reviewing; a legal/process control, not a technical one.
- **T5.3 Ship a serving image that exfiltrates weights (builder attacks the customer's data, inverse direction).** Note: out of primary scope (WCM protects the builder from the customer), but the sovereign case inverts trust. Mitigation: reproducible builds + independent audit of the serving image (8.3). Residual: the sovereign must trust the auditor; this is the crux of open question 8.3.

### 4.5 ADV-6 (side channel) against A1 / A2

- **T6.1 Recover key or weight fragments via cache/timing/power side channels.** Mitigation: largely inherited from the hardware platform; constant-time crypto for A2 handling in the enclave. Residual: **side channels are a known, only-partially-mitigated class for both SEV-SNP and GPU CC.** Documented as a residual risk, not fully defended. Dedicated tenancy (no co-location) is the operational mitigation for high-value deployments and is now a spec profile: `tenancy: dedicated` (design 3.1), opt-in, default `shared`.

### 4.6 ADV-7 (supply chain) against A1

- **T7.1 Compromise the serving or KBS image before signing.** Mitigation: reproducible builds + independent audit binding measurement to certified source (8.3); this is exactly why measurement-only disclosure was rejected as the sole posture. Residual: trust in the build pipeline and the auditor. This threat is the reason 8.3's posture is a security control and not only a commercial concession.

---

## 5. Explicitly out of scope

Naming these prevents the spec from silently pretending to cover them.

- **Model quality or safety.** WCM governs custody, not whether the model is good or safe (design doc section 6).
- **In-envelope distillation.** See T1.5. Partial mitigation only; full defense is follow-up work.
- **Physical attacks below the hardware guarantee.** De-capping, invasive silicon attacks, physical DRAM extraction beyond what SEV-SNP defends. These are the hardware vendors' threat model, inherited via TCB items 1 to 3.
- **Denial of service.** An adversary who can deny availability (block networking, pull power) can stop the model from serving. WCM treats loss of availability as acceptable and, via wipe-on-lapse, as fail-safe (the model goes dark, not the weights go free).
- **Compromise of a signing key (A7).** Treated as a TCB assumption (item 5), not a defended threat. Key custody (HSM, key-holder enclaves, rotation) is its own spec, referenced but not solved here.

---

## 6. What each attestation proves, and does not

Stated explicitly because the spec's correctness depends on not over-reading a quote.

**Inference enclave quote proves:** genuine SEV-SNP (and, where required, genuine NVIDIA CC) hardware; the exact firmware, kernel, and CVM measurements; and that the running serving image measurement matches `required_serving_image`. It is fresh (nonce-bound, per T4.1) and bound to this enclave instance.

**It does not prove:** that the measured code is free of vulnerabilities (TCB item 4 assumes only that it is the *intended* code, not that the code is bug-free); that no side channel exists (ADV-6); that the customer will not distill within the rate envelope (T1.5); or, until 8.4 closes, that GPU-resident weights are actually isolated (TCB item 2).

**KBS enclave quote (self-custody) proves:** the release logic measurement matches the builder-signed value, so the customer runs the KBS without controlling its behavior (3.5). It does not prove the release logic is bug-free, which is why v1's single-key KBS is a stated single point of failure and threshold is the v2 hardening.

---

## 7. Open items this threat model hands to the spec

1. **Nonce/freshness in the Layer 2 release handshake (T4.1).** Resolved. Specified in design 3.2 as a KBS-issued single-use nonce; stale or reused nonce hard-fails.
2. **Attested KBS even in the Opaque-hosted case (T3.1).** Resolved. The KBS is attested in every profile (design 3.1/3.5, `custody.kbs_image`), not only self-custody.
3. **Dedicated-tenancy deployment profile (T6.1).** Resolved. `tenancy: dedicated` is an opt-in profile (design 3.1); default `shared`.
4. **Serving-image measurement rotation.** Resolved. `required_serving_image.accepted_measurements` carries a small valid set with a retire window (design 3.1/3.2), so a patch adds a measurement instead of invalidating live manifests.
5. **GPU CC assessment (8.4). Done.** NVIDIA CC is custody-grade against software and remote adversaries but not against a physical operator: it protects GPU memory by access-control firewalling, not HBM encryption, and scopes sophisticated physical attacks out. Folded into design-doc 3.6 and TCB item 2; T1.2 downgraded accordingly. It also surfaced an attestation phone-home dependency (NRAS/RIM), now a documented sovereign deployment requirement.
6. **CPU-CVM physical surface (8.6). Assessed: yes, and it reaches attestation.** A TEE.fail-class DDR5 interposer (sub-$1000) and BadRAM (~$10 + SPD access) defeat SEV-SNP/TDX today: they extract keys from live CVM memory (T1.7) and forge attestation quotes that pass at the highest trust level (breaks TCB item 3). Software-only ciphertext-side-channel variants (CipherLeaks, Heracles) do it from a malicious hypervisor with no physical access. Root cause is structural and needs new silicon to fix. So against WCM's target adversary the CPU CVM protects neither the key nor attestation integrity, and the anchor primitive (Principle 2) is not assumable. The positioning response is a strategic decision now open (see design-doc note).

Items 1 to 5 are closed. Item 6 is assessed and its finding folded in; what it leaves open is not technical but strategic, how WCM positions given the anchor primitive does not hold against a hardware owner.
