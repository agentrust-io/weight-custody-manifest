# Known Limitations

What the Weight Custody Manifest does **not** do. Honest scope boundaries prevent misplaced trust; this is the same honesty the spec's §3.6 is built around.

## The load-bearing one: no custody against a hardware owner

WCM protects a builder's weights when they run in a customer's own or sovereign infrastructure. Against a **software** adversary (host OS, hypervisor without ciphertext side channels, remote attacker, an Opaque insider) it is **cryptographic-custody-grade**. Against an operator who **physically owns the hardware** it is **not** custody-grade:

- Cheap published memory-bus attacks - TEE.fail (sub-$1000 DDR5 interposer) and BadRAM (~$10 + SPD access) - extract the decryption key from live CVM memory and, on some platforms, forge attestation quotes that pass verification at the highest trust level. The root cause is structural (deterministic unauthenticated full-DRAM encryption) and is not fixable without new silicon.
- NVIDIA CC protects GPU-resident weights by access-control firewalling, **not** HBM encryption; weights are plaintext in HBM during compute, and NVIDIA scopes sophisticated physical attacks out.

Against the hardware owner, WCM offers **cost, detection and attribution, containment (wipe-on-lapse, revocation), legal recourse, and a mandatory physical-hardening tier** - not silicon-enforced custody. The `physical_hardening` tier is required, not optional, in the hostile-owner posture. See `SPEC.md` §3.6.

## Attestation can be forged (the open half of 8.8)

The measurement-forgery half of forged attestation (BadRAM-class) is detectable by the `memory_fingerprint_challenge`, and the reference SDK now runs the sweep rather than only carrying the policy field. Read that detection narrowly. It shows that the granules it probed behave like distinct storage, and it is evidence the enclave produced rather than an assertion the host made **only** when the sweep's commitment is bound into the attestation quote (`require_memory_fingerprint_binding`, which needs a CPU quote verifier). An alias confined to unprobed granules is not caught, probe density is a deployment parameter, and a clean sweep says nothing about whether memory is encrypted, whether an interposer is attached, or whether an operator can read weights off the bus. It does not prove immunity to memory-extraction attacks; it detects one specific forgery. The full scope statement is [`python/docs/memory-fingerprint.md`](python/docs/memory-fingerprint.md).

The **key-extraction half** (TEE.fail-class) is **not** detectable: a physically-extracted attestation key produces a cryptographically valid quote that no gate-side verification can distinguish from a real one, and such an adversary can fold any fingerprint commitment it likes into `REPORT_DATA`. Compensating controls (live revocation-freshness checks, vendor short-lived certs, mandatory hardening, fleet anomaly monitoring) narrow it; they do not close it. This is why publication is staged.

## Trusted time is an assumption

Wipe-on-lapse bounds exposure only if the enclave's clock cannot be stalled by the host. `trusted_time_source` names the clock per deployment (`secure-tsc` sound, hybrid weaker, best-effort none), and the SDK's `time_floor` reports which - but the SDK cannot make an untrusted clock trustworthy, and cannot self-detect a stalled clock.

## In-envelope distillation is not prevented

Rate ceilings and receipts raise the cost of, and surface, gross model theft. A legitimate high-volume customer distilling a student model within its permitted rate envelope is **not** prevented. Watermarking / response perturbation is noted as follow-up, not delivered.

## What the reference SDK does not do

- **Not a hardware root of trust.** The SDK's authority-layer checks (signatures, lineage) and the KBS gate are only *cryptographic* about the runtime when a real quote verifier is wired. AMD SEV-SNP quote verification is implemented and hardware-validated; **GPU-side (NVIDIA) quote verification is not yet implemented** (pending hardware), so composite CPU+GPU verification is CPU-only today.
- **Not a key manager.** Signing and decryption keys must live in a KMS/HSM; the SDK provides the protocol, not custody of the private keys.
- **Not automatic.** Re-attestation, rotation, and revocation are triggered by the caller; the SDK provides the mechanisms, not the scheduling.
- **Audit receipts reuse TRACE**, a separate package; the extraction-detection story depends on it.

## Azure confidential VMs: attestation is vTPM-rooted, not direct `/dev/sev-guest`

Azure SEV-SNP CVMs run behind a Hyper-V paravisor: there is no `/dev/sev-guest`, and the SNP report is read from the vTPM NV index `0x01400001` (HCL-wrapped). The guest does **not** control `REPORT_DATA` - the paravisor binds it to the vTPM runtime-data hash - so the caller-nonce binding does not apply on Azure; verification there is cert-chain + report signature. Use `AzureSnpVtpmProvider`, not the bare-metal `SevSnpProvider`. This path was validated against a live Azure SEV-SNP VM; the bare-metal `/dev/sev-guest` ioctl offsets remain provisional, and Intel TDX / NVIDIA GPU paths are not yet hardware-validated.
