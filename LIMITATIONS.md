# Known Limitations

What the Weight Custody Manifest does **not** do. Honest scope boundaries prevent misplaced trust; this is the same honesty the spec's §3.6 is built around.

## The load-bearing one: no custody against a hardware owner

WCM protects a builder's weights when they run in a customer's own or sovereign infrastructure. Against a **software** adversary (host OS, hypervisor without ciphertext side channels, remote attacker, an Opaque insider) it is **cryptographic-custody-grade**. Against an operator who **physically owns the hardware** it is **not** custody-grade:

- Cheap published memory-bus attacks - TEE.fail (sub-$1000 DDR5 interposer) and BadRAM (~$10 + SPD access) - extract the decryption key from live CVM memory and, on some platforms, forge attestation quotes that pass verification at the highest trust level. The root cause is structural (deterministic unauthenticated full-DRAM encryption) and is not fixable without new silicon.
- NVIDIA CC protects GPU-resident weights by access-control firewalling, **not** HBM encryption; weights are plaintext in HBM during compute, and NVIDIA scopes sophisticated physical attacks out.

Against the hardware owner, WCM offers **cost, detection and attribution, containment (wipe-on-lapse, revocation), legal recourse, and a mandatory physical-hardening tier** - not silicon-enforced custody. The `physical_hardening` tier is required, not optional, in the hostile-owner posture. See `SPEC.md` §3.6.

## The platform we validate against does not meet our own ciphertext-hiding precondition

`SPEC.md` §3.6 makes the cryptographic-custody claim against a hypervisor-privileged operator conditional on AMD SEV-SNP **ciphertext hiding** being enabled, because without it a malicious hypervisor extracts keys through ciphertext side channels (CipherLeaks, Heracles) with no physical access.

Measured on both SEV-SNP platforms we have captured, each reporting `PLATFORM_INFO = 0x25` (`ALIAS_CHECK_COMPLETE` **set**, `CIPHERTEXT_HIDING_EN` **clear**): the Azure CVM this SDK is validated against (report version 3), and a live GCP `n2d-standard-4`, AMD EPYC 7B13, captured 2026-09-11 (report version 5). On neither is the precondition met, so the claim does not hold there against a hypervisor-privileged operator. Until this release nothing in the SDK read the field that would have told us.

On GCP this is structural: Google documents SEV-SNP as N2D/Milan only (C3D Genoa and C4D Turin offer plain SEV, and the API rejects `SEV_SNP` on both), while ciphertext hiding requires EPYC 9005 Turin. No GCP SEV-SNP platform can set bit 4 today.

What to do about it: require it. `release_policy.platform_integrity.ciphertext_hiding: required` denies release on a platform that does not report bit 4, which turns an assumption into a gate. Requiring it today will deny on the Azure platform above; that is the correct outcome, and the honest way to run the semi-trusted posture is to verify a platform that sets the bit rather than to assume every platform does.

## Attestation-key revocation is weaker than the spec's compensating control implies

`attestation_revocation_check` is specified as though revocation were a working per-device lifecycle mechanism. Verified on 2026-09-11, it is not:

- **NVIDIA**: every certificate in our own captured H100 device chain carries `notAfter = 9999-12-31 23:59:59 GMT`, root included, and both published CRLs are empty with a **two-year** next-update (`l1-root.crl` to 2028-02-06, `l2-gh100.crl` to 2028-01-16). A CRL fallback learns nothing. Nonce-bound OCSP is the only live control, so OCSP unreachability must fail rather than fall back.
- **AMD**: VCEK certs are minted per request with serial number zero, so a CRL entry has nothing to name. De-facto revocation is fleet-wide TCB versioning.
- **On every vendor the operator cannot invoke revocation.** A customer who knows a host was physically opened has no documented path to get that device's attestation key stopped.

Treat a passing revocation check as evidence that the vendor has not published a revocation, not as evidence that a compromised device would have been caught.

## Attestation can be forged (the open half of 8.8)

The measurement-forgery half of forged attestation (BadRAM-class) is detectable and closed by the `memory_fingerprint_challenge`. The **key-extraction half** (TEE.fail-class) is **not**: a physically-extracted attestation key produces a cryptographically valid quote that no gate-side verification can distinguish from a real one. Compensating controls (live revocation-freshness checks, vendor short-lived certs, mandatory hardening, fleet anomaly monitoring) narrow it; they do not close it. This is why publication is staged.

## Trusted time is an assumption

Wipe-on-lapse bounds exposure only if the enclave's clock cannot be stalled by the host. `trusted_time_source` names the clock per deployment (`secure-tsc` sound, hybrid weaker, best-effort none), and the SDK's `time_floor` reports which - but the SDK cannot make an untrusted clock trustworthy, and cannot self-detect a stalled clock.

## In-envelope distillation is not prevented

Rate ceilings and receipts raise the cost of, and surface, gross model theft. A legitimate high-volume customer distilling a student model within its permitted rate envelope is **not** prevented. Watermarking / response perturbation is noted as follow-up, not delivered.

## What the reference SDK does not do

- **Not a hardware root of trust.** The SDK's authority-layer checks (signatures, lineage) and the KBS gate are only *cryptographic* about the runtime when a real quote verifier is wired. AMD SEV-SNP quote verification is implemented and hardware-validated. GPU-side (NVIDIA) quote verification is also implemented (`NvidiaGpuVerifier`: device chain to NVIDIA's device-identity CA, ECDSA P-384 report signature, raw challenge nonce at offset 4) and validated against a live H100 capture, independently re-run on an H200. The gate checks the GPU report cryptographically only when a device root is configured through `build_gpu_verifier`; without one, `gpu_report_verified` reports structural trust only and says so in its reason.
- **Not a key manager.** Signing and decryption keys must live in a KMS/HSM; the SDK provides the protocol, not custody of the private keys.
- **Not automatic.** Re-attestation, rotation, and revocation are triggered by the caller; the SDK provides the mechanisms, not the scheduling.
- **Audit receipts reuse TRACE**, a separate package; the extraction-detection story depends on it.

## Azure confidential VMs: attestation is vTPM-rooted, not direct `/dev/sev-guest`

Azure SEV-SNP CVMs run behind a Hyper-V paravisor: there is no `/dev/sev-guest`, and the SNP report is read from the vTPM NV index `0x01400001` (HCL-wrapped). The guest does **not** control `REPORT_DATA` - the paravisor binds it to the vTPM runtime-data hash - so the caller-nonce binding does not apply on Azure; verification there is cert-chain + report signature. Use `AzureSnpVtpmProvider`, not the bare-metal `SevSnpProvider`. This path was validated against a live Azure SEV-SNP VM. The bare-metal `/dev/sev-guest` path is validated on a live GCP N2D guest and the bare-metal TDX report path on a live GCP C3 guest, where converting that TDREPORT into a remotely verifiable quote stays provisional. The NVIDIA GPU path is validated against a live H100 capture and independently re-run on an H200.
