---
description: "Where WCM stops: no custody against a hardware owner, an open attestation forgery question, weak vendor key revocation, and trusted time as an assumption."
---

# Limitations

Where WCM stops protecting you, in one list. Read this before relying on WCM for
anything: each item says who can still get at the model key, or which assumption
has to hold for the protection to work.

The canonical, complete list is [`LIMITATIONS.md`](https://github.com/agentrust-io/weight-custody-manifest/blob/main/LIMITATIONS.md). The ones that matter most:

- **No custody against a customer who controls the key service.** A customer
  who can read the key service's (KBS/Trustee) keys, or swap out its checking code
  and policy, can go around the gate without breaking the hardware check at all. The reference server does
  not implement protected KBS provisioning. See the
  [deployment trust checklist](deployment-trust.md).
- **No custody against a hardware owner.** Someone who physically owns the
  machine can use cheap published attacks on the memory bus (TEE.fail, BadRAM) to
  pull out the key and fake the hardware check. There WCM offers higher cost,
  detection, containment, legal recourse and required physical hardening, not
  protection enforced by the chip.
- **Faked hardware checks, the open half.** A faked software fingerprint
  (measurement forgery) can be detected (`memory_fingerprint_challenge`). A stolen
  hardware signing key cannot, and that is why publication is staged (open
  question 8.8).
- **The platform we test on does not meet our own ciphertext-hiding
  precondition.** Ciphertext hiding is an AMD setting that stops the host from
  reading even the encrypted form of protected memory. SPEC §3.6 conditions the semi-trusted-operator custody claim
  on SEV-SNP ciphertext hiding being enabled. The live Azure CVM this SDK is
  validated against reports `PLATFORM_INFO = 0x25`: alias check set, ciphertext
  hiding **clear**. Require it with
  `release_policy.platform_integrity.ciphertext_hiding` rather than assuming it.
- **Cancelling a leaked hardware signing key is weaker than it sounds.**
  Verified 2026-09-11: every certificate in our captured H100 chain carries
  `notAfter = 9999-12-31`, both NVIDIA CRLs are empty with a two-year
  next-update, AMD VCEKs carry serial number zero so a CRL entry cannot name a
  chip, and on no vendor can the operator invoke revocation.
- **Trusted time is an assumption.** The automatic key wipe limits exposure only
  if the clock cannot be stalled; the SDK reports the floor (`time_floor`) but cannot
  make an untrusted clock trustworthy.
- **In-envelope distillation is not prevented.** Rate limits and receipts make
  bulk theft costly and visible, but a legitimate high-volume customer can still
  train a copy of the model from its answers (distillation) while staying inside
  its permitted request rate.
- **The GPU's report is checked by signature only when a device root is
  configured.** A device root is the vendor certificate that GPU signatures are
  checked against. `NvidiaGpuVerifier` verifies the device chain, the ECDSA P-384
  report signature and the raw nonce at offset 4, and is validated on a live
  H100 capture and an H200. A gate built without `build_gpu_verifier` falls back
  to structural trust, and `gpu_report_verified` says so.
- **Azure confidential VMs** use a different hardware check path, rooted in a
  virtual TPM chip (`AzureSnpVtpmProvider`), not
  `/dev/sev-guest`; `REPORT_DATA` is paravisor-bound there.
