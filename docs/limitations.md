# Limitations

The canonical, complete list is [`LIMITATIONS.md`](https://github.com/agentrust-io/weight-custody-manifest/blob/main/LIMITATIONS.md). The load-bearing ones:

- **No custody against a hardware owner.** Against a physical operator who owns
  the box, cheap published memory-bus attacks (TEE.fail, BadRAM) extract the key
  and can forge attestation. WCM offers cost, detection, containment, legal
  recourse, and mandatory physical hardening there - not silicon-enforced custody.
- **Attestation forgery, open half.** Measurement forgery is detectable
  (`memory_fingerprint_challenge`); the key-extraction half is not, and is why
  publication is staged (open question 8.8).
- **Trusted time is an assumption.** Wipe-on-lapse bounds exposure only if the
  clock cannot be stalled; the SDK reports the floor (`time_floor`) but cannot
  make an untrusted clock trustworthy.
- **In-envelope distillation is not prevented.**
- **GPU-side quote verification is cryptographic only when a device root is
  configured.** `NvidiaGpuVerifier` verifies the device chain, the ECDSA P-384
  report signature and the raw nonce at offset 4, and is validated on a live
  H100 capture and an H200. A gate built without `build_gpu_verifier` falls back
  to structural trust, and `gpu_report_verified` says so.
- **Azure CVMs** use a vTPM-rooted attestation path (`AzureSnpVtpmProvider`), not
  `/dev/sev-guest`; `REPORT_DATA` is paravisor-bound there.
