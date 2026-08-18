# Limitations

The canonical, complete list is [`LIMITATIONS.md`](https://github.com/agentrust-io/weight-custody-manifest/blob/main/LIMITATIONS.md). The load-bearing ones:

- **No custody against a hardware owner.** Against a physical operator who owns
  the box, cheap published memory-bus attacks (TEE.fail, BadRAM) extract the key
  and can forge attestation. WCM offers cost, detection, containment, legal
  recourse, and mandatory physical hardening there - not silicon-enforced custody.
- **Attestation forgery, open half.** Measurement forgery is detectable
  (`memory_fingerprint_challenge`, and the SDK runs the sweep); the
  key-extraction half is not, and is why publication is staged (open question
  8.8). The sweep detects address aliasing in the granules it probes, and only
  counts as the enclave's own evidence when its commitment is bound into the
  quote. It is not proof that memory is protected.
- **Trusted time is an assumption.** Wipe-on-lapse bounds exposure only if the
  clock cannot be stalled; the SDK reports the floor (`time_floor`) but cannot
  make an untrusted clock trustworthy.
- **In-envelope distillation is not prevented.**
- **GPU-side quote verification is not yet implemented** (pending hardware), so
  the KBS gate verifies the CPU quote cryptographically but the GPU report only
  structurally today.
- **Azure CVMs** use a vTPM-rooted attestation path (`AzureSnpVtpmProvider`), not
  `/dev/sev-guest`; `REPORT_DATA` is paravisor-bound there.
