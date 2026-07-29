# Roadmap

## Now - pre-1.0 developer preview

Published for review and comment, **not for production**. Publication of the open spec and SDK is **not** gated on the key-extraction half of open question 8.8 (§3.6): that residual is disclosed and scoped out of the operator-trust model rather than treated as a reason to withhold the document.

- **Specification** (`SPEC.md` v0.15): four layers (manifest, attestation-gated release, runtime custody, derivative lineage), transparency log, guarantee-scope honesty (§3.6), a model-signing provenance interop (§3.9), and the open questions in §8.
- **Threat model** (`THREAT-MODEL.md`): assets, TCB, adversaries, threats, residual risk.
- **Python reference SDK** (`python/`, published on PyPI): the full protocol -
  - Layer 1 joint signing + verification (Ed25519, ML-DSA-65, and hybrid profiles)
  - Layer 2 attestation-gated KBS gate + composite verification, with channel binding (SPEC 3.2)
  - Wipe-on-lapse custody (+ operation-count renewal), trusted-time honesty
  - Layer 4 derivative lineage + policy
  - RFC 9162 transparency log; Shamir threshold split-key
  - Quote-verification machinery (X.509 chain + report signature + nonce binding)
  - **The full attestation matrix validated on real silicon: AMD SEV-SNP (Azure), Intel TDX (GCP), and NVIDIA H100 CC (a live H100 capture)**, each with a committed fixture that verifies offline
  - OpenSSF model-signing provenance interop (`verify_provenance`)
  - A `wcm` CLI covering sign/verify, `inspect`, `gate`, `verify-quote`, and `verify-provenance`
  - Reference KBS server (`[server]`) and a CI-validated reproducible KBS image

## Next

- **Bit-for-bit reproducible KBS image** - base-image digest pinning + hash-locked dependencies on top of the current build.
- **Bare-metal `/dev/*-guest` provider validation** - the raw-ioctl SNP/TDX providers stay provisional until validated on a bare-metal host (cloud CVMs use the validated vTPM path).
- **Path to 1.0** - finalize the remaining open questions (8.1 reconciliation window, multi-party co-governance), freeze the manifest schema, and set a versioning policy.
- Community and design-partner feedback on the manifest schema and the sovereign profile.

## Later - 1.0 and standards

- Resolve or bound the remaining open questions in §8 (the key-extraction half of 8.8 needs new silicon and is disclosed as a scoped limit, not a blocker on the spec).
- Standards path: IETF SCITT (technical) and CoSAI (positioning), with WCM constructs mapped to SCITT roles (§3.4); a conformance suite for third-party implementations.
- Threshold and self-custody hardening promoted from preview to specified.
- Additional language SDKs as the community grows.

## What we will not do

- Claim silicon-enforced custody against a bare-metal owner with no physical hardening - out of scope, deliberately (§3.6).
- Ship unvalidated hardware/verification code presented as a security guarantee.

## How to influence the roadmap

Open an issue with the `spec` label describing the problem you are trying to solve, or tag `maintainer-interest` to participate in governance.
