# Roadmap

## Now - pre-1.0 developer preview

Published for review and comment, **not for production**, until the hostile-owner posture stabilizes (open question 8.8).

- **Specification** (`SPEC.md` v0.9): four layers (manifest, attestation-gated release, runtime custody, derivative lineage), transparency log, guarantee-scope honesty (§3.6), and the open questions in §8.
- **Threat model** (`THREAT-MODEL.md`): assets, TCB, adversaries, threats, residual risk.
- **Python reference SDK** (`python/`): the full protocol on software / synthetic test doubles -
  - Layer 1 joint signing + verification (Ed25519, ML-DSA-65, and hybrid profiles)
  - Layer 2 attestation-gated KBS gate + composite verification
  - Wipe-on-lapse custody (+ operation-count renewal), trusted-time honesty
  - Layer 4 derivative lineage + policy
  - RFC 9162 transparency log; Shamir threshold split-key
  - Quote-verification machinery (X.509 chain + report signature + nonce binding)
  - **AMD SEV-SNP quote verification validated against real Azure hardware**
  - Reference KBS server (`[server]`) and a CI-validated reproducible KBS image

## Next

- **GPU-side quote verification** (NVIDIA CC / H100) - pending confidential-GPU hardware.
- **Intel TDX validation** - pending TDX enablement.
- **Bit-for-bit reproducible KBS image** - base-image digest pinning + hash-locked dependencies on top of the current build.
- Community and design-partner feedback on the manifest schema and the sovereign profile.

## Later - 1.0 and standards

- Resolve or bound the open questions in §8 (notably the key-extraction half of 8.8, which needs new silicon).
- Standards path: IETF SCITT (technical) and CoSAI (positioning), with WCM constructs mapped to SCITT roles (§3.4).
- Threshold and self-custody hardening promoted from preview to specified.
- Additional language SDKs as the community grows.

## What we will not do

- Claim silicon-enforced custody against a bare-metal owner with no physical hardening - out of scope, deliberately (§3.6).
- Ship unvalidated hardware/verification code presented as a security guarantee.
- Flip the repository public before the Project Lead judges the 8.8 gate met.

## How to influence the roadmap

Open an issue with the `spec` label describing the problem you are trying to solve, or tag `maintainer-interest` to participate in governance.
