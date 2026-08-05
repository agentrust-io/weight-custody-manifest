# Roadmap

## Now - pre-1.0 developer preview

Published for review and comment, **not for production**. Publication of the open spec and SDK is **not** gated on the key-extraction half of open question 8.8 (§3.6): that residual is disclosed and scoped out of the operator-trust model rather than treated as a reason to withhold the document.

- **Specification** (`SPEC.md` v0.15): four layers (manifest, attestation-gated release, runtime custody, derivative lineage), transparency log, guarantee-scope honesty (§3.6), a model-signing provenance interop (§3.9), and the open questions in §8.
- **Manifest JSON Schema** (`schema/`), the machine-readable form of §3.1, **frozen at v1** and additive-only. One constraint (`derived_from` != `weights_hash`) is not expressible in JSON Schema and stays verifier-side, documented rather than glossed.
- **Conformance suite** (`conformance/`): 83 language-neutral vectors plus a scoring contract, run by `wcm conformance`. **All four levels are vectored** - L1 and L4 over documents, L2 (the release gate) and L3 (runtime custody) as time-ordered scenarios with an injected clock. Cryptographic quote verification inside L2 is the one uncovered requirement, and the runner prints it on every run rather than letting a pass imply it.
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

- **Cross-builder verification of the KBS image.** The image is bit-for-bit reproducible (base pinned by digest, fully hash-locked dependencies, normalized mtimes) and CI proves two `--no-cache` builds produce identical layers. What remains is confirming that across *independent* builders on different machines, which is a certification step rather than a CI one.
- **Bare-metal `/dev/*-guest` provider validation** - the raw-ioctl SNP/TDX providers stay provisional until validated on a bare-metal host (cloud CVMs use the validated vTPM path).
- **Conformance vectors for cryptographic quote verification** - the one uncovered L2 requirement (`WCM-L2-0011`, `WCM-L2-0012`). Needs a vector shape that supplies raw hardware evidence and a trust store, and an honest way to express nonce binding given that the Azure SEV-SNP capture binds the vTPM attestation key in `REPORT_DATA` rather than a caller nonce.
- **Path to 1.0** - finalize the remaining open questions (8.1 reconciliation window, multi-party co-governance). The manifest schema is frozen and its versioning policy is written (`schema/README.md`); what remains is the spec text catching up to it.
- Community and design-partner feedback on the manifest schema and the sovereign profile.

## Later - 1.0 and standards

- Resolve or bound the remaining open questions in §8 (the key-extraction half of 8.8 needs new silicon and is disclosed as a scoped limit, not a blocker on the spec).
- Standards path: IETF SCITT (technical) and CoSAI (positioning), with WCM constructs mapped to SCITT roles (§3.4). The conformance suite third-party implementations are scored against covers all four levels (see **Now** above); the remaining gap is cryptographic quote verification, under **Next**.
- Threshold and self-custody hardening promoted from preview to specified.
- Additional language SDKs as the community grows.

## What we will not do

- Claim silicon-enforced custody against a bare-metal owner with no physical hardening - out of scope, deliberately (§3.6).
- Ship unvalidated hardware/verification code presented as a security guarantee.

## How to influence the roadmap

Open an issue with the `spec` label describing the problem you are trying to solve, or tag `maintainer-interest` to participate in governance.
