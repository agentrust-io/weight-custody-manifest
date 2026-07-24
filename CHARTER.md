# Technical Charter - Weight Custody Manifest

**Standards path**: IETF SCITT (technical) and CoSAI (positioning)
**Status**: pre-1.0 draft - public release is a deliberate Project Lead decision, not gated on open question 8.8
**Version**: 0.1 (aligned with spec v0.9)

---

## 1. Mission

The Weight Custody Manifest project develops and maintains an open specification and reference implementation for protecting a model builder's weights when they are deployed into a customer's own or sovereign infrastructure. It addresses the trust direction most systems ignore: not protecting the customer's data from the model, but protecting the **builder's weights** from the customer's hardware and operators.

The mission includes an explicit honesty commitment: the specification states plainly what current confidential-computing silicon does and does **not** guarantee, and never claims silicon-enforced custody against an operator who physically owns the hardware.

## 2. Scope

- **The specification** (`SPEC.md`) - the manifest schema, attestation-gated key release, runtime custody (wipe-on-lapse), derivative lineage, the transparency log, and the guarantee-scope statement.
- **The threat model** (`THREAT-MODEL.md`) - assets, trusted computing base, adversaries, threats, and residual risk.
- **Reference implementations** - a Python SDK (primary), with additional language SDKs as the community grows.
- **A reproducibly-built reference KBS image** - so the release service's measurement can be independently audited (§8.3).

Out of scope: model identity/passport concerns (left to the agentrust-io Model-* space), and fixing the hardware layer itself (the structural silicon limitation belongs to the CPU/GPU vendors).

## 3. Open-core

The specification, threat model, and reproducible reference KBS image are open (Apache-2.0) and live here. The operated custody service, the cMCP integration, and the enclave engineering are separate and proprietary to OPAQUE Systems. The value is in operating a trustworthy attested custodian and in the enclave implementation, not in keeping the format secret - and an auditable spec is a trust requirement for the builders and sovereigns WCM serves.

## 4. Governance

See [GOVERNANCE.md](GOVERNANCE.md) and [MAINTAINERS.md](MAINTAINERS.md). The Project Lead holds final authority pre-1.0; a Technical Steering Committee will be formalized before any standards-body submission.

## 5. Licensing

- Specification and documentation: Apache License 2.0.
- Code: Apache License 2.0.
- Contributions: under the Developer Certificate of Origin (DCO).
