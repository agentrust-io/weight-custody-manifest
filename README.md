# Weight Custody Manifest (WCM)

An open specification for protecting model weights when a builder deploys them into a customer's own or sovereign infrastructure.

> **Status: pre-1.0, draft. Not ready to build against.**
> This is an open protocol specification under active design, published for review and comment. Several load-bearing questions are still open (see `SPEC.md` section 8), including a known limitation of confidential-computing hardware against an operator who physically owns the machine. Do not rely on it for production.

## What this is

When a frontier model is deployed into a customer's own infrastructure (on-prem, sovereign cloud, air-gapped), the party at risk flips: it is now the model builder whose weights are exposed to the customer's hardware and operators. WCM is the protocol for that direction: a signed manifest describing which weights are released and under what terms, attestation-gated key release into a verified enclave, revocation and wipe-on-lapse, and a chain of custody for derivatives.

## Honest guarantee scope

The dishonest version of this document would say "physically impossible." It isn't, and the spec says so. WCM names two guarantees and never blends them:

- **Cryptographic custody** against software and remote adversaries (host OS, remote attacker, an operator with software access). One caveat: a *malicious hypervisor* can extract keys via ciphertext side channels unless AMD SEV-SNP ciphertext-hiding is enabled, so that is required for the claim to hold against a hypervisor-privileged operator.
- **Accountability-grade** protection against an operator who physically owns the hardware, *not* cryptographic custody. Current confidential-computing silicon (NVIDIA CC, AMD SEV-SNP, Intel TDX) is defeated by cheap, published memory-bus attacks (TEE.fail, BadRAM) that extract keys and forge attestation. There WCM offers cost, detection, containment, legal recourse, and a mandatory physical-hardening tier.

This is stated plainly in `SPEC.md` section 3.6 and throughout `THREAT-MODEL.md`. Read it before forming expectations; the honesty about what does and does not hold is the point.

## In RAND's weight-security terms

Frontier labs grade weight protection in RAND's *Securing AI Model Weights* (RRA2849-1): five attacker tiers (OC1 amateur → OC5 top nation-state) and five security levels, where a security level is a *whole-organization posture* - "a system that can likely thwart" the matching attacker tier. RAND recommends confidential computing as a weight-security measure, "backed by a strong consensus in industry," so WCM is an implementation of a RAND-endorsed measure.

Stated the way a lab grades it:

> **WCM is the RAND-recommended confidential-computing measure; it holds against the OC1–OC3 range and, by its own concession (`SPEC.md` §3.6), not against an OC4–OC5 actor who owns the hardware.**

Not faithful: *"WCM is SL3."* A security level is a whole-system posture (weight storage, physical, network, personnel, supply chain, incident response, …), so assigning one to a single control misuses the unit and reads as not knowing the framework. Place WCM by **OC tier** and by **measure** - the language a lab already grades in, used the way they use it.

_Reference: RAND, *Securing AI Model Weights: Preventing Theft and Misuse of Frontier Models* (RRA2849-1, 2024)._

## Open-core

This repository is the **open protocol layer**: the specification, the threat model, and (forthcoming) a reproducibly-built reference key-release-service image. The operated custody service and the enclave implementation are separate and are not part of this repository.

## Contents

- `SPEC.md` - the specification: manifest schema, attestation-gated release, runtime custody, derivative lineage, guarantee scope, and open questions.
- `THREAT-MODEL.md` - assets, trusted computing base, adversaries, threats, and residual risks.
- `schema/` - the normative manifest JSON Schema, **frozen at v1** and additive-only. The machine-readable form of `SPEC.md` §3.1; see `schema/README.md` for the versioning policy and the one constraint JSON Schema cannot express.
- `conformance/` - language-neutral test vectors an implementation in any language is checked against.
- `python/` - the Python reference SDK (build, sign, verify; the KBS gate and reference server; quote verification; transparency log; threshold; PQ profile). See `python/README.md`.
- `docs/` - documentation site sources (published to wcm.agentrust-io.com).
- `LIMITATIONS.md` - what WCM does **not** do; read alongside `SPEC.md` §3.6.

## Community & governance

- **Contributing**: `CONTRIBUTING.md` (DCO sign-off; the no-overclaiming rule)
- **Governance & maintainers**: `GOVERNANCE.md`, `MAINTAINERS.md`, `CHARTER.md`
- **Conduct & policy**: `CODE_OF_CONDUCT.md`, `ANTITRUST.md`, `PRIVACY.md`
- **Security**: `SECURITY.md` - report privately; the hardware-owner limitation is documented, not a vulnerability
- **Roadmap & changes**: `ROADMAP.md`, `CHANGELOG.md`, `ADOPTERS.md`

## Status

Pre-1.0, published for review and comment, **not for production**. Public release is a deliberate Project Lead decision and is **not** gated on the key-extraction half of open question 8.8: that residual is disclosed and scoped out of the operator-trust model (`SPEC.md` §3.6) rather than treated as a reason to withhold the document.

## License

Apache License 2.0. See `LICENSE`.

