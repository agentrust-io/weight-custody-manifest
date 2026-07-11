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

In RAND's *Securing AI Model Weights* terms, WCM is the recommended confidential-computing measure holding against the OC1-OC3 attacker tiers; it is one control in a weight-security posture, not a whole "security level," and it does not hold against an OC4-OC5 actor who owns the hardware. This is stated plainly in `SPEC.md` section 3.6 and throughout `THREAT-MODEL.md`. Read it before forming expectations; the honesty about what does and does not hold is the point.

## Open-core

This repository is the **open protocol layer**: the specification, the threat model, and (forthcoming) a reproducibly-built reference key-release-service image. The operated custody service and the enclave implementation are separate and are not part of this repository.

## Contents

- `SPEC.md` — the specification: manifest schema, attestation-gated release, runtime custody, derivative lineage, guarantee scope, and open questions.
- `THREAT-MODEL.md` — assets, trusted computing base, adversaries, threats, and residual risks.

## License

Apache License 2.0. See `LICENSE`.
