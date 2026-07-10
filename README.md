# Weight Custody Manifest (WCM)

An open specification for protecting model weights when a builder deploys them into a customer's own or sovereign infrastructure.

> **Status: pre-1.0, draft. Not ready to build against.**
> This is an open protocol specification under active design, published for review and comment. Several load-bearing questions are still open (see `SPEC.md` section 8), including a known limitation of confidential-computing hardware against an operator who physically owns the machine. Do not rely on it for production.

## What this is

When a frontier model is deployed into a customer's own infrastructure (on-prem, sovereign cloud, air-gapped), the party at risk flips: it is now the model builder whose weights are exposed to the customer's hardware and operators. WCM is the protocol for that direction: a signed manifest describing which weights are released and under what terms, attestation-gated key release into a verified enclave, revocation and wipe-on-lapse, and a chain of custody for derivatives.

## Honest guarantee scope

WCM is **custody-grade against software and remote adversaries** (host OS, hypervisor, remote attacker, an operator with software access). It is **not** silicon-absolute against an operator who physically owns the hardware. Current confidential-computing silicon (NVIDIA CC, AMD SEV-SNP, Intel TDX) protects against software attackers but is defeated by cheap, published physical memory-bus attacks (TEE.fail, BadRAM) that can extract keys and forge attestation. Against a hardware owner, WCM offers cost, detection, containment, legal recourse, and a mandatory physical-hardening tier, not absolute custody.

This is stated plainly in `SPEC.md` section 3.6 and throughout `THREAT-MODEL.md`. Read it before forming expectations; the honesty about what does and does not hold is the point.

## In RAND's weight-security terms

Frontier labs grade weight protection in RAND's *Securing AI Model Weights* (RRA2849-1): five attacker tiers (OC1 amateur → OC5 top nation-state) and five security levels, where a security level is a *whole-organization posture* — "a system that can likely thwart" the matching attacker tier. RAND recommends confidential computing as a weight-security measure, "backed by a strong consensus in industry," so WCM is an implementation of a RAND-endorsed measure.

Stated the way a lab grades it:

> **WCM is the RAND-recommended confidential-computing measure; it holds against the OC1–OC3 range and, by its own concession (`SPEC.md` §3.6), not against an OC4–OC5 actor who owns the hardware.**

Not faithful: *"WCM is SL3."* A security level is a whole-system posture (weight storage, physical, network, personnel, supply chain, incident response, …), so assigning one to a single control misuses the unit and reads as not knowing the framework. Place WCM by **OC tier** and by **measure** — the language a lab already grades in, used the way they use it.

_Reference: RAND, *Securing AI Model Weights: Preventing Theft and Misuse of Frontier Models* (RRA2849-1, 2024)._

## Open-core

This repository is the **open protocol layer**: the specification, the threat model, and (forthcoming) a reproducibly-built reference key-release-service image. The operated custody service and the enclave implementation are separate and are not part of this repository.

## Contents

- `SPEC.md` — the specification: manifest schema, attestation-gated release, runtime custody, derivative lineage, guarantee scope, and open questions.
- `THREAT-MODEL.md` — assets, trusted computing base, adversaries, threats, and residual risks.

## License

Apache License 2.0. See `LICENSE`.
