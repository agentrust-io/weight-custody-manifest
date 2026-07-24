# Weight Custody Manifest

An open specification for protecting model weights when a builder deploys them
into a customer's own or sovereign infrastructure.

!!! warning "Pre-1.0, design under review"
    This is a design under review, not a production standard. Public release is a
    deliberate decision by the Project Lead and is not gated on open question 8.8;
    the hostile-owner residual is documented, not a release blocker. Do not rely
    on it for production.

## The trust direction

When a frontier model is deployed into a customer's own infrastructure (on-prem,
sovereign cloud, air-gapped), the party at risk flips: it is now the **model
builder** whose weights are exposed to the customer's hardware and operators. WCM
is the protocol for that direction - a signed manifest describing which weights
are released and under what terms, attestation-gated key release into a verified
enclave, wipe-on-lapse and revocation, and a chain of custody for derivatives.

## Honest guarantee scope

WCM names two guarantees and never blends them:

- **Cryptographic custody** against software and remote adversaries.
- **Accountability-grade** protection against an operator who physically owns the
  hardware - *not* cryptographic custody. Cheap published memory-bus attacks
  (TEE.fail, BadRAM) defeat current confidential-computing silicon; there WCM
  offers cost, detection, containment, legal recourse, and a mandatory
  physical-hardening tier.

The honesty about what does and does not hold is the point. See
[Limitations](limitations.md) and the specification's §3.6.

## Where to go next

- [Specification overview](spec-overview.md) and the full [`SPEC.md`](https://github.com/agentrust-io/weight-custody-manifest/blob/main/SPEC.md)
- [Threat model](threat-model.md)
- [Getting started with the SDK](getting-started.md)
- [Reference KBS image](reference-kbs.md)
- [Roadmap](roadmap.md) · [Governance](governance.md) · [Contributing](contributing.md)
