---
title: Weight Custody Manifest
description: An open, pre-1.0 specification for releasing model weights only to an approved, attested runtime, with the guarantee boundary stated plainly.
---

# Weight Custody Manifest

An open specification for protecting model weights when a builder deploys them
into a customer's own or sovereign infrastructure.

!!! warning "Pre-1.0, design under review"
    This is a design under review, not a production standard. Public release is a
    deliberate decision by the Project Lead and is not gated on open question 8.8;
    the hostile-owner residual is documented, not a release blocker. Do not rely
    on it for production.

!!! tip "TL;DR"
    WCM binds encrypted weights to a signed release policy. A key broker releases
    the decryption key only to a workload whose attestation evidence matches the
    manifest, keeps that authorization short-lived, and leaves portable evidence
    of the decision. The reference SDK, its 91 conformance vectors, the schema and
    the threat model are public under Apache-2.0. Against an adversary who
    physically owns the hardware, WCM offers accountability, not cryptographic
    custody, and says so in [Limitations](limitations.md).

## The trust direction

When a frontier model is deployed into a customer's own infrastructure (on-prem,
sovereign cloud, air-gapped), the party at risk flips: it is now the **model
builder** whose weights are exposed to the customer's hardware and operators. WCM
is the protocol for that direction - a signed manifest describing which weights
are released and under what terms, attestation-gated key release into a verified
enclave, wipe-on-lapse and revocation, and a chain of custody for derivatives.

WCM answers one question: can a model builder release encrypted weights only to
an approved workload, keep that approval short-lived, and retain evidence of what
happened? The answer is yes for the reference protocol and its software checks,
with one boundary stated plainly rather than buried, in the next section.

WCM composes with [OpenSSF Model Signing](oms-interoperability.md) rather than
competing with it: OMS proves which model artifact a signer published; WCM
governs whether the key for those exact bytes may be released to a freshly
attested workload and how long that workload may retain it.

## Honest guarantee scope

WCM names two guarantees and never blends them:

- **Cryptographic custody** against software and remote adversaries.
- **Accountability-grade** protection against an operator who physically owns the
  hardware - *not* cryptographic custody. Cheap published memory-bus attacks
  ([TEE.fail](https://tee.fail/), [BadRAM](https://badram.eu/)) defeat current
  confidential-computing silicon; there WCM offers cost, detection, containment,
  legal recourse, and a mandatory physical-hardening tier.

The honesty about what does and does not hold is the point. See
[Limitations](limitations.md) and the specification's §3.6.

| Against | What you get |
| --- | --- |
| **Local software demo** | Checks the reference protocol in an ordinary process. The operator can inspect its memory. Mock attestation provides no hardware-rooted confidentiality. |
| **Protected runtime** | Requires verified platform evidence, trusted keys, channel binding, workload isolation, and enforced renewal. Platform configuration, firmware, side channels, and the serving application's export paths affect the result. |
| **Physical hardware owner** | Do not assume weight extraction is impossible. Published physical attacks motivate additional hardening and operator assumptions. A valid signature alone cannot distinguish an authorized key from an extracted one. |

The [RAND weight-security report](https://www.rand.org/pubs/research_reports/RRA2849-1.html)
provides threat-model context; it is not a certification of WCM. Passing the
reference suite does not assign a deployment an attacker-resistance tier.

## What is checked today

The reference implementation ships **91 portable conformance vectors**: 32 at L1,
37 at L2, 12 at L3, and 10 at L4. Run them yourself with `wcm conformance`.

This is the reference implementation's self-test, not independent certification
and not a hardware deployment test. CPU quote vectors use synthetic certificate
roots, GPU cryptographic verification is not covered by them, and the runner
prints its uncovered cases. See [Schema and conformance](conformance.md).

## Try it

Python 3.11+ and Git. No cloud account, GPU, model download, or API key. Keep WCM
in its own environment, because other AgenTrust packages may require a different
`cryptography` version.

```bash
python -m venv .venv-wcm
# bash: source .venv-wcm/bin/activate
# PowerShell: .venv-wcm\Scripts\Activate.ps1
python -m pip install weight-custody-manifest
wcm conformance
```

Then run the closed-weight allow/deny example, which supplies an approved serving
measurement and then changes it:

```bash
git clone https://github.com/agentrust-io/demos
cd demos
python demo-07-closed-weight/run.py
```

Expected: joint signature `True`, approved release `True`, then unapproved release
`False`, because the measurement is not in `accepted_measurements`. Both cases use
synthetic attestation and a placeholder key; labels such as "enclave" in the output
do not mean hardware was used. [Getting started](getting-started.md) covers the SDK
in full.

## Where it fits

- **Sovereign deployment.** Run a closed model inside nationally controlled
  infrastructure while making weight release conditional on an approved, attested
  workload.
- **Enterprise and air-gapped.** Deliver encrypted weights to customer-operated
  environments without turning a one-time handoff into permanent authorization.
- **Regulated model delivery.** Carry signed policy, release decisions, renewal
  state, revocation, and derivative lineage as portable evidence.

## Where to go next

- [How WCM works](tutorials/how-it-works.md), the six steps end to end
- [Specification overview](spec-overview.md) and the full [`SPEC.md`](https://github.com/agentrust-io/weight-custody-manifest/blob/main/SPEC.md)
- [Threat model](threat-model.md) and [Limitations](limitations.md)
- [Getting started with the SDK](getting-started.md) and the [reference KBS image](reference-kbs.md)
- [OpenSSF Model Signing interoperability](oms-interoperability.md)
- [Roadmap](roadmap.md) · [Governance](governance.md) · [Contributing](contributing.md)

## Get involved

WCM is pre-1.0 and the review is open. Four routes in:

- **Model owners.** Pressure-test the release policy against your actual threat model.
- **Runtime and cloud teams.** Add or review an attestation profile and prove what
  your protected boundary can support. Start with
  [CONTRIBUTING.md](https://github.com/agentrust-io/weight-custody-manifest/blob/main/CONTRIBUTING.md).
- **Security researchers.** Challenge the threat model, fixtures, hardware
  assumptions, and explicit non-goals. Reporting process in
  [SECURITY.md](https://github.com/agentrust-io/weight-custody-manifest/blob/main/SECURITY.md).
- **Standards contributors.** Review the manifest, portable evidence, conformance
  levels, and interoperability boundaries.

Open an issue or a discussion on
[github.com/agentrust-io/weight-custody-manifest](https://github.com/agentrust-io/weight-custody-manifest).

The specification, schema, conformance suite, reference SDK, threat model, and
reference key-release service are available under Apache-2.0. Vendors may build
interoperable hosted services and protected-runtime implementations. Public
availability does not establish production readiness.
