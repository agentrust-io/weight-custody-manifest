---
title: "Weight Custody Manifest: key release only to attested runtimes"
description: An open, pre-1.0 specification for releasing model weights only to an approved, attested runtime, with the guarantee boundary stated plainly.
hide:
  - navigation
  - toc
---

[01 · Weights: is this the model that was released, and who may release its key?](https://agentrust-io.com/#chain)

# Release model weights only to an attested runtime

When a company hands its AI model to a customer to run on the customer's own
machines, WCM lets the model's maker decide which machines may use it. The
model files stay encrypted, and the key that decrypts them goes only to a program
that can prove, through a hardware check called attestation, that it is the
approved one. WCM is an open, pre-1.0 specification with a reference SDK you can
run today ([the terms, in plain English](https://agentrust-io.com/#plain-terms)).

[Run the 103 conformance vectors](#try-it){ .md-button .md-button--primary }
[What this proves, and what it does not](limitations.md){ .md-button }

!!! tip "TL;DR"
    The reference SDK ([weight-custody-manifest](https://pypi.org/project/weight-custody-manifest/)
    0.30.0, Apache-2.0) runs its test cases on an ordinary laptop with no GPU or
    cloud account, and checks hardware reports captured on real AMD SEV-SNP, Intel
    TDX and NVIDIA H100 machines. Against someone who physically owns the machine,
    WCM gives you a record and a way to hold them to account, not cryptographic
    custody, because published attacks on the memory bus defeat today's
    confidential-computing chips.

<div class="grid cards" markdown>

-   __Run it__

    ---

    `wcm conformance` runs every test level on your own computer. One test uses a
    genuine AMD hardware report; Intel and GPU vendor tests are still to come.

    [Try it](#try-it)

-   __What it proves, and what it does not__

    ---

    What someone who owns the hardware can still do, and why a valid signature
    cannot tell an approved key from a stolen one.

    [Limitations](limitations.md)

-   __Hardware evidence__

    ---

    AMD SEV-SNP (Azure), Intel TDX (GCP) and NVIDIA H100, each with a saved
    hardware report that anyone can re-check offline. H100 landed in
    [#54](https://github.com/agentrust-io/weight-custody-manifest/pull/54).

    [Roadmap](roadmap.md)

-   __The chain__

    ---

    Next: [Agent Manifest](https://manifest.agentrust-io.com) records which AI
    agent loads the model. Check a real Intel TDX hardware report yourself at
    [agentrust-io.com/verify](https://agentrust-io.com/verify/).

    [See the chain](https://agentrust-io.com/#chain)

</div>

!!! warning "Pre-1.0, design under review"
    This is a design under review, not a production standard. Do not rely on it
    for production.

## The trust direction

Usually the customer worries about the AI provider. When a frontier model is
installed inside a customer's own infrastructure (their own data center, a
national cloud, or a network cut off from the internet), the worry runs the other
way: the **model builder** now has its most valuable asset, the trained weights,
sitting on hardware and with staff it does not control. WCM is built for that
direction. It gives the builder:

- a signed manifest, a short document saying which model files may be released
  and on what terms;
- key release only to a workload that passes a fresh hardware check;
- automatic key wipe when approval lapses, and a way to revoke it early;
- a record of fine-tuned copies (derivatives) back to the original.

WCM answers one question: can a model builder release encrypted weights only to
an approved workload, keep that approval short-lived, and keep evidence of what
happened? The answer is yes for the reference protocol and its software checks,
with one boundary stated plainly in the next section.

WCM works alongside [OpenSSF Model Signing](oms-interoperability.md). Model
Signing proves which model files a publisher released. WCM decides whether the
key for those exact files may go to a freshly checked workload, and how long that
workload may keep it.

## Honest guarantee scope

WCM makes two separate promises and never blends them:

- **Cryptographic custody** against attackers working through software or over
  the network.
- **Accountability** against an operator who physically owns the hardware, which
  is *not* cryptographic custody. Cheap published attacks on the memory bus
  ([TEE.fail](https://tee.fail/), [BadRAM](https://badram.eu/)) defeat current
  confidential-computing chips. Against that operator WCM raises the cost, helps
  detect and contain a breach, supports legal recourse, and requires physical
  hardening.

See [Limitations](limitations.md) and the specification's §3.6.

| Against | What you get |
| --- | --- |
| **Local software demo** | Checks the reference protocol in an ordinary program. The operator can read its memory. The simulated hardware check gives no real confidentiality. |
| **Protected runtime** | Needs verified hardware evidence, trusted keys, a key sent only over the checked connection, an isolated workload, and enforced renewal. The machine's configuration, firmware, side channels and any way the serving software can export data all affect the result. |
| **Physical hardware owner** | Do not assume the weights cannot be extracted. Published physical attacks are why extra hardening and operator assumptions are needed. A valid signature alone cannot tell an approved key from an extracted one. |

The [RAND weight-security report](https://www.rand.org/pubs/research_reports/RRA2849-1.html)
gives background on the threats; it is not a certification of WCM. Passing the
reference test suite does not give a deployment an attacker-resistance rating.

## What is checked today

The reference implementation ships **103 portable conformance vectors**: 38 at L1,
43 at L2, 12 at L3, and 10 at L4. A conformance vector is a test case written as a
JSON file, so any implementation in any language can run it. Run them yourself
with `wcm conformance`.

This is the reference implementation testing itself, not independent
certification and not a test on real deployment hardware. One L2 vector checks a
genuine AMD SEV-SNP hardware report against AMD's published root certificate;
Intel vendor evidence and GPU signature checks are not yet covered, and the runner
prints those limits. See [Schema and conformance](conformance.md).

## Try it

You need Python 3.11+ and Git. No cloud account, GPU, model download, or API key.
Install WCM in its own environment, because other AgenTrust packages may need a
different version of the `cryptography` library.

```bash
python -m venv .venv-wcm
# bash: source .venv-wcm/bin/activate
# PowerShell: .venv-wcm\Scripts\Activate.ps1
python -m pip install weight-custody-manifest
wcm conformance
```

Then run the closed-model allow/deny example. It first presents an approved
software fingerprint (a measurement), then changes it:

```bash
git clone https://github.com/agentrust-io/integrations
cd integrations/demos
python demo-07-closed-weight/run.py
```

Expected: joint signature `True`, approved release `True`, then unapproved release
`False`, because the measurement is not in `accepted_measurements`. Both cases use
synthetic attestation and a placeholder key; words such as "enclave" in the output
do not mean real hardware was used. [Getting started](getting-started.md) covers
the SDK in full.

## Where it fits

- **National (sovereign) deployment.** Run a closed model inside infrastructure a
  country controls, while releasing the weights only to an approved, checked
  workload.
- **Enterprise and offline networks.** Deliver encrypted weights to machines the
  customer runs, without turning a one-time handoff into permanent permission.
- **Regulated model delivery.** Carry the signed policy, release decisions,
  renewals, revocations and fine-tune history as evidence others can check.

## Where to go next

- [How WCM works](tutorials/how-it-works.md), the six steps end to end
- [Specification overview](spec-overview.md) and the full [`SPEC.md`](https://github.com/agentrust-io/weight-custody-manifest/blob/main/SPEC.md)
- [Threat model](threat-model.md) and [Limitations](limitations.md)
- [Getting started with the SDK](getting-started.md) and the [reference KBS image](reference-kbs.md)
- [OpenSSF Model Signing interoperability](oms-interoperability.md)
- [Roadmap](roadmap.md) · [Governance](governance.md) · [Contributing](contributing.md)

## Get involved

WCM is pre-1.0 and open for review. Four ways in:

- **Model owners.** Test the release policy against the risks you actually face.
- **Runtime and cloud teams.** Add or review support for your hardware platform
  and show what your protected environment can deliver. Start with
  [CONTRIBUTING.md](https://github.com/agentrust-io/weight-custody-manifest/blob/main/CONTRIBUTING.md).
- **Security researchers.** Challenge the threat model, the saved test data, the
  hardware assumptions, and what WCM says it does not cover. Reporting process in
  [SECURITY.md](https://github.com/agentrust-io/weight-custody-manifest/blob/main/SECURITY.md).
- **Standards contributors.** Review the manifest, the portable evidence, the
  test levels, and where WCM meets other standards.

Open an issue or a discussion on
[github.com/agentrust-io/weight-custody-manifest](https://github.com/agentrust-io/weight-custody-manifest).

The specification, schema, test suite, reference SDK, threat model, and
reference key-release service are free to use under Apache-2.0. Vendors may build
compatible hosted services and protected-runtime products. Public availability
does not establish production readiness.

**Status:** pre-1.0 · SDK 0.30.0 · Apache-2.0 · SCITT and CoSAI standards path on
the [roadmap](roadmap.md) · Sponsored by OPAQUE, which funds the engineering,
infrastructure and confidential-computing work behind these projects. More
sponsors are welcome.
