[01 · Weights: is this the model that was released, and who may release its key?](https://agentrust-io.com/#chain)

# Release model weights only to an attested runtime

WCM is an open, pre-1.0 specification that binds encrypted weights to a signed release policy, so a key broker releases the decryption key only to a workload whose attestation matches the manifest.

[Run the 95 conformance vectors](#try-it) [What this proves, and what it does not](https://wcm.agentrust-io.com/limitations/index.md)

TL;DR

The reference SDK ([weight-custody-manifest](https://pypi.org/project/weight-custody-manifest/) 0.28.4, Apache-2.0) runs its conformance vectors offline with no GPU or cloud account, and verifies AMD SEV-SNP, Intel TDX and NVIDIA H100 CC evidence captured on real hardware. Against an operator who physically owns the machine, WCM offers accountability, not cryptographic custody, because published memory-bus attacks defeat current confidential-computing silicon.

- **Run it**

  ______________________________________________________________________

  `wcm conformance` runs every level offline. One vector uses a genuine AMD report and staged root; Intel and GPU vendor vectors remain open.

  [Try it](#try-it)

- **What it proves, and what it does not**

  ______________________________________________________________________

  What an operator who owns the hardware can still do, and why a valid signature cannot tell an authorized key from an extracted one.

  [Limitations](https://wcm.agentrust-io.com/limitations/index.md)

- **Hardware evidence**

  ______________________________________________________________________

  AMD SEV-SNP (Azure), Intel TDX (GCP) and NVIDIA H100 CC, each with a committed fixture that verifies offline. H100 landed in [#54](https://github.com/agentrust-io/weight-custody-manifest/pull/54).

  [Roadmap](https://wcm.agentrust-io.com/roadmap/index.md)

- **The chain**

  ______________________________________________________________________

  Next: [Agent Manifest](https://manifest.agentrust-io.com) records the agent that loads the weights. Check a real TDX quote yourself at [agentrust-io.com/verify](https://agentrust-io.com/verify/).

  [See the chain](https://agentrust-io.com/#chain)

Pre-1.0, design under review

This is a design under review, not a production standard. Do not rely on it for production.

## The trust direction

When a frontier model is deployed into a customer's own infrastructure (on-prem, sovereign cloud, air-gapped), the party at risk flips: it is now the **model builder** whose weights are exposed to the customer's hardware and operators. WCM is the protocol for that direction: a signed manifest describing which weights are released and under what terms, attestation-gated key release into a verified enclave, wipe-on-lapse and revocation, and a chain of custody for derivatives.

WCM answers one question: can a model builder release encrypted weights only to an approved workload, keep that approval short-lived, and retain evidence of what happened? The answer is yes for the reference protocol and its software checks, with one boundary stated plainly rather than buried, in the next section.

WCM composes with [OpenSSF Model Signing](https://wcm.agentrust-io.com/oms-interoperability/index.md) rather than competing with it: OMS proves which model artifact a signer published; WCM governs whether the key for those exact bytes may be released to a freshly attested workload and how long that workload may retain it.

## Honest guarantee scope

WCM names two guarantees and never blends them:

- **Cryptographic custody** against software and remote adversaries.
- **Accountability-grade** protection against an operator who physically owns the hardware, *not* cryptographic custody. Cheap published memory-bus attacks ([TEE.fail](https://tee.fail/), [BadRAM](https://badram.eu/)) defeat current confidential-computing silicon; there WCM offers cost, detection, containment, legal recourse, and a mandatory physical-hardening tier.

See [Limitations](https://wcm.agentrust-io.com/limitations/index.md) and the specification's §3.6.

| Against                     | What you get                                                                                                                                                                                                                 |
| --------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Local software demo**     | Checks the reference protocol in an ordinary process. The operator can inspect its memory. Mock attestation provides no hardware-rooted confidentiality.                                                                     |
| **Protected runtime**       | Requires verified platform evidence, trusted keys, channel binding, workload isolation, and enforced renewal. Platform configuration, firmware, side channels, and the serving application's export paths affect the result. |
| **Physical hardware owner** | Do not assume weight extraction is impossible. Published physical attacks motivate additional hardening and operator assumptions. A valid signature alone cannot distinguish an authorized key from an extracted one.        |

The [RAND weight-security report](https://www.rand.org/pubs/research_reports/RRA2849-1.html) provides threat-model context; it is not a certification of WCM. Passing the reference suite does not assign a deployment an attacker-resistance tier.

## What is checked today

The reference implementation ships **97 portable conformance vectors**: 32 at L1, 43 at L2, 12 at L3, and 10 at L4. Run them yourself with `wcm conformance`.

This is the reference implementation's self-test, not independent certification and not a hardware deployment test. One L2 vector verifies genuine AMD SEV-SNP evidence against the staged AMD root; Intel vendor evidence and GPU cryptographic verification remain uncovered, and the runner prints those limits. See [Schema and conformance](https://wcm.agentrust-io.com/conformance/index.md).

## Try it

Python 3.11+ and Git. No cloud account, GPU, model download, or API key. Keep WCM in its own environment, because other AgenTrust packages may require a different `cryptography` version.

```
python -m venv .venv-wcm
# bash: source .venv-wcm/bin/activate
# PowerShell: .venv-wcm\Scripts\Activate.ps1
python -m pip install weight-custody-manifest
wcm conformance
```

Then run the closed-weight allow/deny example, which supplies an approved serving measurement and then changes it:

```
git clone https://github.com/agentrust-io/demos
cd demos
python demo-07-closed-weight/run.py
```

Expected: joint signature `True`, approved release `True`, then unapproved release `False`, because the measurement is not in `accepted_measurements`. Both cases use synthetic attestation and a placeholder key; labels such as "enclave" in the output do not mean hardware was used. [Getting started](https://wcm.agentrust-io.com/getting-started/index.md) covers the SDK in full.

## Where it fits

- **Sovereign deployment.** Run a closed model inside nationally controlled infrastructure while making weight release conditional on an approved, attested workload.
- **Enterprise and air-gapped.** Deliver encrypted weights to customer-operated environments without turning a one-time handoff into permanent authorization.
- **Regulated model delivery.** Carry signed policy, release decisions, renewal state, revocation, and derivative lineage as portable evidence.

## Where to go next

- [How WCM works](https://wcm.agentrust-io.com/tutorials/how-it-works/index.md), the six steps end to end
- [Specification overview](https://wcm.agentrust-io.com/spec-overview/index.md) and the full [`SPEC.md`](https://github.com/agentrust-io/weight-custody-manifest/blob/main/SPEC.md)
- [Threat model](https://wcm.agentrust-io.com/threat-model/index.md) and [Limitations](https://wcm.agentrust-io.com/limitations/index.md)
- [Getting started with the SDK](https://wcm.agentrust-io.com/getting-started/index.md) and the [reference KBS image](https://wcm.agentrust-io.com/reference-kbs/index.md)
- [OpenSSF Model Signing interoperability](https://wcm.agentrust-io.com/oms-interoperability/index.md)
- [Roadmap](https://wcm.agentrust-io.com/roadmap/index.md) · [Governance](https://wcm.agentrust-io.com/governance/index.md) · [Contributing](https://wcm.agentrust-io.com/contributing/index.md)

## Get involved

WCM is pre-1.0 and the review is open. Four routes in:

- **Model owners.** Pressure-test the release policy against your actual threat model.
- **Runtime and cloud teams.** Add or review an attestation profile and prove what your protected boundary can support. Start with [CONTRIBUTING.md](https://github.com/agentrust-io/weight-custody-manifest/blob/main/CONTRIBUTING.md).
- **Security researchers.** Challenge the threat model, fixtures, hardware assumptions, and explicit non-goals. Reporting process in [SECURITY.md](https://github.com/agentrust-io/weight-custody-manifest/blob/main/SECURITY.md).
- **Standards contributors.** Review the manifest, portable evidence, conformance levels, and interoperability boundaries.

Open an issue or a discussion on [github.com/agentrust-io/weight-custody-manifest](https://github.com/agentrust-io/weight-custody-manifest).

The specification, schema, conformance suite, reference SDK, threat model, and reference key-release service are available under Apache-2.0. Vendors may build interoperable hosted services and protected-runtime implementations. Public availability does not establish production readiness.

**Status:** pre-1.0 · SDK 0.28.4 · Apache-2.0 · SCITT and CoSAI standards path on the [roadmap](https://wcm.agentrust-io.com/roadmap/index.md) · Sponsored by OPAQUE, which funds the engineering, infrastructure and confidential-computing work behind these projects.
