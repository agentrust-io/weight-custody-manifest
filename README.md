# Weight Custody Manifest (WCM)

An open specification for protecting model weights when a builder deploys them into a customer's own or sovereign infrastructure.

> **Status: pre-1.0 public review release.** The protocol and SDK are ready for independent review and interoperability work; production deployments still require the limits in `LIMITATIONS.md` and `THREAT-MODEL.md` to be accepted.
> This is an open protocol specification under active design, published for review and comment. Several load-bearing questions are still open (see `SPEC.md` section 8), including a known limitation of confidential-computing hardware against an operator who physically owns the machine. Do not rely on it for production.

## Start here

WCM answers one question:

> **Can a model builder release encrypted weights only to an approved workload,
> keep that approval short-lived, and retain evidence of what happened?**

The answer is **yes for the reference protocol and software checks**, with an
important boundary: hardware owners remain outside the cryptographic guarantee.
WCM makes that limitation visible instead of turning it into a marketing claim.

Choose the path that matches what you need:

| If you are… | Read this first | What you will learn |
|---|---|---|
| An executive, policymaker, or risk owner | [The two-minute overview](docs/index.md) | The problem, guarantee, and residual risk without implementation detail |
| A security reviewer | [Threat model](THREAT-MODEL.md), then [limitations](LIMITATIONS.md) | Assets, adversaries, controls, and what a hardware owner can still do |
| A protocol or standards reviewer | [Specification](SPEC.md), then [schema policy](schema/README.md) | Normative behavior, open questions, and compatibility rules |
| An application engineer | [Python quick start](python/README.md) | Build, sign, verify, and gate a manifest locally |
| A platform or confidential-computing engineer | [How it works](docs/tutorials/how-it-works.md), then [measured launch](docs/measured-launch.md) | CPU/GPU attestation, PCR binding, key release, renewal, and wipe semantics |
| An implementer in another language | [Conformance suite](conformance/README.md) | Portable vectors, levels, error codes, and runner contract |
| A contributor or maintainer | [Contributing](CONTRIBUTING.md), then [public release](PUBLIC-RELEASE.md) | Change rules, required evidence, CI, and release safety |

### The protocol in six steps

1. The builder encrypts model weights and signs a manifest containing the exact
   weight and approved-workload measurements.
2. A protected workload asks the key broker (KBS) for a fresh, single-use
   challenge.
3. CPU—and, when required, GPU—attestation binds that challenge, the workload
   measurement, and an ephemeral transport key to the current launch.
4. The KBS independently checks the manifest policy, certificate chain,
   signatures, revocation state, measurements, freshness, and channel binding.
5. Only if every required check passes, the KBS seals the model key to the
   attested transport key. It does not send plaintext key material.
6. The protected runtime periodically renews authorization. A lapse means stop
   serving and wipe the in-memory key; resuming requires a new successful
   attestation and release.

### Five-minute local proof

This exercises the reference implementation with synthetic evidence. It proves
the SDK and policy gate work together; it is **not** hardware validation.

```bash
cd python
python -m venv .venv
# Linux/macOS: source .venv/bin/activate
# Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
pytest -q tests/test_examples.py tests/test_kbs.py tests/test_custody.py
wcm conformance
```

Success means the example, release gate, custody state machine, and portable
conformance vectors pass on your machine. For real deployment evidence, use the
provider-specific procedures linked from [the implementation README](python/README.md).

### What is implemented, and what still needs hardware evidence

| Capability | Repository status | Claim you may make |
|---|---|---|
| Manifest schema, signatures, lineage, and portable conformance | Implemented and tested | Protocol/reference behavior conforms to the checked vectors |
| Attestation-gated, transport-key-sealed release | Implemented; provider paths have documented validation status | A configured verifier fails closed on the checks it performs |
| Azure vTPM workload binding | PCR 23 digest is checked against the manifest-approved measurement | The signed quote matches the expected measured-launch PCR state |
| Renewable lease and wipe-on-lapse semantics | Reference state machine implemented | The Python reference transitions to wiped and refuses later use |
| Protected-memory fingerprint sweep | Policy plumbing exists; protected-boundary implementation evidence remains open | Do **not** claim the repository detects real memory aliasing yet |
| Production zeroization and inference termination | Reference semantics exist; production controller evidence remains open | Do **not** claim language/runtime/hardware zeroization from unit tests |

The last two rows are deliberately explicit: issues
[#79](https://github.com/agentrust-io/weight-custody-manifest/issues/79) and
[#78](https://github.com/agentrust-io/weight-custody-manifest/issues/78) require
evidence from the actual protected runtime, not a more persuasive simulation.

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

This repository is the **open protocol layer**: the specification, the threat model, and a reproducibly-built reference key-release-service image. The operated custody service and the enclave implementation are separate and are not part of this repository.

## Contents

- `SPEC.md` - the specification: manifest schema, attestation-gated release, runtime custody, derivative lineage, guarantee scope, and open questions.
- `THREAT-MODEL.md` - assets, trusted computing base, adversaries, threats, and residual risks.
- `schema/` - the normative manifest JSON Schema, **frozen at v1** and additive-only. The machine-readable form of `SPEC.md` §3.1; see `schema/README.md` for the versioning policy and the one constraint JSON Schema cannot express.
- `conformance/` - language-neutral test vectors and a scoring contract, run by `wcm conformance`. All four levels are vectored (91 vectors) and every reportable error code is exercised; L1 and L4 over documents, L2 and L3 as time-ordered scenarios. The runner prints its remaining limits (a synthetic PKI rather than vendor roots, and no GPU-side crypto vectors) on every run, so a pass is not read as more than it is. See `conformance/README.md`.
- `python/` - the Python reference SDK (build, sign, verify; the KBS gate and reference server; quote verification; transparency log; threshold; PQ profile). See `python/README.md`.
- `docs/` - documentation site sources (published to wcm.agentrust-io.com).
- `docs/oms-interoperability.md` - how WCM composes with OpenSSF Model Signing:
  OMS proves artifact authenticity and integrity; WCM governs attestation-gated
  key release and runtime custody for those exact bytes.
- `LIMITATIONS.md` - what WCM does **not** do; read alongside `SPEC.md` §3.6.
- `PUBLIC-RELEASE.md` - the reproducible checklist for cutting a public release without treating a green build as a security certification.

## Community & governance

- **Contributing**: `CONTRIBUTING.md` (DCO sign-off; the no-overclaiming rule)
- **Governance & maintainers**: `GOVERNANCE.md`, `MAINTAINERS.md`, `CHARTER.md`
- **Conduct & policy**: `CODE_OF_CONDUCT.md`, `ANTITRUST.md`, `PRIVACY.md`
- **Security**: `SECURITY.md` - report privately; the hardware-owner limitation is documented, not a vulnerability
- **Roadmap & changes**: `ROADMAP.md`, `CHANGELOG.md`, `ADOPTERS.md`

## Status

Pre-1.0, published for review and comment, **not a production certification**. Public release is a deliberate project decision and is **not** gated on the key-extraction half of open question 8.8: that residual is disclosed and scoped out of the operator-trust model (`SPEC.md` §3.6) rather than treated as a reason to withhold the document.

## License

Apache License 2.0. See `LICENSE`.

