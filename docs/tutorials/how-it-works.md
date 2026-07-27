# How WCM works (the six steps)

A plain-language tour of the flow. Nothing here assumes cryptography background;
the [runnable examples](https://github.com/agentrust-io/examples/tree/main/weight-custody-manifest) then run it for real.

## The problem, in one sentence

When a model builder deploys weights into **someone else's** infrastructure
(on-prem, sovereign cloud, air-gapped), the usual trust direction flips: the
party at risk is the **builder**, whose weights now sit on hardware and
operators it does not control. WCM is the protocol for that direction.

## The cast

- **Builder** - signs off on which weights and which serving stack are approved.
- **Custodian** - operates the key broker (KBS) that gates release. Jointly signs
  the manifest with the builder so neither acts alone.
- **Customer / operator** - runs the enclave on their own hardware. They are the
  party being constrained, so they never sign the manifest alone.
- **KBS** - the key broker: issues challenges, verifies attestation, releases the
  decryption key only into a verified enclave.

For an open-weight deployment these roles often collapse into one enterprise
governance function (see the [runnable examples](https://github.com/agentrust-io/examples/tree/main/weight-custody-manifest)).

## The six steps

**0. Certify - the manifest.** The builder writes a signed manifest: the
`weights_hash`, the release terms (license, permitted derivatives), and the
release policy (which hardware, which serving-image measurement, trusted-time
source). It is signed **jointly** by builder and custodian. This is the
enforceable, machine-checkable version of the deployment agreement.

**1. Verify - is this the real manifest?** Anyone can check the joint signature:
both the builder and the custodian (and the sovereign signer, under the
sovereign profile) must have signed, over the exact bytes. A tampered manifest
does not verify.

**2. Gate - attestation-gated release.** The KBS issues a single-use nonce. The
enclave returns evidence: a CPU confidential-VM quote and a *separate* GPU
report, both echoing the nonce. The KBS checks all of it - genuine hardware, the
platform the manifest requires, and a serving-image measurement matching what
the builder signed - and only then releases the decryption key into the enclave.
The key decrypts weights **only** under the builder-signed, measured serving
stack, so "no raw weight export path" can be a real property, not a promise.

**3. Custody - wipe-on-lapse.** The enclave holds the key only for the manifest's
attestation cadence window. If it does not re-attest in time, it **zeroizes** the
key from its own memory and stops serving - the key is gone, not suspended. This
bounds worst-case exposure to one cadence window even if a compromised host
blocks every revocation signal, *provided the clock cannot be stalled*
(`trusted_time_source`).

**4. Terms - license and field-of-use.** The manifest's `release_terms` carry the
license and usage restrictions; release happens only under the disclosed,
conforming configuration. The manifest turns contract text into a technical
release condition.

**5. Derive - lineage.** If the customer is permitted to fine-tune inside the
enclave, the result gets its own manifest with `derived_from` pointing at the
parent and a `rights_holder` recording the IP split - a chain of custody back to
the original.

**6. Revoke - the kill switch.** Either party (or the sovereign quorum) can
revoke; the enclave stops serving on the next cadence lapse at the latest.
Wipe-on-lapse is the floor underneath revocation.

## The honesty at the center

WCM never claims silicon-enforced custody against an operator who **physically
owns the hardware**. Cheap published attacks (TEE.fail, BadRAM) defeat current
confidential-computing silicon. Against that adversary WCM offers cost,
detection, containment, legal recourse, and mandatory physical hardening - not
cryptographic custody. See [Limitations](../limitations.md) and `SPEC.md` §3.6.

## Closed vs open weights

For a **closed** model, steps 0-2 are doing secrecy work: keep the weights
hidden. For an **open** model the base weights are public, so that secrecy is
theater - but the same steps still do integrity, license, and (above all)
derivative-custody work. That flip is shown in the
[runnable open-model example](https://github.com/agentrust-io/examples/tree/main/weight-custody-manifest).
