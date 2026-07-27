# Specification overview

The full normative text is [`SPEC.md`](https://github.com/agentrust-io/weight-custody-manifest/blob/main/SPEC.md) (v0.13). WCM is four layers plus a transparency log.

## Layer 1 - the manifest

A builder issues a signed manifest describing exactly which weights are released
and under what terms: `weights_hash`, release terms, release policy (assurance
tier, required platforms and serving image, trusted-time source, memory
fingerprint challenge), and custody. It is signed **jointly** by the builder and
the custodian - never by the customer alone - with an optional sovereign quorum.

## Layer 2 - attestation-gated key release

The key broker (KBS) issues a single-use nonce; the enclave returns composite
evidence (a CPU CVM quote and a *separate* GPU report, both bound to the nonce);
the KBS releases the key only if every check passes (platform, assurance tier,
serving-image status with prefer-current, GPU measurement and CPU↔GPU binding,
memory fingerprint in the hostile-owner posture, revocation freshness).

## Layer 3 - runtime custody (wipe-on-lapse)

The enclave holds the key only for the attestation cadence window and zeroizes it
if it does not re-attest in time - the key is *gone*, not suspended. This bounds
worst-case exposure to one cadence window against an operator who cannot forge
attestation, subject to a trusted clock (`trusted_time_source`).

## Layer 4 - derivative lineage

A fine-tune produces a new `weights_hash` with `derived_from` pointing at its
parent and a `rights_holder` recording the IP split, forming a chain of custody
back to the root.

## Transparency (§3.7)

An append-only Merkle log (RFC 9162) with signed tree heads makes equivocation
and suppressed revocations detectable.

## Guarantee scope (§3.6) - read this

WCM does not claim silicon-enforced custody against a bare-metal owner with no
physical hardening. That configuration is out of scope, deliberately. See
[Limitations](limitations.md).
