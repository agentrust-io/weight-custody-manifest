# Specification overview

A one-page summary of what the WCM specification defines, for readers deciding
whether to read the full text. Each layer below starts with what it does in plain
words, then names the parts the specification pins down.

The full normative text (the binding rules) is [`SPEC.md`](https://github.com/agentrust-io/weight-custody-manifest/blob/main/SPEC.md) (v0.15). WCM is four layers plus a public, append-only log. The machine-readable form of the manifest, and the test cases an implementation is checked against, are on the [schema and conformance](conformance.md) page.

## Layer 1 - the manifest

A signed document saying exactly which model files may be released, and on what
terms.

It records the `weights_hash`, the release terms, the release policy (assurance
tier, required platforms and serving image, trusted-time source, memory
fingerprint challenge), and custody details. The builder and the custodian sign it
**together**, never the customer alone, and a group of national signers can be
added.

## Layer 2 - attestation-gated key release

The key goes out only after fresh hardware evidence passes every check.

The key broker (KBS) sends a one-time number (nonce). The enclave returns combined
evidence: a signed report from the CPU's protected virtual machine and a
*separate* GPU report, both tied to that number. The KBS releases the key only if
every check passes: platform, assurance tier, serving-image status (preferring the
current approved image), GPU measurement and the link between CPU and GPU, a
memory fingerprint when the hardware owner is treated as hostile, and up-to-date
revocation information.

## Layer 3 - runtime custody (wipe-on-lapse)

The protected environment keeps the key only for a short window and must keep
proving itself to hold on to it.

The enclave holds the key only for the attestation window and erases it if it
does not pass the check again in time; the key is *gone*, not paused. This limits
the worst case to one window against an operator who cannot fake the hardware
check, as long as the clock can be trusted (`trusted_time_source`).

## Layer 4 - derivative lineage

Fine-tuned copies keep a record that points back to the original.

A fine-tune produces a new `weights_hash`, with `derived_from` pointing at its
parent and a `rights_holder` recording who owns what, forming a chain back to the
original model.

## Transparency (§3.7)

A public log that can only be added to, so nobody can quietly show different
people different histories or hide a revocation.

It is an append-only Merkle log (RFC 9162) with signed tree heads, which makes
that kind of double-dealing (equivocation) and suppressed revocations detectable.

## Guarantee scope (§3.6) - read this

WCM does not claim that the chip alone keeps the key safe from someone who owns
the bare machine and has done no physical hardening. That setup is out of scope on
purpose. See [Limitations](limitations.md).
