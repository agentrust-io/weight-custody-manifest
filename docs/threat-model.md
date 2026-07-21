# Threat model

The full threat model is [`THREAT-MODEL.md`](https://github.com/agentrust-io/weight-custody-manifest/blob/main/THREAT-MODEL.md). A map of every threat to what the SDK actually enforces is in the [implementation audit](https://github.com/agentrust-io/weight-custody-manifest/blob/main/python/docs/threat-model-implementation-audit.md).

## Assets

Decrypted weights, the decryption key, manifest integrity, attestation quotes,
audit receipts, derivative weights, and signing keys.

## Adversaries

A malicious or compromised customer operator (privileged on the host), a
malicious custodian insider, a network adversary, a malicious or coerced builder
(the sovereign case), a co-located side-channel tenant, and a supply-chain
attacker.

## The load-bearing assumption

WCM's guarantees hold only as far as the trusted computing base does. The honest
core: current confidential-computing silicon does **not** protect the key or
attestation integrity against an operator who physically owns the hardware
(TEE.fail, BadRAM). Against that adversary WCM provides cost, detection,
containment, legal recourse, and mandatory physical hardening - not cryptographic
custody. See [Limitations](limitations.md).
