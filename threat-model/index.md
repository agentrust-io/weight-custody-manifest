# Threat model

What WCM protects, who it protects against, and the one assumption everything rests on. Security reviewers should start here, then read [Limitations](https://wcm.agentrust-io.com/limitations/index.md).

The full threat model is [`THREAT-MODEL.md`](https://github.com/agentrust-io/weight-custody-manifest/blob/main/THREAT-MODEL.md). A map of every threat to what the SDK actually enforces is in the [implementation audit](https://github.com/agentrust-io/weight-custody-manifest/blob/main/python/docs/threat-model-implementation-audit.md).

## Assets

The things worth stealing or tampering with: decrypted weights, the decryption key, manifest integrity, attestation quotes (signed hardware reports), audit receipts, derivative weights, and signing keys.

## Adversaries

The people WCM plans for: a malicious or compromised customer operator with admin rights on the host, a malicious insider at the custodian, an attacker on the network, a malicious or pressured builder (the sovereign case), another tenant on the same machine trying to read data through side channels, and an attacker who tampers with software before it arrives (supply chain).

## The load-bearing assumption

The model owner must trust whoever controls key release. A customer who can read the model key, or swap out the key service's (KBS/Trustee) checking code and policy, can go around the hardware check without attacking the protected hardware (the TEE) at all. Internal separation of administrators does not protect against the entity that can override them. See the [deployment configurations and checklist](https://wcm.agentrust-io.com/deployment-trust/index.md).

WCM's guarantees hold only as far as the hardware and software it relies on (the trusted computing base) hold. The honest core: current confidential-computing chips do **not** protect the key, or the honesty of the hardware check, against an operator who physically owns the hardware (TEE.fail, BadRAM). Against that adversary WCM provides cost, detection, containment, legal recourse, and mandatory physical hardening - not cryptographic custody. See [Limitations](https://wcm.agentrust-io.com/limitations/index.md).
