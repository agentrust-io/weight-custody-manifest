# Measured launch and Azure PCR 23

This page is for platform engineers implementing the Azure SNP/vTPM release
path. It defines the measurement that the verifier checks; selecting a PCR in a
signed quote is not enough on its own.

## Contract

WCM reserves application-controlled SHA-256 PCR 23 for one workload event:

1. Start from the reset value: 32 zero bytes.
2. Resolve the approved serving-image value from the signed manifest. It must be
   `sha256:` followed by 64 lowercase hexadecimal digits.
3. Decode those digits to the 32-byte event digest.
4. Before accepting model material, extend PCR 23 exactly once with that digest.
5. Quote SHA-256 PCR 23 together with the fresh KBS challenge and ephemeral
   transport-key binding.

The expected quoted digest is:

```text
SHA256(00 × 32 || serving_image_digest)
```

The KBS supplies the manifest-approved measurement to the verifier. It does not
use `cpu.serving_image_measurement` as proof by itself. The verifier parses the
signed quote's `TPM2B_DIGEST` and compares it in constant-size byte form with the
independently calculated value.

## Fail-closed cases

Release is denied when PCR 23 is absent, uses a non-SHA-256 bank, has a malformed
digest, represents a different PCR state, or the KBS has no approved workload
measurement. A valid AK signature, fresh nonce, and correct transport key do not
override a PCR mismatch.

## Reproducible Azure validation

The repository's isolated tests build a sanitized quote and cover valid launch,
wrong PCR digest, wrong policy measurement, malformed digest, and missing PCR.
A real Azure confidential-VM capture is still required before claiming the
measured-launch procedure was validated on that platform. A publishable receipt
must contain only hashes, tool versions, generic VM/SKU information, boolean
verdicts, and timestamps. It must not contain raw HCL, certificates tied to a
tenant, provider tokens, subscription/resource identifiers, hostnames, IPs,
customer names, or event-specific material.

## What this proves

It proves that the authenticated AK signed the expected PCR state for this fresh
release attempt. It does not prove immunity to physical extraction, forged
attestation after hardware-key compromise, or memory-bus attacks. See the
[threat model](threat-model.md).
