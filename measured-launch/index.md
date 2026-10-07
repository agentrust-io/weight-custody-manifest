# Measured launch and Azure PCR 23

On Azure, the hardware check for a confidential VM goes through a virtual TPM, a security chip emulated for each VM. This page defines exactly what fingerprint of the serving software that chip must record before WCM releases a key, so the key goes only to the approved software. It is written for platform engineers building the Azure release path; the summary below is enough for everyone else.

In short: just before loading the model, the VM writes the approved software's fingerprint into one reserved slot of the TPM (PCR 23, a register that can only be added to, never set directly). The TPM then signs a report that includes that slot and the key service's fresh challenge. The key service works out what the slot should contain from the signed manifest and releases the key only if the signed report matches. Selecting a PCR in a signed report is not enough on its own; its value must match.

## Contract

WCM reserves application-controlled SHA-256 PCR 23 for one workload event:

1. Start from the reset value: 32 zero bytes.
1. Resolve the approved serving-image value from the signed manifest. It must be `sha256:` followed by 64 lowercase hexadecimal digits.
1. Decode those digits to the 32-byte event digest.
1. Before accepting model material, extend PCR 23 exactly once with that digest.
1. Quote SHA-256 PCR 23 together with the fresh KBS challenge and ephemeral transport-key binding.

The reference Azure provider performs steps 1 to 4 with `tpm2_pcrreset 23` followed by `tpm2_pcrextend 23:sha256=<serving-image-digest>`, then immediately requests the AK-signed quote. Missing tools, an invalid measurement, or either TPM command failing aborts evidence production; the provider never falls back to quoting an unmeasured PCR state.

PCR 23 after the reset and extend is:

```
SHA256(00 × 32 || serving_image_digest)
```

The TPM quote's signed `pcrDigest` hashes the concatenated selected PCR values. WCM selects only PCR 23, so the verifier expects:

```
SHA256(SHA256(00 × 32 || serving_image_digest))
```

The KBS supplies the manifest-approved measurement to the verifier. It does not use `cpu.serving_image_measurement` as proof by itself. The verifier parses the signed quote's `TPM2B_DIGEST` and compares it in constant-size byte form with the independently calculated value.

## Fail-closed cases

"Fail closed" means that when anything is missing or wrong, the answer is no. Release is denied when PCR 23 is absent, uses a non-SHA-256 bank, has a malformed digest, represents a different PCR state, or the KBS has no approved workload measurement. A valid AK signature, fresh nonce, and correct transport key do not override a PCR mismatch.

## Reproducible Azure validation

This has been tested both in software and on a real Azure confidential VM. The repository's isolated tests build a sanitized quote and cover valid launch, wrong PCR digest, wrong policy measurement, malformed digest, and missing PCR. The procedure was also exercised on an Azure `Standard_DC2as_v5` confidential VM with AMD SEV-SNP and a vTPM. The sanitized, commit-pinned receipt and its reproduction notes are in the [Azure PCR 23 validation pack](https://github.com/agentrust-io/weight-custody-manifest/blob/main/python/tests/fixtures/live-validation/weight-custody-manifest/azure-pcr23-2026-08-23/README.md).

A publishable receipt contains only hashes, tool versions, generic VM/SKU information, boolean verdicts, and timestamps. It must not contain raw HCL, certificates tied to a tenant, provider tokens, subscription/resource identifiers, hostnames, IPs, customer names, or event-specific material.

## What this proves

It proves that the authenticated AK (the TPM's own signing key) signed the expected PCR state for this fresh release attempt. It does not prove immunity to physical extraction, forged attestation after hardware-key compromise, or memory-bus attacks. See the [threat model](https://wcm.agentrust-io.com/threat-model/index.md).
