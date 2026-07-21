# Changelog

Notable changes to the Weight Custody Manifest specification and Python SDK.
Format loosely follows [Keep a Changelog](https://keepachangelog.com/); the SDK
uses semantic-ish versioning while pre-1.0.

## Unreleased

**[SDK]** In flight (open PRs): `AzureSnpVtpmProvider` (SEV-SNP on Azure CVMs via
the vTPM path), the reference KBS HTTP server (`[server]` extra), and a
CI-validated reproducible reference KBS image.

## SDK

### 0.15.0
- **Explicit `base_confidentiality`** (`confidential` | `gated-open` | `open`)
  and **`deployment_model`** (`builder-to-customer` | `byom-symmetric`) on the
  manifest, both under the joint signature (added to `WCM_SIGNED_FIELDS`). A
  manifest that omits them reads as the original confidential, builder-to-customer
  posture, so this is backward-compatible for parsing.
- `verify_manifest` now returns non-blocking `notes`: it discloses that an `open`
  base is not protected for secrecy (the layers still enforce integrity, license,
  derivative custody, and the kill switch), flags secrecy-only controls on an open
  base, and confirms symmetric self-custody. `notes` never change `ok`.
- `byom-symmetric` structurally requires `customer-self-custody`.
- **Spec**: SPEC.md v0.10 documents both fields and reframes BYOM from
  "out of scope" to a named posture (multi-stage pipeline stays out of scope).

### 0.11.x
- **RFC 8785 conformance fix**: canonicalizer sorts object keys by UTF-16 code
  units (not code points), so the interop claim holds for non-BMP keys.
- **AMD SEV-SNP quote verification** (`snp.py`): real v3 report parser, VCEK
  report-signature verification, Azure vTPM HCL extraction, and `SnpQuoteParser`.
  Validated against a live Azure SEV-SNP report and the real AMD Milan chain.
- **RSA-PSS cert-chain fix** (`_quote_verify`): honor each cert's own signature
  parameters - found by validating against real AMD VCEK/ASK/ARK certificates.
- Parser fuzzing and a threat-model → implementation audit.

### 0.10.0
- **Post-quantum profile**: ML-DSA-65 (FIPS 204, via cryptography's native
  support) and an Ed25519 + ML-DSA-65 hybrid; `verify_manifest` dispatches per
  signature by algorithm.

### 0.7.0 – 0.9.0
- **Layer 4 derivative lineage** (`derived_from` / `rights_holder`, structured
  `derivatives` policy); **transparency log** (RFC 9162 Merkle, signed tree
  heads, inclusion/consistency proofs); **threshold split-key** (Shamir/GF(256)).

### 0.2.0 – 0.6.0
- **Layer 2 attestation-gated release gate** (composite CPU+GPU verification,
  single-use nonces); **wipe-on-lapse custody** with trusted-time honesty and
  operation-count renewal; hardware provider scaffolding; quote-verification
  machinery (X.509 chain + report signature + nonce binding).

### 0.1.0
- **Layer 1 reference SDK**: manifest Pydantic model, RFC 8785 canonicalization,
  Ed25519 joint (builder + custodian) signing and verification, `wcm` CLI.

## Specification

- **v0.9** - Layer 4 fields (`derived_from`, `rights_holder`, structured
  `derivatives`) synced into the manifest examples.
- **v0.8** - resolved trusted time (`trusted_time_source`, three tiers) and split
  forged attestation into a closed half (measurement forgery →
  `memory_fingerprint_challenge`) and the honestly-open key-extraction half.
- **v0.7** - resolved standards home (SCITT + CoSAI), the profile-list `required_hw_platform`, and sovereign dual-protection framing.
- **v0.6** - external-panel corrections: hypervisor ciphertext side channel,
  trusted-time requirement, transparency log, cryptographic-custody vs
  accountability-grade distinction.
- **v0.1 – v0.5** - initial four-layer design, wipe-on-lapse, sovereign
  revocation profile, attested-KBS self-custody, confidential-GPU and CPU-CVM
  assessments, open-core model.
