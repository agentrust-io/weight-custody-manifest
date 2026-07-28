# Changelog

Notable changes to the Weight Custody Manifest specification and Python SDK.
Format loosely follows [Keep a Changelog](https://keepachangelog.com/); the SDK
uses semantic-ish versioning while pre-1.0.

## Unreleased

**[repo]** Moved the runnable examples and demos out of this repo into the public
[agentrust-io/examples](https://github.com/agentrust-io/examples/tree/main/weight-custody-manifest)
(per-product catalog) and [agentrust-io/demos](https://github.com/agentrust-io/demos)
(talk track), where they depend on the published `weight-custody-manifest` PyPI
package rather than an in-repo checkout. The SDK keeps `examples/manifest.example.json`
as a CLI docs fixture. The demo notes below describe those examples as originally
added here.

**[demo]** Run WCM on a real open model, locally (`examples/real_open_model.py`):
downloads a real open-weight model (default SmolLM2-135M), hashes its ACTUAL
safetensors into the manifest, and runs the whole flow (sign, gate, wipe-on-lapse,
license, derivative + lineage) with the software attestation mock. Includes a
tamper demo (a one-byte-flipped fork no longer matches the manifest) and an
optional `--infer` that loads the model and generates so the certified serving
stack is a real running model. Adds a "Test on your machine" tutorial. No library
change; download/inference deps are imported lazily and CI does not download.

**[demo/tools]** Offline SEV-SNP quote replay: `examples/snp_replay.py` runs the
KBS's Layer 2 CPU gate (parse, VCEK->ASK->ARK chain, report signature, nonce
binding) against a recorded quote, with a committed synthetic bundle so it runs
anywhere. `tools/capture_snp_quote.py` captures a genuine bundle on an Azure
SEV-SNP CVM; the replay handles both the guest-nonce (bare-metal) and the Azure
vTPM freshness topologies honestly (on Azure, REPORT_DATA binds the vTPM AK, not
our nonce). Ships a **genuine** quote captured from a live Azure SEV-SNP CVM
(`tests/fixtures/snp_quote_azure.json`, real VCEK->ASK->ARK) that the replay
verifies offline, alongside the synthetic one. Adds a "Replaying a real SEV-SNP
quote" tutorial and wires the tutorials into the docs nav. No library API change.

**[demo]** Sovereign self-custody with threshold release
(`examples/sovereign_self_custody.py`, SPEC 3.5 / decision 15): a 2-of-3 split
across builder, sovereign, and custodian, gated by an attested KBS, showing that
no single party (and no single forged KBS quote) can assemble the key, so
threshold is a prerequisite for sovereign self-custody, not optional hardening.
Composes the shipped `split_secret`/`combine_shares` with `KeyBrokerService`; no
new library API. Adds a "Sovereign self-custody (threshold)" tutorial.

## SDK

### 0.21.0
- **OpenSSF model-signing provenance interop** (SPEC 3.9): a manifest can carry an
  optional, signed `provenance.model_signing` reference to an OpenSSF model-signing
  signature over the base weights (`Provenance` / `ModelSigningProvenance`, added to
  `WCM_SIGNED_FIELDS`). `verify_manifest` records it as a non-blocking note; new
  `verify_provenance(manifest, model_path, signature_path, public_key)` (module
  `wcm.provenance`) cryptographically verifies the model-signing signature over the
  model files and binds it to the manifest by re-deriving `signed_digest`
  (`model_signing_digest`). Positions WCM as the custody-and-release layer on top of
  model signing, not a competitor. `model-signing` is an optional dependency
  (`pip install "weight-custody-manifest[model-signing]"`). Backward-compatible: the
  field defaults absent, so existing manifests and pre-images are unchanged.

### 0.20.0
- **NVIDIA CC GPU-report verification** (SPEC 3.2 composite attestation): new
  `wcm.nvidia` (`build_gpu_verifier`, `NvidiaCcReportParser`) verifies the H100
  CC GPU report with the same machinery as the CPU quote (cert chain to NVIDIA's
  device root, report signature, nonce binding), reusing `QuoteVerifier`.
  `KeyBrokerService` gains `gpu_report_verifier`: when set, a new
  `gpu_report_verified` gate cryptographically checks the GPU chain; when unset
  it stays structural-only and says so, so default behaviour is unchanged. The
  GPU report is bound to the CPU quote by the shared KBS nonce. Honest scope: it
  ships no NVIDIA root, and the binary SPDM report offsets are PROVISIONAL until
  validated against a real H100 capture (`NCC40ads_H100_v5`); the reused
  verification machinery is tested against a synthetic device PKI.
  Backward-compatible.

### 0.19.0
- **Channel binding for Layer 2 key release** (SPEC 3.2, CVE-2026-33697): closes
  the quote-relay / key-diversion gap that nonce binding alone left open. New
  `wcm._seal` (`generate_transport_keypair`, `seal_to_public_key`, `open_sealed`,
  `SealError`) object-seals a released key to the enclave's attested transport key
  (ephemeral-static X25519 + HKDF-SHA256 + ChaCha20-Poly1305, stdlib crypto, no
  new dependency), mirroring cA2A's sealed-channel scheme. `CpuQuote` gains
  `transport_public_key`; providers fold it into REPORT_DATA under the nonce
  (`sha256(nonce || transport_pubkey)`), so a relay cannot substitute its own key
  without failing verification. `QuoteVerifier.verify` and `verify_tdx_quote` take
  a `channel_binding` kwarg; `KeyBrokerService` takes `require_channel_binding`
  (default False) and adds a `channel_binding` gate check, and `ReleaseDecision`
  gains `sealed_key`. When channel binding is required the raw key is never
  returned, only the sealed blob, so a relayed release yields ciphertext the relay
  cannot open. The reference server (`wcm.server`) now requires channel binding
  and returns `sealed_key_b64` instead of a plaintext key. Backward-compatible:
  `channel_binding` defaults empty (reduces to `sha256(nonce)`) and
  `require_channel_binding` defaults off, so existing evidence and flows are
  unchanged.

### 0.18.0
- **Multi-stage BYOM enforcement in `verify_lineage`** (SPEC 3.8): monotone rights
  (a derivative may narrow but never widen the structured `derivatives` policy or
  `permitted_environments` relative to its parent), plus optional `logged=` (every
  manifest in the chain must be present and in-force in the transparency log) and
  `revoked=` (a revocation anywhere in the chain cascades to invalidate the leaf)
  gates. `verify_lineage` stays pure, no crypto: the caller supplies the
  logged/revoked hash sets from already-verified inclusion proofs. Backward-
  compatible, the gates default off; monotone-rights is always on (structural).

### 0.17.0
- **Azure Intel TDX provider** (`AzureTdxVtpmProvider`): Azure TDX CVMs have no
  `/dev/tdx-guest`; the paravisor exposes a TD report in the same vTPM NV index
  SNP uses (`0x01400001`), and since a TD report is not self-verifiable this
  provider exchanges it for a DCAP quote at the Azure IMDS `/acc/tdquote` service.
  Validated on a live Azure `DCes_v6` host in westeurope; the captured quote
  (`tests/fixtures/tdx_quote_azure.json`) verifies through `tdx.py` and chains to
  Intel's real SGX Root CA. `select_cpu_provider` prefers it over the Azure SNP
  catch-all by reading the HCL's TD-report type byte.
- **`verify_tdx_quote(expected_nonce=...)` is now optional.** Pass `None` on the
  Azure vTPM path, where REPORT_DATA is paravisor-bound to the vTPM AK rather than
  a caller nonce (freshness comes from the enclosing vTPM quote); bare-metal /
  configfs-tsm guests still pass the nonce.

### 0.16.0
- **Intel TDX quote verification** (`tdx.py`): `parse_tdx_quote` and
  `verify_tdx_quote` for the DCAP v4 ECDSA quote. The two-level Intel structure
  (attestation key signs the quote; the QE report binds that key; the PCK leaf
  signs the QE report; PCK chains to the Intel SGX Root CA) plus the nonce
  binding, so TDX reaches SEV-SNP parity on the verify side. Exercised against a
  synthetic DCAP quote AND a genuine GCP c3-standard-4 TDX capture
  (`tests/fixtures/tdx_quote_gcp.json`), which verifies offline and chains to
  Intel's real published SGX Root CA (fingerprint pinned in the test).

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

- **v0.14** - added provenance interop (section 3.9): an optional `provenance`
  field, under the joint signature, references an OpenSSF model-signing signature
  over the base weights, and `verify_provenance` cryptographically checks that
  signature and binds it to the manifest by re-deriving the signed digest. WCM
  composes with model signing (the provenance layer) rather than replacing it, and
  does not re-sign the model files. No change to release, attestation, or custody
  semantics.
- **v0.13** - added channel binding to the Layer 2 release handshake (section
  3.2). The enclave folds a transport public key into the quote's REPORT_DATA
  under the nonce, and the KBS seals the released key to that transport key rather
  than returning it on the channel. Closes the quote-relay / key-diversion gap
  (the intra-handshake binding gap, CVE-2026-33697) that nonce binding alone left
  open: a relayed quote yields only ciphertext the relay cannot open, and
  substituting a transport key breaks quote verification. New threat T4.4 in the
  threat model (v0.5). No new manifest fields.
- **v0.12** - reframed the publication posture: closing the key-extraction half
  of open question 8.8 is no longer a precondition for publishing the open spec
  and SDK. That half is disclosed as a scoped limit against a hardware owner
  outside the operator-trust model (a party a builder self-selects against),
  addressed by physical hardening + accountability today and extraction-resistant
  silicon on the vendor roadmap. Security claims unchanged; only the "therefore
  withhold" logic is dropped, in favour of leading with the limit.
- **v0.11** - specified the KBS enclave image contents and threat model to
  implementable detail (resolving open question 8.2, so self-custody moves from
  described to specified), and added multi-stage BYOM as a sequential re-custody
  protocol over the existing lineage and transparency-log primitives (section
  3.8: chained `derived_from`, release gated on upstream being logged, monotone
  rights, cascading revocation). No new manifest fields; broad multi-party
  co-governance stays the one deliberately-open BYOM piece.
- **v0.10** - `base_confidentiality` (`confidential` | `gated-open` | `open`) and
  `deployment_model` (`builder-to-customer` | `byom-symmetric`) added to the
  manifest, both under the joint signature; the verifier reports non-blocking
  consistency notes rather than blocking.
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
