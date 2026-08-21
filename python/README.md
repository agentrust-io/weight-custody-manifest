# WCM reference SDK (Python) - Layers 1, 2 (gate), and wipe-on-lapse

Reference implementation of the [Weight Custody Manifest](../SPEC.md):

- **Layer 1** - build a manifest, sign it **jointly** (builder + custodian, plus
  a sovereign quorum when the sovereign profile is on), and verify those signatures.
- **Layer 2 (gate)** - the attestation-gated key-release handshake: the KBS
  issues a nonce, the enclave returns composite CPU+GPU evidence over it, and the
  KBS releases the key only if every §3.2 check passes.
- **Wipe-on-lapse** - the runtime custody floor: the enclave holds a released key
  only for the cadence window and zeroizes it if it does not re-attest in time.
- **Quote verification** - the KBS-side trust decision: cert-chain validation +
  report-signature check + cryptographic nonce binding on the raw quote.
- **Layer 4 (lineage)** - derivative manifests chain back to the root via
  `derived_from`; the lineage verifier resolves the chain, detects cycles and
  missing parents, and enforces a parent's structured `derivatives` policy.
- **Transparency log** - an append-only Merkle log (RFC 9162) with signed tree
  heads, inclusion proofs, and consistency proofs, so equivocation and
  suppressed revocations become detectable.
- **Threshold split-key** - Shamir sharing so a sovereign self-custody key needs
  a quorum of custodians to reconstruct; no single party can self-release.
- **Post-quantum profile** - ML-DSA-65 (FIPS 204) and an Ed25519+ML-DSA-65
  hybrid; manifests verify under the standard, PQ, or hybrid profile.
- **AMD SEV-SNP quote verification** - real v3 report parser + VCEK report-signature
  verification, validated against a live Azure SEV-SNP report and the real AMD
  Milan chain (RSA-PSS) - the latter committed as a CI fixture.

> **Pre-1.0, tracking a pre-1.0 spec. Not ready to build against.**
> The cert-chain + signature + nonce-binding **machinery is validated against real
> hardware**: an AMD SEV-SNP report and the real VCEK→ASK→ARK Milan chain (this is
> what surfaced and fixed the RSA-PSS bug). What is still **not** validated: the
> `/dev/sev-guest` ioctl offsets in `_hw_providers` (Azure uses the vTPM path
> instead - see `snp.extract_snp_report_from_hcl`), and the **NVIDIA GPU** path,
> which stays provisional until an H100 CC report is captured. None of this closes
> the key-extraction hole (open question 8.8): a physically-extracted key produces
> a genuinely valid signature that passes every check. Wipe-on-lapse bounds
> exposure only if the clock cannot be stalled (`trusted_time_source` →
> `time_floor`) and only against an operator who cannot forge attestation.
> Intel TDX validation, GPU-side quote verification, and the reproducible
> reference KBS image are **not** here yet - see the repo `ROADMAP.md`.

## What it does

Layer 1 (authority):

- **`models.py`** - the manifest schema as Pydantic v2 with `extra="forbid"`,
  including the v0.8 fields (`trusted_time_source`, `memory_fingerprint_challenge`,
  `attestation_revocation_check`).
- **`_canonicalize.py`** - RFC 8785 (JCS), kept in sync with the agentrust-io
  family so a manifest signed by one tool verifies under another.
- **`_signing.py`** - Ed25519 (standard profile), ML-DSA-65 (post-quantum, FIPS
  204, via cryptography's native support), and an Ed25519+ML-DSA-65 hybrid where
  both must verify. One signature block per party, tagged with `role` and `signer`.
- **`_verify.py`** - checks the required roles signed and every signature is
  cryptographically valid; enforces the sovereign quorum rule.
- **`cli.py`** - `wcm keygen | sign | verify | inspect | gate | verify-quote | verify-provenance`.
  `inspect` summarizes a manifest; `gate` runs the release policy against a mock
  attestation and prints every check (a diagnostic, not a live release);
  `verify-quote --kind {snp,tdx,gpu}` verifies a captured quote bundle; and
  `verify-provenance` cross-verifies an OpenSSF model-signing signature (needs the
  `[model-signing]` extra).

Layer 2 (release gate):

- **`_challenge.py`** - single-use KBS nonces with expiry (`kbs-nonce-required`).
- **`attestation.py`** - evidence models: a CPU CVM quote and a separate GPU
  report echoing the same nonce, plus the v0.8 memory-fingerprint response.
- **`providers.py`** - `AttestationProvider` interface + a `SoftwareProvider`
  mock (no hardware root of trust; for tests and local dev only).
- **`_hw_providers.py`** - hardware producers: `SevSnpProvider` /
  `TdxProvider` (CPU quote via `/dev/sev-guest` / `/dev/tdx-guest`),
  `AzureSnpVtpmProvider` (SEV-SNP on an Azure CVM via the vTPM NV `0x01400001`
  paravisor path - the flow validated on a live Azure host),
  `NvidiaCcProvider` (GPU report via an external tool), `HardwareCompositeProvider`,
  and `select_provider()` (auto-select, software fallback). The SEV-SNP ioctl
  path is validated on a live GCP N2D guest. TDX report generation is validated
  on a live GCP C3 guest, while remote quote generation remains provisional;
  the Azure vTPM extraction is validated.
- **`kbs.py`** - `KeyBrokerService`: composite verification (nonce, platform,
  assurance tier, serving-image status + prefer-current, GPU measurement and
  CPU↔GPU binding, memory-fingerprint, revocation freshness, optional
  cryptographic quote verification) and gated release.
- **`_quote_verify.py`** - `QuoteVerifier`: X.509 cert-chain validation +
  report-signature check + nonce binding, with a pluggable `TrustStore` and
  `QuoteParser`. Wire it into the KBS via `cpu_quote_verifier=`; when unset, the
  gate says `structural trust only` in its check detail.

Wipe-on-lapse (runtime custody):

- **`custody.py`** - `EnclaveSession`: holds a released key for the cadence
  window, renews on `reattest()`, zeroizes on lapse; `use_key()` never serves
  past the deadline. `time_floor` reports how much the bound is worth given the
  manifest's `trusted_time_source`. For the hybrid, `max_operations` anchors the
  serving case: after N operations `use_key()` raises `ReattestationRequired`
  (the key is not wiped) until the session re-attests. After an admitted runtime
  opens the key once, `authorize_operation()` applies the same lease and budget
  checks to later inference operations without returning another key copy. The
  initial `use_key()` call and every authorization each count as one operation.

For verifiable renewal, use a fresh KBS challenge and evidence rather than calling
the low-level `reattest()` compatibility method:

```python
challenge = kbs.issue_challenge()
evidence = provider.produce(
    challenge,
    serving_image_measurement=current_measurement,
    gpu_measurement=required_gpu_measurement,
)
renewal = kbs.verify_for_renewal(manifest, evidence)
session.apply_renewal(manifest, renewal)
```

The initial release pins the KBS renewal public key. The renewal decision is
short-lived, signed, single-use at the session, and bound to hashes of the fresh
challenge, complete evidence, signed manifest, and weights. It contains no model
key. A KBS restart with an unpersisted renewal signer safely prevents renewal;
production deployments should inject a protected persistent signing key.

Layer 4 (derivative lineage):

- **`lineage.py`** - `verify_lineage(manifests, leaf_hash)` walks `derived_from`
  to the root, returning the chain, cycles/missing-parent violations, and policy
  notes. A parent's structured `derivatives` policy (`none` / `fine-tune-only` /
  `unrestricted`) is enforced; the freeform `permitted_derivatives` legal string
  is left to human review. `derived_from` and `rights_holder` are under the joint
  signature.

Transparency (authority-layer integrity):

- **`_merkle.py`** - RFC 9162 Merkle tree: inclusion and consistency proofs.
- **`transparency.py`** - `TransparencyLog`: append manifests / revocations /
  measurement-set changes, emit Ed25519 signed tree heads, and prove inclusion
  and append-only growth. `find()` lets a monitor detect a *missing* expected
  entry (a suppressed revocation). Verification (`verify_sth` / `verify_inclusion`
  / `verify_log_consistency`) needs only the proofs and heads, not the store.

Sovereign self-custody:

- **`threshold.py`** - `split_secret(key, threshold=t, shares=n)` /
  `combine_shares()`: Shamir Secret Sharing over GF(256). Any `t` shares
  reconstruct the key; any `t-1` reveal nothing, so no single custodian (the
  builder included) can self-release (SPEC §3.5, decision 15).

Post-quantum profile:

- ML-DSA-65 and hybrid signing live in `_signing.py`; `VerificationContext`
  gains `add_ml_dsa65_key()` / `add_hybrid_key()`, and `verify_manifest`
  dispatches per signature by algorithm. Uses cryptography's native ML-DSA (no
  external liboqs); on a cryptography build without it, PQ raises a clear error
  while the rest of the package keeps working.

AMD SEV-SNP (vendor quote verification):

- **`snp.py`** - `parse_snp_report` (v3 ABI), `verify_snp_report_signature`
  (VCEK, ECDSA P-384, AMD's little-endian r‖s), `extract_snp_report_from_hcl`
  (Azure vTPM `0x01400001` wrapper), and `SnpQuoteParser`, which plugs a report +
  its VCEK/ASK/ARK chain into the generic `QuoteVerifier`. Validated against a
  live Azure SEV-SNP report; the real public AMD Milan chain is a CI fixture.

## Reference KBS server (optional)

`wcm.server.create_app(kbs)` builds a FastAPI surface for the key broker
(`POST /challenge`, `POST /release`, `GET /health`) with the same semantics as
the library `KeyBrokerService`. Install the extra: `pip install ".[server]"`.

```python
from wcm import KeyBrokerService
from wcm.server import create_app
app = create_app(KeyBrokerService({weights_hash: key_bytes}))
# uvicorn module:app
```

Reference-only: `/release` returns the key in the response body. A production
KBS wraps the key to the requesting enclave's attested transport instead - do
not expose this as-is on an untrusted network.

## Install

```bash
pip install -e ".[dev]"    # from this python/ directory
```

## Quickstart (CLI)

```bash
# 1. keys for the two required parties (writes builder + builder.pub, etc.)
wcm keygen --out builder
wcm keygen --out custodian

# 2. joint signature over the example manifest
wcm sign examples/manifest.example.json \
  --role builder    --signer example-builder --key-file builder    --out signed.json
wcm sign signed.json \
  --role custodian  --signer opaque-systems  --key-file custodian  --out signed.json

# 3. verify against the two trusted public keys
wcm verify signed.json --key-file builder.pub --key-file custodian.pub
# -> {"ok": true, ...}   (exit 0)
```

Keys are read from files, never passed on the command line: a private key on
argv leaks into process listings and shell history, and a base64url key can
start with `-`.

## Quickstart (library)

```python
from wcm import (
    WeightCustodyManifest, Ed25519Signer, generate_ed25519,
    VerificationContext, verify_manifest,
)
import json

manifest = WeightCustodyManifest.model_validate(
    json.load(open("examples/manifest.example.json"))
)

builder, custodian = generate_ed25519(), generate_ed25519()
sigs = [
    Ed25519Signer(builder).sign(manifest.unsigned_dict(), role="builder", signer="example-builder"),
    Ed25519Signer(custodian).sign(manifest.unsigned_dict(), role="custodian", signer="opaque-systems"),
]
manifest = manifest.with_signatures(sigs)

ctx = VerificationContext()
ctx.add_key(builder.public_bytes)
ctx.add_key(custodian.public_bytes)
print(verify_manifest(manifest, ctx).ok)  # True
```

## Quickstart (Layer 2 release gate)

```python
from wcm import KeyBrokerService, SoftwareProvider, WeightCustodyManifest
import json

manifest = WeightCustodyManifest.model_validate(
    json.load(open("examples/manifest.example.json"))
)

# The KBS holds the decryption key keyed by weights_hash.
kbs = KeyBrokerService({manifest.weights_hash: b"the-decryption-key"})

# 1. KBS issues a fresh nonce. 2. Enclave attests over it (mock here).
challenge = kbs.issue_challenge()
evidence = SoftwareProvider().produce(
    challenge,
    serving_image_measurement="sha256:" + "5e2d" * 16,  # a 'current' accepted image
    gpu_measurement="nvidia-rim:driver+vbios golden measurement id",
)

# 3. Composite verification, then gated release.
decision = kbs.verify_and_release(manifest, evidence)
print(decision.released)                 # True
print(decision.key)                      # b"the-decryption-key"
# On failure: decision.released is False and decision.failures names each check.
```

## Quickstart (wipe-on-lapse)

```python
from wcm import EnclaveSession

# The enclave takes custody of the key the KBS just released.
session = EnclaveSession.from_release(manifest, decision)

session.use_key()          # serves while holding
session.reattest()         # renew before the cadence window closes
print(session.time_floor)  # 'sound' for secure-tsc, 'weaker' for the hybrid, 'none' otherwise

# If the window lapses without a re-attestation, the key is zeroized, not suspended:
#   session.use_key()  ->  raises KeyWipedError
```

## End-to-end examples

Runnable end-to-end demos live in the public examples repo,
[agentrust-io/examples/weight-custody-manifest](https://github.com/agentrust-io/examples/tree/main/weight-custody-manifest),
where they depend on the published `weight-custody-manifest` package: the full
six-step flow on an open-weight model, a 2-of-3 sovereign threshold release, and
an offline SEV-SNP quote replay. They are honest about the open-weight reframe
(base-weight secrecy is moot; the work is integrity, license, and derivative
custody).

## Test

```bash
pytest
```

## License

Apache-2.0. Crypto primitives adapted from the agentrust-io/agent-manifest SDK.
