# WCM reference SDK (Python) — Layers 1, 2 (gate), and wipe-on-lapse

Reference implementation of the [Weight Custody Manifest](../SPEC.md):

- **Layer 1** — build a manifest, sign it **jointly** (builder + custodian, plus
  a sovereign quorum when the sovereign profile is on), and verify those signatures.
- **Layer 2 (gate)** — the attestation-gated key-release handshake: the KBS
  issues a nonce, the enclave returns composite CPU+GPU evidence over it, and the
  KBS releases the key only if every §3.2 check passes.
- **Wipe-on-lapse** — the runtime custody floor: the enclave holds a released key
  only for the cadence window and zeroizes it if it does not re-attest in time.
- **Quote verification** — the KBS-side trust decision: cert-chain validation +
  report-signature check + cryptographic nonce binding on the raw quote.
- **Layer 4 (lineage)** — derivative manifests chain back to the root via
  `derived_from`; the lineage verifier resolves the chain, detects cycles and
  missing parents, and enforces a parent's structured `derivatives` policy.

> **Pre-1.0, tracking a pre-1.0 spec. Not ready to build against.**
> The hardware providers (SEV-SNP / TDX / NVIDIA CC) do real device I/O but their
> ioctl layouts and report offsets are **NOT validated against real silicon** —
> provisional until checked on hardware. Quote verification ships the real,
> tested **machinery** (X.509 chain + signature + nonce binding, exercised
> against a synthetic PKI) but **no AMD/NVIDIA root certificates and no vendor
> binary parser** — those plug in as a `TrustStore` and a `QuoteParser`, and are
> the parts that need real captured quotes to validate. None of this closes the
> key-extraction hole (open question 8.8): a physically-extracted key produces a
> genuinely valid signature that passes every check. Wipe-on-lapse bounds exposure
> only if the clock cannot be stalled (`trusted_time_source` → `time_floor`) and
> only against an operator who cannot forge attestation. GPU-side quote
> verification, real vendor roots/parsers, the reproducible reference KBS image,
> and the post-quantum profile are **not** here yet — see the repo `ROADMAP.md`.

## What it does

Layer 1 (authority):

- **`models.py`** — the manifest schema as Pydantic v2 with `extra="forbid"`,
  including the v0.8 fields (`trusted_time_source`, `memory_fingerprint_challenge`,
  `attestation_revocation_check`).
- **`_canonicalize.py`** — RFC 8785 (JCS), kept in sync with the agentrust-io
  family so a manifest signed by one tool verifies under another.
- **`_signing.py`** — Ed25519 (standard profile). One signature block per party,
  tagged with `role` and `signer`.
- **`_verify.py`** — checks the required roles signed and every signature is
  cryptographically valid; enforces the sovereign quorum rule.
- **`cli.py`** — `wcm keygen | sign | verify`.

Layer 2 (release gate):

- **`_challenge.py`** — single-use KBS nonces with expiry (`kbs-nonce-required`).
- **`attestation.py`** — evidence models: a CPU CVM quote and a separate GPU
  report echoing the same nonce, plus the v0.8 memory-fingerprint response.
- **`providers.py`** — `AttestationProvider` interface + a `SoftwareProvider`
  mock (no hardware root of trust; for tests and local dev only).
- **`_hw_providers.py`** — hardware producers: `SevSnpProvider` /
  `TdxProvider` (CPU quote via `/dev/sev-guest` / `/dev/tdx-guest`),
  `NvidiaCcProvider` (GPU report via an external tool), `HardwareCompositeProvider`,
  and `select_provider()` (auto-select, software fallback). **ABI/offsets are
  provisional and unvalidated against real silicon.**
- **`kbs.py`** — `KeyBrokerService`: composite verification (nonce, platform,
  assurance tier, serving-image status + prefer-current, GPU measurement and
  CPU↔GPU binding, memory-fingerprint, revocation freshness, optional
  cryptographic quote verification) and gated release.
- **`_quote_verify.py`** — `QuoteVerifier`: X.509 cert-chain validation +
  report-signature check + nonce binding, with a pluggable `TrustStore` and
  `QuoteParser`. Wire it into the KBS via `cpu_quote_verifier=`; when unset, the
  gate says `structural trust only` in its check detail.

Wipe-on-lapse (runtime custody):

- **`custody.py`** — `EnclaveSession`: holds a released key for the cadence
  window, renews on `reattest()`, zeroizes on lapse; `use_key()` never serves
  past the deadline. `time_floor` reports how much the bound is worth given the
  manifest's `trusted_time_source`. For the hybrid, `max_operations` anchors the
  serving case: after N operations `use_key()` raises `ReattestationRequired`
  (the key is not wiped) until the session re-attests.

Layer 4 (derivative lineage):

- **`lineage.py`** — `verify_lineage(manifests, leaf_hash)` walks `derived_from`
  to the root, returning the chain, cycles/missing-parent violations, and policy
  notes. A parent's structured `derivatives` policy (`none` / `fine-tune-only` /
  `unrestricted`) is enforced; the freeform `permitted_derivatives` legal string
  is left to human review. `derived_from` and `rights_holder` are under the joint
  signature.

A post-quantum profile (ML-DSA-65) is on the roadmap, not in this preview.

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

## Test

```bash
pytest
```

## License

Apache-2.0. Crypto primitives adapted from the agentrust-io/agent-manifest SDK.
