# WCM reference SDK (Python) — Layer 1

Reference implementation of **Layer 1** of the [Weight Custody Manifest](../SPEC.md):
build a manifest, sign it **jointly** (builder + custodian, plus a sovereign
quorum when the sovereign profile is on), and verify those signatures.

> **Pre-1.0, tracking a pre-1.0 spec. Not ready to build against.**
> This is the authority layer only. Layer 2 (attestation-gated key release),
> the reference KBS, runtime custody, and derivative lineage are **not** here
> yet — see the repo `ROADMAP.md`. Verifying a manifest signature proves who
> authorized it and that it was not altered after signing; it says nothing
> about the runtime environment or whether adversary-owned silicon forged an
> attestation quote (SPEC open question 8.8).

## What it does

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

## Test

```bash
pytest
```

## License

Apache-2.0. Crypto primitives adapted from the agentrust-io/agent-manifest SDK.
