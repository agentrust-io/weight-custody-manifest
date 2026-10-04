# Getting started

The reference SDK lives in [`python/`](https://github.com/agentrust-io/weight-custody-manifest/tree/main/python). It implements the full protocol on software / synthetic test doubles, with AMD SEV-SNP quote verification validated against real hardware.

## Install

```bash
git clone https://github.com/agentrust-io/weight-custody-manifest
cd weight-custody-manifest/python
pip install --require-hashes -r ../requirements/dev.txt   # includes the KBS server deps
pip install --no-deps -e .
```

### Azure confidential VMs

Both Azure providers (`AzureSnpVtpmProvider`, `AzureTdxVtpmProvider`) read the
HCL report from the vTPM with `tpm2_nvread` from `tpm2-tools`, and need
`/dev/tpmrm0`. The SNP provider's measured-launch quote also runs
`tpm2_pcrreset`, `tpm2_pcrextend`, `tpm2_readpublic` and `tpm2_quote`:

```bash
sudo apt-get install -y tpm2-tools
```

Without the package both providers report unavailable. On an Azure CVM, where
the bare-metal providers (`/dev/sev-guest`, `/dev/tdx_guest`) are absent, that
leaves no CPU provider, so `select_provider()` falls back to `SoftwareProvider`
unless it is called with `require_hardware=True`; the error it raises then names
only `/dev/sev-guest` and `/dev/tdx-guest`, not the missing tool. The Canonical
`ubuntu-24_04-lts:cvm` image (`24.04.202608260`, observed on 2026-09-10) ships
`/dev/tpmrm0` and `libtss2-*` but not `tpm2-tools`.

## Build, sign, verify a manifest

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
signed = manifest.with_signatures([
    Ed25519Signer(builder).sign(manifest.unsigned_dict(), role="builder", signer="example-builder"),
    Ed25519Signer(custodian).sign(manifest.unsigned_dict(), role="custodian", signer="opaque-systems"),
])

ctx = VerificationContext()
ctx.add_key(builder.public_bytes)
ctx.add_key(custodian.public_bytes)
print(verify_manifest(signed, ctx).ok)   # True
```

A manifest is valid only when **both** the builder and custodian have signed
(and the declared sovereign signer, under the sovereign profile). Post-quantum
(`add_ml_dsa65_key`) and hybrid (`add_hybrid_key`) profiles verify the same way.

## Gate a key release

```python
from wcm import KeyBrokerService, SoftwareProvider, manifest_identity

kbs = KeyBrokerService(
    {manifest.weights_hash: b"the-decryption-key"},
    trusted_manifest_identities={manifest_identity(manifest)},
)
challenge = kbs.issue_challenge()
evidence = SoftwareProvider().produce(
    challenge,
    serving_image_measurement="sha256:" + "5e2d" * 16,
    gpu_measurement="nvidia-rim:driver+vbios golden measurement id",
)
decision = kbs.verify_and_release(manifest, evidence)
print(decision.released)   # True on a passing gate
```

`SoftwareProvider` is a mock with no hardware root of trust. For real evidence
see `snp.py` (AMD SEV-SNP, hardware-validated) and the provider auto-selection in
`_hw_providers.py`.

## CLI

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

See the [`python/` README](https://github.com/agentrust-io/weight-custody-manifest/blob/main/python/README.md) for the full module tour.
