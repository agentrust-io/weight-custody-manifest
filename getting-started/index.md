# Getting started

This page is for developers who want to try WCM in code. In about ten minutes you install the Python SDK, sign a manifest, check it, and run a simulated key release on your own computer.

The reference SDK lives in [`python/`](https://github.com/agentrust-io/weight-custody-manifest/tree/main/python). It runs the whole protocol using software stand-ins for the hardware, so no special machine is needed. Its check of AMD SEV-SNP hardware reports has also been tested against real hardware.

## Install

```
git clone https://github.com/agentrust-io/weight-custody-manifest
cd weight-custody-manifest/python
pip install --require-hashes -r ../requirements/dev.txt   # includes the KBS server deps
pip install --no-deps -e .
```

## Build, sign, verify a manifest

A manifest is a short signed document that names the model files and the rules for releasing their key. Two parties sign it: the builder (who made the model) and the custodian (who runs the key service).

```
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

A manifest is valid only when **both** the builder and custodian have signed (and the declared sovereign signer, under the sovereign profile). Post-quantum (`add_ml_dsa65_key`) and hybrid (`add_hybrid_key`) profiles verify the same way.

## Gate a key release

The key broker service (KBS) holds the decryption key. It sends a one-time challenge, checks the evidence that comes back, and releases the key only if everything matches the manifest.

```
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

`SoftwareProvider` is a stand-in that produces fake evidence with no real hardware behind it, so this example proves nothing about hardware. For real evidence see `snp.py` (AMD SEV-SNP, hardware-validated) and the provider auto-selection in `_hw_providers.py`.

## CLI

The same steps from the command line: make keys for both parties, sign, verify.

```
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
