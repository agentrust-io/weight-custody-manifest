# OpenSSF Model Signing + WCM

OpenSSF Model Signing (OMS) and WCM answer different questions in one release
pipeline:

- **OMS:** Are these the authentic, untampered model files published by the
  expected signer?
- **WCM:** May the decryption key for those exact files be released to this
  attested workload, under these custody terms, now?

WCM does not replace or redefine OMS. OMS is the provenance layer; WCM binds
that provenance to jointly approved release policy, fresh platform evidence,
transport-sealed key delivery, runtime custody, revocation, and derivative
lineage.

## Where the boundary sits

| Concern | OMS | WCM |
|---|---:|---:|
| Multi-file model inventory and hashes | Yes | References and cross-checks it |
| Artifact signature and signer identity | Yes | References and cross-checks it |
| Builder and custodian jointly approve release policy | No | Yes |
| Model confidentiality and decryption-key release | No | Yes |
| Fresh CPU/GPU/workload attestation | No | Yes |
| Key sealed to the attested workload's transport key | No | Yes |
| Re-attestation, revocation, and wipe-on-lapse | No | Yes |
| Derivative rights and custody lineage | Metadata can be signed | Enforced as custody policy |

This boundary follows OMS's own scope: signing establishes artifact integrity
and authenticity, but is not confidentiality, access control, or comprehensive
runtime security.

## Composition flow

```text
model files
    │
    ├── OMS inventory + detached signature
    │       proves artifact integrity and signer identity
    │
    └── WCM manifest references the OMS-derived digest
            │
            ├── builder + custodian jointly sign the WCM policy
            ├── KBS verifies fresh CPU/GPU/workload evidence
            ├── KBS seals the DEK to the attested transport key
            └── runtime re-attests or zeroizes the key on lapse/revocation
```

The OMS reference lives inside WCM's jointly signed field set. It therefore
cannot be substituted after builder and custodian approval.

## Verify the two bindings

Install WCM with the optional OMS implementation dependency:

```bash
pip install "weight-custody-manifest[model-signing]"
```

After producing an OMS signature for the model, derive WCM's stable digest of
the OMS resource inventory:

```python
from wcm import model_signing_digest

print(model_signing_digest("./model"))
# sha256:...
```

Record that value in the WCM manifest before the builder and custodian sign it:

```json
{
  "provenance": {
    "model_signing": {
      "method": "openssf-model-signing",
      "signed_digest": "sha256:<derived digest>",
      "signer": "release@example.com"
    }
  }
}
```

Then verify both the detached OMS signature and its binding to the WCM
manifest:

```bash
wcm verify-provenance signed-wcm-manifest.json \
  --model ./model \
  --signature ./model.sig \
  --public-key ./model-signing.pub
```

The command fails closed if:

- the OMS signature does not verify over the supplied model files;
- any signed model file changed after signing;
- the WCM manifest has no OMS provenance reference; or
- the digest derived from the supplied model differs from the digest jointly
  approved in the WCM manifest.

Run `wcm verify` separately to verify the builder/custodian signatures and the
rest of the manifest. Successful provenance verification does not by itself
authorize a key release; the WCM attestation and policy gate must also pass.

## Digest note

`provenance.model_signing.signed_digest` and WCM's `weights_hash` are related to
the same physical artifact but serve different formats and are not
interchangeable. The former is WCM's stable fold of the OMS resource inventory;
the latter is WCM's own artifact identity. An ingest pipeline must compute both
from the same accepted bytes.

## Project references

- [OpenSSF Model Signing project](https://openssf.org/projects/model-signing/)
- [OpenSSF Model Signing specification](https://github.com/ossf/model-signing-spec)
- [Model Signing implementation](https://github.com/sigstore/model-transparency)
- [WCM specification §3.9](https://github.com/agentrust-io/weight-custody-manifest/blob/main/SPEC.md#39-provenance-interop-composing-with-model-signing)
