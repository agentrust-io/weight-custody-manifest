# WCM conformance error codes

A stable identifier for each way an implementation can reject an input. The
point is interoperability of *diagnosis*: two implementations that both reject a
manifest should agree on why, and a conformance run checks the code as well as
the verdict, so "reject everything" cannot pass the suite.

Codes are `WCM-<level>-<number>`. Within a level, `0001`-`0099` is the first
concern and `0101`-`0199` the second, where a level has two (L1 is structural
validity then joint-signature verification). Codes are append-only: a retired
code is not reused, and a description is only ever widened, never narrowed.

One marker appears below:

- **diagnostic only** - names a way an implementation can be *wrong* rather than
  an outcome it reports. Nothing raises "your re-attestation failed to renew the
  lease"; the suite concludes it when a step that should have succeeded did not.
  A vector can never *expect* one of these.

Every other code is exercised by at least one vector, and a test enforces that.
For limits that are not a whole code (GPU-side cryptographic verification, and
the synthetic PKI the quote vectors use), see `COVERAGE_NOTES` in
`wcm.conformance`, which `wcm conformance` prints on every full run.

This file and `wcm.conformance.CODES` are checked against each other in CI, so
an implementation can rely on either.

## L1 - Manifest and joint signature

| Code | Meaning | |
| --- | --- | --- |
| `WCM-L1-0001` | unknown field (no object in the manifest accepts extra properties) |  |
| `WCM-L1-0002` | a required field is absent |  |
| `WCM-L1-0003` | hash value is not sha256/shake256 with 64 lowercase hex characters |  |
| `WCM-L1-0004` | value outside the permitted set for its field |  |
| `WCM-L1-0005` | list is empty where at least one entry is required |  |
| `WCM-L1-0006` | retire_after is absent on a retiring measurement, or present on one that is not retiring |  |
| `WCM-L1-0007` | sovereign profile is inconsistent (enabled without quorum, or without a sovereign_signer) |  |
| `WCM-L1-0008` | deployment_model contradicts custody.custodian_type |  |
| `WCM-L1-0009` | derived_from equals the manifest's own weights_hash (self-derivation) |  |
| `WCM-L1-0101` | a required signature role has no valid signature |  |
| `WCM-L1-0102` | signature does not verify over the manifest pre-image |  |
| `WCM-L1-0103` | signature key_id is not trusted by the verifier |  |
| `WCM-L1-0104` | signature algorithm does not match the algorithm its key is trusted for |  |
| `WCM-L1-0105` | sovereign signature is not from the declared sovereign_signer |  |

## L2 - Attestation-gated release

| Code | Meaning | |
| --- | --- | --- |
| `WCM-L2-0001` | KBS nonce is unknown, expired, or already used |  |
| `WCM-L2-0002` | platform is not in required_hw_platform |  |
| `WCM-L2-0003` | assurance tier is below required_assurance_tier |  |
| `WCM-L2-0004` | serving-image measurement is not in accepted_measurements |  |
| `WCM-L2-0005` | a retiring serving image was released while a current one was available |  |
| `WCM-L2-0006` | serving-image measurement is revoked |  |
| `WCM-L2-0007` | GPU report is absent while required_gpu_measurement is set |  |
| `WCM-L2-0008` | CPU and GPU evidence do not echo the same nonce |  |
| `WCM-L2-0009` | memory-fingerprint challenge is absent or failed in a posture that requires it |  |
| `WCM-L2-0010` | attestation-revocation check is absent or staler than the policy allows |  |
| `WCM-L2-0011` | quote signature or certificate chain does not verify to a trusted root |  |
| `WCM-L2-0012` | REPORT_DATA does not bind the challenge nonce |  |
| `WCM-L2-0013` | released key is not sealed to the attested transport key (channel binding) |  |
| `WCM-L2-0014` | a retiring serving image was released past its retire_after |  |
| `WCM-L2-0015` | GPU measurement does not match required_gpu_measurement.rim_pin |  |
| `WCM-L2-0016` | the attestation key is listed as revoked |  |
| `WCM-L2-0017` | no key is held for this weights_hash |  |

## L3 - Runtime custody

| Code | Meaning | |
| --- | --- | --- |
| `WCM-L3-0001` | key was usable after the attestation lease lapsed (must be zeroized, not suspended) |  |
| `WCM-L3-0002` | operation budget was exhausted without requiring re-attestation |  |
| `WCM-L3-0003` | successful re-attestation did not renew the lease or reset the budget | *diagnostic only* |
| `WCM-L3-0004` | reported trusted-time floor is stronger than the one actually in force | *diagnostic only* |

## L4 - Derivative lineage

| Code | Meaning | |
| --- | --- | --- |
| `WCM-L4-0001` | a manifest in the chain is not in the manifest set |  |
| `WCM-L4-0002` | the lineage chain contains a cycle |  |
| `WCM-L4-0003` | a derivative exists of a parent whose derivatives policy is none |  |
| `WCM-L4-0004` | a derivative widens rights beyond its parent (non-monotone) |  |
| `WCM-L4-0005` | a manifest in the chain is not present or in force in the transparency log |  |
| `WCM-L4-0006` | a manifest in the chain is revoked; revocation cascades to the leaf |  |
