# Schema and conformance

Two machine-readable artifacts sit alongside the specification text, so an
independent implementation has something to build and check against rather than
prose to interpret.

## The manifest JSON Schema

[`schema/wcm-manifest-v1.schema.json`](https://github.com/agentrust-io/weight-custody-manifest/blob/main/schema/wcm-manifest-v1.schema.json)
is the normative machine-readable form of `SPEC.md` §3.1. JSON Schema 2020-12,
identified by `https://wcm.agentrust-io.com/schema/manifest/v1.json`.

It is **frozen at v1 and additive-only**. Fields and permitted enum values may be
added; nothing is removed, renamed, made required, narrowed, or repurposed. A
breaking change would publish `.../manifest/v2.json` alongside rather than edit
v1. The specification itself is still pre-1.0, so this is a deliberate trade:
implementers get a stable target now, and whatever the spec grows into arrives as
an addition.

From Python:

```python
from wcm.schema import manifest_schema
schema = manifest_schema()
```

**One constraint is not expressible in JSON Schema:** `derived_from` must not
equal `weights_hash`. Standard JSON Schema cannot compare the values at two
instance locations, so this stays a verifier-side check. It matters, because a
self-derived manifest makes the lineage walk in §3.4 non-terminating. An
implementation that delegates all structural validation to the schema will fail
the corresponding conformance vector. See
[`schema/README.md`](https://github.com/agentrust-io/weight-custody-manifest/blob/main/schema/README.md).

## The conformance suite

[`conformance/`](https://github.com/agentrust-io/weight-custody-manifest/tree/main/conformance)
holds language-neutral JSON vectors and a scoring contract. Four levels are
defined, matching the four protocol layers:

| Level | Title | Vectors | Shape |
| --- | --- | --- | --- |
| L1 | Manifest and joint signature | 32 | documents |
| L2 | Attestation-gated release | 37 | scenarios |
| L3 | Runtime custody | 12 | scenarios |
| L4 | Derivative lineage | 10 | documents |

91 vectors. All four levels are vectored and every reportable error code is
exercised by at least one vector, which a test enforces. L1 and L4 ask a question
about a document. L2 and L3 ask what a system does over *time*, so their vectors are
ordered scenarios with an injected clock and named nonces: a nonce is single-use, a
lease lapses, an operation budget runs down.

Two limits remain, and `wcm conformance` prints both on every full run rather than
leaving a green result to be over-read:

- **The quote vectors use a synthetic PKI**, not vendor roots. They prove an
  implementation verifies a certificate chain, a report signature and a
  `REPORT_DATA` nonce binding correctly. They do not prove it can parse a real AMD,
  Intel or NVIDIA quote, which is vendor-format work the SDK covers with committed
  real-silicon fixtures.
- **GPU-side cryptographic verification is not vectored.** The quote vectors cover
  the CPU quote; the NVIDIA device chain is covered by the SDK's H100 fixture.

Running it:

```sh
pip install weight-custody-manifest

wcm conformance                              # self-test this SDK
wcm conformance --level L4
wcm conformance --list-vectors
wcm conformance --list-codes

wcm conformance --results my-results.json    # score another implementation
```

An implementation in any language reads the vectors, emits a results file naming
each vector's verdict and, for a rejection, its `WCM-*` code, and gets scored.
Three rules make a pass mean something: every valid input must be accepted, every
invalid one must be rejected *for the declared reason*, and a vector with no
reported result counts as a failure. So neither "reject everything" nor a partial
submission can claim a level.

The error codes are listed in
[`conformance/codes.md`](https://github.com/agentrust-io/weight-custody-manifest/blob/main/conformance/codes.md),
and the full contract, including two interop details that trip implementations
(defaults must be materialized before the signing pre-image is computed, and the
self-derivation check has to live outside the schema), is in
[`conformance/README.md`](https://github.com/agentrust-io/weight-custody-manifest/blob/main/conformance/README.md).
