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

| Level | Title | Vectors |
| --- | --- | --- |
| L1 | Manifest and joint signature | 32 |
| L2 | Attestation-gated release | **none yet** |
| L3 | Runtime custody | **none yet** |
| L4 | Derivative lineage | 10 |

**L2 and L3 have no vectors, so no implementation can be scored on them today.**
Their requirements are written down and their error codes are allocated, but L1
and L4 are checks over documents while L2 and L3 are protocol behaviour over live
state (single-use nonces, released keys, clocks, operation counters). Expressing
those needs a scripted-scenario format that is not designed yet. Passing L1 and
L4 is conformance to the manifest and lineage layers, not to WCM as a whole, and
the runner says so on every run.

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
