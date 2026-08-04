# Manifest JSON Schema

`wcm-manifest-v1.schema.json` is the machine-readable form of the Layer 1
manifest specified in [SPEC.md](../SPEC.md) section 3.1. It is a JSON Schema
2020-12 document, identified by:

```
https://wcm.agentrust-io.com/schema/manifest/v1.json
```

That `$id` is an identity, not a fetch guarantee. It resolves once the
documentation site is served; until then, use the file in this directory or the
copy inside the Python package (`wcm.schema.manifest_schema()`).

## Frozen at v1

The manifest schema is frozen. From v1 onward, changes are **additive only**:

- A new optional field may be added.
- A new permitted value may be added to an enum, if the existing values keep
  their meaning.
- Descriptions, `$comment`s, and titles may change freely.

The following are **breaking** and will not happen inside v1:

- Removing a field, or renaming one.
- Making an optional field required.
- Removing a permitted enum value, or narrowing a pattern or type.
- Changing what an existing field means.

A change that needs any of those gets a new schema (`.../manifest/v2.json`)
published alongside v1, not an edit to this file. A manifest declares its own
version in `manifest_version`, which is a free-form string this schema
deliberately does not constrain: it identifies the *manifest instance's* version
under the issuing builder's own scheme, not the schema version.

The specification itself is still pre-1.0 and evolving (see
[ROADMAP.md](../ROADMAP.md)). Freezing the schema ahead of a 1.0 spec is a
deliberate trade: implementers get a stable target now, and any field set the
spec grows into arrives as an addition rather than as a redefinition.

## What this schema does not express

The schema and the reference model
([`wcm.models.WeightCustodyManifest`](../python/src/wcm/models.py)) agree on
structural validity and on all but one cross-field constraint. Four cross-field
rules are carried in the schema as `if`/`then` blocks:

| Rule | Where |
| --- | --- |
| `retire_after` is required by, and exclusive to, a `retiring` accepted measurement | `$defs.AcceptedMeasurement` |
| An enabled `sovereign_profile` requires `revocation_authority: quorum` and a non-empty `sovereign_signer` | `$defs.SovereignProfile` |
| `deployment_model: byom-symmetric` requires `custody.custodian_type: customer-self-custody` | top-level `allOf` |
| An enabled `sovereign_profile` requires `release_policy.revocation_authority: quorum` | top-level `allOf` |

One rule is **not expressible**:

> `derived_from` must not equal the manifest's own `weights_hash`.

Standard JSON Schema cannot compare the values at two instance locations. A
schema-only implementation must enforce self-derivation rejection separately;
this is not an optional nicety, because a manifest that derives from itself makes
the lineage walk in section 3.4 non-terminating. The reference model enforces it
in a validator, and the conformance vectors include it as a negative case so an
implementation cannot pass by delegating everything to the schema.

Two further things live outside the schema by design:

- **Signature verification.** The schema validates the shape of the `signatures`
  array. Whether those signatures verify, and whether the required roles are
  present, is Layer 1 verification (`wcm.verify_manifest`), not schema validation.
- **Consistency notes.** `base_confidentiality: open` carried alongside
  secrecy-only controls is reported as a non-blocking note by the reference
  verifier. It is valid, so the schema says nothing about it.

## Regenerating

The structural half is generated from the Pydantic reference model; the
cross-field `if`/`then` blocks are hand-maintained in the generator. From
`python/`:

```sh
python tools/gen_schema.py            # rewrite the committed schema
python tools/gen_schema.py --check    # exit 1 if the committed file is stale
```

`tests/test_schema.py` runs the `--check` equivalent in CI, and separately
asserts that the schema and the model accept and reject the same vectors in
[`conformance/vectors/manifest/`](../conformance/vectors/manifest/). A validator
change that is not mirrored into the schema therefore fails CI rather than
silently weakening the schema.
