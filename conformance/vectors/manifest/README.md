# Manifest structural vectors

Language-neutral test vectors for Layer 1 manifest *structural* validity: the
field sets, value sets, and cross-field rules specified in
[SPEC.md](../../../SPEC.md) section 3.1 and expressed in
[`schema/wcm-manifest-v1.schema.json`](../../../schema/wcm-manifest-v1.schema.json).

These vectors say nothing about signatures. A vector with an `accept` verdict is
asserting that the document is a well-formed manifest, not that its signatures
verify or that the required roles signed. Signature verification is Layer 1
*verification*, a separate concern with separate vectors.

## Format

One JSON file per vector, named after its `id`:

```json
{
  "id": "reject-retire-after-on-current",
  "description": "why this case exists and what it protects",
  "expect": "accept" | "reject",
  "reject_reason": "the constraint that is violated (reject only)",
  "schema_expressible": true,
  "manifest": { }
}
```

`schema_expressible` appears on `reject` vectors only. It is `true` when the
committed JSON Schema rejects the manifest on its own. It is `false` when the
constraint cannot be expressed in standard JSON Schema, so a schema-only
implementation will *accept* the manifest and must enforce the rule elsewhere.

Exactly one vector is currently marked `false`: `reject-self-derivation`. JSON
Schema has no standard way to compare the values at two instance locations, so
`derived_from != weights_hash` has to be a verifier-side check. See
[`schema/README.md`](../../../schema/README.md).

## Using them

An implementation in any language reads each file, validates `manifest`, and
compares its verdict against `expect`. Two rules make the result meaningful:

1. Every `accept` vector must be accepted. Rejecting a valid manifest is as much
   a conformance failure as accepting an invalid one, and it is the more common
   direction for an over-strict implementation.
2. Every `reject` vector must be rejected, including the ones where
   `schema_expressible` is `false`. Delegating everything to the JSON Schema is
   not sufficient to pass.

The reference implementation runs them in
[`python/tests/test_schema.py`](../../../python/tests/test_schema.py), which
checks both the Pydantic model and the JSON Schema against the corpus and asserts
that the only divergence between the two is the documented one.

## Adding a vector

Write a new file. There is no index to update and no generator to re-run. Keep
the manifest as small as the case needs, so a reader can see what is being tested
without diffing against another vector, and make `description` say what the rule
protects rather than restating the JSON.
