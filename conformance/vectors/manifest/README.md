# L1 manifest structural vectors

Layer 1 *structural* validity: the field sets, value sets, and cross-field rules
specified in [SPEC.md](../../../SPEC.md) §3.1 and expressed in
[`schema/wcm-manifest-v1.schema.json`](../../../schema/wcm-manifest-v1.schema.json).

These vectors say nothing about signatures. An `accept` verdict here asserts that
the document is a well-formed manifest, not that its signatures verify. That is
the [`signature/`](../signature/) corpus.

See [`conformance/README.md`](../../README.md) for the vector format, the levels,
and how to claim one. Two things specific to this corpus:

**`schema_expressible`.** On `reject` vectors only. `true` means the committed
JSON Schema rejects the manifest on its own. `false` means the constraint cannot
be expressed in standard JSON Schema, so a schema-only implementation will
*accept* it and must enforce the rule elsewhere.

Exactly one vector is marked `false`: `reject-self-derivation`. JSON Schema has no
standard way to compare the values at two instance locations, so
`derived_from != weights_hash` has to be a verifier-side check. See
[`schema/README.md`](../../../schema/README.md).

**Two test suites read these files.**
[`python/tests/test_schema.py`](../../../python/tests/test_schema.py) checks the
JSON Schema and the Pydantic model against the corpus and asserts the only
divergence between them is the documented one;
[`python/tests/test_conformance.py`](../../../python/tests/test_conformance.py)
checks the reference implementation reaches each vector's declared `WCM-*` code.
