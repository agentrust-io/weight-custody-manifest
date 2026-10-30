# Canonical byte compatibility review

This candidate corrects the number placement and string escaping used by the
public canonicalizer to match its documented RFC 8785 contract. It reuses the
Apache-2.0 Agent Manifest formatter, with its authorship lineage retained in
the module documentation. It adds no runtime dependency.

Before the correction, a float such as `1e-6` produces `1e-06` instead of
`0.000001`. U+007F through U+009F and U+2028/U+2029 receive additional escapes.
Those are valid JSON spellings but different canonical bytes. A signer and
verifier using different spellings compute different hashes and signatures.

The existing optional-null projection and rejection of non-NFC strings remain
unchanged. This candidate does not implement the safe-integer/key/surrogate
work in PR #242, and does not declare all other RFC 8785 behavior conformant.

## Release decision required

Affected old signatures and hashes cannot be silently reinterpreted. Before
merging or releasing, maintainers need to inventory persisted manifests,
evidence, renewal records and other callers containing affected values, decide
the release/version treatment, and state which historical verifier remains
available for archived artifacts. Regenerating a signed artifact requires its
authorized signer; a verifier must not try legacy variants until one verifies.

This remains a draft until that decision is recorded. The candidate adds no
legacy fallback, automatic re-signing, data migration, or normative amendment.
Its small known-answer suite is an interoperability regression sample, not a
complete independent canonicalization certification.
