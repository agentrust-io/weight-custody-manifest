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

## Source inventory and bounded compatibility evidence

Inventory against candidate `ef56fd265db277a01d92510d01f8284165e6c8c9`
and base `3f17c2c9f4a4c3783744ba2fb4a44bea6f1c6199`:

| Consumer | Persisted boundary | Adoption owner/action |
| --- | --- | --- |
| `_signing.signing_pre_image`, `renewal.manifest_identity` | Joint signatures and manifest identity over `WCM_SIGNED_FIELDS` | Builder/custodian inventory affected signed fields and authorize replacement signatures if needed. |
| `renewal.evidence_identity`, `RenewalDecision` | Evidence digest, renewal signature and renewal ID; checks carry arbitrary JSON | Broker operator inventory decisions and bound evidence; retain original identifiers and verifier provenance. |
| `RuntimeRecord` | Signature, record hash and following previous-record-hash links; detail is arbitrary JSON | Runtime operator inventory whole chains; re-signing one record cannot preserve original history. |
| `transparency.make_leaf_preimage` | Arbitrary statement bytes, Merkle leaves, roots and proofs | Log operator retain original leaf bytes/checkpoints; never silently recalculate archived roots. |
| `transparency._sth_preimage` | Signed tree-head payload (integer size and string fields) | Log operator check actual values and root provenance; unchanged header spelling does not establish unchanged leaves. |
| `memory_sweep` | Signed result, including nonce/identity strings | Controller operator inventory captured results; this work adds no hardware evidence. |
| `providers.MockProvider` | Synthetic readback hash over nonce | Keep fixture compatibility separate from physical-memory evidence. |
| Public `canonicalize` / `canonical_hash` | External callers' arbitrary persisted JSON-derived bytes/hashes | Downstream owners identify their stores; repository search cannot enumerate them. |

`deployment_identity.DeploymentApproval.canonical_bytes` and
`provisioning.BrokerProvisioningPolicy.context` use separate `json.dumps`
formats, unchanged by this patch. References to affected WCM identities still
need consumer review.

All 167 tracked `*.json` files in the candidate were parsed and compared using
both whole-object canonicalizers with default null-exclusion: 167 byte-identical
outputs, no comparison errors. This is not a deployed-artifact inventory or
validation of every fixture. Signing projections, embedded JSON/JSONL,
generated records and external stores were not covered by that scan. Existing
fixtures alone therefore cannot establish migration safety.

`tests/test_canonical_history.py` exercises the actual runtime-record verifier
with explicit historical preimages and a public test key. An integer control
still verifies and keeps its record hash. The `1e-6` and U+2028 cases verify
against their original bytes but fail under the corrected verifier and have
different record hashes. Fresh records verify in all three cases. Reverting
the canonicalizer makes both affected assertions fail while the valid control
passes. These synthetic archive controls are not recovered production records
or a historical-verification service.

## Decision owner and adoption sequence

Implementation and follow-through: @dinakarjs. Independent SDK maintainers and
the Project Lead retain review/release authority. Existing requests name
@zohebk8s / @imran-siddique; neither is claimed to have accepted a new assignment.

1. Operators and downstream owners report affected artifact families and
   retention needs using the inventory above. Unknown inventories stay unknown.
2. Maintainers select the release/version boundary and availability of an
   explicitly identified historical verifier. An isolated, pinned verifier for
   archive review is a proposal, not an approved runtime fallback or permission
   to deploy old code in production.
3. Authorized signers decide whether new artifacts are needed. Preserve old
   signed bytes, identities and log/chain history; specify how new history
   references them instead of overwriting original evidence.
4. Independent review accepts the compatibility policy and boundary tests, and
   exact-head checks pass, before draft removal and release adoption.
5. After adoption, @dinakarjs maintains regressions and follows one named
   downstream consumer through its transition. No downstream commitment or
   release date has yet been obtained.

This PR remains draft until steps 1–4 are resolved. No automatic fallback,
re-signing, selected release policy or completed migration is claimed.
