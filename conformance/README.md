# WCM conformance suite

Language-neutral test vectors and a scoring contract, so an independent
implementation of the Weight Custody Manifest can be checked against the same
inputs the reference implementation is, in whatever language it is written.

The vectors are plain JSON. The reference runner is Python, but nothing about the
suite is: an implementation reads the vectors, records what it concluded, and
gets scored.

## Coverage, stated up front

| Level | Title | Vectors | Shape |
| --- | --- | --- | --- |
| L1 | Manifest and joint signature | **32** | documents |
| L2 | Attestation-gated release | **29** | scenarios |
| L3 | Runtime custody | **12** | scenarios |
| L4 | Derivative lineage | **10** | documents |

All four levels are vectored. L1 and L4 ask a question about a document. L2 and L3
ask what a system does over *time*, so their vectors are ordered scenarios (see
[Scenario vectors](#scenario-vectors) below).

**One requirement inside L2 is still not covered:** cryptographic quote
verification, meaning the quote signature and certificate chain against a vendor
root (`WCM-L2-0011`, `WCM-L2-0012`). Those need raw hardware evidence plus trust
anchors rather than the declarative evidence these vectors carry. The repo has
real-silicon fixtures to build them from, but two things need designing first: how
a vector supplies a trust store, and how to express nonce binding honestly given
that on the Azure SEV-SNP capture `REPORT_DATA` binds the vTPM attestation key
rather than a caller-supplied nonce. Both codes are listed in
`wcm.conformance.NOT_YET_VECTORED_CODES` and marked in [`codes.md`](codes.md), and
the runner prints them on every full run, so a pass is not read as covering them.

## The levels

### L1 - Manifest and joint signature

Accept exactly the manifests [SPEC.md](../SPEC.md) §3.1 defines as valid and
reject the rest, including the cross-field rules; and verify the joint signature.

Verifying the joint signature means all of:

- every required role has a valid signature: builder and custodian always, plus
  sovereign when `release_policy.sovereign_profile.enabled`;
- every signature verifies against a key the verifier *trusts for that
  algorithm*, so a signature naming a different algorithm than its trusted key is
  rejected rather than retried;
- a signature whose `key_id` is not trusted is a failure, not merely an
  unverified extra: a cryptographically valid signature by the wrong party must
  not satisfy a role;
- the sovereign role is satisfied only by the declared `sovereign_signer`, not by
  anyone presenting a block tagged `sovereign`;
- a malformed signature value fails closed as a verification failure rather than
  raising out of the verifier.

**Two things trip implementations here, both learned from building the vectors:**

1. **Materialize defaults before computing the pre-image.** The signing pre-image
   is the `WCM_SIGNED_FIELDS` subset of the manifest *with its defaults present*
   (`base_confidentiality`, `deployment_model`, `physical_hardening`, and the
   rest). A verifier parses the manifest, which fills defaults in, and then
   canonicalizes. An implementation that canonicalizes the raw document as
   received computes a different pre-image and rejects valid signatures. The
   signature vectors carry manifests with defaults already materialized, so this
   is testable rather than a trap.
2. **`derived_from` must not equal `weights_hash`.** This one constraint cannot
   be expressed in JSON Schema, so an implementation that delegates structural
   validation entirely to
   [`schema/wcm-manifest-v1.schema.json`](../schema/wcm-manifest-v1.schema.json)
   will accept a self-derived manifest and fail `reject-self-derivation`. That is
   deliberate: it makes the lineage walk in §3.4 non-terminating, so the check is
   load-bearing rather than cosmetic. See [`schema/README.md`](../schema/README.md).

### L2 - Attestation-gated release

Gate key release on composite evidence (§3.2): single-use KBS nonce; platform and
assurance tier; serving-image measurement with prefer-current and a hard fail on
`revoked`; CPU-to-GPU nonce binding; the memory-fingerprint challenge where the
posture requires it; attestation-revocation freshness; quote signature and
certificate chain to a trusted root; and channel binding, so the released key is
sealed to the attested transport key rather than returned on the channel.

Vectored as scenarios (`vectors/gate/`). The policy gate is fully covered. The
cryptographic half, verifying the quote signature and certificate chain against
a vendor root, is not: see the coverage note above.

### L3 - Runtime custody

Enforce the wipe-on-lapse floor (§3.2, §3.3): zeroize the key when the
attestation lease lapses, rather than suspending its use; require re-attestation
when the operation budget is exhausted, *without* wiping in that case, since the
two outcomes are deliberately different; renew on successful re-attestation; and
report the trusted-time floor actually in force instead of implying a stronger
one.

Vectored as scenarios (`vectors/custody/`), including the distinction that trips
implementations: an exhausted operation budget demands re-attestation and the key
SURVIVES, while a lapsed wall-clock lease zeroizes it. Conflating the two is the
difference between a wipe and a suspend.

### L4 - Derivative lineage

Resolve a lineage chain and enforce §3.4 and §3.8: terminate on cycles and on
unresolvable parents rather than looping or treating a missing parent as a root;
forbid a derivative of a parent whose `derivatives` policy is `none`; keep rights
monotone down the chain, both the derivative policy and `permitted_environments`;
gate on every upstream manifest being present in the transparency log; and
cascade revocation from any chain member to the leaf.

## Scenario vectors

L2 and L3 vectors are ordered steps rather than a single input, because the
properties they check are about sequence: a nonce is single-use, a lease lapses, a
budget runs down. Two things are pinned so a scenario means the same thing
everywhere:

- **The clock is supplied by the vector** and only moves on an explicit
  `advance_clock` step. "The lease lapsed" is then a fact about the scenario, not
  about how long the test took to run.
- **Nonces are generated by the implementation**, since they must be
  unpredictable and a vector cannot hardcode them. A `challenge` step binds one to
  a name, and later steps reference it as `"$name"`. Writing a literal value where
  a reference would go is how a never-issued nonce is expressed.

### L2 steps (`kind: gate`)

```jsonc
{
  "manifest": { },
  "kbs": {
    "clock": "2026-01-01T00:00:00+00:00",
    "keystore": { "sha256:...": "<key as hex>" },
    "challenge_ttl_seconds": 300,
    "max_attestation_cache_age_seconds": 600,
    "revoked_attestation_keys": [],
    "require_channel_binding": false
  },
  "steps": [
    { "op": "challenge", "as": "n1" },
    { "op": "advance_clock", "seconds": 301 },
    { "op": "release", "evidence": { "cpu": { "nonce_echo": "$n1" } },
      "expect": "allow", "key_form": "sealed" },
    { "op": "release", "evidence": { }, "expect": "deny", "code": "WCM-L2-0001" }
  ]
}
```

`evidence` is the composite bundle (SPEC 3.2): a `cpu` quote, an optional `gpu`
report, an optional `memory_fingerprint`. It is declarative on purpose: an
implementation builds its own evidence objects from these fields rather than
parsing bytes we chose. `key_form` is `clear` or `sealed`, and on a channel-bound
release it must be `sealed`, since returning the key in the clear is the gap
channel binding exists to close.

### L3 steps (`kind: custody`)

```jsonc
{
  "manifest": { },
  "custody": { "clock": "...", "key": "<hex>", "max_operations": 2 },
  "steps": [
    { "op": "use_key", "expect": "ok" },
    { "op": "use_key", "expect": "error", "code": "WCM-L3-0002" },
    { "op": "reattest", "expect": "ok" },
    { "op": "advance_clock", "seconds": 3601 },
    { "op": "tick", "state": "wiped" },
    { "op": "assert_state", "state": "wiped" },
    { "op": "assert_time_floor", "floor": "sound" },
    { "op": "assert_operations_remaining", "remaining": 0 }
  ]
}
```

The cadence and the trusted-time source come from the manifest, because that is
where the protocol puts them. `max_operations` is passed separately: it is a
deployment parameter, not a manifest field (SPEC open question 8.9 residual).

## Vector format

One JSON file per vector, under `vectors/<kind>/<id>.json`:

```json
{
  "id": "reject-cycle",
  "level": "L4",
  "kind": "lineage",
  "description": "why this case exists and what it protects",
  "expect": "accept" | "reject",
  "code": "WCM-L4-0002",
  "reject_reason": "human-readable statement of the violated constraint"
}
```

`code` and `reject_reason` appear on `reject` vectors only. The rest of the object
is the kind-specific input:

| Kind | Level | Input fields |
| --- | --- | --- |
| `manifest` | L1 | `manifest`, plus `schema_expressible` (whether the JSON Schema alone rejects it) |
| `signature` | L1 | `manifest` (with `signatures`), `trusted_keys` (`algorithm`, `public_key` as base64url raw, `role_hint`) |
| `gate` | L2 | `manifest`, `kbs` config, `steps` (see [Scenario vectors](#scenario-vectors)) |
| `custody` | L3 | `manifest`, `custody` config, `steps` |
| `lineage` | L4 | `manifests` (array), `leaf`, and optionally `logged` and `revoked` |

A vector `id` must be unique across **every** kind, not just within its own
directory, because the results-file contract keys on `id` alone and two vectors
sharing a name would silently collapse into one scored entry.

The signature vectors use fixed Ed25519 keys derived from constant seeds, and the
scenario vectors use fixed hex key material, so both are reproducible and contain
no secret worth protecting. They are test keys and nothing else.

## Claiming a level

Run the vectors, emit a results file, and score it:

```jsonc
{
  "implementation": "my-wcm 0.3.0",
  "results": [
    { "id": "accept-minimal", "verdict": "accept" },
    { "id": "reject-cycle", "verdict": "reject", "code": "WCM-L4-0002" }
  ]
}
```

```sh
wcm conformance --results my-results.json          # score an implementation
wcm conformance --results my-results.json --level L4
wcm conformance                                    # self-test the reference SDK
wcm conformance --list-vectors
wcm conformance --list-codes
```

Exit status is 0 only if every scored level passed. Three rules make a pass mean
something:

1. **Every `accept` vector must be accepted.** Rejecting a valid manifest is as
   much a failure as accepting an invalid one, and over-strictness is the more
   common direction.
2. **Every `reject` vector must be rejected with the declared code.** Verdict
   alone is not enough, or an implementation that rejects everything would score
   perfectly.
3. **A vector with no result counts as a failure.** Silence about a vector is not
   evidence of passing it, so a partial results file cannot claim a level.

Results naming vectors this corpus does not contain are reported too. That is not
a failure, since it may be a newer suite, but it is not silently dropped either.

## Reference self-test

`wcm conformance` with no `--results` evaluates the vectors with this SDK and
checks verdicts *and* codes. This is a weaker signal than an independent
implementation passing, since the same codebase authored both sides, and the
runner labels its output accordingly. Its real job is to catch a vector whose
expectation drifts from the implementation, which is why it runs in CI.

## Adding a vector

Write a new JSON file in the right `vectors/<kind>/` directory. There is no index
to update. Then make sure the reference derives the declared code: the tests
assert every reject vector's code is the one the reference reports, so a new
vector with a code the reference cannot produce fails loudly rather than being
quietly unenforced.

Keep the input as small as the case needs, and make `description` say what the
rule protects rather than restating the JSON.

Two registry markers exist and both are deliberately small, with a test asserting
neither grows quietly. Adding to one should be a decision, not the way a failing
code is made to disappear:

- **diagnostic only** (`WCM-L3-0003`, `WCM-L3-0004`) names a way an implementation
  can be *wrong* rather than an outcome it reports. Nothing raises "your
  re-attestation failed to renew the lease"; the suite concludes it when a step
  that should have succeeded did not. A vector can never *expect* one.
- **not yet vectored** (`WCM-L2-0011`, `WCM-L2-0012`) is reportable but unexercised,
  listed so the gap is visible instead of merely absent.

## What building this corpus found

Worth recording, because it is the argument for having a suite at all rather than
trusting that the implementation is right:

- **`retire_after` without a timezone crashed the gate.** The value arrives in a
  manifest and the gate's clock is timezone-aware, so a naive timestamp raised
  `TypeError` out of `verify_and_release` and aborted the whole release path. Now a
  naive value is read as UTC, an explicit offset is honoured, and an unparseable one
  fails closed: a deadline you cannot read is not a deadline that has not passed.
- **Signing needs defaults materialized first**, or valid signatures are rejected
  (see the L1 section above).
