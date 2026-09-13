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
| L2 | Attestation-gated release | **37** | scenarios |
| L3 | Runtime custody | **12** | scenarios |
| L4 | Derivative lineage | **10** | documents |

91 vectors. All four levels are vectored and **every reportable error code is
exercised by at least one vector**, which a test enforces. L1 and L4 ask a question
about a document. L2 and L3 ask what a system does over *time*, so their vectors
are ordered scenarios (see [Scenario vectors](#scenario-vectors)).

That is the point at which a pass gets over-read, so here is what it still does
**not** mean. Both limits are printed by `wcm conformance` on every full run, from
`COVERAGE_NOTES` in `wcm.conformance`:

- **The quote vectors use a synthetic PKI, not vendor roots.** They prove an
  implementation verifies a certificate chain, a report signature and a
  `REPORT_DATA` nonce binding correctly. They do not prove it can parse a real AMD,
  Intel or NVIDIA quote. That is vendor-format work, and the SDK covers it with
  committed real-silicon fixtures rather than with vectors.
- **GPU-side cryptographic verification is not vectored.** The L2 quote vectors
  verify the CPU quote. The NVIDIA path is a separate verifier over a real device
  chain with a raw nonce at offset 4, and the H100 fixture in the SDK's own tests
  is what covers it today.

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

Vectored as scenarios (`vectors/gate/`), covering both halves: the policy gate, and
cryptographic quote verification through the reference JSON container (chain to a
trusted root, report signature, and `REPORT_DATA` binding including the transport
key when channel binding is in use). See the coverage notes above for what the
synthetic PKI does and does not establish.

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
    "cpu_quote_verifier": { "parser": "json", "trusted_roots_pem": ["..."] },
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

#### Quote recipes

When `kbs.cpu_quote_verifier` is set, `cpu.quote` carries a **recipe** rather than a
finished quote, and the runner assembles the quote at scenario time:

```jsonc
"cpu": {
  "quote": {
    "report_data": { "nonce": "$n1", "transport_public_key": "b2b2..." },
    "report_data_offset": 0,
    "leaf_pem": "...", "leaf_key_pem": "...", "intermediates_pem": ["..."],
    "tamper_report_after_signing": false
  }
}
```

A recipe rather than a fixed artifact for one unavoidable reason: `REPORT_DATA` has
to bind the nonce, and the nonce is generated at scenario time because it must be
unpredictable. A pre-baked quote could only ever demonstrate a *mismatch*. So the
vector supplies the chain, a test signing key, and a description of what
`REPORT_DATA` should bind, and the implementation assembles it: report body =
`offset` zero bytes, then `sha256(nonce || transport_key?)`, then trailing body
bytes, signed ECDSA/SHA-256 by the leaf key. The container is
`base64(JSON)` in the shape `JsonQuoteParser` documents (`report_b64`,
`signature_b64`, `leaf_pem`, `intermediates_pem`, `report_data_offset`).

`tamper_report_after_signing` flips a byte outside `REPORT_DATA` after signing, so
the chain and the nonce binding stay intact and only the signature can catch it.

The keys in these vectors are test keys, generated once and committed. They protect
nothing.

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

## Vendor-evidence vectors (`kind: vendor`)

Every certificate in `vectors/gate/` is one this project minted. Those vectors
prove an implementation verifies a chain, a report signature and a `REPORT_DATA`
binding; they cannot prove it parses a real AMD, Intel or NVIDIA quote, because
they contain none. A `vendor` vector carries a capture taken from real silicon.

### Vector shape: named root

The vector **names its root** by the SHA-256 of the root's DER and **carries
leaf and intermediates inline**. The runner resolves the root from the root
store (see [`roots/README.md`](roots/README.md)) and fails with `root not
staged` rather than fetching.

A chain carrying its own anchor proves internal consistency, which the synthetic
PKI already proves, and the point of a vendor capture is to be about the vendor.

Where a vendor does not publish a root in a form a runner can stage, the vector
says so in `chain.root_limit`, as a stated limit, rather than letting the chain
anchor itself quietly.

One rule, for every vendor, with no exception. A TDX quote carries a copy of its
PCK chain inside the signed bytes and would verify without these fields ever
being read, so the runner checks the carried chain against the named root before
the format's own verifier runs. Otherwise the fields would be decorative on that
one vendor, and `stripped-chain` would report a refusal nobody performed.

### Binding kinds

Real captures do not uniformly echo a caller nonce, so each capture declares
what its `REPORT_DATA` is bound to:

| `binding.kind` | Meaning |
| --- | --- |
| `nonce-digest` | `REPORT_DATA` equals `sha256(nonce)` |
| `nonce-and-transport` | `sha256(nonce \|\| transport key)`, which is what stops relay |
| `nonce-echo` | the nonce appears **verbatim** in the report at `nonce_offset`, rather than as a digest of it |
| `attestation-key` | bound to a platform key, as on the Azure SEV-SNP vTPM path; no caller freshness |
| `none` | signature and chain only, and nothing about freshness |

An unrecognised kind is a **hard failure, never a skip**. The silent skip is the
failure mode that matters, because a runner that skips what it does not
understand reports a pass it never performed.

`none` earns its place: some real captures prove only that a chip signed
something, and a format that cannot say so will have a nonce invented for it.

`nonce-echo` earns its place for the opposite reason. NVIDIA device reports
carry no `REPORT_DATA` and echo the raw nonce at offset 4. Declaring that as
`nonce-digest` verifies correctly, which is the problem: the label names a
mechanism that is not in those bytes, and a closed vocabulary exists to stop
exactly that. It is named for what the bytes do rather than for the vendor,
because any platform echoing a nonce verbatim belongs in it, and `nonce_offset`
is a field rather than a constant so a second such platform needs a value and
not a branch. The runner checks the declared offset against the report format
before verifying, and refuses `nonce_offset` on any kind that binds a digest,
since a digest has no offset to declare.

### Expiry

| Tier | Clock | Scored |
| --- | --- | --- |
| conformance | `validity.now`, from the vector | yes |
| live | wall clock | no, reported separately |

The live tier runs on every vendor capture and prints under the level table on
every full run, as its own block, touching no score:

```
live  3/4 vendor captures verify against the wall clock (reported, not scored)
        accept-some-capture: certificate outside validity window: ...
```

That is where a capture ageing out becomes visible. It only works if somebody
reads it, and who that is has not been settled.

`validity.not_after` records the shortest-lived certificate in the vector and is
**required, not optional**. The horizon is 2032, and a refresh process built now
would be six years of maintenance for a problem the recorded `not_after` will
surface on its own. Recording it is what makes that a decision rather than an
oversight.

### Refusals

Six mutations, applied by the runner to every capture, so a new capture cannot
arrive with only a happy path:

| Case | Expected |
| --- | --- |
| `wrong-binding` | `REPORT_DATA` mismatch |
| `tampered-report` | signature fails |
| `tampered-signature` | signature fails |
| `stripped-chain` | no path to a trusted root |
| `out-of-chain-root` | no path to a trusted root |
| `expired-at-now` | outside the validity window |

The expiry mutation steps the smallest representable amount past `not_after`
rather than a whole second. Every NVIDIA certificate in this repository is valid
until 9999-12-31T23:59:59, where a one-second step overflows; validity is an
inclusive comparison, so a one-microsecond step is outside the window and the
case applies to that capture like any other.

The **out-of-chain untrusted root is one root shipped with the suite**, not
invented per vector. Both obvious ways to invent it look like passes: an anchor
taken from the capture's own chain verifies correctly, and a VCEK is rejected on
certificate policy for a non-positive serial before any chain logic runs. Every
runner should fail that case for the same reason, which only happens if they are
all given the same root.

Each case declares `reason_contains`, a **substring** of the refusal reason and
never an exact message, or the vectors become a change detector for wording.

Both tamper mutations are told where to land by the evidence format rather than
guessing at "the last byte" or "the middle". An SEV-SNP report carries reserved
bytes after its signature field, and a TDX quote is mostly certification data
that no signature covers, so a mutation placed by eye can change nothing at all
and the case then reports a refusal it never performed.

### The GPU rule

**A vector must not pin a digest of the report, nor the full report bytes.** It
may pin the verification outcome, the chain identity, and the binding check.

The reason belongs next to the rule, because the rule without the reason will be
relaxed by whoever finds it inconvenient. Three ranges of a 4,129-byte H200
report move between calls: the nonce at `[4, 36)`, the signature at
`[4033, 4129)`, and 32 bytes at `[3565, 3597)` that change **even under an
identical nonce**. Those 32 bytes only appear if you fetch one report twice
under the same nonce and once under a different one. Varying the nonce hides
them, so a pin built by diffing two reports taken under *different* nonces looks
stable and is not.

That is a method note, not a numbers note, and it is the part that stops the
next person repeating it.

A vendor vector is always an `accept`. Its negatives are the matrix above,
derived by the runner rather than written by hand, which is what stops a capture
arriving with only a happy path. A contributed reject vector would compete with
the derived ones and could not be scored honestly either, since this kind has no
`WCM-*` code vocabulary to declare.

### The shape

```jsonc
{
  "id": "accept-snp-azure-attestation-key",
  "level": "L2",
  "kind": "vendor",
  "description": "why this capture exists and what it establishes",
  "expect": "accept",

  "capture": {
    "vendor": "amd", "technology": "sev-snp",
    "part": "EPYC Milan", "tcb": "...",
    "captured_at": "2026-09-08", "source": "Azure DCasv5 confidential VM"
  },

  "evidence": { "format": "sev-snp-report", "report_b64": "..." },

  "chain": {
    "leaf_pem": "...", "intermediates_pem": ["..."],
    "root": { "id": "amd-ark-milan", "der_sha256": "sha256:..." },
    "root_source": "AMD KDS, staged by the runner"
  },

  "binding": {
    "kind": "attestation-key",
    "note": "the paravisor binds REPORT_DATA to the vTPM AK, not a guest nonce"
  },

  "validity": { "now": "...", "not_after": "..." },

  "refusals": {
    "wrong-binding":      { "reason_contains": "does not bind" },
    "tampered-report":    { "reason_contains": "signature does not verify" },
    "tampered-signature": { "reason_contains": "signature does not verify" },
    "stripped-chain":     { "reason_contains": "trusted root" },
    "out-of-chain-root":  { "reason_contains": "trusted root" },
    "expired-at-now":     { "reason_contains": "validity window" }
  }
}
```

The machine-readable form is
[`schema/wcm-vendor-vector-v1.schema.json`](../schema/wcm-vendor-vector-v1.schema.json).

No captures are committed under this kind yet. The format lands first so that
captures fit the format rather than the format bending around whichever capture
arrives first.

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
| `vendor` | L2 | `capture`, `evidence`, `chain`, `binding`, `validity`, `refusals` (see [Vendor-evidence vectors](#vendor-evidence-vectors-kind-vendor)) |

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

One registry marker exists, and a test asserts it does not grow quietly. Adding to
it should be a decision, not the way a failing code is made to disappear:

- **diagnostic only** (`WCM-L3-0003`, `WCM-L3-0004`) names a way an implementation
  can be *wrong* rather than an outcome it reports. Nothing raises "your
  re-attestation failed to renew the lease"; the suite concludes it when a step
  that should have succeeded did not. A vector can never *expect* one.

`NOT_YET_VECTORED_CODES` is currently empty. It stays as a mechanism, because if a
code is ever added ahead of its vector, declaring the gap is better than leaving it
implicit.

## What building this corpus found

Worth recording, because it is the argument for having a suite at all rather than
trusting that the implementation is right:

- **A configured quote verifier could be bypassed by omitting the quote.** Or so it
  needed checking: `reject-quote-missing-when-a-verifier-is-configured` exists
  because falling back to structural trust would turn a configured verifier into a
  no-op, which is the kind of thing that passes review and fails in production. The
  gate does deny; now something proves it.
- **`retire_after` without a timezone crashed the gate.** The value arrives in a
  manifest and the gate's clock is timezone-aware, so a naive timestamp raised
  `TypeError` out of `verify_and_release` and aborted the whole release path. Now a
  naive value is read as UTC, an explicit offset is honoured, and an unparseable one
  fails closed: a deadline you cannot read is not a deadline that has not passed.
- **Signing needs defaults materialized first**, or valid signatures are rejected
  (see the L1 section above).
