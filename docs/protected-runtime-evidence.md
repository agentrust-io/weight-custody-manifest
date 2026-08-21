# Protected-runtime evidence plan

Two WCM controls cannot be established by the reference SDK alone. This page
defines the evidence a protected-runtime implementation must produce before the
project closes the corresponding issues. A unit-test simulation is useful for
development but is not acceptable proof.

## Protected-memory fingerprint sweep (issue #79)

Run the sweep in the same measured, protected execution boundary that receives
the model key. For each fresh KBS release challenge, the runtime must:

1. Allocate and declare the exact protected virtual and physical range being
   tested, excluding only documented runtime-reserved pages.
2. Derive unpredictable per-address values from protected randomness plus the
   fresh KBS nonce. Do not accept host-supplied expected values.
3. Visit pages in a nonce-derived permutation, write the values, issue the
   architecture-appropriate ordering barriers, then read in a different
   nonce-derived permutation.
4. Detect missing, duplicated, aliased, or inconsistent locations before
   reducing the observations to a fingerprint.
5. Bind the range, algorithm version, challenge nonce, result, and fingerprint
   into the same attested release attempt. The KBS must verify that binding and
   consume the nonce even on failure.
6. Erase temporary values before model loading continues.

The controlled negative harness must expose two virtual locations backed by the
same test page and show a denial. Separate cases must cover an omitted range,
replayed result, host-authored result, and incomplete sweep.

Record only algorithm/version identifiers, declared byte/page counts, nonce and
result hashes, attestation receipt hashes, timestamps, and verdicts. Do not
record page contents, raw quotes, provider tokens, tenant/resource identifiers,
hostnames, IPs, customer names, or model material.

Passing proves the tested address map behaved consistently during that attempt.
It does not prove immunity to later remapping, bus probing, cold-boot extraction,
key extraction, or every physical-memory attack.

## Lease lapse, zeroization, and execution stop (issue #78)

Use the production custody controller and the actual inference boundary:

1. Start from clean persistent state, attest, receive a transport-sealed model
   key, decrypt one protected model, and record the lease deadline.
2. Complete one signed renewal and one successful inference.
3. Before the next deadline, block the renewal service or revoke the workload.
4. At the effective boundary, require the controller to emit distinct signed
   records for `wipe_requested`, `wipe_completed`, and `process_terminated`.
5. Attempt inference after the boundary and require failure.
6. Inspect the controller's supported key handle—not arbitrary language memory—
   and require the cryptographic operation to fail after zeroization.
7. Restart from the encrypted artifacts and stale local state. Require a new
   attestation and release before any inference can succeed.

Run separate cases for explicit revocation and unreachable renewal service.
Verify the signed record chain, monotonic sequence, manifest/weights identity,
lease identifier, timestamps, and previous-record hash. Publish hashes and
boolean outcomes, not keys, plaintext model data, raw attestation evidence, or
environment identifiers.

The result applies only to the tested controller, key API, language/runtime,
hardware, compiler, and build. A best-effort overwrite of a Python `bytes`
object is not proof of hardware-backed zeroization. The evidence must name the
primitive that makes the key handle unusable and the mechanism that terminates
in-flight and future inference.

The SDK provides `RuntimeRecord`, `sign_runtime_record`, and
`verify_runtime_record_chain` as the portable receipt contract. Records are
Ed25519-signed and hash-chained across one weights hash, manifest hash, and lease
identifier. A terminal proof must start with `lease_started`, may contain
`renewal_succeeded` records, then contain exactly one `lapse_detected` or
`revocation_detected` boundary followed—in order—by `wipe_requested`,
`wipe_completed`, and `process_terminated`. The verifier rejects tampering,
reordering, missing terminal events, signer substitution, and cross-lease
splicing. The production controller must call this contract from inside its
protected control path; signatures created by an external observer are not
evidence of protected execution.

## Review gate

For either issue, merge only when the sanitized receipt, verifier, negative
case, exact build identity, and rerun instructions are committed together. A
green SDK suite confirms reference semantics; it does not substitute for this
protected-runtime evidence.
