# Protected-runtime evidence plan

Two WCM controls cannot be established by the reference SDK alone. This page
defines the evidence a protected-runtime implementation must produce before the
project closes the corresponding issues. A unit-test simulation is useful for
development but is not acceptable proof.

## Protected-memory fingerprint sweep (issue #79)

The SDK supplies `BytearrayMemoryRange`, `run_memory_sweep`, and
`verify_memory_sweep` as the executable reference contract. The runner derives
different full-page values and write/read permutations from protected secret
material plus the fresh KBS nonce, writes and reads every declared page, detects
inconsistent mappings, and signs the complete transcript with Ed25519. The KBS
fails closed unless a policy-pinned sweep public key verifies that transcript;
its production default does not accept the earlier unsigned structural shape.
Language-neutral conformance vectors retain an explicitly isolated declarative
mode because the frozen v1 vectors cannot carry a signature over a runtime nonce.

This implementation executes over a real allocated byte range and its controlled
test adapter detects aliased logical pages. That is reference-algorithm evidence,
not proof that a production enclave covered its physical memory. The remaining
work is to provide a `ProtectedMemoryRange` adapter owned by the actual protected
runtime and capture the receipt described below.

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

### Serving shutdown integration

The reference SDK provides `EnclaveSession(on_stop=...)` and `ServingShutdown`
as integration points, not an inference engine or a hardware erasure driver.
Pass a `ServingShutdown` instance as `on_stop` when constructing the session
(also supported by `from_release`). Supply these measured-runtime callbacks:

1. `stop_admission`: close the request queue and reject new inference.
2. `cancel_inflight`: stop active inference and quiesce device work. Return only
   when buffers are no longer in use; raise if this cannot be established.
3. `unload_weights`: overwrite/release supported model and temporary buffers,
   destroy model/allocator objects and GPU contexts, and invoke available
   hardware sanitization. This step is skipped if cancellation fails.
4. `terminate`: enforce serving-worker termination, including a forced fallback
   when earlier cleanup failed. This is attempted even if previous callbacks
   raise. It must not merely log a request to stop.

The session marks itself wiped and overwrites its held key before invoking the
hook. Authorization and renewal then fail permanently. Teardown runs once;
ordinary callback failures are collected in an `ExceptionGroup` after the
termination attempt. Callback return values are not signed proof of physical
erasure or process exit. An independent protected supervisor must confirm worker
exit; a process cannot truthfully attest its own completed termination before
exiting. Do not emit `wipe_completed` or `process_terminated` on a failed attempt.

Start `session.monitor()` in a supervised asyncio task before admitting work,
and keep it running alongside bounded renewal I/O. It checks idle leases and
wipes at `now >= deadline`. Once running, cancellation, clock errors, and monitor
failure also trigger the stop hook. Retain and await the task so teardown errors
are observed. All authorization, renewal, explicit zeroization, and monitor
calls must be serialized on the same event loop; the session is not thread-safe.
Do not cancel the monitor just because an individual renewal attempt failed.

No unsuccessful renewal extends the original deadline, but an unreachable or
unverifiable response and an authenticated denial are different signals. Treat an
unreachable or unverifiable response as inconclusive and retry with fresh
challenges within the existing lease and operation budget. Treat a verified signed
decision that refused renewal as a verdict, not a transport error: stop admitting
new work, and call `session.zeroize()` immediately when its reasons are
revocation-class, such as a revoked serving image, a revoked attestation key, or a
manifest no longer in force. Apply only verified successful signed renewals. Call
`session.zeroize()` immediately for an independently verified revocation under the
manifest's profile.

`apply_renewal` surfaces that distinction rather than leaving it to the caller to
re-derive: a decision that verifies and reports `renewed: false` raises
`RenewalDenied`, carrying the signed `failed_checks` and `failed_check_names`,
while an unverifiable, expired, replayed, cross-model or self-contradictory
decision raises plain `ValueError`. `RenewalDenied` subclasses `ValueError`, so
existing handlers keep working and only code that wants the distinction needs to
ask for it. The SDK does not classify a denial as revocation-class. The decision
carries no signed disposition field yet, so that mapping is deployment policy;
until it exists, treat a revocation-class gate name in `failed_check_names` as the
trigger for immediate termination.

A session constructed without a teardown adapter reports `stop_floor` as `none`
rather than failing quietly, the same disclosure `trusted_time_source` requires of
`none-best-effort`. It still ends custody and stops authorizing at the boundary;
nothing tears its loaded model down. Record the reported `stop_floor` alongside the
receipts below, because a `none` result bounds what the rest of the evidence can
claim.

Check `authorize_operation()` on every inference dispatch, including requests
already queued. Admission checks alone do not stop a long-running operation:
the cancellation/termination callbacks must enforce that boundary as well.
For graceful draining, close admission sufficiently early and finish work before
expiry. At expiry there is no additional drain grace period and no partial result
should escape from cancelled work. Restart from a fresh release, never from the
wiped session or previously loaded model objects.

The asyncio monitor is cooperative, not a trusted timer. Blocking the event loop
or a synchronous cleanup callback can delay it. Callbacks must use bounded native
runtime primitives, with an independent protected watchdog to force execution
stop if renewal, cleanup, or the serving worker hangs. Neither these SDK hooks
nor their unit tests close issue #78: the hardware-specific callbacks, trusted
time source, enforced stop latency, memory cleanup limits, and receipt capture
still require the production evidence described above.

## Review gate

For either issue, merge only when the sanitized receipt, verifier, negative
case, exact build identity, and rerun instructions are committed together. A
green SDK suite confirms reference semantics; it does not substitute for this
protected-runtime evidence.
