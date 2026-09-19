# Provisioning lifecycle and recovery

The reference provisioning service separates owner authorization, envelope
delivery, receiver installation and workload execution. This guide records its
software transitions and recovery requirements for
[#145](https://github.com/agentrust-io/weight-custody-manifest/issues/145).
It does not establish protected restart, trusted time or secure erasure.

## States and observations

| Component / state | Event | Result |
|---|---|---|
| Owner / policy admitted | Issue challenge | Fresh nonce kept in this owner process; the durable database stores only the policy floor. |
| Owner / challenge pending | Authenticate report and seal key | Challenge consumed; one envelope bound to policy, nonce and receiver boot key. Failed attempts also consume the challenge after the epoch guard admits the operation. |
| Owner / any state | Restart | Pending nonces are lost. Admission checks the configured durable floor; a new challenge is required. |
| Owner / policy admitted | Advance policy | Higher epoch required; local pending challenges discarded. Other owners sharing the database reject stale operations. Previously produced envelopes remain usable at their original receiver within its pending window. |
| Receiver / fresh boot | Request native report | Fresh boot key and locally computed configuration bind the report. One pending installation slot is set. |
| Receiver / pending | Request another report | New nonce replaces the pending slot. Reusing a nonce in the same boot is refused. |
| Receiver / pending | Install envelope | Pending slot consumed before signature verification. Correct owner, policy, boot key, nonce and time are required. Success enables workload release and drops the provisioning private-key reference. |
| Receiver / pending | Invalid, expired or clock-failed install | No workload release; pending slot consumed. An old attempt against a replaced slot also consumes that newer slot. Recovery needs a fresh challenge. |
| Receiver / installed | Provision again | Refused; no overwrite or rekey operation exists. |
| Receiver / any state | Retire | Permanently deny report, install, challenge and release on that object; discard key references. |
| Receiver / any state | New process | Fresh key and unprovisioned state. Old envelopes cannot install under the new boot key. This describes a fresh process, not restoration of a memory snapshot. |
| Worker / key received | Broker retires or owner advances policy | Its previously received key and loaded weights are unaffected. Local custody and serving controls remain necessary. |
| Worker / holding | Local lease reaches deadline | `EnclaveSession` ends authorization at `now >= deadline`, wipes its own mutable key buffer, then invokes the configured stop adapter once. |

Cryptographic authorization to release an envelope does not show that it was
delivered. Sending the POST does not show that it installed. Even an
`{"installed":true}` response is an ordinary HTTP acknowledgement: the owner
receipt retains `installation_proven: false`. The tests include an intermediary
that acknowledges without installing. Neither acknowledgement nor successful
local installation establishes that a model executed.

The reference receiver exposes no authenticated installation proof, remote
retirement or recovery API. Health is an availability response, not lifecycle
evidence. There is no persistent owner delivery journal or exactly-once network
transaction. `OwnerEpochStore` must not be used as an installation ledger.

## Unknown outcomes and recovery

The owner client performs one report request and one installation request,
without redirects or automatic retry. A dropped connection after the POST can
mean either that installation did not happen or that installation succeeded
and the acknowledgement was lost. Both cases fail at the client; they cannot
be distinguished from that failure alone. Malformed or unsuccessful responses
also must not be treated as evidence that no key was installed.

After an uncertain outcome, preserve the protected deployment's identity and
reconcile through a separately authenticated control plane. Do not have a job
runner blindly rerun the CLI or restart the receiver. The no-retry behavior is
per invocation; it does not prevent a supervisor or operator from invoking the
client again. A replacement receiver is a new instance, not proof that the old
one or its workers stopped.

Recovery requires the operator to establish which old receiver and workers
remain active, stop them under the deployment's policy, and authorize a fresh
instance and challenge. If that cannot be established, retain an unknown state
and withhold another release under that recovery procedure. This is an external
operational requirement; the reference service cannot enforce it. Restoring an
owner process does not recover its old pending challenge; restoring a receiver
memory snapshot is outside the fresh-process restart guarantee.

## Authoritative owner state

Use a single owner-controlled database and stable namespace for each broker
policy lineage, including key rotations. Protect the database, its parent path,
namespace, policy files and signing keys from substitution, deletion and
rollback. Reopening the same protected database preserves the epoch floor and
rejects lower epochs and changed policy at the same epoch.

`BEGIN IMMEDIATE` serializes admission and envelope construction for owners
sharing that database. A failed guarded operation rolls back its database
changes. The lock ends before the CLI's installation POST: a concurrent policy
advance cannot retract an envelope that another owner already sealed. A lock
timeout fails the operation; it is not permission to bypass the guard.

SQLite does not establish storage identity or freshness. The test suite
explicitly demonstrates that restoring an old database, deleting it and
reinitializing, substituting a database with no matching namespace, changing
namespace, or using an old clone permits old admission. These are expected
counterexamples to an anti-rollback claim. Concurrent owners on separate clones
do not share a floor. Production recovery needs an external authoritative,
rollback-resistant store and control of namespace selection. The constructor's
creation of a missing database is bootstrap behavior, not safe automatic
recovery after unexplained storage loss.

## Clocks, idle time and suspend/resume

Owner challenges default to aware system UTC and a 60-second TTL. The receiver
uses its own system UTC and caps a pending installation at the earlier of the
offered expiry and 60 seconds after report request. The current provisioning
checks reject times strictly **after** expiry; equality is accepted. This
differs from the inclusive worker custody deadline. Receiver installation
rechecks time even if no traffic arrived while pending. A clock exception during
installation consumes that pending attempt without installing a key.

Worker custody uses the injected clock or system UTC. Run and supervise
`EnclaveSession.monitor()` independently of inference traffic. The existing
monitor ends custody on expiry, cancellation or a clock exception. On simulated
resume with a clock advanced beyond the deadline it stops on its first check;
this is not a real suspend/resume experiment. A stalled or rewound system clock
can extend apparent time, and a blocked event loop can delay the monitor.
Selecting a `trusted_time_source` label does not validate the supplied clock.
The default `TimeFloor.none` discloses the absence of a real-time bound.

A deployment claiming a wall-time stop bound needs trusted time that accounts
for suspension, an independently enforced watchdog, and bounded worker-stop
operations. It must validate those properties on the target platform. Software
tests here establish state transitions against the clock supplied to them.

## Already-loaded workers and serving stop

Reuse `EnclaveSession`, `ServingShutdown` and the serving-stop contract in
[SPEC §3.2](https://github.com/agentrust-io/weight-custody-manifest/blob/main/SPEC.md); do not substitute broker retirement for worker shutdown.
The integration tests open an actual software release envelope, create a
custody session and attach a fake loaded worker through the existing adapter.
They show that broker retirement denies future release while the loaded worker
remains authorized until its own local stop. No model or GPU executes in these
tests.

The adapter calls stop-admission, cancel-inflight, unload-weights and terminate
in that order, once. If cancellation fails, it skips memory release and still
attempts termination; cleanup failure never restores session authorization.
The existing custody suite covers those failures. These callbacks must be
implemented and bounded by the protected runtime. Without an adapter,
`stop_floor` is `none`: session key wiping does not stop loaded weights.

Failed renewal must not extend the lease. The existing `RenewalDenied` result
exposes an authenticated refusal; controller policy must stop admission and
classify revocation-class reasons for immediate teardown. The session library
does not implement that controller policy or a remote revocation channel.

Dropping Python references is not secure erasure. Other key copies, decrypted
host weights, GPU buffers, in-flight kernels and restored snapshots require
separate controls. Owner policy advancement and receiver retirement do not
revoke material already delivered to another component.

## Reproduce the software controls

From `python/` after installing `.[dev]`:

```sh
python -m pytest -q tests/test_provisioning_lifecycle.py tests/test_provisioning_state.py tests/test_broker_receiver.py tests/test_owner_provision.py tests/test_custody.py
```

The lifecycle suite adds real loopback HTTP acknowledgement loss, false
acknowledgement, owner restart, pending-install failure/recovery, delayed
delivery after policy advancement, storage counterexamples, and the
release-to-worker-stop path. The existing suites supply fresh receiver restart,
same-epoch substitution, concurrent shared-store admission, signature rejection
and teardown-failure controls. All reports use synthetic signing keys; tests
share the existing report fixtures and SDK implementation. They do not provide
an independent protocol implementation or new hardware evidence.

Live lifecycle acceptance remains dependent on measured application identity
[#144](https://github.com/agentrust-io/weight-custody-manifest/issues/144), the
controlled host in [#149](https://github.com/agentrust-io/weight-custody-manifest/issues/149),
and protected execution [#146](https://github.com/agentrust-io/weight-custody-manifest/issues/146).

## Composed software development slice

The source-pinned harness in `python/composed/` continues from installation
through deterministic model computation, a real cMCP tool subprocess, cA2A
HTTP response authentication and exact-output disclosure. Its workflow retains
separate state and boundary observations plus six deliberate weakening controls.
Attestation is synthetic and the host/controller is trusted. No agent confinement,
protected model execution or complete integrations#199 acceptance is claimed.
See `python/composed/README.md` for pins, commands and remaining controls.
