# L3 runtime custody scenarios

The wipe-on-lapse floor (SPEC.md §3.2, §3.3): what happens to a released key as
time passes and operations are served. Ordered **scenarios** with an injected
clock, so "the lease lapsed" is a fact about the vector rather than about how long
the test took to run.

See [`conformance/README.md`](../../README.md) for the step format and how to claim
a level.

## The distinction these vectors exist to enforce

Two limits bound a session and they are **not** interchangeable:

| | Wall-clock lease | Operation budget |
| --- | --- | --- |
| Exhausted by | time passing | operations served |
| Outcome | the key is **zeroized** | re-attestation is **required** |
| Key survives | no | yes |
| Code | `WCM-L3-0001` | `WCM-L3-0002` |
| Recover by | a fresh release from the KBS | re-attesting |

An implementation that wipes on budget exhaustion is needlessly destructive. One
that merely suspends on lease lapse has a *suspend*, not a wipe, and the guarantee
in §3.3 is gone: an enclave that lost its attestation standing could resume serving
by waiting. `reject-operation-budget-exhausted` and
`reject-wall-clock-wins-over-a-remaining-budget` are the pair that catch each
mistake.

## Also covered

- a lapse is detected on **any** interaction, including an idle `tick`, so exposure
  is bounded by the cadence rather than by when someone next asks for the key
- re-attestation renews the lease and resets the budget, but only while holding: a
  late re-attestation must fail, because the key is already gone
- the cadence is read from the manifest, so a 15m deployment gets 15m
- the reported trusted-time floor matches the source: `sound` for `secure-tsc`,
  `weaker` for the hybrid, `none` for best-effort. Reporting a stronger floor than
  the source supports (`WCM-L3-0004`) would state a bound that does not hold, which
  is the same overclaiming the spec's §3.6 exists to avoid.

## A note on the floor

`none-best-effort` still enforces the deadline against whatever clock it has. The
floor describes what that enforcement is *worth*, not whether it happens: with an
untrusted clock the host can stall time, so there is no bound to claim. That is why
`accept-time-floor-none-on-best-effort` asserts both that the floor reads `none`
and that the key still serves.
