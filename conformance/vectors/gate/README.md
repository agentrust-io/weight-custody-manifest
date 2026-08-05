# L2 attestation-gated release scenarios

The Layer 2 gate: what a key broker must refuse, and why (SPEC.md §3.2). These are
ordered **scenarios**, not single inputs, because the properties are about
sequence: a nonce is single-use, a challenge expires, a denied attempt still spends
its nonce.

See [`conformance/README.md`](../../README.md) for the step format, the clock and
nonce-binding conventions, and how to claim a level.

## What is covered

The policy gate, in full:

- nonce freshness, single use, and expiry, including that a **failed** attempt
  still consumes its nonce (otherwise one challenge buys unlimited tries)
- platform and assurance tier against the manifest
- serving-image status: unknown, revoked, prefer-current, and past `retire_after`
- composite binding: a GPU report present, echoing the *same* nonce as the CPU
  quote, and matching the pinned RIM
- the memory-fingerprint challenge: present, bound to this challenge, and not
  reporting aliasing
- attestation-key revocation, and cache freshness against the policy window
- channel binding: a transport key present and well formed, and the released key
  returned **sealed** rather than in the clear
- key availability for the requested `weights_hash`

And cryptographic quote verification, through the reference JSON container:

- the certificate chain reaches a **pinned trusted root**, so presenting your own
  self-signed CA does not help
- the report signature verifies under the leaf key, catching a report edited after
  signing even when the chain and the nonce binding are intact
- an expired leaf is refused, which is what makes short-lived attestation-key
  certificates a real compensating control rather than a decoration
- `REPORT_DATA` binds the presented nonce, so a captured quote cannot be replayed
- with channel binding, `REPORT_DATA` binds `sha256(nonce || transport_key)`, so a
  **relay substituting its own transport key** is detected (CVE-2026-33697). The
  relay cannot re-sign the report, so the binding stops matching.
- a configured verifier does not silently fall back to structural trust when the
  evidence carries no raw quote

## What is not covered

- **A synthetic PKI, not vendor roots.** These vectors prove an implementation
  verifies a chain, a signature and a nonce binding correctly. They do not prove it
  can parse a real AMD, Intel or NVIDIA quote: that is vendor-format work, covered
  by the SDK's committed real-silicon fixtures rather than by vectors.
- **GPU-side cryptographic verification.** The quote vectors verify the CPU quote.
  The NVIDIA path is a separate verifier over a real device chain with the raw nonce
  at offset 4, and the H100 fixture in the SDK's own tests covers it today.

## Reading a denial

Each `reject` vector names the code the gate must report, not merely that it must
deny. That matters because several distinct failures come out of one check: the
`serving_image` check alone produces `WCM-L2-0004` (not accepted), `WCM-L2-0005`
(prefer-current), `WCM-L2-0006` (revoked) and `WCM-L2-0014` (past `retire_after`),
and an implementation that collapses them tells an operator nothing about which
policy actually bit.
