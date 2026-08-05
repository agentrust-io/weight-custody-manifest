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

## What is not covered

**Cryptographic quote verification** (`WCM-L2-0011`, `WCM-L2-0012`): the quote
signature and certificate chain against a vendor root, and `REPORT_DATA` nonce
binding. The evidence in these vectors is declarative, so an implementation builds
its own evidence objects from named fields rather than parsing bytes chosen here.
Verifying real quotes needs raw hardware evidence plus trust anchors, which is a
different vector shape. The repo has real-silicon fixtures for SEV-SNP, TDX and
H100 CC to build it from.

So a green L2 run means the gate enforces the manifest's policy. It does not mean
the gate can tell a genuine quote from a fabricated one.

## Reading a denial

Each `reject` vector names the code the gate must report, not merely that it must
deny. That matters because several distinct failures come out of one check: the
`serving_image` check alone produces `WCM-L2-0004` (not accepted), `WCM-L2-0005`
(prefer-current), `WCM-L2-0006` (revoked) and `WCM-L2-0014` (past `retire_after`),
and an implementation that collapses them tells an operator nothing about which
policy actually bit.
