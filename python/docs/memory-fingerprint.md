# The memory-fingerprint challenge: what it establishes, and what it does not

`memory_fingerprint_challenge` is WCM's detection for the *measurement-forgery*
half of open question 8.8 (SPEC.md sections 3.1 and 3.6). This document is the
honest scope statement for it. Read it before quoting the check in a security
argument, because the gap between what the sweep demonstrates and what it is
easy to assume it demonstrates is wide.

Implementation: `wcm.memory_sweep` (the sweep), `wcm.kbs._check_memory_fingerprint`
(the gate), `tests/test_memory_sweep.py` and the `deny-memory-fingerprint-*`
conformance vectors.

## The attack it is aimed at

BadRAM (CVE-2024-21944) reprograms an SPD so the DIMM reports more capacity than
it has. The top address bits fold: two distinct guest-physical addresses land in
one DRAM cell. The attestation signing key never leaves the chip, so the quote is
genuinely valid, and the measurement is taken over an address space that reads
clean while the guest actually runs from aliased memory.

Nothing in a vendor's stock attestation flow catches this, because from the
silicon's point of view nothing is wrong. What does catch it is that aliased
memory cannot hold two different values in two addresses that share a cell.

## How the sweep works

1. The KBS issues a single-use nonce (`_challenge.ChallengeStore`).
2. The enclave declares a protected range and derives, from the nonce and that
   range: a set of probe addresses, a distinct 32-byte value per address, a write
   order and a different read order. All four are `SHAKE256` outputs under
   separate domain tags.
3. It writes every probe value into its protected memory in the write order,
   then reads every probe back in the read order.
4. It hashes the readback, sets `aliasing_detected` if anything came back wrong,
   and commits to the challenge, the range and the outcome
   (`fingerprint_commitment`).
5. It folds that 32-byte commitment into the attestation quote's `REPORT_DATA`,
   alongside the nonce and, when channel binding is in use, the transport key.
6. The KBS re-derives the whole plan from the nonce and the declared range,
   compares the readback hash against the one an honest sweep must produce, and
   checks the commitment is the one the quote vouches for.

Each derivation is nonce-based for a reason:

| Derived from the nonce | Because otherwise |
|---|---|
| Probe addresses | an operator who controls the memory map aliases only granules nobody probes |
| Probe values | a readback captured under an earlier nonce would still verify |
| Write order | the surviving value in an aliased pair is predictable |
| Read order | a partial emulation can answer from its most recent write |

## What a clean result establishes

**Within the probed granules, the range behaves like distinct storage.** Every
probed address returned the value written to it, so no two probed addresses share
a cell. Against the BadRAM shape, where the fold is a power-of-two wrap across
the whole range, a probe set spread over the range hits a colliding pair with
high probability, and once it does, detection is certain rather than statistical:
the two values differ in 32 bytes, so the survivor cannot match both.

**The result belongs to this release attempt.** The commitment binds the nonce,
the declared range, the readback and the aliasing verdict together. A result from
another attempt, another range, or another outcome does not recompute.

**With `require_memory_fingerprint_binding`, the result came from inside the
attested boundary.** The commitment is covered by the quote signature, so a host
that cannot sign a quote cannot present a sweep result at all.

## What it does not establish

**It does not prove the enclave ran a sweep, unless the binding is enforced.**
The probe plan and the honest readback follow from the nonce and the declared
range by a public rule. Anyone holding those two values can compute the answer
without touching memory. `min_memory_sweep_bytes` and the readback check catch an
incoherent or trivial response; they do not catch a competent host that simply
does the arithmetic. Only `require_memory_fingerprint_binding=True`, with a CPU
quote verifier configured, makes the result evidence rather than an assertion. The
gate says which of the two it is in the check detail, and a KBS run without the
binding reports `structural trust only` on the way past.

**It does not survive a lifted attestation key.** This is the open half of 8.8. An
adversary who has physically extracted the signing key (TEE.fail class) signs a
quote for a fabricated environment, and can fold any commitment they like into
`REPORT_DATA`. The sweep detects measurement forgery with the key intact; it has
nothing to say about key extraction, and the compensating controls for that are
in SPEC.md 3.6.

**It does not cover unprobed granules.** Probes cover `probe_count` of the
range's granules. An alias confined to granules the plan never selected produces
a clean readback. `tests/test_memory_sweep.py` asserts this outright rather than
leaving it implied. Probe density is a deployment parameter; a range of 64 GiB
probed 256 times is a different claim from the same range probed 65536 times, and
the manifest does not currently express which one was run.

This is a deliberate deviation from the wording of SPEC.md 3.1 and 3.6, which
describe writing values "across its full declared DRAM range". Sampling is what
makes the challenge affordable inside a release path: a full pass over 64 GiB is
minutes of memory bandwidth on every release, against a cadence that may be
measured in minutes. Full coverage is expressible, `probe_count == granules`, and
a hostile-owner deployment that can afford it should ask for it. What the SDK
will not do is call a sample a full sweep. If the sampled claim is the one being
relied on, the manifest should eventually carry the density so a verifier can
tell the two apart; that is a spec change, tracked separately from this
implementation.

**It does not prove physical memory protection.** It says nothing about whether
DRAM contents are encrypted, whether an interposer is attached, or whether an
operator can read the weights off the bus. Those are the hardware assumptions in
SPEC.md 3.6, and a clean sweep is not evidence about any of them. A deployment
that reads this check as "memory is protected" has drawn a conclusion the
mechanism does not support.

**It is not a rowhammer, ECC or DRAM-reliability test.** A single pass of write
then read finds address aliasing. It is not aimed at bit flips, retention faults
or disturbance errors, and it should not be reported as memory diagnostics.

**No hardware validation yet.** The sweep runs over a real allocation and the
detection is exercised against a region that really aliases, but neither has been
run against a genuinely SPD-aliased DIMM. The claim rests on the structure of the
attack, not on a capture. Treat this the way the repository treats every
un-captured claim: real code, not yet hardware-validated.

## Configuring it

| Knob | Where | Effect |
|---|---|---|
| `memory_fingerprint_challenge` | manifest `release_policy` | requires the challenge in the hostile-owner posture |
| `min_memory_sweep_bytes` | `KeyBrokerService` | smallest declared range the gate accepts; 0 means no floor, and the check says so |
| `require_memory_fingerprint_binding` | `KeyBrokerService` | the commitment must be present and carried by a verified quote; fails closed with no verifier configured |

`probe_count` is capped at `MAX_PROBE_COUNT` (65536). The gate re-derives every
probe from a range the evidence declares, so an uncapped count would let a
response make the verifier hash its way through billions of probes before it
could decide anything. A range wanting proportionally more coverage raises its
granule size rather than its probe count.

The range is declared by the party being tested, so a deployment in the
hostile-owner posture should set `min_memory_sweep_bytes` to the DRAM the enclave
is supposed to have and turn the binding on. Without both, the challenge is a
well-formed answer to a question nobody enforced.
