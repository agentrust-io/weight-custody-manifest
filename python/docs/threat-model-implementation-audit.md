# Threat-model → implementation audit

Maps every threat in [`THREAT-MODEL.md`](../../THREAT-MODEL.md) to what **this
reference SDK** actually enforces, versus what is a hardware/TCB assumption, an
operational/legal control, or an acknowledged residual. The point is honesty
about where the code is load-bearing and where it is not.

Legend for **Enforced by**:
- **SDK** — the SDK enforces this in software (module named), and CI tests it.
- **SDK (structural)** — the SDK checks the *claim* but the cryptographic root
  of trust requires a real quote verifier to be wired (see the gap notes).
- **Hardware/TCB** — relies on a TCB assumption (SEV-SNP/TDX/NVIDIA CC); not the SDK.
- **Operational/legal** — a deployment or contract control; not the SDK.
- **Residual** — acknowledged, not defended.

| Threat | Mitigation | Enforced by | Where in the SDK |
|---|---|---|---|
| T1.1 read CPU-enclave memory | SEV-SNP encryption | Hardware/TCB | — (TCB item 1) |
| T1.2 read GPU memory | NVIDIA CC firewalling | Hardware/TCB | — (honest downgrade vs physical operator) |
| T1.3 substitute serving image | `required_serving_image` measurement | SDK (structural) | `kbs._check_serving_image` (status, prefer-current); cryptographic once a quote verifier is wired |
| T1.4 keep serving after partition | wipe-on-lapse | **SDK** | `custody.EnclaveSession` (zeroize on cadence lapse) |
| T1.5 in-envelope distillation | rate ceilings (partial) | Residual | — (out of scope, acknowledged) |
| T1.6 snapshot enclave memory | SEV-SNP at rest | Hardware/TCB | — |
| T1.7 physical key extraction / forge attestation | none at silicon; compensating controls | SDK (partial) + Residual | `kbs._check_attestation_revocation` (revocation freshness), `memory_sweep` + `kbs._check_memory_fingerprint` (BadRAM-class, real sweep; scope in `memory-fingerprint.md`); key-extraction half open (8.8) |
| T1.8 stall the clock | trusted monotonic time | SDK (reports) + Hardware/TCB | `custody.time_floor` surfaces `sound`/`weaker`/`none`; the bound itself needs `secure-tsc` |
| T3.1 insider releases key wrongly | attestation gate + joint signature | **SDK** | `verify_manifest` (builder+custodian), `kbs.verify_and_release` |
| T3.2 suppress/delay revocation | wipe-on-lapse + transparency log | **SDK** | `custody` + `transparency.TransparencyLog.find` (missing-entry detection) |
| T3.3 observe decrypted weights via infra | SEV-SNP | Hardware/TCB | — |
| T4.1 replay an old quote | single-use KBS nonce | **SDK** | `_challenge.ChallengeStore` (consume-once), `kbs` nonce check |
| T4.2 block re-attestation | fail-safe (darks, not exposes) | **SDK** | `custody` (lapse → zeroize) |
| T4.3 MITM manifest/revocation | signatures | **SDK** | `verify_manifest` |
| T5.1 builder unilaterally darks sovereign model | `sovereign_profile` quorum | **SDK** | `models.SovereignProfile` validators + `verify_manifest` (requires the declared sovereign signer) |
| T5.2 manifest over-collects | customer reviews terms | Operational/legal | `release_terms` is expressed; enforcement is human review |
| T5.3 builder ships exfiltrating image | reproducible build + audit | Operational | — (8.3) |
| T6.1 side channel | hardware + dedicated tenancy | Hardware/TCB + SDK (expresses) | `models` `tenancy: dedicated` control; enforcement is deployment |
| T7.1 supply-chain image compromise | reproducible build + audit; measurement pinning | Operational + SDK (structural) | `required_serving_image` / `custody.kbs_image` measurement pinning |
| A3 manifest integrity | joint signature | **SDK** | `_signing` + `verify_manifest` (Ed25519 / ML-DSA-65 / hybrid) |
| A6 derivative lineage | `derived_from` chain + policy | **SDK** | `lineage.verify_lineage` |
| A5 audit receipts | TRACE hash-chained receipts | Not in this SDK | reuses TRACE (separate package) |

## Findings / gaps (honest)

1. **The gate is only cryptographic when a quote verifier is wired.** `kbs.verify_and_release` checks serving-image and GPU *claims* structurally; the
   `cpu_quote_verified` check reports **"structural trust only"** until a
   `cpu_quote_verifier` is configured. AMD SEV-SNP quote verification now exists
   (`snp.py`, validated on real hardware); **GPU-side (NVIDIA) quote verification
   is not yet implemented** (pending H100 hardware), so composite CPU+GPU
   cryptographic verification is CPU-only today. This is the single most
   important thing a deployer must not over-read.
2. **T1.7 key-extraction stays open (8.8).** The SDK enforces the compensating
   controls it can (revocation freshness, memory-fingerprint for the
   measurement-forgery half); a physically-extracted attestation key still
   produces a genuinely valid signature that passes every check.
3. **T1.8 cannot be self-detected.** The SDK enforces the cadence deadline against
   whatever clock it is given and *reports* the floor via `time_floor`; it cannot
   make an untrusted clock trustworthy. The bound requires `secure-tsc`.
4. **A5 audit receipts are out of scope for this package** (WCM reuses TRACE); the
   extraction-detection story depends on that separate component.
5. **The memory-fingerprint sweep is only evidence when it is bound.** The sweep
   is real (`memory_sweep`: nonce-derived probe addresses and values, two
   derived orderings, readback re-derived by the gate), and aliasing detection is
   exercised against a region that really aliases. But the honest readback is
   computable by anyone holding the nonce and the declared range, so a host can
   author a clean result unless `require_memory_fingerprint_binding` is on and a
   CPU quote verifier is wired; without both, the gate reports `structural trust
   only`. An alias in unprobed granules is missed by construction, and none of
   this has been run against a genuinely SPD-aliased DIMM. Scope statement:
   `memory-fingerprint.md`.

## What CI verifies

Every **SDK**-enforced row above is covered by tests (signing/verify, KBS gate,
wipe-on-lapse, transparency, lineage, quote verification incl. the real AMD
Milan chain, PQ). Robustness of every parser is fuzzed (`test_fuzz.py`). The
Hardware/TCB and Operational/legal rows are, by definition, not things the SDK
can test — they are assumptions and deployment controls, named here so they are
not mistaken for code guarantees.
