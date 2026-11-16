# Hybrid release quote-verification review follow-up

Date: 13 November 2026. PR: [#264](https://github.com/agentrust-io/weight-custody-manifest/pull/264).
Reviewed parent: `92a955874b5352093333472ff01fbcb24c3e4571`.

## Review finding and change

The review correctly distinguished descriptor validation from recipient
authentication. Before this revision, selecting the hybrid transport required
channel binding but could still inherit the manifest's structural-only evidence
waiver when no CPU quote verifier was configured. A well-formed descriptor could
therefore receive a sealed key without verified CPU quote binding.

The hybrid profile now always requires CPU quote verification. A missing verifier
fails `cpu_quote_verified` with no plaintext or sealed key, even when
`require_evidence_verification` is false and the constructor's
`require_cpu_quote_verification` is omitted or explicitly false. A configured
verifier must successfully check the quote, including its nonce and complete
transport descriptor. Initial release and renewal use the same gate.

The classical profile's existing waiver behavior and the standalone sealing API
are unchanged. Raw sealing still requires caller-managed recipient authentication
and release policy. No envelope, KDF, wire encoding, schema or dependency changed.

## Regression evidence

Eight refusal cases failed on the previous implementation, reproducing release
without a configured quote verifier. They cover initial release and renewal,
an absent or supplied-but-unverified quote, and the default or explicit false
constructor option. With the fix, all eight refuse solely on `cpu_quote_verified`
and consume the failed attempt's nonce.

The verified-quote positive control now runs with both default and explicit false
options, successfully opens the released envelope and refuses nonce replay. Four
additional cases reject absent, malformed, untrusted and wrong-nonce quotes when
a verifier is configured. Existing descriptor-substitution checks now also run
without explicitly enabling the quote-verification flag.

On Linux/Python 3.12, removing only the new mandatory hybrid requirement inside
the disposable container made all eight refusal regressions fail again. The
original source was restored before packaging. This confirms that the tests
exercise the requested enforcement change rather than another refusal gate.

## Local Linux results

| Python | Full suite passed | Skipped | Focused hybrid passed | Coverage |
| --- | ---: | ---: | ---: | ---: |
| 3.11.18 | 1,703 | 36 | 113 | 93.35% |
| 3.12.16 | 1,703 | 36 | 113 | 93.33% |
| 3.13.18 | 1,703 | 36 | 113 | 93.35% |

Every full run also reports 31 passing subtests and 72 warnings. No test file
was excluded. The 36 existing skips are unchanged: privileged loader execution
(11), pinned edk2 inputs (7), pinned independent predictor inputs (17), and a
non-public device receipt (1). No hybrid test was skipped.

Strict mypy on 46 source files, configured Bandit, dependency checks, source
disclosure scanning and conformance passed on all three versions. Python 3.12
also passed the eight existing cryptographic negative controls, source/wheel
builds, metadata and archive scans, and an installed-wheel hybrid smoke check.
The hybrid sealing module retains 100% line coverage; coverage is not a security
proof.

The existing local Linux test images were used with networking disabled, two CPUs
and 2 GiB per container, all capabilities dropped and no-new-privileges enabled.
A read-only snapshot was extracted inside each disposable container. No cloud
VM or consuming application was accessed or changed. The
[original reproduction procedure](hybrid-key-sealing-linux-2026-11-12.md#reproduction)
applies to this revision; the focused test count is now 113.

Tested production and regression source SHA-256:

| File | SHA-256 |
| --- | --- |
| `python/src/wcm/kbs.py` | `6493a1614841c45b63a3218c3c4fcc62b005000487746e63dd813aeeb6a03b1c` |
| `python/tests/test_hybrid_release.py` | `1730cc586efaedf1b4c206bab98e2c811554b3166212588da1e651bfbc9a860d` |

Only documentation was added after these runs; the tested source and test bytes
were checked again before staging.

## Scope

The quote tests use signed synthetic evidence and test certificate chains.
They validate SDK gating and binding, not live hardware or deployment behavior.
A correctly configured and qualified verifier remains a trusted dependency.
This revision does not add FIPS validation, independent cryptanalysis, hardware
qualification or an end-to-end post-quantum security claim.
