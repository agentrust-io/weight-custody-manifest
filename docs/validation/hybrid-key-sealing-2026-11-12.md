# Local validation: NIST-guided hybrid key-share sealing

Date: 12 November 2026. Branch: `feat/hybrid-key-share-protection`.
Base: `fb88cc41a8785f49fba481bfc65b1e5e88883014`.
Profile: `mlkem768-x25519-sha3-256-aes256gcm-v1`.

This report concerns an uncommitted local SDK candidate, not a published release.
No consuming application was changed. This initial Windows validation did not
use a VM, push a branch, deploy anything or establish FIPS validation. The later
Linux run used the already-running local Docker engine, as documented separately.

## Follow-up

The [complete local Linux matrix](hybrid-key-sealing-linux-2026-11-12.md) now
passes on Python 3.11, 3.12 and 3.13 with 1,690 passed / 36 skipped per version.
The results below retain the earlier Windows observations.

## What changed

The previous local X-Wing draft-11 experiment was replaced by a separately
versioned envelope using finalized NIST guidance: native ML-KEM-768 and X25519,
one-step SHA3-256 derivation with complete ciphertext/public-key context,
and AES-256-GCM. Component private keys are generated independently. The prior
experiment was preserved outside the source tree; its format is not accepted by
the new profile. Existing classical APIs, defaults and manifest schema remain
unchanged. No additional runtime dependency was added.

The fixed algorithm ordering, exact byte encoding, responsibilities and limits
are specified in [the profile document](../hybrid-key-sealing.md).

## Observed results

Environment: native Windows, Python 3.12.10, cryptography 50.0.1,
OpenSSL 4.0.2 (25 August 2026). Dependencies came from repository hash-locked
requirements in a disposable environment.

| Check | Result |
| --- | --- |
| Focused hybrid suite | **99 passed** |
| Official NIST ACVP ML-KEM-768 key-generation vectors | **25 matched**, source revision and SHA-256 retained in fixture |
| Primitive known answers | RFC 7748 X25519 and NIST AES-256-GCM Example 2 passed |
| Independent encoding oracle | SHA3 derivation and AES-GCM envelopes checked in both directions |
| Deliberate envelope corruption | **2,000** reproducible one-byte mutations refused, plus truncation and size/type boundaries |
| Two-holder software flow | Both provisioning hops and two synthetic-quote release gates; reconstruction and AES-GCM decryption of non-secret test bytes passed |
| Hybrid module coverage | **100% line coverage**, 115 statements |
| Candidate regression, excluding Bash workflow file | **1,667 passed / 44 skipped / 0 failed**, 72 warnings and 27 subtests passed |
| Untouched upstream control, same exclusion | **1,568 passed / 44 skipped / 0 failed**, 72 warnings and 27 subtests passed |
| Candidate regression coverage | **93.31%** |
| Strict mypy | Passed, **46 source files** |
| Configured Bandit | Passed |
| Packaging | Source archive and wheel built; both passed `twine check` |
| Installed wheel | Hybrid round trip, profile selection and schema access passed outside the checkout |
| Dependency consistency | `pip check` passed |
| Negative controls | **8 of 8** deliberately weakened variants caused assertion failures |
| Disclosure scan / whitespace | Passed without weakening scanner rules |

The full native Windows run excludes `tests/test_dependabot_auto_merge.py`.
It invokes Bash/jq; the available Bash path resolves to the WSL launcher.
No Linux VM was started to satisfy it. Earlier runs on candidate and untouched
upstream had the same 13 failures in that workflow file. Full Linux CI remains
pending, including that file and the supported Python-version matrix. The 44
ordinary skips are reported, not counted as passed.

An initial regression run found local filesystem paths in a generated coverage
database at the repository root. Coverage databases were moved to temporary
storage, subsequent runs explicitly set `COVERAGE_FILE` outside the tree, and
the entire regression run above passed. No disclosure-scanner exception or
production workaround was added.

## Failure paths exercised

Tests refuse the wrong recipient, either wrong private-key component, altered
holder/model/transaction context, malformed descriptors and private encodings,
low-order X25519 points, noncanonical ML-KEM public coefficients, unavailable
backends, classical downgrade and the old X-Wing profile. Tampering covers both
encapsulation components, nonce, header, ciphertext and GCM tag.

Signed synthetic quote tests bind the entire descriptor. Substituting either
public key refuses release and consumes the challenge. Replay and expired
challenges refuse release; a failed seal returns no plaintext key. Rotation to
a new runtime key prevents opening envelopes addressed to the previous key.

The threshold test is a harness, not a production holder service. It reconstructs
two shares and decrypts test bytes; no real model inference, hardware quote,
customer data, private production keys or receipts are involved.

## Negative controls

Separate Python processes applied in-memory substitutions only. Test failures
were observed when each of these controls was deliberately broken:

1. Omit the ML-KEM shared secret.
2. Omit the X25519 shared secret.
3. Omit both public keys from derivation.
4. Omit both encapsulation components from derivation.
5. Omit the SP 800-56C counter.
6. Replace AES-GCM with a different AEAD.
7. Ignore caller associated data.
8. Remove input-size/type bounds.

These are targeted regression controls, not exhaustive mutation testing or
independent cryptanalysis. Detailed results and source hashes are in the
[machine-readable summary](hybrid-key-sealing-2026-11-12.json).

## Measured software overhead

100 measured iterations after 10 warmups, using 33-byte non-secret shares and
caller context on this machine. No network, attestation, model loading or
inference costs are included. These are local observations, not a production SLA.

| Operation | Median |
| --- | --- |
| Generate recipient key | 0.501 ms |
| Seal share | 0.323 ms |
| Open share | 0.133 ms |

Public descriptor: **1,221 bytes**. A sealed 33-byte share: **1,186 bytes**.
Envelope overhead is **1,153 bytes**, compared with 61 for the unchanged
classical format.

## Remaining gates

Before merge: repository CI and independent review of
the versioned WCM envelope and its composition. This is not a new NIST-standardized
wire format and test vectors are not a proof of quantum resistance.

Before deployment: integrate both transport hops, authenticate holder keys,
verify grants and transaction state, qualify protected key generation/storage
and real quote binding, and test rotation, recovery and expiry with the consuming
services. This work does not migrate a CLI, HTTP server or existing deployment.

Before any FIPS claim: establish a validated module boundary and approved-mode
service covering the composition. Current Python orchestration, exported secret
bytes and the unqualified backend do not meet that claim. A certificate for an
underlying provider alone would not establish that this hybrid service is
covered. See the profile's FIPS section for the distinction and official sources.
