# Pre-PR review: hybrid key-share protection

Date: 12 November 2026. Local branch: `feat/hybrid-key-share-protection`.
Profile: `mlkem768-x25519-sha3-256-aes256gcm-v1`.

## Disposition

No blocking implementation finding was identified in this review of the opt-in
software scope. Production source is byte-for-byte unchanged from the recorded
99-test validation. One additional regression test now explicitly exercises an
X25519 encoding alias; the focused suite passes **100 tests**, with **100% line
coverage** of the 115-statement hybrid module.

This is a review performed during implementation, not an independent
cryptographic assessment or a proof of security. The subsequent
[local Linux matrix](hybrid-key-sealing-linux-2026-11-12.md) passed on all three
supported Python versions. No consuming application was changed.

## Areas reviewed

| Area | Finding and evidence |
| --- | --- |
| Composition | One-step derivation includes the required counter, ordered ML-KEM/X25519 secrets, both encapsulation components, both public keys, domain/version and output length. The independent encoding oracle checks both directions. |
| Authentication | AES-256-GCM covers header, recipient descriptor and caller context. Wrong recipient/context and corruption refuse plaintext output. This is ciphertext integrity, not sender authentication. |
| Encoding aliases | X25519 masks a coordinate's high bit. The added test confirms that flipping this bit preserves the raw shared secret but changes the derived envelope key and is refused. Full transcript binding is therefore exercised beyond ordinary corruption. |
| Downgrade | Trusted KBS configuration selects the suite. Hybrid mode requires channel binding; classical-only, prior experimental and unknown profiles are refused. Existing classical defaults are unchanged. |
| Release gate | Manifest trust, nonce consumption, expiry and quote verification execute before sealing. A sealing failure returns neither the plaintext key nor a sealed key. |
| Attestation scope | Real quote verification still depends on the caller configuring a qualified verifier and requiring its use. A syntactically valid descriptor is not proof of attestation. Tests use signed synthetic quotes. |
| Key lifecycle | Components are generated independently. Secret export is explicit and versioned. Python all-copy zeroization, forward secrecy after full recipient-key compromise and protected hardware storage are not claimed. |
| Input boundary | Exact descriptor/private-key lengths, bounded payload/AAD, noncanonical ML-KEM coefficients, low-order X25519 inputs and backend failures have refusal coverage. |
| Compatibility | Additive optional API and KBS keyword; no manifest schema, classical envelope or dependency changes. The previous full native Windows suite and wheel checks cover production source unchanged here. |
| Standards claims | Final NIST primitive/KDF guidance is distinguished from WCM's experimental envelope. No FIPS module certification or end-to-end PQ claim is made. |

## Executed checks and Linux follow-up

The focused suite now passes **100 tests**. Existing production-source evidence
remains **1,667 passed / 44 skipped** for the native Windows regression run with
the Bash workflow file excluded; eight negative controls, strict typing,
configured Bandit and wheel installation also passed in that run. Those results
are not relabelled as Linux results or as a new full run of the extended test suite.

The initial environment check found stopped Linux environments. After the user
started Docker Desktop, the complete suite ran locally in isolated containers,
including the Bash/jq workflow tests. Python 3.11, 3.12 and 3.13 each reported
1,690 passed / 36 skipped; typing, security scanning and the additional packaging
checks passed. The Linux report records the full scope and skip reasons.

Maintainer/cryptographic review remains appropriate before merging a new
cryptographic envelope. Deployment qualification and FIPS certification are
separate from these local SDK checks.

See the [profile](../hybrid-key-sealing.md) and
[previous validation evidence](hybrid-key-sealing-2026-11-12.md).
