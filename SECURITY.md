# Security Policy

## Scope

This policy covers:

- Vulnerabilities in the WCM Python reference SDK (`python/`)
- Cryptographic flaws in the Weight Custody Manifest specification (`SPEC.md`) - signing, attestation-gated release, canonicalization, transparency log, or threshold scheme
- Weaknesses in the manifest signing / verification, quote-verification, or KBS-gate logic
- Issues with the reference KBS image or server that would release a key against manifest policy

Out of scope: general Python dependency vulnerabilities (run `pip-audit`), GitHub Actions supply-chain issues, and issues in third-party TEE platforms (AMD SEV-SNP, Intel TDX, NVIDIA CC) themselves - those belong to the hardware vendors' threat models.

## The honest baseline (read before reporting)

WCM does **not** claim silicon-enforced custody against an operator who physically owns the hardware. Cheap published memory-bus attacks (TEE.fail, BadRAM) extract keys and, on some platforms, forge attestation; WCM's response there is cost, detection, containment, legal recourse, and mandatory physical hardening, **not** cryptographic custody. This is stated throughout `SPEC.md` §3.6 and `THREAT-MODEL.md`, and the key-extraction half of open question 8.8 is deliberately open. A report that "a hardware owner can extract the key" is a known, documented limitation, not a vulnerability. A report that the SDK's authority-layer logic can be bypassed *within* its stated model is in scope.

## Reporting a vulnerability

Use [GitHub private vulnerability reporting](https://github.com/agentrust-io/weight-custody-manifest/security/advisories/new) for all security issues. Do not file a public issue.

Include:
- A description of the vulnerability and its impact, relative to WCM's stated trust model (semi-trusted vs hostile-owner posture)
- Steps to reproduce or a proof-of-concept (SDK bugs), or a counter-example sketch (spec/protocol flaws)
- The spec section or SDK module affected
- Whether you believe it affects the semi-trusted posture (the near-term commercial surface) or only the hostile-owner posture

## Response timeline

| Stage | Target |
|-------|--------|
| Acknowledgment | 2 business days |
| Initial assessment | 5 business days |
| Fix or spec erratum issued | 30 days for critical, 90 days for moderate |

## Publication status

This repository is pre-1.0. Its public release is a deliberate decision by the Project Lead and is not gated on open question 8.8; the hostile-owner residual is documented (see the honest baseline above), not a release blocker. Treat everything here as a design under review, not a production security boundary.
