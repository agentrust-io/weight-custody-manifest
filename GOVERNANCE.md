# Governance

## Roles

### Contributor

Anyone who submits a PR, files an issue, or participates in discussion. No formal appointment required. Must follow the [Code of Conduct](CODE_OF_CONDUCT.md) and sign commits with DCO.

### Reviewer

Trusted contributors with triage and review rights. Can approve PRs but cannot merge without a Maintainer approval on security-sensitive paths. See [CODEOWNERS](.github/CODEOWNERS) for path-specific rules.

**Advancement**: 3+ merged substantive PRs. Nominated by any Maintainer, confirmed by the Project Lead.

### Maintainer

Full review and merge rights on designated areas; publish rights on the `weight-custody-manifest` package. Responsible for reviewing PRs within their area promptly.

**Advancement**: active Reviewer for 60+ days, 5+ merged PRs, demonstrated judgment on spec or SDK design. Nominated by any Maintainer, confirmed by the Project Lead.

### Project Lead

Final decision authority on specification changes, publication timing, conformance disputes, and Maintainer appointments. Currently: Imran Siddique.

**Succession**: if the Project Lead is unavailable for 30+ days without notice, the active Maintainers vote to appoint an interim lead. A Technical Steering Committee will be formalized before any standards-body submission.

## Decision making

Routine changes (bug fixes, non-breaking additions, docs) merge on one Maintainer approval. Breaking spec changes and guarantee-scope changes require an issue, a comment period, and Project Lead sign-off. The bar throughout is the project's honesty principle: no change may strengthen a security claim beyond what the hardware and protocol actually deliver (`SPEC.md` Â§3.6).

## Repository controls

The default branch requires current checks, a code-owner review, resolution of
review threads, and approval after the latest push. Stale approvals are dismissed.
The maintainer gate also checks current-head approval for outside contributors.
The Project Lead retains an explicit branch-rule bypass for exceptional changes;
its use should be explained on the pull request. Branch deletion and force pushes
remain blocked by a separate rule without a bypass.

GitHub Actions use commit-pinned actions and read-only default permissions.
Release uploads require environment approval after validation; version tags
cannot be rewritten or deleted. See [the release procedure](python/RELEASING.md).
Security reports belong in the private channel described in [SECURITY.md](SECURITY.md).

## Publication posture

This repository is **pre-1.0**. Public release is a deliberate Project Lead decision, but it is **not gated** on closing the key-extraction half of open question 8.8. That hardware-owner residual is disclosed and scoped out of WCM's cryptographic-custody claim (`SPEC.md` Â§3.6); physical hardening and accountability are the current controls for that posture. The project must not strengthen its claims to make publication easier.

## Relationship to the agentrust-io family

WCM is part of the agentrust-io family (alongside TRACE, cMCP, Agent Manifest, cA2A): open spec, independent implementations, shared conventions. Cryptographic primitives are kept in sync across the family so an artifact produced by one tool verifies under another.

## Sponsorship and independence

The project may accept financial, engineering, infrastructure, or other support from sponsors listed in [SPONSORS.md](SPONSORS.md). Sponsorship and contributor affiliations are informational. They do not confer ownership of the project, additional decision rights, preferential treatment in specification or conformance decisions, or endorsement of a sponsor's implementation.

Maintainers and the Project Lead participate in their project roles as individuals. They must disclose a material conflict of interest and recuse from a decision when their employer, sponsor, or commercial interest would prevent impartial project judgment.
