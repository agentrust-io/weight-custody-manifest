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

Final decision authority on specification changes, publication timing (see below), conformance disputes, and Maintainer appointments. Currently: Imran Siddique (OPAQUE Systems).

**Succession**: if the Project Lead is unavailable for 30+ days without notice, the active Maintainers vote to appoint an interim lead. A Technical Steering Committee will be formalized before any standards-body submission.

## Decision making

Routine changes (bug fixes, non-breaking additions, docs) merge on one Maintainer approval. Breaking spec changes and guarantee-scope changes require an issue, a comment period, and Project Lead sign-off. The bar throughout is the project's honesty principle: no change may strengthen a security claim beyond what the hardware and protocol actually deliver (`SPEC.md` §3.6).

## Publication gate

This repository is **pre-1.0 and its public release is staged** behind the hostile-owner posture stabilizing - specifically the still-open key-extraction half of open question 8.8, which needs new silicon to close. The Project Lead decides when the gate is met. Readiness work (governance, community health, SDK, validation) proceeds independently of the visibility flip.

## Relationship to the agentrust-io family

WCM is part of the agentrust-io family (alongside TRACE, cMCP, Agent Manifest, cA2A): open spec, independent implementations, shared conventions. Cryptographic primitives are kept in sync across the family so an artifact produced by one tool verifies under another.
