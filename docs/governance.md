# Governance

Who makes decisions about WCM and how changes get accepted, for anyone thinking
of contributing or depending on the project.

The canonical governance doc is [`GOVERNANCE.md`](https://github.com/agentrust-io/weight-custody-manifest/blob/main/GOVERNANCE.md); maintainers are in [`MAINTAINERS.md`](https://github.com/agentrust-io/weight-custody-manifest/blob/main/MAINTAINERS.md).

- **Roles**: Contributor → Reviewer → Maintainer → Project Lead (currently Imran
  Siddique). Contributions are DCO-signed (each commit carries a sign-off line
  confirming you have the right to submit it).
- **Decisions**: routine changes merge on one Maintainer approval. Changes that
  break the spec or alter what WCM promises need an issue, a comment period, and
  Project Lead sign-off. No change may strengthen a security claim beyond what the hardware
  and protocol deliver.
- **Publication**: public release is a deliberate decision by the Project Lead.
  It does not wait on the key-extraction half of open question 8.8, which is
  written down as a known remaining risk rather than a reason to hold release.
- **Family**: WCM is part of the AgenTrust family (TRACE, cMCP, Agent Manifest,
  cA2A): open specifications, separate implementations, shared conventions.
- **Sponsors**: support is recognized separately from governance. Sponsorship
  does not confer ownership, decision rights, conformance preference, or an
  endorsement of a sponsor's implementation.

See also the [Code of Conduct](https://github.com/agentrust-io/weight-custody-manifest/blob/main/CODE_OF_CONDUCT.md), [Antitrust Policy](https://github.com/agentrust-io/weight-custody-manifest/blob/main/ANTITRUST.md), and [Sponsors](https://github.com/agentrust-io/weight-custody-manifest/blob/main/SPONSORS.md).
