# Contributing

How to send a change to WCM and what it needs to pass before it is merged.

The canonical guide is [`CONTRIBUTING.md`](https://github.com/agentrust-io/weight-custody-manifest/blob/main/CONTRIBUTING.md). In short:

- Sign commits with DCO (`git commit -s`).
- The tests (`pytest -q`), the type checker (`mypy --strict src/wcm`) and the security linter (`bandit`) must pass, with test coverage of 80% or more.
- Tests cover the normal case **and** the failure cases for anything that affects security.
- Changes that break the spec or alter what WCM promises need an issue and a comment period first; open with the [spec change template](https://github.com/agentrust-io/weight-custody-manifest/issues/new?template=spec_change.md).
- The one firm rule: **do not overclaim.** No change may strengthen a security claim beyond what the hardware and protocol actually deliver.

Security issues go through [private disclosure](https://github.com/agentrust-io/weight-custody-manifest/security/advisories/new), not public issues. See [`SECURITY.md`](https://github.com/agentrust-io/weight-custody-manifest/blob/main/SECURITY.md).
