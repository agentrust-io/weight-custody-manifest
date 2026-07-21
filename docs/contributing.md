# Contributing

The canonical guide is [`CONTRIBUTING.md`](https://github.com/agentrust-io/weight-custody-manifest/blob/main/CONTRIBUTING.md). In short:

- Sign commits with DCO (`git commit -s`).
- `pytest -q`, `mypy --strict src/wcm`, and `bandit` must pass; coverage ≥ 80%.
- Tests cover the happy path **and** the failure paths for anything
  security-relevant.
- Breaking spec / guarantee-scope changes need an issue and a comment period
  first; open with the [spec change template](https://github.com/agentrust-io/weight-custody-manifest/issues/new?template=spec_change.md).
- The non-negotiable: **do not overclaim.** No change may strengthen a security
  claim beyond what the hardware and protocol actually deliver.

Security issues go through [private disclosure](https://github.com/agentrust-io/weight-custody-manifest/security/advisories/new), not public issues - see [`SECURITY.md`](https://github.com/agentrust-io/weight-custody-manifest/blob/main/SECURITY.md).
