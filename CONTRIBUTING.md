# Contributing to the Weight Custody Manifest

WCM is an open specification and reference SDK for protecting model weights when a builder deploys them into a customer's own or sovereign infrastructure. Contributions are welcome in three areas: the specification (`SPEC.md`, `THREAT-MODEL.md`), the Python reference SDK (`python/`), and the tests.

## Before you start

This is a **pre-1.0 design under review**. Its public release is a deliberate call by the Project Lead, not gated on open question 8.8 (the hostile-owner residual is documented as an honest limitation, not a release blocker). Breaking spec changes (schema incompatibilities, changed release/attestation semantics, guarantee-scope changes) require an issue and discussion before a PR. Non-breaking additions and bug fixes can go straight to a PR.

The one non-negotiable: **do not overclaim.** WCM's value is its honesty about what the silicon does and does not guarantee (see `SPEC.md` §3.6). A contribution that quietly strengthens a claim beyond what the hardware delivers will be rejected.

## DCO sign-off

All commits must be signed off with the [Developer Certificate of Origin](https://developercertificate.org/):

```
git commit -s -m "feat: add foo"
```

PRs without DCO sign-off will not be merged.

## Development setup

```bash
git clone https://github.com/agentrust-io/weight-custody-manifest
cd weight-custody-manifest/python
pip install -e ".[dev]"
```

```bash
pytest -q                    # tests
mypy src/wcm                 # strict type checking
bandit -q -c pyproject.toml -r src/wcm   # security scan
```

## Submitting a PR

1. Fork and branch from `main`.
2. Write tests for any SDK change. Anything security-relevant (signing, verification, the KBS gate, quote verification, custody) needs both a happy path and the failure paths.
3. Ensure `pytest`, `mypy --strict`, and `bandit` pass locally; keep coverage ≥ 80%.
4. Open a PR against `main` and fill in the template.
5. One maintainer approval is required to merge (see [CODEOWNERS](.github/CODEOWNERS)).

## Spec changes

1. Open an issue describing the problem and the proposed change; reference the spec section.
2. Allow a short comment period for reviewer feedback.
3. Submit a PR to `SPEC.md` (or `THREAT-MODEL.md`) and update the SDK + tests so the executable model still matches the text (the example-validation test is what catches drift).
4. Update `CHANGELOG.md` and the spec version footer.

## Hardware-validated code

Code that parses or verifies real attestation formats (e.g. `snp.py`) must be validated against real hardware or captured vectors before its claims are stated as fact; until then it is labeled **provisional**. Do not remove a "provisional / unvalidated" label without the validation to back it. See `python/docs/` and the PR history for how the AMD SEV-SNP path was validated.

## Code conventions

- Python 3.11+; strict mypy
- Pydantic v2 for data models (`extra="forbid"`)
- Standard library first; no new runtime dependency without discussion
- Conventional commits: `type(scope): short description`

## License

By contributing you agree that your contributions are licensed under Apache 2.0.
