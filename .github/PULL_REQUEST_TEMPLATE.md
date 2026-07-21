<!-- Thanks for contributing to the Weight Custody Manifest. -->

## What and why

<!-- What does this change do, and why? Reference the issue and the spec section if applicable (e.g. SPEC §3.2). -->

## Type

- [ ] Bug fix
- [ ] SDK feature
- [ ] Spec change (breaking - filed an issue and allowed a comment period)
- [ ] Docs / governance / CI

## Checklist

- [ ] Commits are DCO signed off (`git commit -s`)
- [ ] `pytest -q`, `mypy --strict src/wcm`, and `bandit` pass locally; coverage ≥ 80%
- [ ] Tests cover the happy path **and** the failure paths for anything security-relevant
- [ ] `CHANGELOG.md` updated (and the spec version footer, for spec changes)
- [ ] **No overclaiming**: this change does not strengthen any security claim beyond what the hardware and protocol actually deliver (`SPEC.md` §3.6). Any hardware/verification code that isn't validated against real silicon or captured vectors is labeled provisional.

## Notes for reviewers

<!-- Anything reviewers should focus on: a threat-model implication, a scope caveat, a stacked-PR dependency, etc. -->
