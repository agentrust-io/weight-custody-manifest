# Releasing the WCM package

Publishing uses PyPI Trusted Publishing (OIDC) through
`.github/workflows/publish.yml`. No long-lived upload token is stored in the
repository. Release environments require Project Lead approval.

## Prepare a release

1. Update `__version__` in `python/src/wcm/__init__.py` and `CHANGELOG.md`.
   Compare the changelog with commits since the previous release.
2. Submit a signed-off pull request. Required tests, packaging, compatibility,
   downstream examples, disclosure scanning and maintainer review must pass.
3. Merge to `main`, then create a version tag and GitHub Release at that commit.
   The tag must be `v` followed by the SDK version. Version tags cannot be
   deleted or rewritten.
4. Review the publication workflow and approve the `pypi` environment deployment.
5. Verify the published wheel and source distribution hashes against the built
   artifacts, then install the release in a fresh environment and run
   `wcm conformance`.

The publication workflow reruns the Python test matrix, compatibility checks,
packaging and downstream examples. It verifies that the release commit belongs
to `main` and that the tag matches the checkout and SDK version. It scans both
the source tree and the built distributions before an upload can proceed.

## TestPyPI dry run

Dispatch the **publish** workflow from the current `main` commit. After validation,
approve the `testpypi` environment deployment. Install the resulting package in
an isolated environment and run the conformance suite.

## Publisher configuration

Both indexes use repository `agentrust-io/weight-custody-manifest` and workflow
`publish.yml`. The production publisher uses environment `pypi`; the test
publisher uses `testpypi`. Production deployments accept version tags only;
test deployments accept `main` only. Environment approvals cannot be bypassed
by administrators. The designated release approver may approve their own run.

## Local package checks

From the repository root:

```bash
python tools/leak_scan.py
python -m build --outdir dist python
python -m twine check dist/*
python tools/leak_scan.py --archives dist/*.whl dist/*.tar.gz
```

The scanner uses documented patterns and scoped synthetic test exceptions.
It cannot prove that every kind of confidential information is absent. Review
the package inventory and disclosure scope as well as the automated results.
