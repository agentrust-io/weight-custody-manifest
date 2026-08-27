# Releasing the `weight-custody-manifest` package

Publishing uses **PyPI Trusted Publishing** (OIDC) via `.github/workflows/publish.yml`.
No API token is stored in the repo.

> Publishing puts the SDK **source** on a public index (the sdist and wheel
> contain the code). That is a deliberate go-public decision; cutting a Release
> is the trigger. The repo can stay private while the package is public, but the
> code is public either way.

## One-time setup (Project Lead)

Configure a trusted publisher on each index (this is done in the PyPI web UI, not
in this repo):

**PyPI** (https://pypi.org/manage/account/publishing/) - add a pending publisher:
- Project: `weight-custody-manifest`
- Owner: `agentrust-io`  ·  Repository: `weight-custody-manifest`
- Workflow: `publish.yml`  ·  Environment: `pypi`

**TestPyPI** (https://test.pypi.org/manage/account/publishing/) - same, Environment `testpypi`.

Also create the GitHub Environments `pypi` and `testpypi` (Settings → Environments),
optionally with required reviewers so a publish needs an approval.

## Dry run (TestPyPI)

Actions → **publish** → *Run workflow* (manual dispatch). This builds, `twine check`s,
and uploads to TestPyPI. Verify:

```bash
pip install -i https://test.pypi.org/simple/ weight-custody-manifest
```

## Cut a real release

1. Bump `__version__` in `python/src/wcm/__init__.py`.
2. Update `CHANGELOG.md`. **Diff it against `git log v<last>..HEAD` first.** 0.27.0
   found seven merged PRs with no entry at all, one of them a security change, and
   a notes section covering two of nine changes is worse than none because it
   reads as complete.
3. Commit via PR, merge to `main`. The `downstream-examples` job has already run
   the public demos in `agentrust-io/examples` against a wheel built from the
   branch, so a change that breaks them fails on the PR rather than after upload.
   If it did fail, that is not automatically a reason to revert: a security fix
   *should* break a demo relying on the hole. Land the demo fix alongside.
4. Tag and create a GitHub Release on that commit:
   ```bash
   git tag v0.25.0 && git push origin v0.25.0
   gh release create v0.25.0 --target main --title v0.25.0 --notes-from-tag
   ```
5. The `publish` workflow builds and uploads to PyPI via the trusted publisher.

## Notes

- The version is dynamic (read from `__init__.py`); the tag and `__version__`
  should match.
- Artifacts are built from `python/` (`python -m build`); the base package's only
  runtime deps are `pydantic` and `cryptography` (see `NOTICE`).
- `twine check` runs in CI before upload; it also runs locally:
  `cd python && python -m build && twine check dist/*`.
