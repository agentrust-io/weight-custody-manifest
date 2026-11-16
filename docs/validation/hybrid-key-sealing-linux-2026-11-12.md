# Linux validation: hybrid key-share protection

Date: 12 November 2026. Branch: `feat/hybrid-key-share-protection`.
Base: `fb88cc41a8785f49fba481bfc65b1e5e88883014`.
Profile: `mlkem768-x25519-sha3-256-aes256gcm-v1`.

## Result

The remaining Linux tests passed locally in isolated Docker containers across
the repository's Python 3.11 / 3.12 / 3.13 matrix. No test file was excluded.
This includes the Bash/jq workflow tests previously unavailable in the Windows
run. No production implementation change was needed after the implementation
review; the focused suite includes its additional X25519 encoding-alias test.

| Local Linux runtime | Full suite | Focused hybrid tests | Strict mypy / Bandit | Coverage |
| --- | --- | --- | --- | --- |
| Python 3.11.18 | 1,690 passed / 36 skipped | 100 passed | Both passed | 93.33% |
| Python 3.12.16 | 1,690 passed / 36 skipped | 100 passed | Both passed | 93.33% |
| Python 3.13.18 | 1,690 passed / 36 skipped | 100 passed | Both passed | 93.33% |

Each full run also reports 31 passing subtests and 72 warnings. The hybrid
module has 100% line coverage (115 statements). Coverage is not a security proof.
All runs passed dependency consistency, source disclosure scanning and WCM
conformance. Strict typing covers 46 source files.

Python 3.12 additionally passed all eight negative controls, source/wheel builds,
`twine check`, archive disclosure scans and installation of the built wheel into
a separate environment. The installed wheel passed a hybrid seal/open check
outside the source checkout. The source archive was built first, and the wheel
was built from that archive using the normal `python -m build --no-isolation`
path. No network was available during validation or packaging.

## Environment and source identity

- Local Docker Desktop Linux, x86_64, glibc 2.36; already running before testing.
- Existing WCM test images for each Python version, refreshed against the current
  repository hash-locked development, build and backend requirements.
- cryptography 50.0.1, OpenSSL 4.0.2 (25 August 2026).
- Two CPUs and 2 GiB memory per test container, network disabled, capabilities
  dropped and no-new-privileges enabled.
- Only a temporary WCM snapshot was mounted read-only. The source was extracted
  into each disposable container; neither the host checkout nor a consuming
  application's files were mounted writable.
- Results were retained outside the scanned source tree. Test containers removed
  themselves on exit. No remote machines or hardware environments were used.

The snapshot contains the base revision and the explicit candidate files.
Each changed source/test file was verified against its recorded SHA-256 before
execution. The [machine-readable results](hybrid-key-sealing-linux-2026-11-12.json)
record both tested byte hashes and LF-normalized hashes, because Git normalizes
Windows text line endings when publishing. Documentation was updated after the
runs; production and test logic were not changed.

## Skips and boundaries

The 36 existing skips are explicit:

| Reason | Count |
| --- | --- |
| Dedicated privileged Linux loader job required | 11 |
| Pinned edk2 source / compiled firmware controls required | 7 |
| Pinned independent predictor checkout required | 17 |
| Original device-identifying receipt not publicly distributed | 1 |

None of the new hybrid tests were skipped. These results do not establish
hardware attestation, a deployment migration, all-copy zeroization, formal
cryptographic security, or FIPS module validation. The quote tests are signed
synthetic evidence. The envelope follows finalized NIST guidance but remains
an experimental WCM format, requiring maintainer/cryptographic review before
merge. Repository CI still applies to the eventual PR.

## Reproduction

Use Linux with Python 3.11, 3.12 or 3.13 and Bash, jq and Git available. Install
only the repository-pinned test/build dependencies before disabling network:

```sh
python -m pip install --require-hashes -r requirements/dev.txt
python -m pip install --require-hashes -r requirements/build.txt
python -m pip install --require-hashes -r python/docker/requirements-build.lock
python -m pip install --no-deps --no-build-isolation ./python
cd python
export PYTHONPATH="$PWD/src"
export COVERAGE_FILE=/tmp/wcm-hybrid.coverage
python -m mypy --strict src/wcm
python -m bandit -q -c pyproject.toml -r src/wcm
python -m pytest -q --cov=wcm --cov-report=term-missing
python -m pytest -q tests/test_hybrid_seal.py tests/test_hybrid_release.py tests/test_hybrid_nist.py
python -m build --no-isolation --outdir /tmp/wcm-hybrid-dist
python -m twine check /tmp/wcm-hybrid-dist/*
```

See the [profile](../hybrid-key-sealing.md),
[implementation review](hybrid-key-sealing-pre-pr-review-2026-11-12.md) and
[earlier Windows validation](hybrid-key-sealing-2026-11-12.md).
