# Release verification

WCM releases include a reference SDK, schemas, conformance vectors and
verification tools. A passing test suite establishes the behavior covered by
those tests. It is not a production security certification.

## Reproduce the release checks

From a checkout of the release tag, install the SDK and development dependencies
in an isolated Python environment:

```bash
python -m pip install -e "./python[dev]"
python -m pytest python/tests -q
```

From the `python/` directory, check the generated artifacts:

```bash
python tools/gen_schema.py --check
python tools/gen_kbs_lock.py --check
```

For an already published version, generate its package inventory with
`python tools/release_bom.py --version VERSION --out OUTPUT_DIRECTORY` from
`python/`. Replace the placeholders with the release version and a new output
directory. This command reads public PyPI metadata.

The release workflow tests supported Python versions, builds the source
distribution, installs it in a fresh environment and runs `wcm conformance`.
Review the workflow results for the exact release commit. Check the release
inventory for unexpected files and verify the published package hashes before
installation.

The disclosure scanner checks the source tree and release archives. It reports
locations and pattern categories without printing matched values. Its exceptions
cover synthetic test inputs; a passing scan does not replace human review or
an audit of earlier commits and previously published packages.

## Evidence and scope

Release notes should identify the tag and commit, package hashes, conformance
results and documentation version. Hardware evidence should identify the tested
platform, verification policy and reproducible procedure, with sensitive
infrastructure identifiers excluded from the published report.

Distinguish synthetic test fixtures, captured hardware evidence and live
verification. Software-only readiness results do not establish hardware
attestation. Device discovery does not establish that an attestation chain or
workload binding was verified.

The reference KBS is software that operators deploy; this repository does not
provide an operated key-broker service. Security claims depend on the stated
attacker model, hardware assumptions and verification policy.

See [LIMITATIONS.md](LIMITATIONS.md), [THREAT-MODEL.md](THREAT-MODEL.md) and
[SECURITY.md](SECURITY.md) for assurance boundaries and vulnerability reporting.
See [CONTRIBUTING.md](CONTRIBUTING.md) and [GOVERNANCE.md](GOVERNANCE.md) for
contribution and review requirements.
