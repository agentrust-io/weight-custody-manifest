# Composed software research reproduction

This bundle fetches immutable WCM, cMCP and cA2A source revisions, creates a fresh
virtual environment and runs the composed acceptance harness. No existing
checkout or project environment is needed. Python 3.12, Git, network access to
GitHub and PyPI, and enough disk space for those sources and dependencies are
required. The reference environment is Ubuntu 24.04.

After extracting the ZIP, run:

```sh
python reproduce.py --workspace ../composed-reproduction
```

The workspace must not exist. Evidence appears in its `evidence/` directory:
`manifest.json`, `observations.jsonl`, `pytest.log` and this bundle's manifest.
A successful portable run has 32 cases: 16 normal scenarios and 16 deliberate
weakenings. Inspect the observations as well as the exit code.

For all 36 cases, use `--confined` on native Linux with Docker. This builds the
pinned agent image and includes four container-isolation cases. A piped host
core-dump policy is unsupported. The launcher does not change host policy;
use an appropriately configured disposable test host. Review the source
harness README for the exact host and supervisor assumptions.

The package is a source-based research artifact. Required cMCP disclosure and
cA2A response APIs are not yet available together as released packages; moving
this into integrations#199 remains gated on those releases and package-only
validation. Runtime dependency versions come from the reference run. This is
not an offline archive or a complete hash-locked build environment. GitHub,
PyPI, dependency build tools and the optional Docker registry remain inputs.

Attestation is synthetic, the diagnostic model computes `3 * 7 + 2` on the
trusted host, and the tool, peer and recipient share an operator. Success does
not establish hardware custody or independent operation. SHA-256 values detect
file changes relative to the bundle manifest; they do not authenticate its
publisher. Obtain the ZIP and its digest from the reviewed GitHub Actions run.
