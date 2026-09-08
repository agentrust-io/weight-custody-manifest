# Public release checklist

This checklist is the release contract for WCM's first public announcement. It is
deliberately stricter than “the tests are green”: a passing suite establishes
repeatable reference behavior, not a production security certification.

## Before changing repository visibility

Run from a clean `main` checkout:

```bash
python tools/go_public.py --root .
```

The read-only preflight must report every required file, the `wcm.agentrust-io.com`
domain, a clean tree, and the expected default branch. The command refuses to
mutate anything unless its exact repository confirmation token is supplied.

Confirm these independently:

- `python -m pytest -q` passes on Python 3.11, 3.12, and 3.13 in CI;
- the packaging job builds an sdist, installs from that sdist in a fresh virtual
  environment, and runs `wcm conformance`;
- `python tools/gen_schema.py --check` and `python tools/gen_kbs_lock.py --check`
  pass;
- `python tools/release_bom.py` produces the release inventory and its output is
  reviewed for unexpected files;
- `python -m build` followed by `twine check` succeeds locally or in CI;
- `SECURITY.md`, `THREAT-MODEL.md`, `LIMITATIONS.md`, `GOVERNANCE.md`, and
  `CONTRIBUTING.md` are linked from the landing page; and
- no fixture, log, or example contains credentials, provider tokens, private
  endpoints, or customer material.

## September 8 cutover order

The temporary Cloudflare 307 redirect from `wcm.agentrust-io.com` to the
`/wcm/` landing page must be removed first at the scheduled cutover. DNS is
already configured; the local CNAME check does not validate DNS or the edge rule.
Capture the redirect rule before removing it so the landing page can be restored
if documentation delivery fails.

Run the guarded tool only after reviewing the preflight and public-release scope.
It changes repository visibility and About/website, applies repository controls,
and configures Pages with `build_type: legacy`, source `gh-pages` at `/`, and
custom domain `wcm.agentrust-io.com`. This matches the existing `mkdocs gh-deploy`
workflow. `docs/CNAME` ensures every MkDocs build carries the custom domain;
the repository-root CNAME alone is not copied into the generated site. The API's `workflow` mode requires a Pages deployment workflow and is
not the branch-publication mode used here. See the
[GitHub Pages API](https://docs.github.com/en/rest/pages/pages).

Afterward, inspect the Pages certificate state and enable HTTPS enforcement once
the certificate is ready. Verify the docs at the custom domain, including a deep
link, rather than treating a successful API update as proof of delivery. Retain
`agentrust-io.com/wcm/` as the marketing page pointing to the docs. A Pages failure
can be mitigated by restoring the temporary redirect; changing repository visibility
back cannot retract copies of already-public source.

## What the announcement may claim

WCM is an open protocol and reference SDK for signed model-weight custody,
attestation-gated release, runtime wipe-on-lapse custody, derivative lineage, and
portable conformance vectors. The repository includes validated parsing and
verification paths for AMD SEV-SNP, Intel TDX, and NVIDIA H100 evidence, plus a
reproducibly-built reference KBS image.

The announcement must also link the limits: current confidential-computing silicon
does not provide cryptographic custody against an attacker who physically owns the
machine; the reference KBS is not an operated service; and conformance vectors use
synthetic PKI for portability even though the SDK also carries real-silicon fixtures.

Do not call WCM “unbreakable,” “production certified,” or a security level. Describe
the attacker tier, hardware assumptions, evidence boundary, and residual risk.

## After the release

Create the GitHub Release from the reviewed tag, let the trusted-publishing workflow
publish the package, and verify the package from a clean environment. Record the
release tag, wheel and sdist hashes, conformance output, and documentation URL in
the release notes. Re-run the public preflight after the visibility change and keep
the report with the release record.
