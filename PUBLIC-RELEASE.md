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
