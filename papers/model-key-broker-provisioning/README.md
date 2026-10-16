# Owner-Approved Provisioning of a Model-Key Broker

Technical report, version 1, October 1, 2026. Imran Siddique, OPAQUE Systems. Not peer reviewed.

Build: `python build_paper.py --source . --output paper.pdf` (ReportLab 5.0.1 and PyMuPDF
1.28.2). It reads Times New Roman, Arial and Courier New TrueType files from `--fonts`
(default `C:/Windows/Fonts`); fonts are not bundled. `manifest.json` lists the SHA-256 of
every other file in this package.

Paper text is licensed CC BY 4.0: https://creativecommons.org/licenses/by/4.0/
Project code retains its existing project license; see https://github.com/agentrust-io/weight-custody-manifest.

The report evaluates Weight Custody Manifest db8f106 (merged in WCM PR 148 on September 20,
2026). Rerun the experiments from this directory with a Python 3.12 environment that has
pytest, cryptography 50.x and pydantic 2.x installed:

    python -B experiments/rerun.py --repo <weight-custody-manifest clone> --output <new directory> [--revision <commit>]

`experiments/results/rerun-2026-10-01/` holds the October 1 runs at the evaluated revision
(`evaluated-db8f106/`) and at main 5ef8c12 (`main-5ef8c12/`). Each `summary.json` records
commands, package versions and every count; local paths are replaced by placeholders. The
memory scan in `experiments/lifecycle.py` uses Windows `ReadProcessMemory` and records
"unsupported" on other platforms.

Software only. Attestation reports are synthetic SNP-format reports signed by a generated
certificate chain; no SEV-SNP hardware, real model key or production broker was used.
Current implementation guidance: https://wcm.agentrust-io.com/
