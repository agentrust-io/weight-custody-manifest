# Receipt-Gated Model Serving

Technical report, version 1, October 1, 2026. Imran Siddique, OPAQUE Systems. Not peer reviewed.

Build: `python build_paper.py --source . --output paper.pdf` (ReportLab 5.0.1 and PyMuPDF
1.28.2). It reads Times New Roman, Arial and Courier New TrueType files from `--fonts`
(default `C:/Windows/Fonts`); fonts are not bundled. `manifest.json` lists the SHA-256 of
every other file in this package.

Paper text is licensed CC BY 4.0: https://creativecommons.org/licenses/by/4.0/
The reference implementation and experiment scripts in `experiments/` are published with this
report under the same license.

The evaluated planner is in an internal repository; its source is not published. The record
keeps its commit identifiers, test counts and file hashes, with its failing tests under generic
labels (`experiments/results/rerun-2026-10-01/REDACTIONS.md`). Every experiment in section 6 also
runs against the reference implementation in `experiments/reference/receipt_gate.py`, which needs
Python 3.12 and the `cryptography` package:

    cd experiments
    python -m venv .venv
    .venv/Scripts/python -m pip install pytest==9.1.1 pytest-asyncio==1.4.0 cryptography==50.0.1
    .venv/Scripts/python -B rerun.py --output results/<new directory>

See `experiments/README.md` for the expected outcomes. Software only: no cluster, confidential
GPU or model inference was used.
