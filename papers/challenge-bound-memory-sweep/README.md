# A Challenge-Bound Memory-Consistency Predicate for Model-Key Release

Technical report, version 1, October 1, 2026. Imran Siddique, OPAQUE Systems. Not peer reviewed.

Build: `cd challenge-bound-memory-sweep && tectonic paper.tex` (prepared with Tectonic 0.16.9; set
SOURCE_DATE_EPOCH=1790812800 to reproduce the published PDF byte for byte). The fonts and their OFL
licenses are in `_paper-assets/fonts/`, the same relative path the manuscript uses.

Paper text is licensed CC BY 4.0: https://creativecommons.org/licenses/by/4.0/
Project code retains its existing project license; see https://github.com/agentrust-io/weight-custody-manifest.

This package contains the manuscript source, the experiment runner and probes, and the records
of the September 27 and October 1, 2026 reruns. The evaluated code is Weight Custody Manifest
commit 2acedfa (`wcm.memory_sweep` and the broker's memory-fingerprint check). The October 1
rerun used fresh clones and a fresh environment: 35 memory-sweep and broker tests passed at the
pin, and the two memory probes were also run at main of September 30, 2026. Rerun with:

    cd challenge-bound-memory-sweep/experiments
    python reproduce.py --prepare-from CLONES --source-root EMPTY_DIR --output out
    python boundary_probes.py --source-root EMPTY_DIR --output out

`CLONES` holds clones of agentrust-telemetry, weight-custody-manifest and agent-manifest. The
runner extracts each pinned commit with `git archive` and refuses any other revision.

Software only. The 256 MiB protected-guest figure comes from a receipt retained in the Weight
Custody Manifest repository (August 27, 2026); that hardware run was not repeated.
Current implementation guidance: https://wcm.agentrust-io.com/
