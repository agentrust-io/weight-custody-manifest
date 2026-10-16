# Experiments

| File | What it is |
|---|---|
| [reference/receipt_gate.py](reference/receipt_gate.py) | Reference implementation: hosting grant, signed receipt chain, verifier, admission-gated planner |
| [reference/test_receipt_gate.py](reference/test_receipt_gate.py) | 8 unit tests for the reference implementation |
| [backend.py](backend.py) | Selects the implementation: `RGS_BACKEND=reference` (default) or `pinned` (evaluated code from a `git archive` snapshot in the working directory) |
| [boundary_experiment.py](boundary_experiment.py) | Six correctly signed wrong-binding receipts; stale admission after revocation |
| [controller_experiment.py](controller_experiment.py) | Prototype controller with a durable per-session ledger, a fake Kubernetes API in a separate process, the 12-case matrix and three controls |
| [rerun.py](rerun.py) | Runs everything for each target and writes a scrubbed record |

## Run

Python 3.12 in a fresh virtual environment:

```
python -m venv .venv
.venv/Scripts/python -m pip install pytest==9.1.1 pytest-asyncio==1.4.0 cryptography==50.0.1
.venv/Scripts/python -B rerun.py --output results/<new directory>
```

On Linux or macOS use `.venv/bin/python`. Run from this folder. The output
directory must be new or empty. Expected for the reference target: 8 tests
pass; removing the admission check fails 2 and setting the restart policy to
Always fails 1; the boundary experiment reports 6 rejections and
`old_admission_after_revocation_accepted_by_planner: true`; the controller
passes 12 of 12 durable, 5 of 12 with the ledger check removed, 5 of 12 with an
in-memory ledger, 10 of 12 when revocation must chain directly to the
admission; and `rollback_limit_restored_ledger_replay_routes_again: true`.

To include the evaluated planner, add `--evaluated-repo <clone> --commit <sha>`
(repeatable) and `--private-logs <directory outside this repository>`. Pytest
logs for that target quote its test source, so they go only to
`--private-logs`; the public record keeps counts and hashes. `rerun.py` still writes the
evaluated failing-test names into `rerun.json`; replace them with generic
labels before publishing, as
[results/rerun-2026-10-01/REDACTIONS.md](results/rerun-2026-10-01/REDACTIONS.md)
does.

## October 1, 2026 record

[results/rerun-2026-10-01](results/rerun-2026-10-01/) was produced with:

```
python -B rerun.py --output results/rerun-2026-10-01 \
  --evaluated-repo <internal clone> \
  --commit 52632cce4d21098cf00283075254c3e0de2a461a \
  --commit 3d5b48a5294bc73d42a2bd4fbd23415027e773a7 \
  --private-logs <outside the repository>
```

Windows 11 (10.0.26200), Python 3.12.10, pytest 9.1.1, pytest-asyncio 1.4.0,
cryptography 50.0.1; the full package list is in `rerun.json`. Local paths are
replaced by placeholders. `console.txt` is the run's console output and
`SHA256SUMS.json` hashes every file.

| Target | Tests | Admission check removed | Restart Always | Wrong bindings refused | Stale admission accepted by planner | Controller durable | Ledger check removed | In-memory ledger | Direct-chain revocation | Ledger rollback reopens |
|---|---|---|---|---|---|---|---|---|---|---|
| Evaluated 52632cc | 6 passed, 97 deselected | 1 failed | 2 failed | 6 of 6 | yes | 12 of 12 | 5 of 12 | 5 of 12 | 10 of 12 | yes |
| Evaluated 3d5b48a | 6 passed, 109 deselected | 1 failed | 2 failed | 6 of 6 | yes | 12 of 12 | 5 of 12 | 5 of 12 | 10 of 12 | yes |
| Reference | 8 passed | 2 failed | 1 failed | 6 of 6 | yes | 12 of 12 | 5 of 12 | 5 of 12 | 10 of 12 | yes |

Against the September 23 and September 27, 2026 internal records for commit
52632cc, every count and failing-test list matches. The controller matrix has
one new case (revocation after a served request) and one new control
(direct-chain revocation). The original 11 cases pass, and the two original
controls fail the same 7 cases as before (4 of 11 then, 5 of 12 now, because
the new case passes in both).
