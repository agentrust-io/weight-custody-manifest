# Experiments

Run from this directory, with the dependencies listed in
`results/rerun-2026-10-01/README.md` (exact versions) or `results/rerun-2026-10-01/pinned/results.json`:

```
python reproduce.py --prepare-from /path/to/clones --source-root /path/to/empty-dir --output out
python boundary_probes.py --source-root /path/to/empty-dir --output out
```

`--prepare-from` takes a directory holding clones of agentrust-telemetry,
weight-custody-manifest and agent-manifest. It runs `git archive` of each pinned commit
(no checkout, no branch switch), checks the commit id embedded in the tar and extracts it.
Alternatively point `--source-root` at checkouts that are already at the pinned commits with
clean tracked files. The runner refuses any other revision. Outputs contain no absolute paths.

The runner covers three related reports; this paper relies on memory-tests.txt and on the
two memory entries in `boundary-probes.json`. `boundary_probes.py` records what each probe
observed instead of asserting, so it can also be run against later revisions.

Neither script reproduces the historical protected-hardware receipt. The repository's offline
re-check of that receipt can be run in `<source-root>/weight-custody-manifest/python` with
`python -m pytest -p no:cacheprovider -o pythonpath=src tests/test_protected_runtime_receipt.py -v`.
`reproduce.py` and `boundary_probes.py` are identical copies of the files in
`../../_paper-assets/`.
