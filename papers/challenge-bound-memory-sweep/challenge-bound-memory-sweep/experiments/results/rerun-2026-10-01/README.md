# October 1, 2026 rerun

Fresh clones of the three source repositories, a fresh virtual environment, and the
unchanged scripts in `experiments/`. Run on one Windows 11 workstation.

## Environment

Python 3.12.10 in a new venv. Installed with exact versions:

```
python -m pip install pytest==8.4.2 cryptography==50.0.0 pydantic==2.13.4 jsonschema==4.26.0 \
  referencing==0.37.0 rfc8785==0.1.4 cbor2==5.9.0 agentrust-trace==0.9.0 \
  opentelemetry-sdk==1.44.0 jcs==0.2.1 PyYAML==6.0.3
```

cbor2 stays at 5.9.0 as in the September 27 run (local application control blocks the 6.x
compiled extension). The selected test modules do not exercise COSE or CBOR.

## `pinned/`

Commands, run from `experiments/`:

```
python reproduce.py --prepare-from CLONES --source-root SRC_PINNED --output pinned
python boundary_probes.py --source-root SRC_PINNED --output pinned
```

`reproduce.py` ran `git archive` of each pinned commit, checked the tar's embedded commit id and
extracted it: weight-custody-manifest 2acedfa883204f7d1fd457d3ee603198d85be82c,
agentrust-telemetry 29c13cfa4047a0f5784a90df63b22a3568453158, agent-manifest
934809709a2815695d65cfacb45dc0a164286046. `results.json` holds versions, commands, exit codes
and log hashes.

| Task | Result | September 27 |
|---|---|---|
| memory-tests (test_memory_sweep.py, test_kbs.py) | 35 passed | 35 passed |
| telemetry-tests | 111 tests, OK | same |
| telemetry-conformance | 13 of 13 | same |
| approval-tests | 74 passed, 1 warning | same |
| boundary probes (11) | identical observations | |

This paper uses `memory-tests.txt` and the two memory probes in `boundary-probes.json`
(`signed_bad_memory_is_authentic_not_acceptable` and
`signature_verifier_has_no_freshness_input`, both observed true).

`receipt-tests.txt` is an extra run of the offline re-check of the retained August 27, 2026
protected-runtime receipt at the pinned commit:

```
python -m pytest -p no:cacheprovider -o pythonpath=src tests/test_protected_runtime_receipt.py -v
```

run in `SRC_PINNED/weight-custody-manifest/python`; 13 passed. It re-checks the receipt's
recorded fields and its custody record chain. The receipt holds the sweep outcome as fields,
not the signed sweep transcript, so the sweep signature itself cannot be re-verified offline.

## `main/`

Current `main` on October 1, 2026, extracted with `git archive` (tar commit id checked):

```
weight-custody-manifest 5ef8c122479f5df79ad8a7c04b70f4a43bbdb313 (2026-09-30)
agentrust-telemetry     c86753cad6bbe9f00c5080489a12e0f94df34899 (2026-09-30)
agent-manifest          fed9aeb091e4c77e0b40e12e959bee30b52e3c75 (2026-09-30)
```

- `boundary-probes.json`: `python boundary_probes.py --source-root SRC_MAIN --output main`.
  Both memory probes observed true, as at the pin.
- `memory-tests.txt`: the same pytest command as `reproduce.py` uses, in
  `SRC_MAIN/weight-custody-manifest/python`; 46 passed. The 11 added tests are broker tests
  (GPU confidential-compute mode, evidence-verification defaults, lone-surrogate denial). The
  five memory-sweep tests and four memory-fingerprint broker tests are the same as at the pin.

Source facts checked at main: `python/src/wcm/memory_sweep.py` has no commits since the pin;
`KeyBrokerService._check_memory_fingerprint` is unchanged; the broker still has no
expected-range pin for the sweep. `kbs.py` changed in six merged revisions since the pin
(PRs 120, 142, 156, 163, 162, 154).

Logs replace local paths with `<source-root>`, `<python-prefix>` and `<home>`. Software only:
no protected hardware was used in this rerun.
