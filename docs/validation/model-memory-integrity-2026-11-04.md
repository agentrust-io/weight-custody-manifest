# Loaded-model memory integrity: Linux and H100 validation

Date: 4 November 2026. These are author-operated functional results for the
experimental SDK addition, not independent certification or a hardware attack
reproduction. The tested base is
`82bdaaf232804c9ed14efd7c740908f20bf67f44` plus this feature.
The accompanying [JSON record](model-memory-integrity-2026-11-04.json) provides
implementation hashes, counts, commands' exit statuses and evidence checksums.
Hashes identify the recorded artifacts; they are not independent proof that a
run occurred.

## Linux results

The default Python CI matrix was reproduced locally in separate Linux Docker
containers with WCM's hash-pinned development dependencies.

| Python | Passed | Failed | Skipped | SDK statement coverage | New module coverage |
|---|---:|---:|---:|---:|---:|
| 3.11 | 1,543 | 0 | 36 | 93.09% | 100% |
| 3.12 | 1,543 | 0 | 36 | 93.07% | 100% |
| 3.13 | 1,543 | 0 | 36 | 93.07% | 100% |

Strict mypy, Bandit, source disclosure scanning, the CPU worker demonstration
and conformance checks passed on each version. Python 3.12 additionally passed
sdist/wheel building, Twine checks, archive disclosure scanning, clean installation
from the sdist, installed conformance and new-module import/hash checks.

All 13 offline demos and their unit tests in `agentrust-io/integrations`, commit
`deca590870634ce490e3674d046c2f41f0d62eb0`, passed against the candidate wheel.
Its runner excludes `real_open_model.py` (model download) and
`real_lora_custody.py` (training and download); neither is counted as a pass.

The same 36 tests were explicitly skipped in each default Linux run:

- 11 require the dedicated privileged Linux loader job.
- 7 require pinned edk2 source and compiled firmware controls.
- 17 require the pinned independent measurement predictor.
- 1 requires an original device-identifying receipt not distributed publicly.

These results do not replace those separate CI jobs. No assertions were weakened
to obtain a pass. An earlier Windows run's 13 Bash workflow failures reproduced
on unchanged upstream: the Windows WSL Bash launcher selected a distribution
without `/bin/bash`. Those tests passed on Linux. One Windows disclosure-scan
failure came from local report files in the source tree; moving results outside
source resolved it, and the scanner tests and source/archive scans passed.

## H100 functional results

Environment: NVIDIA H100 80 GB HBM3, driver 595.71.05, Ubuntu kernel
6.8.0-110-generic, Python 3.12.3, PyTorch 2.8.0+cu128.

**62 tests passed, zero failures or skips:** the 51 feature tests and 11 optional
CUDA adapter cases now included in `python/tools/test_model_memory_cuda.py`.
The CUDA cases check actual device storage using independently prepared expected
bytes for FP16, BF16, FP32 and INT8, mutations at the beginning/end and across
1 MiB read boundaries, a mixed CPU/GPU inventory, missing inventory, signed
observations/replay, and rejection of noncontiguous adapter input. Restoring
bytes after a failure does not reopen the guard.

The separate CUDA process demonstration produced:

| Observation | Result |
|---|---|
| Approved three-weight computation | 47.0 |
| Deliberately mutated computation with guard bypassed as negative control | 119.0 |
| Saved reference bytes | Unchanged |
| Fresh observation after mutation | Rejected |
| Guarded dispatch after mutation | Refused |
| Test session key | Wiped through the existing session hook |
| Stop callback | Called once |
| Worker | Alive before mutation; exited successfully after refusal |

One boundary test deliberately verifies that a genuine earlier observation can
still pass after a subsequent mutation; a fresh local scan detects the change.
This documents the point-in-time limit rather than hiding it.

These are tiny tensor/worker fixtures. The CPU spill buffer is explicitly
provided by the test, not an actual engine's automatic offload. A provider-labelled
confidential VM was used, but CPU/GPU attestation was not verified in this run.
The mutations were intentional tensor writes, not a DMA exploit. Worker exit and
test session-key wipe do not prove erasure of every host/GPU plaintext copy.
PyTorch emitted a non-fatal warning about absent optional NumPy; these adapters
read tensor bytes without NumPy.

## Reproduce

The ordinary feature tests and CPU demo use WCM's normal development environment:

```sh
cd python
python -m pytest -q tests/test_model_memory.py
python tools/model_memory_demo.py --device cpu
```

On a separate Linux CUDA node, install the repository's pinned development
dependencies and the candidate SDK in a virtual environment first. With a
compatible NVIDIA driver, the recorded optional GPU configuration is:

```sh
python -m pip install torch==2.8.0 --index-url https://download.pytorch.org/whl/cu128
cd python
python -m pytest -q tests/test_model_memory.py tools/test_model_memory_cuda.py
python tools/model_memory_demo.py --device cuda
```

The GPU tests are outside the default `tests/` collection. They require real CUDA
and intentionally fail rather than silently falling back to CPU. PyTorch is a
test-only dependency, not a new WCM runtime requirement. All writes affect only
the fixture's own allocated tensors.

## Qualification boundary

See the [integration and trust model](../model-memory-integrity.md). An approved
baseline, trustworthy observer, complete inventory and synchronized actual
buffers are prerequisites. Full-model scan overhead and production engine
adapters remain unqualified. This addition does not change default key release,
prevent DMA, fix hardware isolation, or establish continuous integrity. A
separate holder/KBS policy integration needs specification discussion.
