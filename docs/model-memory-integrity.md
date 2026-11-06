# Experimental loaded-model integrity checks

Status: opt-in SDK proposal. No change to the manifest schema, release protocol,
default KBS checks, existing memory sweep, or default runtime behavior.

## The question this answers

A valid artifact signature tells a verifier about the approved artifact. It does
not measure the model currently loaded in RAM or GPU memory. This module checks
the bytes returned by an enrolled model-memory observer against a separately
approved baseline. It provides a pre-dispatch guard and challenge-bound signed
observations. It does **not** prevent DMA, fix IOMMU settings, establish hardware
integrity, or make an untrusted observer trustworthy.

The existing `memory_fingerprint_challenge` writes and reads patterns over a
declared test region. This addition is read-only and measures named model
buffers. The two checks have different purposes; never run a destructive sweep
over loaded weights.

## Two distinct stages

1. **Release and load.** Existing WCM policy, hardware evidence and channel
   binding control the initial key release. The approved runtime decrypts and
   loads the model with serving disabled. There is no claim that a ciphertext's
   future plaintext memory was measured before it existed.
2. **Check and serve.** The trusted runtime enumerates every immutable serving
   buffer, including adapters and CPU/GPU partitions. It synchronizes writes,
   checks the approved baseline, and only then dispatches inference. Repeat
   before each operation in this reference implementation. Existing custody
   authorization and time limits still apply independently.

```text
Approver's trusted build/loader -> approved memory baseline + observer key pin
                                                  |
Existing WCM KBS -> sealed model key -> approved runtime (serving disabled)
                                                  |
                                           decrypt and load
                                                  |
                  custody check -> quiesce + read actual model buffers
                                                  |
                         mismatch/read error -----+----- match
                                |                           |
                     latch guard closed            recheck lease deadline
                     invoke teardown                      |
                                                    dispatch inference

Optional reviewer/holder -> fresh challenge -> enrolled observer
                        <- signed, challenge-bound observation
                        -> signature + bindings + exact inventory verification
```

An application may compose a verified observation with its own holder checks.
This proposal does **not** automatically add an integrity condition to KBS
release or renewal decisions. A future standardized release-policy field or
post-load authorization protocol requires a separate specification discussion,
including bootstrap, evidence age, downgrade rules, and two-holder semantics.
Do not put an optional extension in a manifest and assume older verifiers enforce it.

## Trust configuration

`ModelMemoryBaseline` commits to the exact manifest identity, artifact hash,
serving image measurement, loader/layout ID and a sorted, unique inventory of
buffer names, byte counts and SHA-256 hashes. A layout ID identifies the qualified
engine/loader, tensor representation, precision, sharding and adapter arrangement.
The in-memory representation need not hash to the encrypted or packaged file.

Create the baseline from independently approved model preparation. Authenticate
and pin it through the same trusted policy distribution used by the deployment.
The module does not certify that process. **Do not learn the expected baseline
from the possibly compromised live runtime being checked.** Unknown adapters,
missing regions, changed sizes or changed bytes must fail. Legitimate model
updates require a separately approved baseline and a new authorized session.

Pin the observer public key out of band. Keep its private key inside the
qualified observer boundary, inaccessible to the infrastructure operator. A
software key generated in a demonstration does not establish that separation.
The approved runtime measurement and trusted configuration must cover this
guard, its complete buffer-enumeration adapter and its baseline/pin requirements;
an operator-selectable check that can be bypassed supplies no enforcement.
Verify hardware evidence separately: it must bind the same runtime transport key,
approved image and observer. Merely repeating a transport key in signed JSON is
not a hardware binding. Do not store observer private keys in an untrusted host
or expose a signing endpoint that accepts arbitrary caller-supplied digests.

## Signed observation verification

`ModelMemoryVerifier.issue_challenge()` issues a fresh, single-use nonce, using
WCM's existing `ChallengeStore` (30-second default for this observer exchange).
`observe_model_memory()` reads the actual supplied buffers and signs their
measurements with Ed25519 over canonical JSON. The signed domain is
`wcm-model-memory-observation-v1`. The report binds the full baseline digest,
challenge nonce and runtime transport key. It does not carry a self-authorizing
observer public key or a caller-selected algorithm.

`verify(report, challenge_nonce=expected_nonce)` consumes the verifier-issued
challenge even on a failed attempt, validates the signature against the pinned
observer key, checks the expected bindings, and compares the complete inventory.
Malformed, expired, unknown, replayed, incorrectly signed or mismatched reports
are refusals. This is a point-in-time observer statement. It is not a serving
lease, independent CPU/GPU attestation, proof of continuous integrity or proof
of erasure/shutdown. Retain the baseline and trusted public-key reference if
observations will be audited later; a successful historical check is not a fresh
authorization. Challenge-store persistence/rollback and trusted time remain
deployment responsibilities.

## Runtime composition

```python
from wcm.model_memory import ModelMemoryGuard

# baseline: authenticated, separately approved ModelMemoryBaseline
# session: existing authorized EnclaveSession with qualified on_stop adapter
# buffers: complete mapping of names to ModelBuffer readers
guard = ModelMemoryGuard(baseline, on_failure=session.zeroize)

def dispatch(request):
    # Run under the runtime's existing serialized dispatch/lease ownership.
    # Quiesce and synchronize the engine before the scan.
    session.authorize_operation()
    guard.check_before_operation(buffers)
    # Hashing a large model takes time. Do not dispatch on an expired lease.
    if session.tick().value == "wiped":
        raise RuntimeError("authorization expired during integrity check")
    return worker.infer(request)
```

The runtime must also supervise expiry while inference is active, prevent restart
outside this path, and qualify its teardown adapter. `ModelMemoryGuard` latches
closed on a mismatch or reader failure before calling `on_failure` once. Failure
of that callback does not reopen the guard; it is reported as teardown failure,
not successful shutdown. Restoring the bytes does not clear the latch. No key
release or recovery authority is granted by constructing a new guard.

CPU readers hash a contiguous live buffer in bounded chunks without writing it.
GPU adapters must synchronize relevant streams, read the actual device tensors
used for inference, and cover their CPU spill partitions. Hashing a checkpoint
file or a stale CPU mirror is insufficient. No GPU adapter is included in the
runtime SDK in this proposal; the qualification demo supplies an optional CUDA
reader for its own tiny tensor only. It is not an adapter for a complete model
server. KV caches, activations, compiled kernels and executable code need their
own integrity policies; they are not silently included in a model-weight claim.

## Boundaries and cost

- No claim of detecting arbitrary physical attacks or forged hardware evidence.
- A malicious observer can sign a lie. Authenticating its report is not proof of
  truthful measurement. Hardware isolation, observer provenance and protected
  key provisioning are prerequisites for stronger assurance.
- The check detects persistent changes present when the affected bytes are read.
  Concurrent writes can produce an incoherent view. A writer can change and
  restore bytes between scans or corrupt them after a scan. A Python lock does
  not stop DMA. Qualified memory isolation is still required.
- No claim of continuous monitoring, in-flight cancellation, all-copy zeroization
  or automatic recovery from this module alone.
- Full scans are O(total measured bytes) before every operation. Their throughput
  and latency cost must be measured on the target model/hardware. This is an
  experimental correctness reference, not a qualified high-throughput serving
  configuration. Sampling is not equivalent to full-buffer coverage.
- A normal VM can exercise the code but adds no confidential-computing evidence.
  Hardware qualification needs a separate supported configuration and workload.

## Reproduce

From `python/`, with the repository's pinned development dependencies installed:

```console
python -m pytest tests/test_model_memory.py -q
python tools/model_memory_demo.py --device cpu
```

The tests include a real AES-GCM encrypted artifact, a sealed WCM key release,
decryption/load, tiny linear inference, an in-memory mutation while the file
remains unchanged, guard refusal and the existing session's key wipe/stop hook.
The KBS integration test explicitly uses WCM's **software** attestation fixture;
it is not a TDX, SEV-SNP, GPU confidential-computing or DMA test.

The optional `--device cuda` demo requires an isolated machine with PyTorch/CUDA.
Run it only on a dedicated test node. It is functional device-memory validation,
not an exploit reproduction or a confidential-computing qualification.

The [Linux and H100 validation record](validation/model-memory-integrity-2026-11-04.md)
lists actual results, explicit skips and optional CUDA adapter reproduction
commands. It does not qualify a complete production serving engine.

## Motivation and references

- [Eclypsium: Trusted AI Requires Trusted Infrastructure](https://eclypsium.com/wp-content/uploads/Trusted-AI-Requires-Trusted-Infrastructure.pdf).
  The reported experiment's permissive memory-access configuration and attack
  prerequisites matter. These SDK tests do not reproduce that attack.
- WCM `memory_sweep.py`, `custody.py`, and `LIMITATIONS.md`: existing memory-region
  sweep, runtime custody and the distinction between enforcement and evidence.
