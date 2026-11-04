"""Isolated functional test: tiny model, real memory mutation, worker exit.

No hardware attestation, DMA attack, confidential mode or model-server claim.
CUDA mode requires an existing PyTorch/CUDA installation on a dedicated node.
"""
from __future__ import annotations

import argparse
import array
import hashlib
import json
import multiprocessing as mp
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from wcm import EnclaveSession
from wcm._seal import generate_transport_keypair
from wcm._signing import _b64url_encode
from wcm._types import HashValue
from wcm.model_memory import (
    BufferMemoryReader, ModelMemoryBaseline, ModelMemoryError, ModelMemoryGuard,
    ModelMemoryVerifier, measure_model_buffers, observe_model_memory,
)


def _hash(data: bytes) -> HashValue:
    return HashValue("sha256:" + hashlib.sha256(data).hexdigest())


def _worker(connection: Any, device: str) -> None:
    try:
        if device == "cuda":
            import torch
            if not torch.cuda.is_available():
                raise RuntimeError("CUDA unavailable; no CPU fallback permitted")
            weights = torch.tensor([2.0, 3.0, 4.0], device="cuda", dtype=torch.float32)
            inputs = torch.tensor([4.0, 5.0, 6.0], device="cuda", dtype=torch.float32)

            class DeviceReader:
                @property
                def nbytes(self) -> int:
                    return int(weights.numel() * weights.element_size())

                def read(self, offset: int, length: int) -> bytes:
                    torch.cuda.synchronize(weights.device)
                    # This view aliases the actual tensor used by dot(), not a checkpoint.
                    raw = weights.view(torch.uint8).flatten()
                    return bytes(raw[offset:offset + length].cpu().tolist())

            reader = DeviceReader()
            def infer() -> float:
                return float(torch.dot(weights, inputs).item())
            def mutate() -> None:
                weights[0] = 20.0
                torch.cuda.synchronize(weights.device)
            description = torch.cuda.get_device_name(0)
        else:
            cpu_weights = array.array("f", [2.0, 3.0, 4.0])
            reader = BufferMemoryReader(memoryview(cpu_weights))
            def infer() -> float:
                return float(sum(w * x for w, x in zip(cpu_weights, (4, 5, 6))))
            def mutate() -> None:
                cpu_weights[0] = 20.0
            description = "CPU array of three float32 model weights"

        buffers = {"linear.weight": reader}
        artifact = reader.read(0, reader.nbytes)  # Separate approved reference for this fixture.
        baseline = ModelMemoryBaseline(
            manifest_hash=_hash(b"demo-manifest"), weights_hash=_hash(artifact),
            serving_image_measurement=_hash(b"demo-observer"),
            layout_id="tiny-linear-f32-v1", buffers=measure_model_buffers(buffers),
        )
        teardown = []
        session = EnclaveSession(b"demo-session-key", cadence_seconds=60,
                                  on_stop=lambda: teardown.append("stop_requested"))
        guard = ModelMemoryGuard(baseline, on_failure=session.zeroize)
        key = Ed25519PrivateKey.generate()
        _, transport = generate_transport_keypair()
        verifier = ModelMemoryVerifier(
            baseline=baseline, transport_public_key=transport,
            observer_public_key_b64url=_b64url_encode(key.public_key().public_bytes_raw()),
        )

        def observation():
            nonce = verifier.issue_challenge().nonce
            report = observe_model_memory(buffers, baseline=baseline, challenge_nonce=nonce,
                                           transport_public_key=transport, signing_key=key)
            return report, nonce

        report, nonce = observation()
        verified = verifier.verify(report, challenge_nonce=nonce)[0]
        replay_denied = not verifier.verify(report, challenge_nonce=nonce)[0]
        session.authorize_operation()
        guard.check_before_operation(buffers)
        if session.tick().value == "wiped":
            raise RuntimeError("lease expired during baseline check")
        good = infer()
        connection.send({"phase": "serving", "inference": good})
        if connection.recv() != "mutate":
            raise RuntimeError("unexpected test command")
        mutate()
        bypassed = infer()  # Deliberate negative control, never a production dispatch path.
        report, nonce = observation()
        mismatch_denied = not verifier.verify(report, challenge_nonce=nonce)[0]
        try:
            session.authorize_operation()
            guard.check_before_operation(buffers)
        except ModelMemoryError:
            denied = True
        else:
            denied = False
        result = {
            "device": device, "device_description": description,
            "scope": "functional tiny-model memory test; no hardware attestation or DMA attack",
            "approved_inference": good, "unguarded_mutated_inference": bypassed,
            "artifact_hash_unchanged": _hash(artifact) == baseline.weights_hash,
            "genuine_observation_verified": verified, "replay_denied": replay_denied,
            "changed_memory_observation_denied": mismatch_denied,
            "guard_denied_dispatch": denied, "session_key_wiped": session.is_wiped,
            "stop_callback_called_once": len(teardown) == 1,
        }
        result["checks_passed"] = (
            good == 47.0 and bypassed == 119.0 and all(result[name] for name in (
                "artifact_hash_unchanged", "genuine_observation_verified", "replay_denied",
                "changed_memory_observation_denied", "guard_denied_dispatch",
                "session_key_wiped", "stop_callback_called_once",
            ))
        )
        connection.send(result)
        # Successful serving stays alive. Only the failed-integrity teardown path
        # exits; the parent checks this rather than merely observing script end.
        if not (denied and session.is_wiped and len(teardown) == 1):
            connection.recv()
    except Exception as exc:
        connection.send({"checks_passed": False, "error": f"{type(exc).__name__}: {exc}"})
    finally:
        connection.close()


def run(device: str) -> dict[str, Any]:
    context = mp.get_context("spawn")
    receiving, sending = context.Pipe(duplex=True)
    process = context.Process(target=_worker, args=(sending, device))
    process.start()
    sending.close()
    try:
        if not receiving.poll(60):
            raise RuntimeError("test worker timed out")
        ready = receiving.recv()
        was_serving = ready.get("phase") == "serving" and process.is_alive()
        if was_serving:
            receiving.send("mutate")
            if not receiving.poll(60):
                raise RuntimeError("mutated worker timed out")
            result: dict[str, Any] = receiving.recv()
        else:
            result = ready
        process.join(10)
        result["worker_alive_before_mutation"] = was_serving
        result["worker_exited"] = not process.is_alive() and process.exitcode == 0
        result["checks_passed"] = bool(result["checks_passed"] and result["worker_exited"] and was_serving)
        return result
    finally:
        if process.is_alive():
            process.terminate()
            process.join(10)
        receiving.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--device", choices=("cpu", "cuda"), default="cpu")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    outcome = run(args.device)
    text = json.dumps(outcome, indent=2) + "\n"
    if args.output:
        args.output.write_text(text, encoding="utf-8")
    print(text)
    raise SystemExit(0 if outcome["checks_passed"] else 1)
