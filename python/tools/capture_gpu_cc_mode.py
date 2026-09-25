#!/usr/bin/env python3
"""Capture what an NVIDIA GPU will and will not say about confidential mode.

    python tools/capture_gpu_cc_mode.py --out tests/fixtures/nvidia/cc-mode

Run it once on a device with confidential compute on and once on a device with
it off. Needs ``nvidia-ml-py`` and a GPU; it makes no network requests.

What it records, per device:

* the driver's own view, from ``nvidia-smi conf-compute``.
* whether each confidential-compute NVML call answers, with the numeric return
  code when it does not. The non-attestation calls are included on purpose: if
  they answer while the attestation calls refuse, the refusal is the feature
  being unavailable rather than a missing device node or a blocked interface.
* the attestation report's opaque fields, parsed from the bytes. The layout is
  solved rather than assumed: the signature is the trailing 96, and the opaque
  length field is the offset whose little-endian value equals the distance from
  just past it to the signature.

Pass ``--ready-state-sweep`` to pull a second report with the GPUs ready state
off, which is the only confidential-compute control a guest can operate. Note
that on the device tested, that transition was one way from inside the guest:
setting it back required a reboot. Do not run the sweep on a machine you need.
"""
from __future__ import annotations

import argparse
import base64
import ctypes
import json
import pathlib
import subprocess
import sys

NONCE = bytes.fromhex("00" * 16 + "a5" * 16)


def smi(*args: str) -> str:
    try:
        done = subprocess.run(["nvidia-smi", "conf-compute", *args],
                              capture_output=True, text=True, timeout=30)
        return done.stdout.strip()
    except Exception as exc:  # noqa: BLE001
        return f"unavailable: {exc}"


def opaque_fields(raw: bytes) -> dict:
    """Tag, size and value for each opaque field, read positionally."""
    end = len(raw) - 96
    at = next(i for i in range(end)
              if int.from_bytes(raw[i:i + 2], "little") == end - (i + 2))
    data, fields, off = raw[at + 2:end], {}, 0
    while off + 4 <= len(data):
        tag = int.from_bytes(data[off:off + 2], "little")
        size = int.from_bytes(data[off + 2:off + 4], "little")
        fields[str(tag)] = {"size": size, "hex": data[off + 4:off + 4 + size].hex()}
        off += 4 + size
    return {"report_bytes": len(raw), "opaque_at": at + 2,
            "opaque_bytes": len(data), "fields": fields}


def probe(nvml, handle) -> dict:
    """Every confidential-compute call, with the numeric code when it refuses."""
    out: dict = {}
    calls = [
        ("attestation_report", lambda: nvml.nvmlDeviceGetConfComputeGpuAttestationReport(handle, NONCE)),
        ("gpu_certificate", lambda: nvml.nvmlDeviceGetConfComputeGpuCertificate(handle)),
        ("protected_memory", lambda: nvml.nvmlDeviceGetConfComputeProtectedMemoryUsage(handle)),
        ("mem_size_info", lambda: nvml.nvmlDeviceGetConfComputeMemSizeInfo(handle)),
    ]
    for name, call in calls:
        try:
            call()
            out[name] = {"answered": True}
        except nvml.NVMLError as exc:
            out[name] = {"answered": False, "nvml_code": int(exc.value), "error": str(exc)}
        except Exception as exc:  # noqa: BLE001
            out[name] = {"answered": False, "error": repr(exc)}
    return out


def report_bytes(nvml, handle) -> bytes:
    raw = nvml.nvmlDeviceGetConfComputeGpuAttestationReport(handle, NONCE)
    size = int(raw.attestationReportSize)
    buf = raw.attestationReport
    if isinstance(buf, (bytes, bytearray)):
        return bytes(buf[:size])
    return bytes(ctypes.string_at(ctypes.addressof(buf), size))


def cert_chain(nvml, handle) -> str:
    raw = nvml.nvmlDeviceGetConfComputeGpuCertificate(handle)
    size = int(raw.attestationCertChainSize)
    buf = raw.attestationCertChain
    payload = (bytes(buf[:size]) if isinstance(buf, (bytes, bytearray))
               else bytes(ctypes.string_at(ctypes.addressof(buf), size)))
    return base64.b64encode(payload).decode()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True)
    parser.add_argument("--label", default="device")
    parser.add_argument("--ready-state-sweep", action="store_true")
    args = parser.parse_args()

    import pynvml as nvml

    nvml.nvmlInit()
    handle = nvml.nvmlDeviceGetHandleByIndex(0)
    capture = {
        "label": args.label,
        "device": nvml.nvmlDeviceGetName(handle),
        "driver": nvml.nvmlSystemGetDriverVersion(),
        "conf_compute": {
            "feature": smi("-f"), "ready_state": smi("-grs"),
            "memory": smi("-gm"), "devtools": smi("-d"), "query": smi("-q"),
        },
        "nvml_calls": probe(nvml, handle),
    }

    if capture["nvml_calls"]["attestation_report"]["answered"]:
        capture["report"] = opaque_fields(report_bytes(nvml, handle))
        capture["cert_chain_b64"] = cert_chain(nvml, handle)

    if args.ready_state_sweep and capture["nvml_calls"]["attestation_report"]["answered"]:
        subprocess.run(["sudo", "nvidia-smi", "conf-compute", "-srs", "0"],
                       capture_output=True, text=True, timeout=60)
        capture["ready_state_off"] = {
            "ready_state": smi("-grs"),
            "report": opaque_fields(report_bytes(nvml, handle)),
        }

    out = pathlib.Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    path = out / f"{args.label}.json"
    path.write_text(json.dumps(capture, indent=2) + "\n", encoding="utf-8")
    print(f"written: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
