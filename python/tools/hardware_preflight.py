#!/usr/bin/env python3
"""Read-only preflight for a WCM NVIDIA or Azure Local validation host."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _run(command: list[str], *, timeout: int = 20) -> dict[str, Any]:
    try:
        result = subprocess.run(
            command, capture_output=True, text=True, timeout=timeout, check=False
        )
        return {
            "available": True,
            "exit_code": result.returncode,
            "stdout": result.stdout.strip(),
            "stderr": result.stderr.strip(),
        }
    except (OSError, subprocess.SubprocessError) as exc:
        return {"available": False, "error": str(exc)}


def _tool(name: str, args: list[str]) -> dict[str, Any]:
    path = shutil.which(name)
    if path is None:
        return {"available": False}
    result = _run([path, *args])
    result["path"] = path
    return result


def _devices() -> dict[str, bool]:
    names = (
        "/dev/sev-guest",
        "/dev/tdx_guest",
        "/dev/tdx-guest",
        "/dev/tpm0",
        "/dev/tpmrm0",
        "/dev/nvidia0",
        "/dev/nvidiactl",
    )
    return {name: os.path.exists(name) for name in names}


def _redact_host(text: str) -> str:
    hostname = platform.node()
    return text.replace(hostname, "<host>") if hostname else text


def collect(profile: str) -> dict[str, Any]:
    evidence: dict[str, Any] = {
        "kind": "wcm-hardware-preflight/v1",
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "profile": profile,
        "system": {
            "os": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
            "python": platform.python_version(),
        },
        "devices": _devices(),
        "tools": {
            "nvidia_smi": _tool(
                "nvidia-smi",
                [
                    "--query-gpu=name,driver_version,vbios_version,pci.bus_id",
                    "--format=csv,noheader",
                ],
            ),
            "nvidia_cc": _tool("nvidia-smi", ["conf-compute", "-f"]),
            "nvattest": _tool("nvattest", ["version"]),
            "tpm2_tools": _tool("tpm2_getcap", ["properties-fixed"]),
            "lspci_gpu": _tool("lspci", ["-nn"]),
        },
        "wcm": {
            "nvat_adapter_env_set": bool(os.environ.get("WCM_NVIDIA_ATTESTATION_CMD")),
            "cpu_provider_candidates": [],
        },
    }
    devices = evidence["devices"]
    if devices["/dev/sev-guest"]:
        evidence["wcm"]["cpu_provider_candidates"].append("amd-sev-snp")
    if devices["/dev/tdx_guest"] or devices["/dev/tdx-guest"]:
        evidence["wcm"]["cpu_provider_candidates"].append("intel-tdx-report")
    if devices["/dev/tpmrm0"]:
        evidence["wcm"]["cpu_provider_candidates"].append("tpm2-or-azure-vtpm")
    for result in evidence["tools"].values():
        for field in ("stdout", "stderr"):
            if field in result:
                result[field] = _redact_host(result[field])
    raw = json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode()
    evidence["record_sha256"] = hashlib.sha256(raw).hexdigest()
    return evidence


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=("nvidia", "azure-local"), required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    evidence = collect(args.profile)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(evidence, indent=2))
    gpu_required = args.profile == "nvidia"
    gpu_present = evidence["devices"]["/dev/nvidia0"]
    return 0 if not gpu_required or gpu_present else 2


if __name__ == "__main__":
    raise SystemExit(main())
