"""Read-only prerequisite observations for the provisional Linux/QEMU SNP profile.

No VM launch, device ioctl, attestation, network call or host configuration change.
A successful exit is not hardware acceptance or authorization to launch.
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import re
import stat
import subprocess
import sys
from pathlib import Path

REQUIRED = ("linux-x86_64", "host-sev", "host-kvm", "snp-enabled", "qemu-snp",
            "qemu-kernel-hashes")


def device(path):
    try:
        if not stat.S_ISCHR(path.stat().st_mode):
            return "absent"
    except FileNotFoundError:
        return "absent"
    except OSError:
        return "unavailable"
    # This checks permissions only; it never opens the device or creates a VM.
    return "observed" if os.access(path, os.R_OK | os.W_OK) else "unavailable"


def enabled(path):
    try:
        value = path.read_text(encoding="ascii").strip().lower()
    except (OSError, UnicodeError):
        return "unavailable"
    if value in ("y", "1"):
        return "observed"
    return "absent" if value in ("n", "0") else "unavailable"


def qemu_properties(executable):
    try:
        result = subprocess.run(
            [executable, "-object", "sev-snp-guest,help"],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=10, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return {"qemu-snp": "unavailable", "qemu-kernel-hashes": "unavailable"}
    # Never retain tool output: error text may contain operator paths or identifiers.
    if result.returncode != 0:
        return {"qemu-snp": "unavailable", "qemu-kernel-hashes": "unavailable"}
    output = result.stdout + "\n" + result.stderr
    recognized = re.search(r"(?m)^\s*sev-snp-guest options:\s*$", output) is not None
    hashes = re.search(r"(?m)^\s*kernel-hashes=<bool>(?:\s|$)", output) is not None
    return {"qemu-snp": "observed" if recognized else "unavailable",
            "qemu-kernel-hashes": "observed" if recognized and hashes else "unavailable"}


def report(checks):
    # Unknown/missing observations must never be promoted to success.
    checks = {name: checks.get(name, "unavailable") for name in REQUIRED}
    if any(value not in ("observed", "absent", "unavailable") for value in checks.values()):
        raise ValueError("invalid prerequisite observation")
    complete = all(value == "observed" for value in checks.values())
    return {
        "profile": "wcm-snp-host-preflight-v1",
        "evidence_class": "unauthenticated-local-host-observation",
        "outcome": "prerequisites-observed" if complete else "needs-host-review",
        "checks": checks,
        "hardware_acceptance": "not-tested",
        "limits": ["host output and filesystem are trusted for these observations",
                   "device permissions do not establish working SNP ioctls or capacity",
                   "QEMU help does not establish firmware compatibility or launch success",
                   "no platform security policy, measurement or report was verified",
                   "custom firmware permission and independent owner approval still required"],
    }


def collect(executable):
    linux = platform.system() == "Linux" and platform.machine().lower() in ("x86_64", "amd64")
    checks = {"linux-x86_64": "observed" if linux else "absent"}
    if linux:
        checks.update({"host-sev": device(Path("/dev/sev")),
                       "host-kvm": device(Path("/dev/kvm")),
                       "snp-enabled": enabled(Path("/sys/module/kvm_amd/parameters/sev_snp"))})
        checks.update(qemu_properties(executable))
    return report(checks)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--qemu", default="qemu-system-x86_64",
                        help="operator-trusted QEMU executable; invoked only for property help")
    args = parser.parse_args()
    result = collect(args.qemu)
    print(json.dumps(result, indent=2))
    return 0 if result["outcome"] == "prerequisites-observed" else 2


if __name__ == "__main__":
    sys.exit(main())
