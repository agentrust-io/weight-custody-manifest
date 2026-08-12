#!/usr/bin/env python3
"""Run hardware-independent WCM launch gates and emit JSON plus Markdown receipts."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path


HAPPY_TESTS = (
    "python/tests/test_kbs.py::test_happy_path_releases_key",
    "python/tests/test_kbs.py::test_channel_binding_required_seals_key_to_enclave",
    "python/tests/test_server.py::test_release_happy_path",
    "python/tests/test_provenance.py::test_verify_provenance_round_trip",
    "python/tests/test_nvidia.py::test_real_h100_attestation_verifies_offline",
    "python/tests/test_nvidia.py::test_kbs_releases_with_verified_gpu",
    "python/tests/test_custody.py::test_from_release_starts_custody",
)

NEGATIVE_TESTS = (
    "python/tests/test_kbs.py",
    "python/tests/test_custody.py",
    "python/tests/test_provenance.py::test_verify_provenance_rejects_wrong_digest",
    "python/tests/test_provenance.py::test_verify_provenance_rejects_tampered_model",
    "python/tests/test_nvidia.py::test_real_h100_wrong_nonce_fails",
    "python/tests/test_nvidia.py::test_real_h100_tampered_report_fails_signature",
    "python/tests/test_nvidia.py::test_real_h100_untrusted_root_fails",
    "python/tests/test_nvidia.py::test_kbs_denies_untrusted_gpu",
    "python/tests/test_nvidia.py::test_kbs_gpu_must_bind_this_nonce",
)


def _git_commit(root: Path) -> str:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=root, capture_output=True, text=True, check=False
    )
    return result.stdout.strip() if result.returncode == 0 else "unknown"


def run(mode: str, root: Path) -> dict[str, object]:
    tests = HAPPY_TESTS if mode == "happy" else NEGATIVE_TESTS
    env = os.environ.copy()
    env["PYTHONPATH"] = str(root / "python" / "src")
    started = datetime.now(timezone.utc)
    with tempfile.TemporaryDirectory(prefix=f"wcm-{mode}-", dir=root) as temp:
        command = [
            sys.executable,
            "-m",
            "pytest",
            "-q",
            "--disable-warnings",
            "-p",
            "no:cacheprovider",
            "--basetemp",
            temp,
            *tests,
        ]
        result = subprocess.run(
            command, cwd=root, env=env, capture_output=True, text=True, check=False
        )
    finished = datetime.now(timezone.utc)
    return {
        "kind": "wcm-launch-readiness/v1",
        "mode": mode,
        "hardware_claim": False,
        "release_candidate": _git_commit(root),
        "started_at": started.isoformat(),
        "finished_at": finished.isoformat(),
        "command": [*command[:8], "<temporary-test-directory>", *command[9:]],
        "tests": list(tests),
        "passed": result.returncode == 0,
        "exit_code": result.returncode,
        "stdout": result.stdout.strip(),
        "stderr": result.stderr.strip(),
    }


def write_reports(result: dict[str, object], output: Path) -> None:
    output.mkdir(parents=True, exist_ok=True)
    canonical = json.dumps(result, sort_keys=True, separators=(",", ":")).encode()
    result["record_sha256"] = hashlib.sha256(canonical).hexdigest()
    json_path = output / f"{result['mode']}.json"
    md_path = output / f"{result['mode']}.md"
    json_path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    status = "PASS" if result["passed"] else "FAIL"
    md_path.write_text(
        "\n".join((
            f"# WCM {result['mode']} readiness: {status}",
            "",
            f"- Release candidate: `{result['release_candidate']}`",
            f"- Started: `{result['started_at']}`",
            f"- Finished: `{result['finished_at']}`",
            "- Hardware claim: `false` (software/offline readiness only)",
            f"- Receipt SHA-256: `{result['record_sha256']}`",
            "",
            "## Test output",
            "",
            "```text",
            str(result["stdout"]),
            "```",
            "",
        )),
        encoding="utf-8",
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("happy", "negative"), required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    result = run(args.mode, root)
    write_reports(result, args.out)
    print(json.dumps(result, indent=2))
    return int(not result["passed"])


if __name__ == "__main__":
    raise SystemExit(main())
