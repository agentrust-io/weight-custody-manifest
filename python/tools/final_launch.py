#!/usr/bin/env python3
"""Run WCM launch gates, validate receipts, and emit one final indexed report."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SECRET_PATTERNS = (
    re.compile(r"-----BEGIN (?:EC |RSA )?PRIVATE KEY-----"),
    re.compile(r'(?i)"?(?:private_key|secret|dek|key_b64)"?\s*[:=]'),
    re.compile(r"(?i)authorization:\s*bearer\s+"),
)


def _load(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate_pack(root: Path) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        relative = path.relative_to(root).as_posix()
        entry: dict[str, Any] = {
            "path": relative,
            "bytes": path.stat().st_size,
            "sha256": _sha256(path),
            "passed": True,
        }
        if path.suffix.lower() in {".json", ".md", ".txt", ".log", ".pem"}:
            text = path.read_text(encoding="utf-8", errors="replace")
            matches = [pattern.pattern for pattern in SECRET_PATTERNS if pattern.search(text)]
            if matches:
                entry["passed"] = False
                entry["reason"] = "potential secret material"
            if path.suffix.lower() == ".json":
                try:
                    json.loads(text)
                except json.JSONDecodeError:
                    entry["passed"] = False
                    entry["reason"] = "invalid JSON"
        findings.append(entry)
    return findings


def _write_summary(output: Path, report: dict[str, Any]) -> None:
    canonical = json.dumps(report, sort_keys=True, separators=(",", ":")).encode()
    report["record_sha256"] = hashlib.sha256(canonical).hexdigest()
    (output / "final-launch.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    status = "PASS" if report["passed"] else "BLOCKED"
    (output / "final-launch.md").write_text("\n".join((
        f"# WCM final launch: {status}", "",
        f"- Mode: `{report['mode']}`",
        f"- Release candidate: `{report['release_candidate']}`",
        f"- Hardware claim: `{str(report['hardware_claim']).lower()}`",
        f"- Receipt: `{report['record_sha256']}`", "",
        "## Gates", "",
        *[f"- {'PASS' if gate['passed'] else 'BLOCKED'} — {gate['name']}" for gate in report["gates"]],
        "",
    )), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("software", "partner"), required=True)
    parser.add_argument("--profile", choices=("nvidia", "azure-local"))
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    if args.mode == "partner" and not args.profile:
        parser.error("--profile is required in partner mode")
    root = Path(__file__).resolve().parents[2]
    args.out.mkdir(parents=True, exist_ok=False)
    readiness = _load("launch_readiness", root / "python/tools/launch_readiness.py")
    gates: list[dict[str, Any]] = []
    for mode in ("happy", "negative"):
        result = readiness.run(mode, root)
        readiness.write_reports(result, args.out)
        gates.append({"name": f"software_{mode}", "passed": result["passed"]})
    hardware_claim = False
    if args.mode == "partner":
        preflight = _load("hardware_preflight", root / "python/tools/hardware_preflight.py")
        inventory = preflight.collect(args.profile)
        (args.out / "preflight.json").write_text(json.dumps(inventory, indent=2) + "\n", encoding="utf-8")
        gpu = inventory["devices"]["/dev/nvidia0"]
        cpu = bool(inventory["wcm"]["cpu_provider_candidates"])
        hardware_ready = cpu and (gpu if args.profile == "nvidia" else True)
        gates.append({"name": "partner_hardware_preflight", "passed": hardware_ready})
        hardware_claim = hardware_ready
    inventory = validate_pack(args.out)
    evidence_ok = bool(inventory) and all(item["passed"] for item in inventory)
    gates.append({"name": "evidence_redaction_and_parse", "passed": evidence_ok})
    report = {
        "kind": "wcm-final-launch/v1",
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "mode": args.mode,
        "profile": args.profile,
        "release_candidate": subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=root, text=True
        ).strip(),
        "hardware_claim": hardware_claim,
        "gates": gates,
        "evidence_inventory": inventory,
        "passed": all(gate["passed"] for gate in gates),
    }
    _write_summary(args.out, report)
    print(json.dumps(report, indent=2))
    return int(not report["passed"])


if __name__ == "__main__":
    raise SystemExit(main())
