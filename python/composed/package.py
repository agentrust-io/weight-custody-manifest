"""Build a small research reproduction ZIP from a successfully evaluated checkout."""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import re
import subprocess
import zipfile
from pathlib import Path

from run import PINS

CORE = {"weight-custody-manifest", "cmcp-runtime", "ca2a-runtime"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    revision = subprocess.check_output(
        ["git", "-C", str(root), "rev-parse", "HEAD"], text=True
    ).strip()
    dirty = subprocess.check_output(
        ["git", "-C", str(root), "status", "--porcelain"], text=True
    )
    if dirty:
        raise SystemExit("package only a clean committed checkout")
    evidence = json.loads((args.evidence / "manifest.json").read_text(encoding="utf-8"))
    if evidence["exit_code"] != 0 or evidence["sources"]["wcm"] != revision:
        raise SystemExit("successful evidence must match this WCM revision")
    for name, pin in PINS.items():
        if evidence["sources"].get(name) != pin:
            raise SystemExit(f"{name}: evidence differs from reviewed pin")
    if evidence.get("wcm_tracked_diff_sha256") != hashlib.sha256(b"").hexdigest():
        raise SystemExit("reference evidence includes tracked WCM edits")
    harness = sorted((root / "python/composed").glob("*.py")) + [
        root / "python/composed/Dockerfile"
    ]
    expected_files = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in harness}
    if evidence.get("harness_files") != expected_files:
        raise SystemExit("reference evidence must cover the current harness bytes")
    if evidence["sources"].get("confinement") != "bad751becca0ec5c42d70062e5c9fe5ee1380e85":
        raise SystemExit("reference evidence must include the reviewed confined profile")
    observed = sorted(evidence["dependencies"], key=lambda row: row["name"].lower())
    installed = sorted(
        [
            {"name": d.metadata["Name"], "version": d.version}
            for d in importlib.metadata.distributions()
        ],
        key=lambda row: row["name"].lower(),
    )
    if observed != installed:
        raise SystemExit(
            "build in the same dependency environment as the successful run"
        )
    requirements = []
    for distribution in installed:
        name, version = distribution["name"], distribution["version"]
        if re.sub(r"[-_.]+", "-", name).lower() in CORE:
            continue
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", name) or not re.fullmatch(
            r"[A-Za-z0-9_.+!-]+", version
        ):
            raise SystemExit("dependency cannot be represented as a pinned version")
        requirements.append(f"{name}=={version}")
    files = {
        "reproduce.py": (root / "python/composed/reproduce.py").read_bytes(),
        "requirements.txt": ("\n".join(requirements) + "\n").encode(),
        "README.md": (root / "python/composed/BUNDLE.md").read_bytes(),
    }
    manifest = {
        "format": "wcm-composed-source-bundle-v1",
        "sources": {
            "wcm": revision,
            **PINS,
            "confinement": "bad751becca0ec5c42d70062e5c9fe5ee1380e85",
        },
        "evidence_class": "synthetic-attestation/local-software",
        "evaluated_profile": evidence["profile"],
        "reference_manifest_sha256": hashlib.sha256(
            (args.evidence / "manifest.json").read_bytes()
        ).hexdigest(),
        "files": {
            name: hashlib.sha256(data).hexdigest() for name, data in files.items()
        },
        "limits": [
            "source-based research package; not a released integration",
            "network required for GitHub, PyPI and optional Docker base image",
            "runtime versions pinned; dependencies and build tools not hash locked",
            "bundle hashes detect modification; they are not independent provenance",
            "synthetic attestation, same operator, host-side diagnostic model",
        ],
    }
    files["bundle.json"] = (json.dumps(manifest, indent=2) + "\n").encode()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(args.output, "x", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in sorted(files.items()):
            info = zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            archive.writestr(info, data)
    digest = hashlib.sha256(args.output.read_bytes()).hexdigest()
    args.output.with_suffix(args.output.suffix + ".sha256").write_text(
        f"{digest}  {args.output.name}\n", encoding="utf-8"
    )
    print(digest, args.output)


if __name__ == "__main__":
    main()
