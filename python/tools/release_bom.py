#!/usr/bin/env python3
"""Generate a CycloneDX release BOM from public PyPI and pinned repository inputs."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PACKAGE = "weight-custody-manifest"


def fetch_pypi(version: str) -> dict[str, Any]:
    with urllib.request.urlopen(
        f"https://pypi.org/pypi/{PACKAGE}/{version}/json", timeout=30
    ) as response:
        return json.load(response)


def _base_digest(dockerfile: Path) -> str:
    match = re.search(r"^ARG BASE_DIGEST=(sha256:[0-9a-f]{64})$", dockerfile.read_text(), re.M)
    if not match:
        raise ValueError("Dockerfile has no pinned BASE_DIGEST")
    return match.group(1)


def _tag_commit(root: Path, version: str) -> str:
    tag = f"v{version}"
    local = subprocess.run(
        ["git", "rev-list", "-n", "1", tag], cwd=root, capture_output=True, text=True
    )
    if local.returncode == 0 and local.stdout.strip():
        return local.stdout.strip()
    remote = subprocess.check_output(
        ["git", "ls-remote", "origin", f"refs/tags/{tag}"], cwd=root, text=True
    ).strip()
    if not remote:
        raise ValueError(f"release tag {tag} not found locally or on origin")
    return remote.split()[0]


def build_bom(metadata: dict[str, Any], root: Path, version: str) -> dict[str, Any]:
    info = metadata["info"]
    if info["version"] != version:
        raise ValueError(f"PyPI returned {info['version']} instead of {version}")
    files = []
    for item in sorted(metadata["urls"], key=lambda value: value["filename"]):
        files.append({
            "filename": item["filename"],
            "packagetype": item["packagetype"],
            "bytes": item["size"],
            "sha256": item["digests"]["sha256"],
            "url": item["url"],
            "uploaded_at": item["upload_time_iso_8601"],
        })
    commit = _tag_commit(root, version)
    requirements = sorted(info.get("requires_dist") or [])
    component_ref = f"pkg:pypi/{PACKAGE}@{version}"
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, component_ref + '@' + commit)}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "component": {
                "type": "library",
                "bom-ref": component_ref,
                "name": PACKAGE,
                "version": version,
                "purl": component_ref,
            },
            "properties": [
                {"name": "wcm:source_commit", "value": commit},
                {"name": "wcm:source_tag", "value": f"v{version}"},
                {"name": "wcm:kbs_base_image_digest", "value": _base_digest(root / "python/docker/Dockerfile")},
                {"name": "wcm:manifest_schema", "value": "https://wcm.agentrust-io.com/schema/manifest/v1.json"},
                {"name": "wcm:classification", "value": "public-release-metadata"},
            ],
        },
        "components": [
            {"type": "library", "name": req, "bom-ref": f"requirement:{req}"}
            for req in requirements
        ],
        "dependencies": [{"ref": component_ref, "dependsOn": [f"requirement:{req}" for req in requirements]}],
        "properties": [{"name": "wcm:pypi_artifacts", "value": json.dumps(files, sort_keys=True)}],
    }


def write_bom(bom: dict[str, Any], output: Path) -> None:
    output.mkdir(parents=True, exist_ok=False)
    bom_path = output / "release-bom.cdx.json"
    bom_path.write_text(json.dumps(bom, indent=2) + "\n", encoding="utf-8")
    digest = hashlib.sha256(bom_path.read_bytes()).hexdigest()
    artifacts = json.loads(next(p["value"] for p in bom["properties"] if p["name"] == "wcm:pypi_artifacts"))
    (output / "README.md").write_text("\n".join((
        f"# {PACKAGE} {bom['metadata']['component']['version']} release BOM", "",
        "Classification: **public release metadata**.", "",
        f"- Source commit: `{next(p['value'] for p in bom['metadata']['properties'] if p['name'] == 'wcm:source_commit')}`",
        f"- CycloneDX BOM SHA-256: `{digest}`", "",
        "## Published artifacts", "",
        *[f"- `{item['filename']}` — {item['bytes']} bytes — `sha256:{item['sha256']}`" for item in artifacts], "",
        "Reproduce with:", "", "```text",
        f"python python/tools/release_bom.py --version {bom['metadata']['component']['version']} --out release-bom", "```", "",
    )), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    bom = build_bom(fetch_pypi(args.version), root, args.version)
    write_bom(bom, args.out)
    print(json.dumps(bom, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
