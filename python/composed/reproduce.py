"""Run a reviewed source-based research bundle in a new workspace."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import venv

REPOSITORIES = {
    "wcm": "weight-custody-manifest", "cmcp": "cmcp", "ca2a": "ca2a",
    "confinement": "cmcp",
}


def run(command, **kwargs):
    print("+", " ".join(map(str, command)), flush=True)
    return subprocess.run(list(map(str, command)), check=True, **kwargs)


def validate_bundle(root):
    manifest = json.loads((root / "bundle.json").read_text(encoding="utf-8"))
    if manifest.get("format") != "wcm-composed-source-bundle-v1":
        raise ValueError("unsupported bundle format")
    if set(manifest["sources"]) != set(REPOSITORIES):
        raise ValueError("bundle must identify all four source snapshots")
    for name, revision in manifest["sources"].items():
        if not re.fullmatch(r"[0-9a-f]{40}", revision):
            raise ValueError(f"{name}: expected immutable Git revision")
    if set(manifest["files"]) != {"reproduce.py", "requirements.txt", "README.md"}:
        raise ValueError("unexpected bundle files")
    for name, digest in manifest["files"].items():
        if hashlib.sha256((root / name).read_bytes()).hexdigest() != digest:
            raise ValueError(f"{name}: bundle digest mismatch")
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, required=True,
                        help="new directory; existing paths are refused")
    parser.add_argument("--confined", action="store_true",
                        help="also run the native Linux Docker profile")
    args = parser.parse_args()
    bundle = Path(__file__).resolve().parent
    manifest = validate_bundle(bundle)
    if sys.version_info[:2] != (3, 12):
        raise SystemExit("this bundle was evaluated on Python 3.12")
    if args.confined and platform.system() != "Linux":
        raise SystemExit("the confined profile requires native Linux")
    workspace = args.workspace.resolve()
    workspace.mkdir(parents=True, exist_ok=False)
    env = dict(os.environ)
    # A previous checkout or pytest configuration must not supply the imports.
    for name in ("PYTHONPATH", "PYTHONHOME", "PYTEST_ADDOPTS", "COMPOSED_AGENT_IMAGE"):
        env.pop(name, None)
    env["PYTHONNOUSERSITE"] = "1"
    sources = {}
    for name, revision in manifest["sources"].items():
        if name == "confinement" and not args.confined:
            continue
        source = workspace / name
        run(["git", "init", source], env=env)
        run(["git", "-C", source, "fetch", "--depth=1",
             f"https://github.com/agentrust-io/{REPOSITORIES[name]}.git", revision], env=env)
        run(["git", "-C", source, "checkout", "--detach", "FETCH_HEAD"], env=env)
        actual = subprocess.check_output(
            ["git", "-C", str(source), "rev-parse", "HEAD"], text=True, env=env).strip()
        if actual != revision:
            raise RuntimeError(f"{name}: fetched source differs from bundle")
        sources[name] = source
    environment = workspace / ".venv"
    venv.EnvBuilder(with_pip=True).create(environment)
    python = environment / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    run([python, "-m", "pip", "install", "-r", bundle / "requirements.txt"], env=env)
    # Runtime versions come from the evaluated environment. Core code stays at
    # exact source revisions; build-backend dependencies are not hash locked.
    for name, suffix in (("wcm", "python"), ("cmcp", ""), ("ca2a", "")):
        run([python, "-m", "pip", "install", "--no-deps", "-e", sources[name] / suffix], env=env)
    run([python, "-m", "pip", "check"], env=env)
    command = [python, sources["wcm"] / "python/composed/run.py",
               "--cmcp-source", sources["cmcp"], "--ca2a-source", sources["ca2a"],
               "--output", workspace / "evidence"]
    if args.confined:
        image_id = workspace / "agent-image.txt"
        run(["docker", "build", "--iidfile", image_id,
             sources["wcm"] / "python/composed"], env=env)
        env["COMPOSED_AGENT_IMAGE"] = image_id.read_text(encoding="utf-8").strip()
        command += ["--confinement-source", sources["confinement"]]
    result = subprocess.run(list(map(str, command)), cwd=workspace, env=env, check=False)
    evidence = workspace / "evidence"
    if evidence.exists():
        (evidence / "bundle.json").write_bytes((bundle / "bundle.json").read_bytes())
    return result.returncode


if __name__ == "__main__":
    sys.exit(main())
