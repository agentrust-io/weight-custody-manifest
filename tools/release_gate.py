"""Reject release artifacts not built from reviewed main history or a matching tag."""
from __future__ import annotations

import ast
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def validate(root: Path, event: str, tag: str) -> None:
    subprocess.run(["git", "merge-base", "--is-ancestor", "HEAD", "origin/main"],
                   cwd=root, check=True)
    if event == "workflow_dispatch":
        head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root)
        main = subprocess.check_output(["git", "rev-parse", "origin/main"], cwd=root)
        if head != main:
            raise ValueError("manual publishing requires the current main commit")
        return
    if event != "release":
        raise ValueError("unsupported publication event")
    module = ast.parse((root / "python/src/wcm/__init__.py").read_text(encoding="utf-8"))
    versions = [ast.literal_eval(n.value) for n in module.body if isinstance(n, ast.Assign)
                and any(isinstance(t, ast.Name) and t.id == "__version__" for t in n.targets)]
    if len(versions) != 1 or tag != "v" + versions[0]:
        raise ValueError("release tag does not match the SDK version")
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root)
    tagged = subprocess.check_output(["git", "rev-parse", "--verify", "refs/tags/" + tag + "^{commit}"], cwd=root)
    if head != tagged:
        raise ValueError("release checkout does not match its tag")


if __name__ == "__main__":
    validate(ROOT, os.environ.get("GITHUB_EVENT_NAME", ""), os.environ.get("RELEASE_TAG", ""))
    print("Publication source and version verified.")
