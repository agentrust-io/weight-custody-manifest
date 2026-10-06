"""Publication gates reject mismatched versions and unreviewed commits."""
from __future__ import annotations

import importlib.util
import ast
import subprocess
from pathlib import Path

import pytest
import yaml

SPEC = importlib.util.spec_from_file_location("release_gate", Path(__file__).parents[2] / "tools/release_gate.py")
assert SPEC and SPEC.loader
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)


@pytest.fixture
def repo(tmp_path):
    def git(*args):
        return subprocess.check_output(["git", *args], cwd=tmp_path, stderr=subprocess.DEVNULL)
    git("init", "-b", "main")
    git("config", "user.name", "Example")
    git("config", "user.email", "example@example.org")
    p = tmp_path / "python/src/wcm/__init__.py"
    p.parent.mkdir(parents=True)
    p.write_text('__version__ = "0.0.1"\n')
    git("add", ".")
    git("commit", "-m", "fixture")
    git("update-ref", "refs/remotes/origin/main", "HEAD")
    git("tag", "v0.0.1")
    return tmp_path, git


def test_matching_release_and_main_dry_run_pass(repo):
    root, _ = repo
    gate.validate(root, "release", "v0.0.1")
    gate.validate(root, "workflow_dispatch", "")


def test_version_mismatch_fails(repo):
    root, _ = repo
    with pytest.raises(ValueError, match="version"):
        gate.validate(root, "release", "v0.0.2")


def test_unreviewed_commit_fails(repo):
    root, git = repo
    git("commit", "--allow-empty", "-m", "unreviewed")
    with pytest.raises(subprocess.CalledProcessError):
        gate.validate(root, "release", "v0.0.1")


def test_tag_must_identify_checkout(repo):
    root, git = repo
    git("commit", "--allow-empty", "-m", "next reviewed change")
    git("update-ref", "refs/remotes/origin/main", "HEAD")
    with pytest.raises(ValueError, match="checkout"):
        gate.validate(root, "release", "v0.0.1")


def test_dry_run_cannot_publish_old_main_commit(repo):
    root, git = repo
    git("commit", "--allow-empty", "-m", "new main")
    git("update-ref", "refs/remotes/origin/main", "HEAD")
    git("checkout", "v0.0.1")
    with pytest.raises(ValueError, match="current main"):
        gate.validate(root, "workflow_dispatch", "")


def test_unknown_event_fails(repo):
    root, _ = repo
    with pytest.raises(ValueError, match="event"):
        gate.validate(root, "push", "v0.0.1")


def _workflow():
    path = Path(__file__).parents[2] / ".github/workflows/publish.yml"
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _event_guard(expression, event):
    comparison = ast.parse(expression, mode="eval").body
    assert isinstance(comparison, ast.Compare)
    assert ast.unparse(comparison.left) == "github.event_name"
    assert len(comparison.ops) == 1 and isinstance(comparison.ops[0], ast.Eq)
    assert len(comparison.comparators) == 1
    return event == ast.literal_eval(comparison.comparators[0])


@pytest.mark.parametrize("event", ["workflow_dispatch", "release"])
@pytest.mark.parametrize("validation", ["success", "failure", "cancelled", "skipped"])
def test_rehearsal_and_release_job_graph(event, validation):
    workflow = _workflow()
    jobs = workflow["jobs"]
    assert jobs["validate"]["uses"] == "./.github/workflows/python.yml"
    results = {"validate": validation}
    for name, job in jobs.items():
        if name == "validate":
            continue
        dependencies = job.get("needs", [])
        dependencies = [dependencies] if isinstance(dependencies, str) else dependencies
        assert all(dependency in results for dependency in dependencies)
        allowed = "if" not in job or _event_guard(job["if"], event)
        results[name] = (
            "success" if allowed and all(results[d] == "success" for d in dependencies)
            else "skipped"
        )
    active = [job for name, job in jobs.items() if results[name] == "success"]
    publications = [step for job in active for step in job.get("steps", [])
                    if step.get("uses", "").startswith("pypa/gh-action-pypi-publish@")]
    assert len(publications) == int(event == "release" and validation == "success")
    if event == "workflow_dispatch":
        for job in active:
            assert "environment" not in job
            assert job.get("permissions", workflow["permissions"]).get("id-token") != "write"
    assert jobs["build"]["needs"] == "validate"
    assert jobs["pypi"]["needs"] == "build"


def test_rehearsal_retains_scans_and_downloadable_artifacts():
    workflow = _workflow()
    assert workflow[True]["release"]["types"] == ["published"]
    assert "workflow_dispatch" in workflow[True]
    steps = workflow["jobs"]["build"]["steps"]
    names = {step.get("name") for step in steps}
    assert {"Verify release source and version", "Scan source", "Build sdist + wheel",
            "Scan built distributions"} <= names
    uploads = [step for step in steps if step.get("uses", "").startswith("actions/upload-artifact@")]
    assert len(uploads) == 1
    assert uploads[0]["with"] == {"name": "dist", "path": "dist/"}
