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


# Proposed source baseline for .github#54. Preserve the existing publishing and
# Scorecard grants; changes to this list require an explicit maintainer review.
_OIDC_JOBS = {("publish.yml", "pypi"), ("scorecard.yml", "scorecard")}


def _has_oidc_write(permissions):
    if isinstance(permissions, str):
        if permissions not in {"read-all", "write-all"}:
            raise ValueError("unsupported permission shorthand")
        return permissions == "write-all"
    if not isinstance(permissions, dict):
        raise ValueError("permissions must be a mapping or shorthand")
    return permissions.get("id-token") == "write"


def _check_oidc_permissions(workflows):
    """Fail closed on source drift, including defaults shadowed by job grants."""
    actual = set()
    paths = sorted([*workflows.glob("*.yml"), *workflows.glob("*.yaml")])
    if not paths:
        raise AssertionError("no workflows found")
    for path in paths:
        workflow = yaml.safe_load(path.read_text(encoding="utf-8"))
        defaults = workflow.get("permissions", {})
        # A currently narrowed job must not hide a broad default that a future
        # job could inherit. Inspect source defaults as well as effective grants.
        if _has_oidc_write(defaults):
            raise AssertionError(f"workflow-wide OIDC grant: {path.name}")
        for name, job in workflow.get("jobs", {}).items():
            permissions = job.get("permissions", defaults)
            if permissions == "write-all":
                raise AssertionError(f"OIDC write-all job grant: {path.name}/{name}")
            if _has_oidc_write(permissions):
                actual.add((path.name, name))
    if actual != _OIDC_JOBS:
        raise AssertionError(f"OIDC job allowance drift: {actual ^ _OIDC_JOBS}")


def test_oidc_grants_match_repository_baseline():
    _check_oidc_permissions(Path(__file__).parents[2] / ".github/workflows")


@pytest.mark.parametrize("scenario", [
    "new-yml", "new-yaml", "extra-job", "inherited-default",
    "shadowed-default", "default-write-all", "shadowed-write-all",
    "job-write-all", "removed-publish", "removed-scorecard",
    "renamed-publisher", "renamed-workflow", "allowed-job-write-all",
    "future-inheritance",
])
def test_oidc_guard_rejects_workflow_drift(tmp_path, scenario):
    source = Path(__file__).parents[2] / ".github/workflows"
    for path in [*source.glob("*.yml"), *source.glob("*.yaml")]:
        (tmp_path / path.name).write_bytes(path.read_bytes())
    # Verify the copied real workflows before mutation, so refusal cannot be
    # credited to a fixture that was invalid from the start.
    _check_oidc_permissions(tmp_path)
    path = tmp_path / "publish.yml"
    workflow = yaml.safe_load(path.read_text(encoding="utf-8"))
    if scenario.startswith("new-"):
        path = tmp_path / ("unrelated." + scenario.removeprefix("new-"))
        workflow = {
            "name": "Unexpected", "on": "push",
            "jobs": {"test": {"runs-on": "ubuntu-latest",
                              "permissions": {"id-token": "write"},
                              "steps": [{"run": "echo test"}]}},
        }
    elif scenario == "extra-job":
        workflow["jobs"]["test"] = {"permissions": {"id-token": "write"}}
    elif scenario in {"inherited-default", "shadowed-default", "future-inheritance"}:
        workflow["permissions"] = {"contents": "read", "id-token": "write"}
        if scenario in {"shadowed-default", "future-inheritance"}:
            for job in workflow["jobs"].values():
                job.setdefault("permissions", {"contents": "read"})
        if scenario == "future-inheritance":
            workflow["jobs"]["future-test"] = {
                "runs-on": "ubuntu-latest", "steps": [{"run": "echo test"}],
            }
    elif scenario in {"default-write-all", "shadowed-write-all"}:
        workflow["permissions"] = "write-all"
        if scenario == "shadowed-write-all":
            for job in workflow["jobs"].values():
                job.setdefault("permissions", {})
    elif scenario == "job-write-all":
        workflow["jobs"]["build"]["permissions"] = "write-all"
    elif scenario == "allowed-job-write-all":
        workflow["jobs"]["pypi"]["permissions"] = "write-all"
    elif scenario == "removed-publish":
        workflow["jobs"]["pypi"]["permissions"] = {}
    elif scenario == "removed-scorecard":
        path = tmp_path / "scorecard.yml"
        workflow = yaml.safe_load(path.read_text(encoding="utf-8"))
        workflow["jobs"]["scorecard"]["permissions"].pop("id-token")
    elif scenario == "renamed-publisher":
        workflow["jobs"]["other"] = workflow["jobs"].pop("pypi")
    elif scenario == "renamed-workflow":
        path.unlink()
        path = tmp_path / "publish.yaml"
    path.write_text(yaml.safe_dump(workflow), encoding="utf-8")
    with pytest.raises(AssertionError, match="OIDC"):
        _check_oidc_permissions(tmp_path)


def test_oidc_guard_still_refuses_with_optimized_python(tmp_path):
    path = tmp_path / "unrelated.yaml"
    path.write_text("permissions: write-all\njobs: {}\n", encoding="utf-8")
    # Direct execution bypasses pytest's assertion rewriting. The guard uses
    # explicit raises so Python -O cannot turn the security check into a no-op.
    script = (
        "import runpy; from pathlib import Path; "
        "module = runpy.run_path(__import__('sys').argv[1]); "
        "module['_check_oidc_permissions'](Path(__import__('sys').argv[2]))"
    )
    import sys

    result = subprocess.run(
        [sys.executable, "-O", "-c", script, __file__, str(tmp_path)],
        capture_output=True, text=True, check=False,
    )
    assert result.returncode != 0
    assert "workflow-wide OIDC grant" in result.stderr


@pytest.mark.parametrize("permissions", [None, [], 1, "unsupported"])
def test_oidc_permission_shape_fails_closed(permissions):
    with pytest.raises(ValueError):
        _has_oidc_write(permissions)


def test_oidc_inventory_cannot_be_empty(tmp_path):
    with pytest.raises(AssertionError, match="no workflows"):
        _check_oidc_permissions(tmp_path)


def test_oidc_read_only_inheritance_is_allowed(tmp_path):
    source = Path(__file__).parents[2] / ".github/workflows"
    for path in [*source.glob("*.yml"), *source.glob("*.yaml")]:
        (tmp_path / path.name).write_bytes(path.read_bytes())
    (tmp_path / "read-only.yaml").write_text(
        "name: Read only\non: push\npermissions: read-all\njobs:\n"
        "  test:\n    runs-on: ubuntu-latest\n"
        "    steps:\n      - run: echo test\n", encoding="utf-8",
    )
    _check_oidc_permissions(tmp_path)
