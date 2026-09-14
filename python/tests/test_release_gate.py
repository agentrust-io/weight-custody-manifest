"""Publication gates reject mismatched versions and unreviewed commits."""
from __future__ import annotations

import importlib.util
import subprocess
from pathlib import Path

import pytest

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
