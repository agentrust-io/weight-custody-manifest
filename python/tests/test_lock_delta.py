import importlib.util
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("check_lock_delta", ROOT / "tools/check_lock_delta.py")
guard = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(guard)
H = " --hash=sha256:" + "a" * 64
OLD = "core==1" + H + "\ncolorama==1 ; sys_platform == 'win32'" + H + "\n"


def test_upgrade_preserves_other_pins_and_markers():
    assert guard.check_delta(OLD, OLD.replace("core==1", "core==2")) == ["core"]


@pytest.mark.parametrize("after", [
    "core==1" + H,
    OLD.replace(" ; sys_platform == 'win32'", ""),
    OLD.replace(H, ""),
    OLD.replace("a" * 64, "a" * 63),
    OLD + "core==2" + H,
    "core>=1" + H,
    "",
])
def test_independent_lock_corruptions_are_refused(after):
    with pytest.raises(ValueError):
        guard.check_delta(OLD, after)


def test_reviewed_removal_is_explicit_and_package_scoped():
    assert guard.check_delta(OLD, "core==1" + H, ["colorama"]) == []
    with pytest.raises(ValueError):
        guard.check_delta(OLD, "colorama==1" + H, ["colorama"])


def test_dropped_optional_extra_is_not_a_version_only_change():
    with pytest.raises(ValueError, match="removed pins"):
        guard.check_delta("coverage[toml]==1" + H, "coverage==1" + H)


def test_checked_in_locks_parse():
    for name in ("dev", "composed", "docs", "build"):
        assert guard.parse_lock((ROOT / f"requirements/{name}.txt").read_text())


def test_cli_fails_even_under_optimized_python(tmp_path):
    # CLI path must remain inside the repository; malformed input is created
    # in tools temporarily and removed even if the subprocess check fails.
    path = ROOT / "tools/lock-negative-test.txt"
    try:
        path.write_text("unhashed==1\n")
        result = subprocess.run([sys.executable, "-O", str(ROOT / "tools/check_lock_delta.py"),
                                 str(path)], capture_output=True, text=True)
        assert result.returncode == 1
        assert "missing SHA-256" in result.stderr
    finally:
        path.unlink(missing_ok=True)


def test_renamed_required_lock_cannot_skip_the_old_dependency_baseline(tmp_path):
    root = tmp_path / "repo"
    (root / "tools").mkdir(parents=True)
    (root / "requirements").mkdir()
    shutil.copyfile(ROOT / "tools/check_lock_delta.py", root / "tools/check_lock_delta.py")
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    lock = root / "requirements/dev.txt"
    lock.write_text(OLD)
    subprocess.run(["git", "-C", str(root), "add", "."], check=True)
    subprocess.run(["git", "-C", str(root), "-c", "user.name=Fixture", "-c",
                    "user.email=fixture@example.test", "commit", "-qm", "base"], check=True)
    command = [sys.executable, str(root / "tools/check_lock_delta.py"),
               "--base", "HEAD", "requirements/dev.txt"]
    control = subprocess.run(command, cwd=root, capture_output=True, text=True)
    assert control.returncode == 0, control.stderr
    lock.rename(root / "requirements/renamed.txt")
    (root / "requirements/renamed.txt").write_text("core==1" + H)
    for optimize in ([], ["-O"]):
        result = subprocess.run([sys.executable, *optimize, *command[1:]],
                                cwd=root, capture_output=True, text=True)
        assert result.returncode == 1
        assert "FAIL" in result.stderr and "requirements/dev.txt" in result.stderr
