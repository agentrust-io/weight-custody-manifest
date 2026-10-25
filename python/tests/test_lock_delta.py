import importlib.util
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
