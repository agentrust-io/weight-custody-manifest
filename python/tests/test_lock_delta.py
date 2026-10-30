import importlib.util
import shutil
import subprocess
import sys
import tempfile
import unittest
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

SUFFIX_HASH = " --hash=sha256:" + "a" * 64
SUFFIX_PIN = 'demo==1 ; python_version >= "3.11"'


class TestHashSuffix(unittest.TestCase):
    def test_marker_and_multiple_hashes_remain_valid(self):
        for marker in ('', ' ; python_version >= "3.11"',
                       ' ; os_name == "value --hash=sha256:BAD"'):
            with self.subTest(marker=marker):
                text = "demo==1" + marker + SUFFIX_HASH + SUFFIX_HASH.replace("a" * 64, "b" * 64)
                self.assertEqual(guard.parse_lock(text), {("demo", ("",), marker.strip()): "1"})

    def test_entire_hash_suffix_is_validated(self):
        for marker in ('', ' ; python_version >= "3.11"'):
            for extra in (' --hash=sha256:BAD', ' --hash=sha256:' + 'b' * 63,
                          ' --hash=sha256:' + 'b' * 65, ' --hash=sha512:' + 'b' * 64,
                          ' --index-url=https://example.invalid', ' trailing-junk'):
                with self.subTest(marker=marker, extra=extra):
                    with self.assertRaisesRegex(ValueError, "unsupported lock option or malformed hash"):
                        guard.parse_lock("demo==1" + marker + SUFFIX_HASH + extra)

    def test_unsupported_option_before_valid_hash_is_refused(self):
        with self.assertRaisesRegex(ValueError, "unsupported lock option or malformed hash"):
            guard.parse_lock(SUFFIX_PIN + " --index-url=https://example.invalid" + SUFFIX_HASH)

    def test_required_lock_cli_refuses_malformed_suffix(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "tools").mkdir()
            shutil.copy2(ROOT / "tools/check_lock_delta.py", root / "tools/check_lock_delta.py")
            lock = root / "test.txt"
            for optimize in ([], ["-O"]):
                for extra, expected in (('', 0), (' --hash=sha256:BAD', 1),
                                        (' --index-url=https://example.invalid', 1)):
                    with self.subTest(optimize=optimize, extra=extra):
                        lock.write_text(SUFFIX_PIN + SUFFIX_HASH + extra)
                        result = subprocess.run(
                            [sys.executable, *optimize, str(root / "tools/check_lock_delta.py"), "test.txt"],
                            cwd=root, capture_output=True, text=True, check=False)
                        self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
                        if expected:
                            self.assertIn("unsupported lock option or malformed hash", result.stderr)
