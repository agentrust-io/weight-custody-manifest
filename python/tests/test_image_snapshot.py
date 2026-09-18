"""Build-evidence controls independent of a Docker daemon or hardware quote."""
import importlib.util
import io
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tarfile

import pytest

DOCKER = Path(__file__).resolve().parents[1] / "docker"
pytestmark = pytest.mark.skipif(not DOCKER.is_dir(), reason="image tools require repository checkout")


@pytest.fixture
def snapshotter():
    spec = importlib.util.spec_from_file_location("image_snapshot", DOCKER / "image_snapshot.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.snapshot


def write_export(path, *, target="app.py", uid=10001, gid=10001, mode=0o644,
                 payload=b"approved code", mtime=0, capability="", hardlink=False, reverse=False):
    entries = []
    file = tarfile.TarInfo("app.py")
    file.size = len(payload)
    file.mode, file.uid, file.gid, file.mtime = mode, uid, gid, mtime
    if capability:
        file.pax_headers = {"SCHILY.xattr.security.capability": capability}
    entries.append((file, payload))
    link = tarfile.TarInfo("entrypoint")
    link.type = tarfile.LNKTYPE if hardlink else tarfile.SYMTYPE
    link.linkname = target
    link.mtime = mtime
    entries.append((link, None))
    with tarfile.open(path, "w", format=tarfile.PAX_FORMAT) as tar:
        for item, data in reversed(entries) if reverse else entries:
            tar.addfile(item, io.BytesIO(data) if data is not None else None)
    return path


def inspect_file(path, **changes):
    config = {"User": "10001", "Cmd": ["uvicorn", "wcm.broker_server:app_from_env"],
              "Env": ["MODE=strict"], "WorkingDir": "/app", "Entrypoint": None}
    config.update(changes)
    path.write_text(json.dumps([{"Architecture": "amd64", "Os": "linux", "Config": config}]))
    return path


@pytest.mark.parametrize("change", [
    {"target": "evil.py"}, {"uid": 0}, {"gid": 0}, {"mode": 0o4755},
    {"payload": b"changed code"}, {"capability": "privileged"}, {"hardlink": True},
])
def test_security_relevant_filesystem_changes_alter_snapshot(tmp_path, snapshotter, change):
    inspection = inspect_file(tmp_path / "inspect.json")
    approved = snapshotter(write_export(tmp_path / "approved.tar"), inspection)
    changed = snapshotter(write_export(tmp_path / "changed.tar", **change), inspection)
    assert approved != changed


@pytest.mark.parametrize("change", [{"User": "0"}, {"Cmd": ["unapproved"]},
    {"Env": ["MODE=permissive"]}, {"Entrypoint": ["sh"]}, {"WorkingDir": "/other"}])
def test_runtime_overrides_alter_snapshot(tmp_path, snapshotter, change):
    archive = write_export(tmp_path / "root.tar")
    first = snapshotter(archive, inspect_file(tmp_path / "one.json"))
    second = snapshotter(archive, inspect_file(tmp_path / "two.json", **change))
    assert first != second


def test_timestamp_and_tar_order_noise_do_not_change_snapshot(tmp_path, snapshotter):
    inspection = inspect_file(tmp_path / "inspect.json")
    assert snapshotter(write_export(tmp_path / "one.tar"), inspection) == snapshotter(
        write_export(tmp_path / "two.tar", mtime=1000, reverse=True), inspection)


@pytest.mark.parametrize("name", ["../escape", "/absolute", "nested/../escape"])
def test_ambiguous_export_paths_rejected(tmp_path, snapshotter, name):
    archive = tmp_path / "bad.tar"
    with tarfile.open(archive, "w") as tar:
        member = tarfile.TarInfo(name)
        tar.addfile(member, io.BytesIO())
    with pytest.raises(ValueError, match="filesystem path"):
        snapshotter(archive, inspect_file(tmp_path / "inspect.json"))


def test_duplicate_paths_and_unresolved_links_rejected(tmp_path, snapshotter):
    archive = tmp_path / "bad.tar"
    with tarfile.open(archive, "w") as tar:
        for name in ("app.py", "./app.py"):
            tar.addfile(tarfile.TarInfo(name), io.BytesIO())
    with pytest.raises(ValueError, match="duplicate"):
        snapshotter(archive, inspect_file(tmp_path / "inspect.json"))
    with pytest.raises(ValueError, match="unresolved"):
        snapshotter(write_export(archive, target="missing", hardlink=True), tmp_path / "inspect.json")


def test_truncated_export_and_missing_runtime_config_rejected(tmp_path, snapshotter):
    archive = write_export(tmp_path / "bad.tar", payload=b"x" * 2048)
    archive.write_bytes(archive.read_bytes()[:1024])
    with pytest.raises(tarfile.ReadError):
        snapshotter(archive, inspect_file(tmp_path / "inspect.json"))
    inspection = tmp_path / "missing.json"
    inspection.write_text('[{"Architecture":"amd64","Os":"linux"}]')
    with pytest.raises(ValueError, match="runtime configuration"):
        snapshotter(write_export(archive), inspection)


@pytest.mark.parametrize("fault", ["none", "export", "runtime"])
def test_build_coordinator_fails_closed_with_docker_test_double(tmp_path, fault):
    # Executes the real shell coordinator. The stub supplies fixture exports;
    # this validates error handling, not a real image build.
    bash = "C:/Program Files/Git/bin/bash.exe" if os.name == "nt" else shutil.which("bash")
    if not bash or not Path(bash).exists():
        pytest.skip("bash is required for coordinator test")
    binary = tmp_path / "bin"
    binary.mkdir()
    docker = binary / "docker"
    docker.write_text('''#!/usr/bin/env bash
set -eu
case "$1" in
 build) exit 0 ;;
 create) echo "$2" ;;
 export) cp "$FAKE_TAR" "$4"; [[ "$FAULT" != export ]] || exit 42 ;;
 rm) exit 0 ;;
 image)
   if [[ "$2" == rm ]]; then exit 0; fi
   if [[ "$FAULT" == runtime && "$3" == *-two-* ]]; then cat "$FAKE_OTHER"; else cat "$FAKE_INSPECT"; fi ;;
 *) exit 99 ;;
esac
''', newline="\n")
    docker.chmod(0o755)
    python = binary / "python3"
    python.write_text('#!/usr/bin/env bash\nexec ' + shlex.quote(sys.executable.replace('\\', '/')) + ' "$@"\n', newline="\n")
    python.chmod(0o755)
    archive = write_export(tmp_path / "image.tar")
    inspection = inspect_file(tmp_path / "inspect.json")
    other = inspect_file(tmp_path / "other.json", Cmd=["unapproved"])
    env = dict(os.environ, FAULT=fault, FAKE_TAR=archive.as_posix(), FAKE_INSPECT=inspection.as_posix(),
               FAKE_OTHER=other.as_posix(), TMPDIR=tmp_path.as_posix())
    # Git Bash resolves Windows PATH after startup; put the stub first in-shell.
    binary_path = shlex.quote(binary.as_posix())
    if os.name == "nt":
        binary_path = '"$(cygpath -u ' + binary_path + ')"'
    command = 'export PATH=' + binary_path + ':"$PATH"; bash python/docker/verify-reproducible.sh --target reference'
    result = subprocess.run([bash, "-c", command], cwd=DOCKER.parents[1], env=env,
                            capture_output=True, text=True, timeout=30)
    if fault == "none":
        assert result.returncode == 0, result.stdout + result.stderr
        assert "PASS:" in result.stdout
    else:
        assert result.returncode != 0, result.stdout + result.stderr
        assert "PASS:" not in result.stdout
        if fault == "export":
            assert result.returncode == 42, result.stdout + result.stderr
        else:
            assert "runtime configuration differs" in result.stderr, result.stdout + result.stderr
    assert not list(tmp_path.glob("wcm-repro.*")), "temporary exports must be cleaned"
