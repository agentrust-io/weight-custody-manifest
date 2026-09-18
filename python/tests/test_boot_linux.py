"""Real mount/credential/exec tests, explicitly NOT boot or SNP evidence.

Run only in the dedicated disposable Linux CI job with passwordless sudo.
The production handoff functions are compiled unchanged into a namespace driver.
"""
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

from wcm.boot_bundle import build_initramfs
from tests.test_boot_bundle import runtime

pytestmark = pytest.mark.skipif(
    sys.platform != "linux" or os.environ.get("WCM_BOOT_LINUX_TESTS") != "1",
    reason="requires the dedicated privileged Linux loader job",
)
BOOT = Path(__file__).resolve().parents[1] / "boot"


def compile_c(source, output):
    subprocess.run(["cc", "-static", "-O2", "-Wall", "-Wextra", "-Werror", str(source), "-o", str(output)], check=True)


@pytest.fixture
def binaries(tmp_path):
    init, probe = tmp_path / "init", tmp_path / "probe"
    compile_c(BOOT / "init.c", init)
    compile_c(BOOT / "probe.c", probe)
    return init, probe


def test_real_static_loader_and_independent_cpio_reader(binaries):
    import tarfile
    init, probe = binaries
    image = build_initramfs(runtime([("usr/local/bin/python3", probe.read_bytes(), 0o755, tarfile.REGTYPE)]), init.read_bytes())
    listed = subprocess.run(["cpio", "-it", "--quiet"], input=image, capture_output=True, check=True).stdout.splitlines()
    assert b"init" in listed and b"runtime/usr/local/bin/python3" in listed
    assert subprocess.run([str(init)]).returncode == 111


@pytest.mark.parametrize("mutation", [None, "writable-runtime", "privileged", "environment", "bounding-caps", "descriptors", "new-privileges", "empty-config", "oversized-config"])
def test_actual_handoff_restrictions_and_negative_controls(tmp_path, binaries, mutation):
    _, probe = binaries
    source = (BOOT / "init.c").read_text()
    changes = {
        "writable-runtime": ("MS_BIND | MS_REMOUNT | MS_RDONLY | MS_NOSUID | MS_NODEV", "MS_BIND | MS_REMOUNT | MS_NOSUID | MS_NODEV"),
        "privileged": ("need(setresuid(BROKER_UID, BROKER_UID, BROKER_UID));", "/* deliberately retain root */"),
        "environment": ('char *const env[] = {"LANG=C.UTF-8", NULL};', 'extern char **environ; char **env = environ;'),
        "bounding-caps": ("int cap = 0; ; ++cap", "int cap = 1; ; ++cap"),
        "descriptors": ("need((int)syscall(SYS_close_range, 0U, ~0U, 0));", "/* deliberately retain descriptors */"),
        "new-privileges": ("need(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0));", "/* deliberately permit new privileges */"),
    }
    if mutation in changes:
        old, new = changes[mutation]
        assert old in source
        source = source.replace(old, new)
    unit = tmp_path / "subject.c"
    unit.write_text(source)
    driver = tmp_path / "driver.c"
    driver.write_text('''
#define main production_main
#include "subject.c"
#undef main
int main(int argc, char **argv) {
    if (argc != 2 || getpid() != 1) return 112;
    umask(0);
    need(mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL));
    need(chroot(argv[1])); need(chdir("/"));
    need(open("/outside", O_RDONLY)); /* must not survive the handoff */
    int input = open("/config", O_RDONLY); need(input);
    runtime_mounts(input, makedev(1, 9)); /* synthetic device, no SNP claim */
    enter_runtime(); return 113;
}
''')
    executable = tmp_path / "driver"
    compile_c(driver, executable)
    root = tmp_path / "root"
    for name in ("runtime/usr/local/bin", "runtime/run", "runtime/dev"):
        (root / name).mkdir(parents=True)
    shutil.copyfile(probe, root / "runtime/usr/local/bin/python3")
    (root / "runtime/usr/local/bin/python3").chmod(0o755)
    data = b"" if mutation == "empty-config" else b"x" * (1024 * 1024 + 1) if mutation == "oversized-config" else b"{}"
    (root / "config").write_bytes(data)
    (root / "outside").write_text("not reachable after handoff")
    result = subprocess.run(["sudo", "env", "PYTHONPATH=/outside",
                             "unshare", "--mount", "--pid", "--fork", "--net",
                             str(executable), str(root)], timeout=30, capture_output=True)
    assert result.returncode == {None: 0, "writable-runtime": 20, "privileged": 11,
                                 "environment": 12, "bounding-caps": 16, "descriptors": 111,
                                 "new-privileges": 13, "empty-config": 111,
                                 "oversized-config": 111}[mutation], result.stderr
