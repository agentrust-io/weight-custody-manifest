"""Checks the boot oracle independently of QEMU availability."""
import importlib.util
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "boot/qemu_smoke.py"
spec = importlib.util.spec_from_file_location("qemu_smoke", SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def test_expected_pid1_exit_requires_init_and_exact_status():
    serial = "Run /init as init process\nKernel panic - not syncing: Attempted to kill init! exitcode=0x00006f00"
    module.require_init_exit(serial, 111)
    with pytest.raises(AssertionError):
        module.require_init_exit(serial, 0)


@pytest.mark.parametrize("serial", [
    "", "Kernel panic: no root filesystem",
    "Attempted to kill init! exitcode=0x00006f00",
    "Run /init as init process\nAttempted to kill init! exitcode=0x00000100",
])
def test_unrelated_failure_never_counts_as_expected_refusal(serial):
    with pytest.raises(AssertionError):
        module.require_init_exit(serial, 111)
