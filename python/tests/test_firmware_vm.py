"""VM verdicts require an observed stop code or the actual Linux PID1 oracle."""
import importlib.util
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1] / "boot"
sys.path.insert(0, str(ROOT))
try:
    spec = importlib.util.spec_from_file_location("firmware_vm", ROOT / "firmware_vm.py")
    vm = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(vm)
finally:
    sys.path.remove(str(ROOT))

SERIAL = "Run /init as init process\nKernel panic - not syncing: Attempted to kill init! exitcode=0x00006f00"
NAMED = "WCM_TEST_NAMED_DENY\n"


def test_linux_positive_requires_kernel_and_pid1():
    vm.require_result(0, SERIAL, "", "linux")
    for serial in ("", "Run /init as init process", SERIAL.split("\n")[1]):
        with pytest.raises(AssertionError):
            vm.require_result(0, serial, "", "linux")
    with pytest.raises(AssertionError):
        vm.require_result(35, SERIAL, "", "linux")


@pytest.mark.parametrize("expected,code", [("table", 35), ("hash", 37), ("named", 41)])
def test_rejection_requires_specific_stop_and_no_pid1(expected, code):
    vm.require_result(code, "", NAMED, expected)
    for wrong in (0, 1, -15, 99):
        with pytest.raises(AssertionError):
            vm.require_result(wrong, "", NAMED, expected)
    with pytest.raises(AssertionError):
        vm.require_result(code, SERIAL, NAMED, expected)
    with pytest.raises(AssertionError):
        vm.require_result(code, "Linux version 6.12", NAMED, expected)


def test_generic_manager_stop_does_not_prove_named_rejection():
    for debug in ("", "N", "UNRELATED FIRMWARE ERROR\n"):
        with pytest.raises(AssertionError):
            vm.require_result(41, "", debug, "named")
