"""Prerequisite observations cannot substitute for hardware acceptance."""
import importlib.util
import stat
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "boot" / "host_preflight.py"
spec = importlib.util.spec_from_file_location("host_preflight", SCRIPT)
preflight = importlib.util.module_from_spec(spec)
spec.loader.exec_module(preflight)


def test_positive_does_not_claim_hardware_acceptance():
    result = preflight.report(dict.fromkeys(preflight.REQUIRED, "observed"))
    assert result["outcome"] == "prerequisites-observed"
    assert result["hardware_acceptance"] == "not-tested"


@pytest.mark.parametrize("name", preflight.REQUIRED)
@pytest.mark.parametrize("state", ["absent", "unavailable", None])
def test_each_missing_prerequisite_blocks_success(name, state):
    checks = dict.fromkeys(preflight.REQUIRED, "observed")
    if state is None:
        del checks[name]
    else:
        checks[name] = state
    assert preflight.report(checks)["outcome"] == "needs-host-review"


def test_guest_device_and_regular_files_are_not_host_devices(tmp_path, monkeypatch):
    (tmp_path / "sev-guest").touch()
    assert preflight.device(tmp_path / "sev") == "absent"
    (tmp_path / "sev").touch()
    assert preflight.device(tmp_path / "sev") == "absent"
    node = SimpleNamespace(stat=lambda: SimpleNamespace(st_mode=stat.S_IFCHR))
    monkeypatch.setattr(preflight.os, "access", lambda *a: False)
    assert preflight.device(node) == "unavailable"
    monkeypatch.setattr(preflight.os, "access", lambda *a: True)
    assert preflight.device(node) == "observed"


@pytest.mark.parametrize("value,state", [("Y\n", "observed"), ("1", "observed"),
                                       ("N", "absent"), ("0", "absent"),
                                       ("unknown", "unavailable")])
def test_kernel_parameter(tmp_path, value, state):
    path = tmp_path / "parameter"
    assert preflight.enabled(path) == "unavailable"
    path.write_text(value, encoding="ascii")
    assert preflight.enabled(path) == state


@pytest.mark.parametrize("output,code,expected", [
    ("sev-snp-guest options:\n  kernel-hashes=<bool> - include kernel hashes\n", 0, True),
    ("sev-guest options:\n  kernel-hashes=<bool>\n", 0, False),
    ("sev-snp-guest options:\n", 0, False),
    ("error: sev-snp-guest options: kernel-hashes=<bool>", 0, False),
    ("sev-snp-guest options:\n  kernel-hashes=<bool>\n", 1, False),
])
def test_qemu_property_help(monkeypatch, output, code, expected):
    calls = []
    def run(args, **kwargs):
        calls.append((args, kwargs))
        return SimpleNamespace(stdout=output, stderr="", returncode=code)
    monkeypatch.setattr(preflight.subprocess, "run", run)
    result = preflight.qemu_properties("trusted-qemu")
    assert all(x == "observed" for x in result.values()) == expected
    assert calls[0][0] == ["trusted-qemu", "-object", "sev-snp-guest,help"]
    assert calls[0][1]["timeout"] == 10
    assert not calls[0][1].get("shell", False)


@pytest.mark.parametrize("error", [FileNotFoundError("private-path"),
                                  subprocess.TimeoutExpired("private-path", 10)])
def test_tool_failure_is_unavailable_without_error_disclosure(monkeypatch, error):
    def fail(*args, **kwargs):
        raise error
    monkeypatch.setattr(preflight.subprocess, "run", fail)
    result = preflight.qemu_properties("private-path")
    assert set(result.values()) == {"unavailable"}
    assert "private-path" not in str(result)


def test_unsupported_platform_never_invokes_qemu(monkeypatch):
    monkeypatch.setattr(preflight.platform, "system", lambda: "Windows")
    def unexpected(*args):
        pytest.fail("unsupported platform invoked QEMU")
    monkeypatch.setattr(preflight, "qemu_properties", unexpected)
    result = preflight.collect("unused")
    assert result["outcome"] == "needs-host-review"
    assert result["checks"]["linux-x86_64"] == "absent"
