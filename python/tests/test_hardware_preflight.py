from __future__ import annotations

import importlib.util
from pathlib import Path


MODULE = Path(__file__).parents[1] / "tools" / "hardware_preflight.py"
spec = importlib.util.spec_from_file_location("hardware_preflight", MODULE)
assert spec and spec.loader
preflight = importlib.util.module_from_spec(spec)
spec.loader.exec_module(preflight)


def test_collect_is_sanitized_and_hashed(monkeypatch):
    monkeypatch.setattr(preflight.platform, "node", lambda: "secret-host")
    monkeypatch.setattr(
        preflight,
        "_tool",
        lambda name, args: {
            "available": True,
            "exit_code": 0,
            "stdout": f"{name} on secret-host",
            "stderr": "",
        },
    )
    monkeypatch.setattr(
        preflight,
        "_devices",
        lambda: {
            "/dev/sev-guest": True,
            "/dev/tdx_guest": False,
            "/dev/tdx-guest": False,
            "/dev/tpm0": True,
            "/dev/tpmrm0": True,
            "/dev/nvidia0": True,
            "/dev/nvidiactl": True,
        },
    )
    evidence = preflight.collect("nvidia")
    assert evidence["kind"] == "wcm-hardware-preflight/v1"
    assert evidence["record_sha256"]
    assert evidence["wcm"]["cpu_provider_candidates"] == [
        "amd-sev-snp",
        "tpm2-or-azure-vtpm",
    ]
    assert all("secret-host" not in value.get("stdout", "") for value in evidence["tools"].values())


def test_collect_reports_no_inferred_cpu_provider(monkeypatch):
    monkeypatch.setattr(preflight, "_tool", lambda name, args: {"available": False})
    monkeypatch.setattr(preflight.os.path, "exists", lambda path: False)
    evidence = preflight.collect("azure-local")
    assert evidence["wcm"]["cpu_provider_candidates"] == []
