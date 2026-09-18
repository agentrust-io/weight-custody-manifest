"""Portable patcher checks; executable C and full firmware builds run in CI."""
import importlib.util
import json
import os
from pathlib import Path

import pytest

FILE = Path(__file__).resolve().parents[1] / "boot/firmware_profile.py"
spec = importlib.util.spec_from_file_location("firmware_profile", FILE)
profile = importlib.util.module_from_spec(spec)
spec.loader.exec_module(profile)


def test_function_replacement_preserves_neighbors():
    source = "prefix\nTarget (\n VOID\n )\n{\n if (1) { call(); }\n}\nsuffix"
    assert profile.body(source, "Target", "  stop();") == "prefix\nTarget (\n VOID\n )\n{\nstop();\n}\nsuffix"


@pytest.fixture
def source(tmp_path):
    root = os.environ.get("WCM_FIRMWARE_SOURCE")
    if not root:
        pytest.skip("pinned edk2 source required; compiled control tests run in firmware CI")
    lock = json.loads((FILE.parent / "firmware-source.json").read_text())
    for name in lock["sources"]:
        dest = tmp_path / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes((Path(root) / name).read_bytes())
    return tmp_path


def test_exact_source_profile_and_second_application_rejected(source):
    result = profile.apply(source)
    assert result["hardware_validated"] is False
    assert result["provisional"] is True
    assert len(result["patched_sources"]) == 5
    for name in (profile.DSC, profile.FDF):
        text = (source / name).read_text()
        assert "OvmfPkg/AmdSev/Grub/" not in text
        assert "BootManagerMenuApp" not in text
        assert "ShellComponents.dsc.inc" not in text
        assert "ShellDxe.fdf.inc" not in text
    with pytest.raises(ValueError, match="pinned"):
        profile.apply(source)


@pytest.mark.parametrize("name", [profile.VERIFIER, profile.LOADER, profile.MANAGER, profile.DSC, profile.FDF])
def test_changed_source_fails_before_any_file_is_written(source, name):
    path = source / name
    path.write_bytes(path.read_bytes() + b"\n// unreviewed change\n")
    before = {p: p.read_bytes() for p in source.rglob("*") if p.is_file()}
    with pytest.raises(ValueError, match="pinned"):
        profile.apply(source)
    assert before == {p: p.read_bytes() for p in before}
