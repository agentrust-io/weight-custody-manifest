"""Software-only prediction controls. Padded suffix vectors cannot boot."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
from types import SimpleNamespace
import uuid

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "boot" / "predict_measurement.py"
spec = importlib.util.spec_from_file_location("prediction", SCRIPT)
prediction = importlib.util.module_from_spec(spec)
spec.loader.exec_module(prediction)


@pytest.mark.parametrize("raw", [b"", b"a\n", b"a\r", b"a\0", b"\xff", b"a" * 4096])
def test_command_line_has_no_implicit_normalization(tmp_path, raw):
    path = tmp_path / "cmdline"
    path.write_bytes(raw)
    with pytest.raises(ValueError, match="ASCII"):
        prediction.command_line(path)


def test_complete_hash_table_layout(tmp_path):
    kernel, initrd = tmp_path / "kernel", tmp_path / "initrd"
    kernel.write_bytes(b"kernel vector")
    initrd.write_bytes(b"initrd vector")
    table = prediction.hash_table(kernel, initrd, "console=ttyS0")
    assert len(table) == 176
    assert uuid.UUID(bytes_le=table[:16]) == uuid.UUID("9438d606-4f22-4cc9-b479-a793d411fd21")
    assert struct.unpack_from("<H", table, 16)[0] == 168
    for offset, guid, raw in (
        (18, "97d02dd8-bd20-4c94-aa78-e7714d36ab2a", b"console=ttyS0\0"),
        (68, "44baf731-3a2f-4bd7-9af1-41e29169781d", b"initrd vector"),
        (118, "4de79437-abd2-427f-b835-d5b172d2045b", b"kernel vector"),
    ):
        assert uuid.UUID(bytes_le=table[offset:offset + 16]) == uuid.UUID(guid)
        assert struct.unpack_from("<H", table, offset + 16)[0] == 50
        assert table[offset + 18:offset + 50] == hashlib.sha256(raw).digest()
    assert table[168:] == bytes(8)


def firmware(sections, address=4096):
    return SimpleNamespace(metadata_items=lambda: sections,
                           sev_hashes_table_gpa=lambda: address)


def section(gpa=4096, size=4096):
    return SimpleNamespace(gpa=gpa, size=size, section_type=lambda: 16)


@pytest.mark.parametrize("sections,address", [([], 4096), ([section(), section()], 4096),
    ([section(size=8192)], 4096), ([section(gpa=4097)], 4097),
    ([section()], 0), ([section()], 4095), ([section()], 8192 - 175)])
def test_coverage_rejects_missing_duplicate_or_noncontaining_page(sections, address):
    with pytest.raises(ValueError, match="containing"):
        prediction.require_coverage(firmware(sections, address), SimpleNamespace(SNP_KERNEL_HASHES=16))


def test_coverage_accepts_table_ending_at_page_boundary():
    prediction.require_coverage(firmware([section()], 8192 - 176), SimpleNamespace(SNP_KERNEL_HASHES=16))


@pytest.fixture
def upstream():
    value = os.environ.get("WCM_MEASUREMENT_TOOL")
    if not value:
        pytest.skip("pinned independent predictor checkout required")
    return Path(value).resolve()


def run_cli(upstream, files, **changes):
    options = {"tool-source": upstream, **files, "vcpus": 1,
               "vcpu-type": "EPYC-v4", "guest-features": "0x1", **changes}
    args = [sys.executable, "-I", "-B", "-S", str(SCRIPT)]
    for name, value in options.items():
        args.extend(["--" + name, str(value)])
    return subprocess.run(args, capture_output=True, text=True, timeout=60)


@pytest.fixture
def files(upstream, tmp_path):
    result = {name: tmp_path / name for name in ("firmware", "kernel", "initrd", "command-line")}
    suffix = (upstream / "tests/fixtures/ovmf_AmdSev_suffix.bin").read_bytes()
    # An explicitly synthetic 1 MiB vector, not a firmware image or hardware report.
    result["firmware"].write_bytes(bytes(1024 * 1024 - len(suffix)) + suffix)
    result["kernel"].write_bytes(b"synthetic kernel")
    result["initrd"].write_bytes(b"synthetic initrd")
    result["command-line"].write_bytes(b"console=ttyS0 loglevel=7")
    return result


def test_upstream_published_vector_and_independent_page_info(upstream):
    # The known digest is published in upstream tests/test_guest.py at PIN.
    # This is a software fixture, not an independently observed hardware result.
    code = '''
import importlib.util, pathlib, struct, hashlib
s=importlib.util.spec_from_file_location("prediction", SCRIPT)
p=importlib.util.module_from_spec(s); s.loader.exec_module(p)
guest, ovmf, hashes, modes, cpus, vmms=p.load_tool(pathlib.Path(SOURCE))
from sevsnpmeasure.gctx import GCTX
c=GCTX(); c.update_normal_pages(4096, bytes(4096))
expected=hashlib.sha384(bytes(48)+hashlib.sha384(bytes(4096)).digest()+struct.pack("<H6BQ",112,1,0,0,0,0,0,4096)).digest()
assert c.ld()==expected
with __import__("tempfile").TemporaryDirectory() as d:
    empty=pathlib.Path(d)/"empty"; empty.write_bytes(b"")
    value=guest.calc_launch_digest(modes.SevMode.SEV_SNP,1,cpus.CPU_SIGS["EPYC-v4"],str(pathlib.Path(SOURCE)/"tests/fixtures/ovmf_AmdSev_suffix.bin"),str(empty),str(empty),"console=ttyS0 loglevel=7",1,vmm_type=vmms.VMMType.QEMU)
    assert value.hex()=="6d287813eb5222d770f75005c664e34c204f385ce832cc2ce7d0d6f354454362f390ef83a92046c042e706363b4b08fa"
'''
    result = subprocess.run([sys.executable, "-I", "-B", "-c",
                             f"SCRIPT={str(SCRIPT)!r}; SOURCE={str(upstream)!r}\n" + code],
                            capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("changed", ["firmware", "kernel", "initrd", "command-line", "vcpus", "vcpu-type", "guest-features"])
def test_each_launch_input_changes_prediction(upstream, files, changed):
    baseline = run_cli(upstream, files)
    assert baseline.returncode == 0, baseline.stderr
    first = json.loads(baseline.stdout)
    options = {}
    if changed in files:
        raw = bytearray(files[changed].read_bytes())
        raw[0] ^= 1
        files[changed].write_bytes(raw)
    else:
        options[changed] = {"vcpus": 2, "vcpu-type": "EPYC-Milan-v2", "guest-features": "0x21"}[changed]
    result = run_cli(upstream, files, **options)
    assert result.returncode == 0, result.stderr
    second = json.loads(result.stdout)
    assert first["expected_measurement_hex"] != second["expected_measurement_hex"]
    assert first["hardware_validated"] is False
    assert first["firmware_enforcement_validated"] is False
    for role, path in files.items():
        assert second["artifacts"][role.replace("-", "_")]["sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.mark.parametrize("bad", ["suffix", "standard", "source", "extra-source", "features", "cpu", "vcpus", "empty"])
def test_cli_fails_closed(upstream, files, tmp_path, bad):
    options = {}
    if bad in ("suffix", "standard"):
        name = "ovmf_AmdSev_suffix.bin" if bad == "suffix" else "ovmf_OvmfX64_suffix.bin"
        raw = (upstream / "tests/fixtures" / name).read_bytes()
        files["firmware"].write_bytes(raw if bad == "suffix" else bytes(1024 * 1024 - len(raw)) + raw)
    elif bad in ("source", "extra-source"):
        copy = tmp_path / "tool"
        shutil.copytree(upstream / "sevsnpmeasure", copy / "sevsnpmeasure")
        (copy / "sevsnpmeasure" / ("guest.py" if bad == "source" else "unexpected.py")).write_bytes(b"raise RuntimeError('must not execute')")
        options["tool-source"] = copy
    elif bad == "empty":
        files["initrd"].write_bytes(b"")
    else:
        options.update({"features": {"guest-features": "0x0"},
                        "cpu": {"vcpu-type": "max"}, "vcpus": {"vcpus": 0}}[bad])
    result = run_cli(upstream, files, **options)
    assert result.returncode == 1
    assert not result.stdout
    assert "prediction rejected" in result.stderr
    assert "must not execute" not in result.stderr


def test_tool_siblings_cannot_shadow_standard_library(upstream, files, tmp_path):
    copy = tmp_path / "tool"
    shutil.copytree(upstream / "sevsnpmeasure", copy / "sevsnpmeasure")
    (copy / "ctypes.py").write_text("raise RuntimeError('unverified sibling executed')")
    result = run_cli(copy, files)
    assert result.returncode == 0, result.stderr
