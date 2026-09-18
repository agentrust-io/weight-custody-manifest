"""Offline, provisional QEMU/SNP prediction on a trusted owner build host.

No report is accepted as an input. Metadata coverage is not firmware approval.
The external predictor is a pinned build tool, never a broker dependency.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import struct
import sys
import tempfile
import uuid

PIN = "8f2b337e38bc83f87cd30f3253cdfe8e3e12cc3a"
LOCK = Path(__file__).with_name("measurement-tool.json")


def file_identity(path):
    with path.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    return {"sha256": digest, "size": path.stat().st_size}


def load_tool(source):
    """Check exact source bytes before import; no installed-package fallback."""
    source = source.resolve()
    lock = json.loads(LOCK.read_text(encoding="utf-8"))
    package = source / "sevsnpmeasure"
    actual = {p.relative_to(source).as_posix(): file_identity(p)["sha256"]
              for p in package.rglob("*") if p.is_file()}
    if lock["revision"] != PIN or actual != lock["sources"]:
        raise ValueError("measurement tool source differs from pinned bytes")
    if any(name == "sevsnpmeasure" or name.startswith("sevsnpmeasure.")
           for name in sys.modules):
        raise ValueError("predictor already imported; use a fresh process")
    sys.dont_write_bytecode = True
    # Expose only the verified package, not sibling files that could shadow stdlib.
    spec = importlib.util.spec_from_file_location(
        "sevsnpmeasure", package / "__init__.py", submodule_search_locations=[str(package)])
    module = importlib.util.module_from_spec(spec)
    sys.modules["sevsnpmeasure"] = module
    spec.loader.exec_module(module)
    from sevsnpmeasure import guest, ovmf, sev_hashes, sev_mode, vcpu_types, vmm_types
    return guest, ovmf, sev_hashes, sev_mode, vcpu_types, vmm_types


def command_line(path):
    raw = path.read_bytes()
    if not raw or len(raw) > 4095 or any(c < 32 or c > 126 for c in raw):
        raise ValueError("command line must be 1..4095 printable ASCII bytes, without newline or NUL")
    return raw.decode("ascii")


def hash_table(kernel, initrd, append):
    """Independent encoding of QEMU's complete 176-byte PaddedSevHashTable."""
    entries = (
        ("97d02dd8-bd20-4c94-aa78-e7714d36ab2a", hashlib.sha256(append.encode("ascii") + b"\0").digest()),
        ("44baf731-3a2f-4bd7-9af1-41e29169781d", bytes.fromhex(file_identity(initrd)["sha256"])),
        ("4de79437-abd2-427f-b835-d5b172d2045b", bytes.fromhex(file_identity(kernel)["sha256"])),
    )
    body = b"".join(uuid.UUID(guid).bytes_le + struct.pack("<H", 50) + digest
                    for guid, digest in entries)
    return (uuid.UUID("9438d606-4f22-4cc9-b479-a793d411fd21").bytes_le
            + struct.pack("<H", 168) + body + bytes(8))


def require_coverage(firmware, section_type):
    sections = [s for s in firmware.metadata_items()
                if s.section_type() == section_type.SNP_KERNEL_HASHES]
    address = firmware.sev_hashes_table_gpa()
    if (len(sections) != 1 or not address or sections[0].size != 4096
            or sections[0].gpa % 4096 or address < sections[0].gpa
            or address + 176 > sections[0].gpa + sections[0].size):
        raise ValueError("exactly one containing SNP kernel-hashes page required")


def predict(args):
    if not 1 <= args.vcpus <= 1024:
        raise ValueError("vcpus must be 1..1024")
    features = int(args.guest_features, 16)
    if args.guest_features != hex(features) or not 0 < features < 2**64 or not features & 1:
        raise ValueError("explicit canonical SNP guest features required")
    guest, ovmf, sev_hashes, sev_mode, cpus, vmms = load_tool(args.tool_source)
    if args.vcpu_type not in cpus.CPU_SIGS:
        raise ValueError("unsupported explicit vCPU type")
    # Snapshot inputs once. Digests and prediction refer to these same copies.
    with tempfile.TemporaryDirectory(prefix="wcm-prediction-") as directory:
        paths = {}
        for role in ("firmware", "kernel", "initrd", "command_line"):
            path = Path(directory) / role
            shutil.copyfile(getattr(args, role), path)
            if not path.stat().st_size:
                raise ValueError("empty launch artifact")
            paths[role] = path
        size = paths["firmware"].stat().st_size
        if size < 1024 * 1024 or size > 16 * 1024 * 1024 or size % 4096:
            raise ValueError("full page-aligned 1..16 MiB firmware required; suffix fixtures are not firmware")
        append = command_line(paths["command_line"])
        firmware = ovmf.OVMF(str(paths["firmware"]))
        require_coverage(firmware, ovmf.SectionType)
        kernel, initrd = str(paths["kernel"]), str(paths["initrd"])
        table = hash_table(paths["kernel"], paths["initrd"], append)
        if sev_hashes.SevHashes(kernel, initrd, append).construct_table() != table:
            raise ValueError("independent kernel hash table disagrees with predictor")
        digest = guest.calc_launch_digest(
            sev_mode.SevMode.SEV_SNP, args.vcpus, cpus.CPU_SIGS[args.vcpu_type],
            str(paths["firmware"]), kernel, initrd, append, features,
            vmm_type=vmms.VMMType.QEMU,
        )
        if len(digest) != 48:
            raise ValueError("invalid prediction length")
        return {
            "kind": "wcm/snp-launch-prediction/v1", "provisional": True,
            "hardware_validated": False, "firmware_enforcement_validated": False,
            "expected_measurement_hex": digest.hex(),
            "artifacts": {role: file_identity(path) for role, path in paths.items()},
            "launch": {"vmm_type": "QEMU", "vcpus": args.vcpus,
                       "vcpu_type": args.vcpu_type, "guest_features": args.guest_features},
            "kernel_hashes": True,
            "kernel_hash_table_sha256": hashlib.sha256(table).hexdigest(),
            "tool_revision": PIN, "tool_lock": file_identity(LOCK),
            "python": sys.version,
        }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("tool-source", "firmware", "kernel", "initrd", "command-line"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--vcpus", type=int, required=True)
    parser.add_argument("--vcpu-type", required=True)
    parser.add_argument("--guest-features", required=True)
    args = parser.parse_args()
    try:
        result = predict(args)
    except Exception as exc:
        parser.exit(1, f"prediction rejected ({type(exc).__name__}): {exc}\n")
    print(json.dumps(result, sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
