"""Whole-image TCG controls on explicitly instrumented, non-custody firmware."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

from predict_measurement import file_identity, hash_table
from qemu_smoke import require_init_exit

APPEND = "console=ttyS0 panic=-1 rdinit=/init"


def require_result(code, serial, debug, expected):
    if expected == "linux":
        if code != 0:
            raise AssertionError(f"Linux control exited QEMU with {code}")
        require_init_exit(serial, 111)
    else:
        required = {"table": 35, "hash": 37, "named": 41}[expected]
        if code != required or "Run /init as init process" in serial:
            raise AssertionError(f"expected firmware {expected} stop, got {code}")
        if expected == "named" and "N" not in debug:
            raise AssertionError("named-payload rejection marker absent")


def run(firmware, weakened, kernel, initrd, output):
    output.mkdir(parents=True, exist_ok=False)
    firmware, weakened, kernel, initrd, output = (
        p.resolve() for p in (firmware, weakened, kernel, initrd, output))
    if file_identity(firmware) == file_identity(weakened):
        raise AssertionError("weakening control must be a distinct image")
    table = hash_table(kernel, initrd, APPEND)
    cases = [("positive", table, "linux", None),
             ("missing-table", None, "table", None)]
    for name, offset, replacement in (("short-table", 16, b"\x76\0"),
                                      ("zero-entry", 34, b"\0\0"),
                                      ("duplicate-entry", 118, table[18:34])):
        changed = bytearray(table)
        changed[offset:offset + len(replacement)] = replacement
        cases.append((name, bytes(changed), "table", None))
    for role in ("kernel", "initrd", "cmdline"):
        cases.append(("changed-" + role, table, "hash", role))
    cases += [("named-shim", table, "named", "named"),
              ("weakened-hash-control", table, "linux", "weakened")]
    observations = []
    for name, fixture, expected, change in cases:
        serial = output / (name + ".serial.log")
        debug = output / (name + ".debug.log")
        actual_kernel, actual_initrd = kernel, initrd
        append = APPEND
        if change in ("kernel", "initrd"):
            original = kernel if change == "kernel" else initrd
            altered = output / (name + ".bin")
            # Append one byte: QEMU can still parse the Linux header; the hash
            # check, rather than host format rejection, must produce the verdict.
            altered.write_bytes(original.read_bytes() + b"X")
            if change == "kernel":
                actual_kernel = altered
            else:
                actual_initrd = altered
        if change in ("cmdline", "weakened"):
            append += " changed=1"
        image = weakened if change == "weakened" else firmware
        command = ["qemu-system-x86_64", "-machine", "q35,accel=tcg", "-cpu", "max",
                   "-m", "1536", "-smp", "1", "-nodefaults", "-display", "none",
                   "-monitor", "none", "-serial", "file:" + str(serial),
                   "-debugcon", "file:" + str(debug), "-global", "isa-debugcon.iobase=0x402",
                   "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04", "-no-reboot",
                   "-bios", str(image), "-kernel", str(actual_kernel),
                   "-initrd", str(actual_initrd), "-append", append]
        if fixture is not None:
            path = output / (name + ".table")
            path.write_bytes(fixture)
            command += ["-fw_cfg", "name=opt/wcm/test-hashes,file=" + str(path)]
        if change == "named":
            command += ["-fw_cfg", "name=etc/boot/shim,file=" + str(kernel)]
        with (output / (name + ".qemu.log")).open("wb") as log:
            # Timeout is an error, never a rejection result.
            result = subprocess.run(command, stdout=log, stderr=log, timeout=150, check=False)
        require_result(result.returncode, serial.read_text(errors="replace"),
                       debug.read_text(errors="replace"), expected)
        observations.append({"case": name, "expected": expected, "qemu_exit": result.returncode,
                             "firmware": file_identity(image), "kernel": file_identity(actual_kernel),
                             "initrd": file_identity(actual_initrd), "command_line": append,
                             "table_sha256": None if fixture is None else hashlib.sha256(fixture).hexdigest()})
        print("PASS", name, flush=True)
    (output / "observations.json").write_text(json.dumps({
        "kind": "wcm/test-only-firmware-vm/v1", "hardware_validated": False,
        "production_image_tested": False,
        "qemu": subprocess.check_output(["qemu-system-x86_64", "--version"], text=True),
        "observations": observations}, indent=2) + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("firmware", "weakened", "kernel", "initrd", "output"):
        parser.add_argument(name, type=Path)
    args = parser.parse_args()
    run(args.firmware, args.weakened, args.kernel, args.initrd, args.output)
