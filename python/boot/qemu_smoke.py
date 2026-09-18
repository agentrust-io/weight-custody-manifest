"""Full TCG boot harness. No SNP emulation, quote fabrication or model keys.

The production image must refuse this non-SNP VM. A separately compiled test
loader substitutes only its initial device lookup with /dev/urandom, allowing
the real fw_cfg/mount/exec path to run. The broker's SNP ioctl still fails closed.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import hashlib
from http.client import HTTPConnection
import io
import json
from pathlib import Path
import socket
import subprocess
import sys
import tarfile
import time

from wcm.boot_bundle import build_initramfs
from wcm.guest_broker import guest_inputs

HERE = Path(__file__).resolve().parent
COMMAND_LINE = ("console=ttyS0 panic=-1 rdinit=/init "
                "ip=10.0.2.15::10.0.2.2:255.255.255.0:wcm:eth0:off")


def require_init_exit(serial: str, status: int) -> None:
    """A timeout or unrelated boot panic never counts as an expected refusal."""
    marker = f"Attempted to kill init! exitcode=0x{status << 8:08x}"
    if "Run /init as init process" not in serial or marker not in serial:
        raise AssertionError("expected PID 1 exit was not observed")


def compile_loader(output: Path, *, test_device: bool, writable: bool = False) -> bytes:
    source = (HERE / "init.c").read_text()
    if test_device:
        before = 'stat("/dev/sev-guest", &device)'
        assert source.count(before) == 1
        source = source.replace(before, 'stat("/dev/urandom", &device)')
    if writable:
        before = "MS_BIND | MS_REMOUNT | MS_RDONLY | MS_NOSUID | MS_NODEV"
        assert source.count(before) == 1
        source = source.replace(before, "MS_BIND | MS_REMOUNT | MS_NOSUID | MS_NODEV")
    # ELF symbol metadata includes the source basename even without debug info.
    # Recompile production from its actual path, not a renamed generated copy.
    source_path = HERE / "init.c"
    if test_device or writable:
        source_path = output.with_suffix(".c")
        source_path.write_text(source)
    subprocess.run(["cc", "-static", "-O2", "-Wall", "-Wextra", "-Werror",
                    str(source_path), "-o", str(output)], check=True)
    return output.read_bytes()


def probe_runtime(output: Path) -> bytes:
    subprocess.run(["cc", "-static", "-O2", "-Wall", "-Wextra", "-Werror",
                    str(HERE / "probe.c"), "-o", str(output)], check=True)
    data = output.read_bytes()
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        item = tarfile.TarInfo("usr/local/bin/python3")
        item.mode, item.size = 0o755, len(data)
        archive.addfile(item, io.BytesIO(data))
    return stream.getvalue()


def public_configuration(output: Path) -> bytes:
    # Reuse the existing public-only container fixture, not owner/model secrets.
    subprocess.run([sys.executable, str(HERE.parent / "docker/smoke_provisioned.py"),
                    "fixture", str(output)], check=True)
    old = json.loads((output / "broker.json").read_text())
    config = {
        "cpu_root_pem": (output / "cpu-root.pem").read_text(),
        "cpu_vcek_pem": (output / "cpu-vcek.pem").read_text(),
        "cpu_intermediates_pem": [],
        "trusted_manifest_identities": old["configuration"]["trusted_manifest_identities"],
        "owner_public_key_hex": (output / "owner.pub").read_bytes().hex(),
    }
    data = json.dumps({"configuration": config, "policy": old["policy"]}).encode()
    guest_inputs(data)  # Independently check that positive boot data is admissible.
    return data


def request(port: int, path: str, payload: dict | None = None) -> tuple[int, dict]:
    connection = HTTPConnection("127.0.0.1", port, timeout=2)
    try:
        connection.request("GET" if payload is None else "POST", path,
                           body=None if payload is None else json.dumps(payload),
                           headers={"Content-Type": "application/json"})
        reply = connection.getresponse()
        return reply.status, json.loads(reply.read(4096))
    finally:
        connection.close()


@contextmanager
def guest(kernel: Path, image: Path, config: Path | None, log: Path):
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    command = [
        "qemu-system-x86_64", "-machine", "pc,accel=tcg", "-cpu", "max",
        "-m", "1536", "-smp", "1", "-nodefaults", "-display", "none",
        "-monitor", "none", "-serial", "file:" + str(log),
        "-no-reboot", "-kernel", str(kernel), "-initrd", str(image),
        "-append", COMMAND_LINE, "-device", "e1000,netdev=net0",
        "-netdev", f"user,id=net0,restrict=on,hostfwd=tcp:127.0.0.1:{port}-:8080",
    ]
    if config is not None:
        command += ["-fw_cfg", "name=opt/wcm/config,file=" + str(config).replace(",", ",,")]
    with log.with_suffix(".qemu.log").open("wb") as diagnostics:
        process = subprocess.Popen(command, stdout=diagnostics, stderr=diagnostics)
        try:
            yield process, port
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=10)


def run(kernel: Path, runtime: Path, production: Path, output: Path) -> None:
    output.mkdir(parents=True, exist_ok=False)
    kernel, runtime, production, output = (p.resolve() for p in (kernel, runtime, production, output))
    test_loader = compile_loader(output / "test-only-init", test_device=True)
    weakened_loader = compile_loader(output / "weakened-test-only-init", test_device=True, writable=True)
    probe = probe_runtime(output / "probe")
    runtime_bytes = runtime.read_bytes()
    # Make the relationship to the production image explicit before any VM run.
    production_loader = compile_loader(output / "production-init", test_device=False)
    if build_initramfs(runtime_bytes, production_loader) != production.read_bytes():
        raise AssertionError("production input differs from fresh reviewed-source assembly")
    config = public_configuration(output / "public-fixture")
    (output / "valid.json").write_bytes(config)
    (output / "probe.json").write_bytes(b"{}")
    bad = json.loads(config)
    bad["policy"]["configuration_sha256"] = "00" * 32
    (output / "bad.json").write_text(json.dumps(bad))
    (output / "oversized.json").write_bytes(b"x" * (1024 * 1024 + 1))
    images = {"production": production}
    for name, tar, init in (("broker-test-only", runtime_bytes, test_loader),
                            ("probe-test-only", probe, test_loader),
                            ("weakened-probe-test-only", probe, weakened_loader)):
        images[name] = output / (name + ".cpio")
        images[name].write_bytes(build_initramfs(tar, init))
    observations = []
    # Unchanged production refusal first; every negative must reach PID 1.
    cases = [
        ("production-no-snp", "production", "valid.json", 111),
        ("probe", "probe-test-only", "probe.json", 0),
        ("weakened-readonly", "weakened-probe-test-only", "probe.json", 20),
        ("missing-config", "probe-test-only", None, 111),
        ("oversized-config", "probe-test-only", "oversized.json", 111),
        ("changed-policy", "broker-test-only", "bad.json", 1),
    ]
    for name, image, data, expected in cases:
        log = output / (name + ".serial.log")
        with guest(kernel, images[image], None if data is None else output / data, log) as (process, _):
            process.wait(timeout=150)
        require_init_exit(log.read_text(errors="replace"), expected)
        observations.append({"case": name, "pid1_exit": expected, "image_sha256": hashlib.sha256(images[image].read_bytes()).hexdigest()})
        print("PASS", name, flush=True)
    # Two separate boots must each start unprovisioned and refuse native evidence.
    for boot in (1, 2):
        log = output / f"broker-boot-{boot}.serial.log"
        with guest(kernel, images["broker-test-only"], output / "valid.json", log) as (process, port):
            deadline = time.monotonic() + 150
            while True:
                if process.poll() is not None:
                    raise AssertionError("broker VM stopped before readiness")
                try:
                    if request(port, "/health") == (200, {"status": "ok"}):
                        break
                except (OSError, ValueError):
                    pass
                if time.monotonic() >= deadline:
                    raise AssertionError("broker VM readiness deadline exceeded")
                time.sleep(0.25)
            assert request(port, "/challenge", {})[0] == 409
            now = datetime.now(timezone.utc)
            status, body = request(port, "/provisioning/report", {
                "nonce": "aa" * 32, "issued_at": now.isoformat(),
                "expires_at": (now + timedelta(seconds=60)).isoformat(),
            })
            assert (status, body) == (503, {"detail": "native SNP attestation unavailable"})
            assert request(port, "/challenge", {})[0] == 409
        observations.append({"case": f"broker-boot-{boot}", "health": 200, "report": 503, "release_admission": 409})
        print("PASS", f"broker-boot-{boot}", flush=True)
    summary = {
        "profile": "wcm/qemu-tcg-boot-test/v1", "hardware_validated": False,
        "production_service_started": False, "command_line": COMMAND_LINE,
        "kernel_sha256": hashlib.sha256(kernel.read_bytes()).hexdigest(),
        "runtime_sha256": hashlib.sha256(runtime_bytes).hexdigest(),
        "production_loader_sha256": hashlib.sha256(production_loader).hexdigest(),
        "test_only_loader_sha256": hashlib.sha256(test_loader).hexdigest(),
        "test_only_image_sha256": hashlib.sha256(images["broker-test-only"].read_bytes()).hexdigest(),
        "qemu_version": subprocess.check_output(["qemu-system-x86_64", "--version"], text=True),
        "observations": observations,
    }
    (output / "observations.json").write_text(json.dumps(summary, indent=2) + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("kernel", type=Path)
    parser.add_argument("runtime", type=Path)
    parser.add_argument("production_initrd", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    run(args.kernel, args.runtime, args.production_initrd, args.output)
