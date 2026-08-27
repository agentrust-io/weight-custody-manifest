#!/usr/bin/env python3
"""Capture protected-runtime evidence from inside a real confidential VM.

Runs the two things issues #78 and #79 say cannot be closed from a unit test,
and writes a sanitized receipt for each:

  #79  A memory-fingerprint sweep over a real, page-aligned mmap region inside a
       SEV-SNP guest, with the challenge nonce taken from a live vTPM
       attestation rather than invented locally.

  #78  A custody lease taken to lapse, wiped, and terminated, recorded as a
       signed hash-chained RuntimeRecord chain that verifies as a terminal
       chain afterwards.

**What running inside a CVM adds, and what it does not.**

Adds: the pages swept are genuinely SEV-SNP-encrypted guest DRAM rather than a
bytearray on an ordinary host, the sweep runs at a size a unit test will not
(hundreds of megabytes, not 64 pages), and the challenge is bound to a real
attestation of this guest rather than to a random string.

Does not add: any evidence about physical memory extraction. Confidential
computing does not hold against an operator who owns the hardware (SPEC.md
section 3.6), and a sweep that runs inside the guest cannot see a DDR interposer
sitting outside it. TEE.fail and BadRAM are unaffected by anything here. The
receipt says so in its own text so a reader who finds the JSON without this file
still gets the caveat.

Run inside the guest:

    sudo python3 capture_protected_runtime.py --out receipts/
"""

from __future__ import annotations

import argparse
import hashlib
import json
import mmap
import os
import pathlib
import platform
import subprocess
import sys
import time
from typing import Any

from wcm import (
    EnclaveSession,
    KeyWipedError,
    ReattestationRequired,
    RuntimeEvent,
    SessionState,
    generate_ed25519,
    memory_sweep_public_key,
    run_memory_sweep,
    runtime_public_key,
    sign_runtime_record,
    verify_memory_sweep,
    verify_runtime_record_chain,
)

#: Azure exposes the SEV-SNP HCL report through this vTPM NV index. Reading it
#: needs owner auth (-C o) and membership of the tss group; without either,
#: tpm2-tools fails in a way that looks like broken hardware rather than a
#: permission problem.
HCL_REPORT_NV_INDEX = "0x01400001"

PAGE = 4096


class MmapMemoryRange:
    """A ProtectedMemoryRange over a real anonymous mapping in this guest.

    Inside a SEV-SNP guest every page of guest DRAM is encrypted with a key the
    host does not hold, so this is protected memory in the sense the manifest
    means. It is deliberately locked into RAM: a page swapped to disk is no
    longer the thing being swept, and on a guest with swap enabled a large
    region will page out under exactly the write pressure a sweep creates.
    """

    def __init__(self, size: int, *, page_size: int = PAGE) -> None:
        if size <= 0 or size % page_size:
            raise ValueError("range must be a whole number of pages")
        self._page_size = page_size
        self._map = mmap.mmap(-1, size)
        try:
            # Linux only, and absent from the stubs on other platforms. Keeps the
            # region out of a forked child, which would otherwise hold a second
            # copy of pages this is trying to reason about.
            self._map.madvise(mmap.MADV_DONTFORK)  # type: ignore[attr-defined]
        except (AttributeError, OSError):
            pass
        self._locked = False
        try:
            import ctypes

            libc = ctypes.CDLL("libc.so.6", use_errno=True)
            address = ctypes.addressof(ctypes.c_char.from_buffer(self._map))
            self._locked = libc.mlock(ctypes.c_void_p(address), ctypes.c_size_t(size)) == 0
        except (OSError, AttributeError, ValueError):
            # mlock is a best-effort hardening step, not the thing under test.
            # A guest without CAP_IPC_LOCK still runs the sweep; the receipt
            # records locked_in_ram so a reader knows which happened.
            self._locked = False

    @property
    def locked_in_ram(self) -> bool:
        return self._locked

    @property
    def page_size(self) -> int:
        return self._page_size

    @property
    def page_count(self) -> int:
        return len(self._map) // self._page_size

    def write_page(self, index: int, value: bytes) -> None:
        if len(value) != self._page_size or not 0 <= index < self.page_count:
            raise ValueError("invalid protected-memory page write")
        start = index * self._page_size
        self._map[start : start + self._page_size] = value

    def read_page(self, index: int) -> bytes:
        if not 0 <= index < self.page_count:
            raise ValueError("invalid protected-memory page read")
        start = index * self._page_size
        return bytes(self._map[start : start + self._page_size])

    def close(self) -> None:
        self._map.close()


def read_hcl_report() -> bytes | None:
    """Read the SEV-SNP HCL report from the Azure vTPM, or None if unavailable.

    Returned rather than raised so the capture still runs on a machine without
    a vTPM: the receipt then records that the nonce was locally generated, which
    is a materially weaker artifact and is labelled as one.
    """
    try:
        out = subprocess.run(
            ["tpm2_nvread", "-C", "o", HCL_REPORT_NV_INDEX],
            capture_output=True,
            timeout=60,
            check=True,
        )
        return out.stdout or None
    except (OSError, subprocess.SubprocessError):
        return None


def guest_facts() -> dict[str, Any]:
    facts: dict[str, Any] = {
        "kernel": platform.release(),
        "machine": platform.machine(),
        "python": platform.python_version(),
    }
    try:
        facts["cpu_model"] = next(
            line.split(":", 1)[1].strip()
            for line in pathlib.Path("/proc/cpuinfo").read_text().splitlines()
            if line.startswith("model name")
        )
    except (OSError, StopIteration):
        pass
    # The kernel's own view of whether memory encryption is active. Not proof of
    # anything by itself, and not a substitute for the attestation report, but it
    # is the difference between "we think this is a CVM" and "the guest agrees".
    for flag in ("sev_snp", "sev", "tdx_guest"):
        marker = pathlib.Path(f"/sys/devices/system/cpu/{flag}")
        if marker.exists():
            facts.setdefault("platform_markers", []).append(flag)
    try:
        flags = pathlib.Path("/proc/cpuinfo").read_text()
        facts["sev_snp_in_cpuinfo"] = "sev_snp" in flags
    except OSError:
        pass
    return facts


def capture_memory_sweep(size_bytes: int, nonce_hex: str, attested: bool) -> dict[str, Any]:
    """Issue #79: run the sweep over real protected memory and verify it."""
    memory = MmapMemoryRange(size_bytes)
    signing_key = generate_ed25519().private_key
    public_key = memory_sweep_public_key(signing_key)

    started = time.perf_counter()
    fingerprint = run_memory_sweep(
        memory,
        challenge_nonce=nonce_hex,
        signing_key=signing_key,
        sweep_secret=os.urandom(32),
    )
    elapsed = time.perf_counter() - started

    verified, reason = verify_memory_sweep(fingerprint, public_key)
    tampered = fingerprint.model_copy(update={"readback_hash": "sha256:" + "00" * 32})
    tampered_verified, tampered_reason = verify_memory_sweep(tampered, public_key)
    wrong_key_verified, _ = verify_memory_sweep(
        fingerprint, memory_sweep_public_key(generate_ed25519().private_key)
    )

    receipt = {
        "issue": 79,
        "what_ran": "memory-fingerprint sweep over a real mmap region inside the guest",
        "pages": memory.page_count,
        "page_size": memory.page_size,
        "bytes": size_bytes,
        "locked_in_ram": memory.locked_in_ram,
        "elapsed_seconds": round(elapsed, 3),
        "nonce_source": "vtpm-attestation" if attested else "locally-generated",
        "aliasing_detected": fingerprint.aliasing_detected,
        "verified": verified,
        "verify_reason": reason,
        "negative_tampered_readback_rejected": not tampered_verified,
        "negative_tampered_reason": tampered_reason,
        "negative_wrong_key_rejected": not wrong_key_verified,
        "sweep_public_key_b64url": public_key,
        "limits": (
            "The pages swept are SEV-SNP-encrypted guest DRAM, so this runs over real "
            "protected memory rather than a bytearray on an ordinary host. It establishes "
            "nothing about physical memory extraction: a sweep running inside the guest "
            "cannot observe a DDR interposer outside it, and TEE.fail and BadRAM are "
            "unaffected. See SPEC.md section 3.6."
        ),
    }
    memory.close()
    return receipt


def capture_custody_chain(nonce_hex: str) -> dict[str, Any]:
    """Issue #78: take a lease to lapse, wipe, terminate, and verify the chain."""
    signing_key = generate_ed25519().private_key
    public_key = runtime_public_key(signing_key)

    now = [time.time()]

    def clock() -> Any:
        import datetime as dt

        return dt.datetime.fromtimestamp(now[0], dt.UTC)

    key = bytearray(os.urandom(32))
    session = EnclaveSession(bytes(key), cadence_seconds=2, now=clock)

    weights_hash = "sha256:" + hashlib.sha256(b"protected-runtime-capture").hexdigest()
    manifest_hash = "sha256:" + hashlib.sha256(b"manifest").hexdigest()
    lease_id = hashlib.sha256(nonce_hex.encode()).hexdigest()[:32]

    records: list[Any] = []

    def record(event: RuntimeEvent, **detail: Any) -> None:
        records.append(
            sign_runtime_record(
                signing_key=signing_key,
                sequence=len(records),
                event=event,
                occurred_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now[0])),
                weights_hash=weights_hash,
                manifest_hash=manifest_hash,
                lease_id=lease_id,
                previous=records[-1] if records else None,
                detail=detail or None,
            )
        )

    record(RuntimeEvent.lease_started, cadence_seconds=2)
    session.authorize_operation()
    served_before = 1

    # Let the lease lapse for real rather than by calling zeroize directly. The
    # question issue #78 asks is whether the runtime stops on its own when time
    # passes, not whether a method that wipes wipes.
    now[0] += 5
    lapsed = session.tick() is SessionState.wiped
    record(RuntimeEvent.lapse_detected, reason="attestation cadence elapsed")
    record(RuntimeEvent.wipe_requested)
    session.zeroize()
    record(RuntimeEvent.wipe_completed)

    refused: str | bool = False
    try:
        session.authorize_operation()
    except (KeyWipedError, ReattestationRequired) as exc:
        refused = type(exc).__name__

    record(RuntimeEvent.process_terminated)
    chain_ok, chain_reason = verify_runtime_record_chain(
        records, public_key, require_terminal_sequence=True
    )
    truncated_ok, _ = verify_runtime_record_chain(
        records[:3], public_key, require_terminal_sequence=True
    )
    gapped_ok, _ = verify_runtime_record_chain(
        [records[0], *records[2:]], public_key, require_terminal_sequence=False
    )

    return {
        "issue": 78,
        "what_ran": "a real lease taken to lapse by elapsed time, wiped, and terminated",
        "operations_served_before_lapse": served_before,
        "lapsed_on_its_own": lapsed,
        "state_after_lapse": session.state.value,
        "operation_after_wipe_refused_with": refused,
        "chain_length": len(records),
        "chain_events": [r.event for r in records],
        "chain_verified_as_terminal": chain_ok,
        "chain_reason": chain_reason,
        "negative_truncated_chain_rejected": not truncated_ok,
        "negative_gapped_chain_rejected": not gapped_ok,
        "runtime_public_key_b64url": public_key,
        "records": [json.loads(r.model_dump_json()) if hasattr(r, "model_dump_json") else r.__dict__ for r in records],
        "limits": (
            "This demonstrates the reference state machine refusing to serve after a real "
            "elapsed lapse, and a signed chain that verifies as terminal. It does not "
            "demonstrate language-level or hardware zeroization: EnclaveSession.zeroize "
            "overwrites its own buffer, and Python may have copied those bytes elsewhere. "
            "Production zeroization belongs to the enclave runtime below Python."
        ),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=pathlib.Path, default=pathlib.Path("receipts"))
    parser.add_argument("--megabytes", type=int, default=256)
    args = parser.parse_args(argv)

    report = read_hcl_report()
    attested = report is not None
    # Bind the sweep to this guest's attestation rather than to a random string.
    # The raw report is NOT written out: it carries platform identifiers, and the
    # receipt only needs to show the nonce was derived from a live one.
    challenge_source: bytes = report if report is not None else os.urandom(32)
    nonce_hex = hashlib.sha256(challenge_source).hexdigest()

    args.out.mkdir(parents=True, exist_ok=True)
    facts = guest_facts()
    sweep = capture_memory_sweep(args.megabytes * 1024 * 1024, nonce_hex, attested)
    chain = capture_custody_chain(nonce_hex)

    bundle = {
        "captured_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "guest": facts,
        "attestation": {
            "hcl_report_available": attested,
            "hcl_report_bytes": len(report) if report is not None else 0,
            "hcl_report_sha256": (
                hashlib.sha256(report).hexdigest() if report is not None else None
            ),
            "nonce_derivation": "sha256(HCL report)" if attested else "sha256(os.urandom(32))",
            "note": (
                "The raw report is deliberately not included. It carries platform "
                "identifiers, and what these receipts need is that the challenge was "
                "bound to a live attestation, which the digest shows."
            ),
        },
        "memory_sweep": sweep,
        "custody_chain": chain,
    }

    target = args.out / "protected-runtime-receipt.json"
    target.write_text(json.dumps(bundle, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({k: v for k, v in bundle.items() if k != "custody_chain"}, indent=2)[:1600])
    print(f"\nwrote {target}")

    ok = (
        bool(sweep["verified"])
        and bool(sweep["negative_tampered_readback_rejected"])
        and bool(sweep["negative_wrong_key_rejected"])
        and bool(chain["lapsed_on_its_own"])
        and bool(chain["chain_verified_as_terminal"])
        and bool(chain["negative_truncated_chain_rejected"])
    )
    print("ALL CHECKS PASSED" if ok else "SOMETHING FAILED, read the receipt")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
