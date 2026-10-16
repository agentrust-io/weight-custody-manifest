"""Broker receiver retirement and owner epoch recovery across processes.

Part A (retirement). Hypothesis: once a provisioned BrokerReceiver is retired,
every API path in its process refuses (report data, install, challenge,
release), and only a fresh receiver with fresh provisioning can serve again.
Separately, we measure whether the installed model key is still readable in
the retired process's memory. That second measurement is an observation about
the stated erasure limit, not a pass condition.

Part B (epoch recovery). Hypothesis: with one intact OwnerEpochStore shared by
separate owner processes, a stale live owner, a restarted stale owner and a
same-epoch substitution are refused, and a killed admission leaves the floor
unchanged. Restoring or deleting the store is recorded as the expected
rollback limit.

Usage: exp11_lifecycle.py run SCRATCH. Subcommands receiver/owner are internal.
"""
from __future__ import annotations

import base64
import ctypes
import gc
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

HERE = Path(__file__).resolve()
NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)  # no console window on Windows


def _b(x):
    return base64.b64encode(x).decode()


def _ub(x):
    return base64.b64decode(x)


# ------------------------------------------------------------ Part A child
def receiver_child(config_file: str) -> None:
    """Serve one BrokerReceiver over JSON lines on stdin/stdout."""
    from dataclasses import replace
    from datetime import datetime
    from wcm._challenge import Challenge
    from wcm.attestation import CompositeEvidence
    from wcm.broker_receiver import BrokerEffectiveConfiguration, BrokerReceiver
    from wcm.models import WeightCustodyManifest
    from wcm.provisioning import BrokerProvisioningPolicy, ProvisioningEnvelope
    cfg = json.loads(Path(config_file).read_text(encoding="utf-8"))
    config = BrokerEffectiveConfiguration(_ub(cfg["root"]), _ub(cfg["vcek"]), (),
                                          frozenset(cfg["identities"]), _ub(cfg["owner"]))
    p = cfg["policy"]
    policy = BrokerProvisioningPolicy(p["measurement_hex"], p["configuration_sha256"], p["weights_hash"],
                                      p["epoch"], guest_policy=p["guest_policy"],
                                      minimum_tcb_le_hex=p["minimum_tcb_le_hex"],
                                      required_platform_fields=frozenset(p["required"]),
                                      forbidden_platform_fields=frozenset(p["forbidden"]))
    receiver = BrokerReceiver(config, policy)
    manifest = WeightCustodyManifest.model_validate_json(cfg["manifest"])
    out = sys.stdout

    def reply(obj):
        out.write(json.dumps(obj) + "\n")
        out.flush()

    def challenge(obj):
        return Challenge(obj["nonce"], datetime.fromisoformat(obj["issued_at"]),
                         datetime.fromisoformat(obj["expires_at"]))

    def envelope(obj):
        return ProvisioningEnvelope(obj["nonce"], _ub(obj["ciphertext"]), _ub(obj["signature"]))

    for line in sys.stdin:
        cmd = json.loads(line)
        op = cmd["op"]
        try:
            if op == "public_key":
                reply({"ok": True, "value": receiver.transport_public_key, "pid": os.getpid()})
            elif op == "report_data":
                reply({"ok": True, "value": _b(receiver.provisioning_report_data(challenge(cmd["challenge"])))})
            elif op == "install":
                receiver.install(envelope(cmd["envelope"]))
                reply({"ok": True})
            elif op == "issue_challenge":
                c = receiver.issue_challenge()
                reply({"ok": True, "value": {"nonce": c.nonce, "issued_at": c.issued_at.isoformat(),
                                             "expires_at": c.expires_at.isoformat()}})
            elif op == "release":
                evidence = CompositeEvidence.model_validate_json(cmd["evidence"])
                d = receiver.verify_and_release(manifest, evidence)
                reply({"ok": True, "released": d.released,
                       "sealed": _b(d.sealed_key) if d.sealed_key else None})
            elif op == "retire":
                receiver.retire()
                gc.collect()
                reply({"ok": True})
            elif op == "exit":
                reply({"ok": True})
                return
        except Exception as exc:  # report the refusal class only
            reply({"ok": False, "error": type(exc).__name__})


def scan_process(pid: int, needle: bytes) -> int | None:
    """Count occurrences of needle in the committed readable memory of pid (Windows)."""
    if os.name != "nt":
        return None
    from ctypes import wintypes
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)

    class MBI(ctypes.Structure):
        _fields_ = [("BaseAddress", ctypes.c_void_p), ("AllocationBase", ctypes.c_void_p),
                    ("AllocationProtect", wintypes.DWORD), ("PartitionId", wintypes.WORD),
                    ("RegionSize", ctypes.c_size_t), ("State", wintypes.DWORD),
                    ("Protect", wintypes.DWORD), ("Type", wintypes.DWORD)]
    k32.OpenProcess.restype = wintypes.HANDLE
    k32.VirtualQueryEx.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.POINTER(MBI), ctypes.c_size_t]
    k32.ReadProcessMemory.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t,
                                      ctypes.POINTER(ctypes.c_size_t)]
    handle = k32.OpenProcess(0x0400 | 0x0010, False, pid)
    if not handle:
        return None
    readable = {0x02, 0x04, 0x20, 0x40}
    count, address, mbi = 0, 0, MBI()
    try:
        while k32.VirtualQueryEx(handle, ctypes.c_void_p(address), ctypes.byref(mbi), ctypes.sizeof(mbi)):
            size = mbi.RegionSize
            if mbi.State == 0x1000 and (mbi.Protect & 0xFF) in readable and not mbi.Protect & 0x100:
                buf = ctypes.create_string_buffer(size)
                got = ctypes.c_size_t()
                if k32.ReadProcessMemory(handle, ctypes.c_void_p(address), buf, size, ctypes.byref(got)):
                    count += buf.raw[:got.value].count(needle)
            address = (mbi.BaseAddress or 0) + size
            if address >= 1 << 47:
                break
    finally:
        k32.CloseHandle(handle)
    return count


def part_a(scratch: Path) -> dict:
    import hashlib
    from dataclasses import replace
    from datetime import datetime, timezone
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from wcm import SoftwareProvider, generate_transport_keypair, open_sealed
    from wcm._challenge import Challenge
    from wcm.broker_receiver import BrokerEffectiveConfiguration
    from wcm.models import WeightCustodyManifest
    from wcm.provisioning import OwnerProvisioner
    from wcm.renewal import manifest_identity
    from tests.test_broker_receiver import signed_report, WORKLOAD
    from tests.test_provisioning import POLICY
    from tests.test_snp import _vcek_chain

    model_key = os.urandom(32)  # unique needle for the memory measurement
    example = json.loads((Path("examples") / "manifest.example.json").read_text(encoding="utf-8"))
    manifest = WeightCustodyManifest.model_validate(example)
    manifest.release_policy.required_gpu_measurement = None
    manifest.release_policy.required_serving_image.accepted_measurements[0].measurement = (
        "sha256:" + hashlib.sha256(WORKLOAD).hexdigest())
    root, vcek, signing_key = _vcek_chain()
    owner_key = ed25519.Ed25519PrivateKey.generate()
    der = serialization.Encoding.DER
    config = BrokerEffectiveConfiguration(root.public_bytes(der), vcek.public_bytes(der), (),
                                          frozenset({manifest_identity(manifest)}),
                                          owner_key.public_key().public_bytes_raw())
    policy = replace(POLICY, configuration_sha256=config.digest(), weights_hash=manifest.weights_hash)
    owner = OwnerProvisioner(policy, owner_signing_key=owner_key, trusted_root=root)
    cfg = {"root": _b(root.public_bytes(der)), "vcek": _b(vcek.public_bytes(der)),
           "identities": [manifest_identity(manifest)], "owner": _b(owner_key.public_key().public_bytes_raw()),
           "manifest": manifest.model_dump_json(),
           "policy": {"measurement_hex": policy.measurement_hex, "configuration_sha256": policy.configuration_sha256,
                      "weights_hash": policy.weights_hash, "epoch": policy.epoch, "guest_policy": policy.guest_policy,
                      "minimum_tcb_le_hex": policy.minimum_tcb_le_hex,
                      "required": sorted(policy.required_platform_fields),
                      "forbidden": sorted(policy.forbidden_platform_fields)}}
    cfg_file = scratch / "receiver-config.json"
    cfg_file.write_text(json.dumps(cfg), encoding="utf-8")

    def spawn():
        p = subprocess.Popen([sys.executable, "-B", str(HERE), "receiver", str(cfg_file)], stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE, text=True, creationflags=NO_WINDOW)
        return p

    def call(p, **cmd):
        p.stdin.write(json.dumps(cmd) + "\n")
        p.stdin.flush()
        return json.loads(p.stdout.readline())

    def enc(ch):
        return {"nonce": ch.nonce, "issued_at": ch.issued_at.isoformat(), "expires_at": ch.expires_at.isoformat()}

    def provision(p):
        pub = call(p, op="public_key")["value"]
        ch = owner.issue_challenge()
        data = _ub(call(p, op="report_data", challenge=enc(ch))["value"])
        env = owner.provision(nonce=ch.nonce, report=signed_report(signing_key, data), vcek=vcek,
                              intermediates=[], transport_public_key=pub, model_key=model_key)
        e = {"nonce": env.nonce, "ciphertext": _b(env.ciphertext), "signature": _b(env.owner_signature)}
        return call(p, op="install", envelope=e), e, ch

    def release(p):
        c = call(p, op="issue_challenge")
        if not c["ok"]:
            return c
        v = c["value"]
        ch = Challenge(v["nonce"], datetime.fromisoformat(v["issued_at"]), datetime.fromisoformat(v["expires_at"]))
        private, public = generate_transport_keypair()
        expected = manifest.release_policy.required_serving_image.accepted_measurements[0].measurement
        evidence = SoftwareProvider().produce(ch, serving_image_measurement=expected, include_gpu=False,
                                              transport_public_key=public)
        rd = hashlib.sha256(bytes.fromhex(ch.nonce) + bytes.fromhex(public)).digest() + bytes(32)
        evidence.cpu.quote_b64 = _b(signed_report(signing_key, rd, WORKLOAD))
        r = call(p, op="release", evidence=evidence.model_dump_json())
        if r.get("sealed"):
            r["key_matches"] = open_sealed(_ub(r["sealed"]), private) == model_key
            del r["sealed"]
        return r

    first = spawn()
    try:
        pid = call(first, op="public_key")["pid"]
        installed, old_envelope, old_challenge = provision(first)
        served = release(first)
        mem_before = scan_process(pid, model_key)
        call(first, op="retire")
        time.sleep(0.2)
        mem_after = scan_process(pid, model_key)
        mem_control = scan_process(pid, os.urandom(32))  # never present: scanner negative control
        fresh_ch = owner.issue_challenge()
        probes = {
            "report_data_fresh_challenge": call(first, op="report_data", challenge=enc(fresh_ch)),
            "install_previous_envelope": call(first, op="install", envelope=old_envelope),
            "issue_challenge": call(first, op="issue_challenge"),
            "release": release(first),
        }
        call(first, op="exit")
    finally:
        if first.poll() is None:
            first.kill()
        first.wait(10)
    second = spawn()
    try:
        # A replacement process: the old envelope must not install; fresh provisioning must.
        call(second, op="report_data", challenge=enc(owner.issue_challenge()))
        old_in_new = call(second, op="install", envelope=old_envelope)
        second.kill(); second.wait(10)
        third = spawn()
        fresh_install, _, _ = provision(third)
        fresh_served = release(third)
        call(third, op="exit")
        third.wait(10)
    finally:
        for p in (second,):
            if p.poll() is None:
                p.kill()
    refused = {k: (not v["ok"]) for k, v in probes.items()}
    ok = (installed["ok"] and served.get("released") and served.get("key_matches")
          and all(refused.values()) and not old_in_new["ok"]
          and fresh_install["ok"] and fresh_served.get("released") and fresh_served.get("key_matches"))
    return {"installed": installed["ok"], "served_before_retirement": served,
            "after_retirement": {k: v.get("error", "accepted") if not v.get("ok") else "accepted"
                                 for k, v in probes.items()},
            "all_paths_refused_after_retirement": all(refused.values()),
            "old_envelope_in_replacement_process": old_in_new.get("error", "accepted"),
            "replacement_with_fresh_provisioning": {"installed": fresh_install["ok"], **fresh_served},
            "memory_scan": {"platform_supported": mem_before is not None,
                            "model_key_copies_before_retirement": mem_before,
                            "model_key_copies_after_retirement": mem_after,
                            "random_never_loaded_control_copies": mem_control,
                            "note": "observation only; retirement is an API state, not erasure"},
            "ok": bool(ok)}


# ------------------------------------------------------------ Part B child
def owner_child(db: str, epoch: str, variant: str, action: str, gate: str) -> None:
    """One owner process: construct with a floor store, then optionally provision."""
    from dataclasses import replace
    import wcm.provisioning as provisioning
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from wcm import generate_transport_keypair
    from wcm.provisioning import OwnerProvisioner
    from wcm.provisioning_state import OwnerEpochStore
    from tests.test_provisioning import POLICY, report_for
    from tests.test_snp import _vcek_chain
    from datetime import datetime, timezone
    policy = replace(POLICY, epoch=int(epoch), configuration_sha256=variant * 32)
    root, vcek, key = _vcek_chain()
    result = {}
    try:
        owner = OwnerProvisioner(policy, owner_signing_key=ed25519.Ed25519PrivateKey.generate(),
                                 trusted_root=root, epoch_store=OwnerEpochStore(db, "broker"),
                                 now=lambda: datetime(2026, 7, 20, 12, 0, 0, tzinfo=timezone.utc))
        result["constructed"] = True
    except Exception as exc:
        print(json.dumps({"constructed": False, "error": str(exc)}), flush=True)
        return
    print(json.dumps({"ready": True}), flush=True)
    if gate != "-":
        while not os.path.exists(gate):
            time.sleep(0.01)
    if action == "kill-during-admission":
        class Boom:
            def __init__(self, *a, **k):
                os._exit(73)
        provisioning.ChallengeStore = Boom  # dies inside update_policy's open floor transaction
        owner.update_policy(replace(policy, epoch=policy.epoch + 1))
    try:
        nonce = owner.issue_challenge().nonce
        _, public = generate_transport_keypair()
        owner.provision(nonce=nonce, report=report_for(key, nonce, public, policy), vcek=vcek,
                        intermediates=[], transport_public_key=public, model_key=b"k" * 32)
        result["provisioned"] = True
    except Exception as exc:
        result.update(provisioned=False, error=str(exc))
    print(json.dumps(result), flush=True)


def part_b(scratch: Path) -> dict:
    import sqlite3
    db = scratch / "owner-floor.sqlite"
    snapshot = scratch / "owner-floor-epoch1.sqlite"

    def owner(epoch, variant="aa", action="provision", gate="-", wait=True):
        p = subprocess.Popen([sys.executable, "-B", str(HERE), "owner", str(db), str(epoch), variant, action, gate],
                             stdout=subprocess.PIPE, text=True, creationflags=NO_WINDOW)
        if not wait:
            return p
        out, _ = p.communicate(timeout=120)
        lines = [json.loads(x) for x in out.splitlines() if x.strip()]
        return {**{k: v for line in lines for k, v in line.items() if k != "ready"}, "exit": p.returncode}

    def floor():
        c = sqlite3.connect(db)
        try:
            row = c.execute("SELECT epoch FROM policy_floor WHERE namespace='broker'").fetchone()
            return None if row is None else int(row[0])
        finally:
            c.close()

    steps = []

    def step(name, got, want_provisioned, extra=None):
        prov = bool(got.get("provisioned"))
        steps.append({"step": name, "constructed": got.get("constructed", False), "provisioned": prov,
                      "error": got.get("error"), "floor_after": floor(), "expected_provisioned": want_provisioned,
                      "ok": prov == want_provisioned and (extra is None or extra())})

    step("epoch-1 owner starts and provisions", owner(1), True)
    shutil.copyfile(db, snapshot)
    gate = scratch / "stale-go"
    stale = owner(1, gate=str(gate), wait=False)
    assert json.loads(stale.stdout.readline()).get("ready")
    step("epoch-2 owner admits a new policy", owner(2, "bb"), True)
    gate.write_text("go")
    out, _ = stale.communicate(timeout=120)
    got = json.loads(out.splitlines()[-1])
    got["constructed"] = True
    step("stale live epoch-1 owner provisions after the update", got, False)
    step("epoch-1 owner restarts", owner(1), False)
    step("same-epoch substitution (epoch 2, other configuration)", owner(2, "cc"), False)
    step("epoch-2 owner restarts with the admitted policy", owner(2, "bb"), True)
    killed = owner(2, "bb", action="kill-during-admission")
    steps.append({"step": "epoch-3 admission killed inside the floor transaction", "exit": killed["exit"],
                  "floor_after": floor(), "ok": killed["exit"] == 73 and floor() == 2})
    step("epoch-2 owner after the killed admission", owner(2, "bb"), True)
    step("epoch-3 owner admits normally", owner(3, "dd"), True)
    ok = all(s["ok"] for s in steps)
    # Rollback limit: restore the epoch-1 snapshot, then delete the store.
    shutil.copyfile(snapshot, db)
    for suffix in ("-wal", "-shm", "-journal"):
        Path(str(db) + suffix).unlink(missing_ok=True)
    restored = owner(1)
    db.unlink()
    deleted = owner(1)
    limits = {"restored_epoch1_snapshot_then_epoch1_owner_provisions": bool(restored.get("provisioned")),
              "deleted_store_then_epoch1_owner_provisions": bool(deleted.get("provisioned")),
              "note": "expected rollback limit of an unprotected store"}
    return {"steps": steps, "steps_passed": sum(s["ok"] for s in steps), "steps_total": len(steps),
            "rollback_limit_observations": limits, "ok": ok}


def run(scratch: Path) -> dict:
    scratch.mkdir(parents=True, exist_ok=True)
    a = part_a(scratch)
    b = part_b(scratch)
    passed = int(bool(a["ok"])) + b["steps_passed"]
    total = 1 + b["steps_total"]
    return {"experiment": "broker-retirement-and-epoch-recovery", "retirement": a, "epoch_recovery": b,
            "cases_passed": passed, "cases_total": total, "criterion_met": passed == total}


if __name__ == "__main__":
    cmd = sys.argv[1]
    if cmd == "receiver":
        receiver_child(*sys.argv[2:])
    elif cmd == "owner":
        owner_child(*sys.argv[2:])
    else:
        result = run(Path(sys.argv[2]))
        print(json.dumps(result, indent=2))
        raise SystemExit(0 if result["criterion_met"] else 1)
