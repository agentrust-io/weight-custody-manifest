"""A receipt-gated controller against a fake Kubernetes API.

The planner is stateless and accepts an old admission after revocation. This
harness adds a prototype controller that keeps a durable, monotonic lifecycle
ledger per hosting session and applies the planner's manifests to a fake
Kubernetes API served by a separate process. Every controller action runs in a
new process, so each step is also a controller restart.

Hypothesis: with an intact ledger, every revoked session stays unroutable (no
Service object) through duplicate admission, revocation arriving before
admission, controller restart with replay of the old admission, out-of-band
selector changes, a partially failed apply, and reconciliation. Controls: the
same matrix with the ledger check removed (planner only), with a
non-persistent ledger, and with revocation required to chain directly to the
admission (the first prototype's rule, which refuses a revocation issued after
served requests) must fail. Restoring a ledger snapshot is recorded as the
expected rollback limit.

Usage: [RGS_BACKEND=reference|pinned] python controller_experiment.py run SCRATCH
       [durable|stateless|memory-ledger|admission-predecessor]
Subcommands api and controller are internal. See backend.py for the two backends.
"""
from __future__ import annotations

import copy
import hashlib
import http.server
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request

sys.path.insert(0, str(Path(__file__).resolve().parent))
import backend as b  # noqa: E402

HERE = Path(__file__).resolve()
NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)
TERMINAL_STATES = {"revoked", "failed", "stopped", "expired"}


# ------------------------------------------------------------- fake API
def api(port_file: str) -> None:
    """Minimal namespaced Pod/Service API: create, get, replace, delete, list, faults."""
    objects: dict[str, dict] = {}
    faults: dict[str, int] = {}
    version = [0]
    lock = threading.Lock()

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            return

        def _send(self, code, obj=None):
            data = json.dumps(obj or {}).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _body(self):
            n = int(self.headers.get("Content-Length") or 0)
            return json.loads(self.rfile.read(n)) if n else None

        def do_GET(self):
            with lock:
                if self.path.endswith("/services") or self.path.endswith("/pods"):
                    kind = self.path.rsplit("/", 1)[1]
                    items = [o for k, o in objects.items() if k.split("|")[1] == kind]
                    return self._send(200, {"items": items})
                obj = objects.get(self._key())
            return self._send(200, obj) if obj else self._send(404, {"reason": "NotFound"})

        def _key(self):
            parts = self.path.strip("/").split("/")  # api/v1/namespaces/ns/kind[/name]
            return "|".join([parts[3], parts[4], parts[5] if len(parts) > 5 else ""])

        def do_POST(self):
            if self.path == "/_faults":
                faults.update(self._body())
                return self._send(200)
            body = self._body()
            with lock:
                ns, kind = self.path.strip("/").split("/")[3:5]
                if faults.get("fail_create_" + kind, 0) > 0:
                    faults["fail_create_" + kind] -= 1
                    return self._send(500, {"reason": "InternalError"})
                key = f"{ns}|{kind}|{body['metadata']['name']}"
                if key in objects:
                    return self._send(409, {"reason": "AlreadyExists"})
                version[0] += 1
                body["metadata"]["resourceVersion"] = str(version[0])
                objects[key] = body
            return self._send(201, body)

        def do_PUT(self):
            body = self._body()
            with lock:
                key = self._key()
                if key not in objects:
                    return self._send(404, {"reason": "NotFound"})
                version[0] += 1
                body["metadata"]["resourceVersion"] = str(version[0])
                objects[key] = body
            return self._send(200, body)

        def do_DELETE(self):
            with lock:
                obj = objects.pop(self._key(), None)
            return self._send(200 if obj else 404, obj or {"reason": "NotFound"})

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    Path(port_file).write_text(str(server.server_address[1]), encoding="utf-8")
    server.serve_forever()


def call(base, method, path, body=None):
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(base + path, data=data, method=method,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


# ----------------------------------------------------------- controller
class Controller:
    """Prototype: planner checks plus a durable, monotonic per-session ledger."""

    def __init__(self, base, ledger, planners, variant="durable"):
        self.base, self.planners, self.variant = base, planners, variant
        self.db = sqlite3.connect(":memory:" if variant == "memory-ledger" else ledger)
        self.db.execute("CREATE TABLE IF NOT EXISTS sessions (session_id TEXT PRIMARY KEY, "
                        "state TEXT NOT NULL, admission_hash TEXT, revocation_hash TEXT, admission TEXT)")
        self.db.commit()

    def _state(self, sid):
        row = self.db.execute("SELECT state, admission_hash FROM sessions WHERE session_id=?", (sid,)).fetchone()
        return row if row else (None, None)

    def _path(self, planner, kind, name=""):
        return f"/api/v1/namespaces/{planner.config.namespace}/{kind}" + (f"/{name}" if name else "")

    def admit(self, raw: bytes, after_verify=None):
        receipt_hash = b.receipt_hash
        receipt = json.loads(raw)  # snapshot: the controller never re-reads caller objects
        planner = self.planners[receipt.get("session_id")]
        service = planner.service_manifest(receipt)  # signature, pinned key, bindings
        if after_verify:
            after_verify()
        sid = planner.grant.session_id
        if self.variant != "stateless":
            with self.db:
                self.db.execute("BEGIN IMMEDIATE")
                state, _ = self._state(sid)
                if state == "revoked":
                    return {"applied": False, "reason": "session revoked"}
                self.db.execute("INSERT OR IGNORE INTO sessions VALUES (?, 'admitted', ?, NULL, ?)",
                                (sid, receipt_hash(receipt), raw.decode("utf-8")))
        return self._apply(planner, service)

    def _apply(self, planner, service):
        pod = planner.workload_manifest()
        code, _ = call(self.base, "POST", self._path(planner, "pods"), pod)
        if code not in (201, 409):
            return {"applied": False, "reason": f"pod create {code}"}
        code, _ = call(self.base, "POST", self._path(planner, "services"), service)
        if code == 409:
            existing = call(self.base, "GET", self._path(planner, "services", planner.config.name))[1]
            if existing.get("spec") != service["spec"] or existing["metadata"].get("annotations") != \
                    service["metadata"]["annotations"]:
                service = copy.deepcopy(service)
                code, _ = call(self.base, "PUT", self._path(planner, "services", planner.config.name), service)
                return {"applied": code == 200, "reason": "replaced drifted service"}
            return {"applied": True, "reason": "already present"}
        return {"applied": code == 201, "reason": f"service create {code}"}

    def revoke(self, raw: bytes):
        receipt_hash, verify_hosting_receipt = b.receipt_hash, b.verify_receipt
        rev = json.loads(raw)
        planner = self.planners[rev.get("session_id")]
        sid = planner.grant.session_id
        state, adm_hash = self._state(sid)
        if self.variant == "admission-predecessor" and adm_hash is not None:
            # September 27 prototype: the revocation must chain directly to the admission.
            target = planner.service_delete_target(rev, expected_previous_hash=adm_hash)
        else:
            # Removing routing can only deny, so any authentic terminal record for this session is
            # enough. Chain continuity is kept for audit, not required here: served requests extend
            # the chain, so a revocation rarely follows the admission directly.
            ok, failures = verify_hosting_receipt(rev, expected_public_key_b64url=b.planner_key(planner),
                                                  expected_session_id=sid)
            terminal = rev.get("event") == "lifecycle" and rev.get("decision") == "deny" and                 rev.get("state") in TERMINAL_STATES
            if not ok or not terminal:
                raise ValueError("revocation refused: " + "; ".join(failures or ["not a terminal record"]))
            target = {"metadata": {"name": planner.config.name}}
        if self.variant != "stateless":
            with self.db:  # tombstone first, then remove routing
                self.db.execute("INSERT INTO sessions VALUES (?, 'revoked', NULL, ?, NULL) ON CONFLICT(session_id) "
                                "DO UPDATE SET state='revoked', revocation_hash=excluded.revocation_hash",
                                (sid, receipt_hash(rev)))
        code, _ = call(self.base, "DELETE", self._path(planner, "services", target["metadata"]["name"]))
        return {"deleted": code in (200, 404)}

    def reconcile(self):
        actions = []
        if self.variant == "stateless":
            return actions
        for sid, planner in self.planners.items():
            state, _ = self._state(sid)
            path = self._path(planner, "services", planner.config.name)
            code, live = call(self.base, "GET", path)
            if state == "revoked" and code == 200:
                call(self.base, "DELETE", path)
                actions.append(("deleted", planner.config.name))
            elif state == "admitted":
                # Rebuild only from the admission recorded in the ledger, never from live objects.
                recorded = json.loads(self.db.execute("SELECT admission FROM sessions WHERE session_id=?",
                                                      (sid,)).fetchone()[0])
                expected = planner.service_manifest(recorded)  # re-verified on every repair
                if code != 200 or live["metadata"].get("annotations") != expected["metadata"]["annotations"]                         or live["spec"] != expected["spec"]:
                    if code == 200:
                        call(self.base, "DELETE", path)
                    actions.append(("repaired", planner.config.name, self._apply(planner, expected)))
        return actions


def build_planners(spec_file):
    planners = {}
    for s in json.loads(Path(spec_file).read_text(encoding="utf-8")):
        grant = b.HostingGrant(**s["grant"])
        planners[grant.session_id] = b.make_planner(grant, s["name"], s["key"])
    return planners


def controller_main(base, ledger, spec_file, variant, action, receipt_file) -> None:
    c = Controller(base, ledger, build_planners(spec_file), variant)
    try:
        if action == "admit":
            out = c.admit(Path(receipt_file).read_bytes())
        elif action == "revoke":
            out = c.revoke(Path(receipt_file).read_bytes())
        else:
            out = {"actions": c.reconcile()}
    except Exception as exc:
        out = {"error": str(exc)[:200]}
    print(json.dumps(out))


# ---------------------------------------------------------------- parent
def run(scratch: Path, variant: str = "durable") -> dict:
    RevocationReason, receipt_hash = b.RevocationReason, b.receipt_hash
    scratch.mkdir(parents=True, exist_ok=True)

    class Session:
        def __init__(self):
            self.grant, self.host, _ = b.new_session()

    sessions = [{"session": Session(), "name": f"model-host-{i}"} for i in range(7)]
    spec_file = scratch / "grants.json"
    spec_file.write_text(json.dumps([{"grant": s["session"].grant.bindings(), "name": s["name"],
                                      "key": s["session"].host.public_key_b64url} for s in sessions]),
                         encoding="utf-8")
    port_file = scratch / "api.port"
    api_proc = subprocess.Popen([sys.executable, "-B", str(HERE), "api", str(port_file)], creationflags=NO_WINDOW)
    try:
        while not (port_file.exists() and port_file.read_text()):
            time.sleep(0.05)
        base = "http://127.0.0.1:" + port_file.read_text()
        ledger = scratch / "ledger.sqlite"

        def ctl(action, receipt_file="-"):
            out = subprocess.run([sys.executable, "-B", str(HERE), "controller", base, str(ledger), str(spec_file),
                                  variant, action, str(receipt_file)], capture_output=True, text=True, timeout=120,
                                 creationflags=NO_WINDOW)
            return json.loads(out.stdout) if out.stdout.strip() else {"error": out.stderr[-300:]}

        def save(name, receipt):
            p = scratch / name
            p.write_text(json.dumps(receipt), encoding="utf-8")
            return p

        def service(i):
            code, obj = call(base, "GET", f"/api/v1/namespaces/model-hosting/services/{sessions[i]['name']}")
            return obj if code == 200 else None

        def pod(i):
            return call(base, "GET", f"/api/v1/namespaces/model-hosting/pods/{sessions[i]['name']}")[0] == 200

        cases = []

        def case(name, ok, **obs):
            cases.append({"case": name, **obs, "ok": bool(ok)})

        # Session 0: admit, duplicate admit, revoke, restart + replay old admission.
        h0 = sessions[0]["session"].host
        adm0 = h0.start(sessions[0]["session"].grant.bindings())
        a0 = save("admission-model-host-0.json", adm0)
        r1 = ctl("admit", a0)
        s = service(0)
        case("admission creates Pod and Service bound to the receipt", r1.get("applied") and s and pod(0)
             and s["metadata"]["annotations"][b.ADMISSION_ANNOTATION] == receipt_hash(adm0),
             controller=r1)
        rv = s["metadata"]["resourceVersion"] if s else None
        r2 = ctl("admit", a0)
        s = service(0)
        case("duplicate admission is idempotent", r2.get("applied") and s and s["metadata"]["resourceVersion"] == rv,
             controller=r2)
        snap = scratch / "ledger-before-revocation.sqlite"
        if ledger.exists():
            shutil.copyfile(ledger, snap)  # real snapshot, used only for the rollback limit
        rev0 = save("revocation-0.json", h0.revoke(RevocationReason.policy))
        r3 = ctl("revoke", rev0)
        case("revocation removes the Service", r3.get("deleted") and service(0) is None,
             pod_still_present=pod(0), controller=r3)
        r4 = ctl("admit", a0)  # new process: restart, then replay of the old admission
        case("restart then replay of the old admission stays unroutable", service(0) is None, controller=r4)

        # Session 1: revocation observed before the admission is processed.
        f1 = sessions[1]["session"]
        adm1 = f1.host.start(f1.grant.bindings())
        rev1 = f1.host.revoke(RevocationReason.emergency)
        r5 = ctl("revoke", save("revocation-1.json", rev1))
        r6 = ctl("admit", save("admission-model-host-1.json", adm1))
        case("revocation before admission processing: never routable", service(1) is None,
             controller=[r5, r6])

        # Session 2: out-of-band selector change, then reconcile.
        f2 = sessions[2]["session"]
        a2 = save("admission-model-host-2.json", f2.host.start(f2.grant.bindings()))
        ctl("admit", a2)
        s = service(2)
        drifted = copy.deepcopy(s)
        drifted["spec"]["selector"] = {"app.kubernetes.io/name": "attacker-pod"}
        call(base, "PUT", "/api/v1/namespaces/model-hosting/services/model-host-2", drifted)
        r7 = ctl("reconcile")
        s = service(2)
        case("altered selector is detected and restored by reconcile",
             s and s["spec"]["selector"].get("app.kubernetes.io/name") == "model-host-2", controller=r7)

        # Out-of-band Service for revoked session 0; reconcile must delete it.
        planners = build_planners(spec_file)
        p0 = planners[sessions[0]["session"].grant.session_id]
        call(base, "POST", "/api/v1/namespaces/model-hosting/services", p0.service_manifest(adm0))
        r8 = ctl("reconcile")
        case("out-of-band Service for a revoked session is deleted by reconcile", service(0) is None, controller=r8)

        # Session 3: partial apply failure, then reconcile.
        f3 = sessions[3]["session"]
        a3 = save("admission-model-host-3.json", f3.host.start(f3.grant.bindings()))
        call(base, "POST", "/_faults", {"fail_create_services": 1})
        r9 = ctl("admit", a3)
        mid = {"pod": pod(3), "service": service(3) is not None}
        r10 = ctl("reconcile")
        case("partial apply failure leaves no Service; reconcile completes it",
             not r9.get("applied") and mid == {"pod": True, "service": False} and service(3) is not None,
             after_failure=mid, controller=[r9, r10])

        # Session 4: partial failure, revocation arrives, then reconcile: never routable.
        f4 = sessions[4]["session"]
        adm4 = f4.host.start(f4.grant.bindings())
        a4 = save("admission-model-host-4.json", adm4)
        call(base, "POST", "/_faults", {"fail_create_services": 1})
        ctl("admit", a4)
        r11 = ctl("revoke", save("revocation-4.json", f4.host.revoke(RevocationReason.attestation_key)))
        r12 = ctl("reconcile")
        r13 = ctl("admit", a4)
        case("partial failure then revocation: reconcile and replay never route", service(4) is None,
             controller=[r11, r12, r13])

        # Session 5: receipt object replaced between verification and apply (in process).
        f5 = sessions[5]["session"]
        adm5 = f5.host.start(f5.grant.bindings())
        raw5 = json.dumps(adm5).encode()
        caller_object = json.loads(raw5)
        other = json.loads(json.dumps(adm0))
        c = Controller(base, str(ledger), build_planners(spec_file), variant)
        out = c.admit(raw5, after_verify=lambda: caller_object.update(other))
        s = service(5)
        case("receipt replaced after verification does not change the applied Service",
             out.get("applied") and s and s["metadata"]["annotations"][b.ADMISSION_ANNOTATION]
             == receipt_hash(adm5), controller=out)
        c.db.close()

        # Session 6: requests were served, so the revocation does not chain to the admission.
        f6 = sessions[6]["session"]
        a6 = save("admission-model-host-6.json", f6.host.start(f6.grant.bindings()))
        ctl("admit", a6)
        served = b.serve_once(f6.host, f6.grant)
        r14 = ctl("revoke", save("revocation-6.json", f6.host.revoke(RevocationReason.policy)))
        case("revocation after served requests removes the Service", service(6) is None,
             served_receipt_sequence=served["sequence"], controller=r14)

        # Final sweep after one more restart: every revoked session is unroutable.
        ctl("reconcile")
        revoked = [0, 1, 4, 6]
        sweep = {sessions[i]["name"]: service(i) is None for i in revoked}
        case("final sweep: all revoked sessions have no Service", all(sweep.values()), sweep=sweep)

        passed = sum(c["ok"] for c in cases)
        result = {"experiment": "receipt-gated-controller-fake-api", "backend": b.NAME, "variant": variant, "cases": cases,
                  "cases_passed": passed, "cases_total": len(cases), "criterion_met": passed == len(cases),
                  "observation_pods_remain_after_revocation": {sessions[i]["name"]: pod(i) for i in revoked}}
        if variant == "durable":
            # Rollback limit: restore a ledger copy taken before any revocation, then replay.
            shutil.copyfile(snap, ledger)
            ctl("admit", a0)
            result["rollback_limit_restored_ledger_replay_routes_again"] = service(0) is not None
        return result
    finally:
        api_proc.kill()
        api_proc.wait(10)


if __name__ == "__main__":
    cmd = sys.argv[1]
    if cmd == "api":
        api(*sys.argv[2:])
    elif cmd == "controller":
        controller_main(*sys.argv[2:])
    else:
        variant = sys.argv[3] if len(sys.argv) > 3 else "durable"
        result = run(Path(sys.argv[2]), variant)
        print(json.dumps(result, indent=2))
        raise SystemExit(0 if result["criterion_met"] else 1)
