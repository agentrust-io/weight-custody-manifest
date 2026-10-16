"""Rerun every software experiment in the report and write a scrubbed record.

Targets:
  reference         reference/receipt_gate.py in this folder (always run; public)
  pinned-<sha>      the evaluated planner at a pinned commit, exported with
                    `git archive` from --evaluated-repo (optional; the evaluated
                    repository is private, so only its commit ids and counts are
                    recorded, never its source)

For each target: the unit tests, two control removals (admission check skipped,
restart policy changed to Always), the binding and lifecycle boundary
experiment, and the controller experiment with its two controls.

Usage (from this experiments folder):
  python rerun.py --output results/<new dir> [--evaluated-repo DIR --commit SHA ...]
No network access, no cluster, no package installation, no repository edits.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import xml.etree.ElementTree as ET

HERE = Path(__file__).resolve().parent
NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)
PINNED_MUTANTS = [
    ("control-admission-check-skipped", "level2/orchestrator.py",
     "failures = self._admission_failures(admission_receipt)", "failures = []"),
    ("control-restart-policy-always", "level2/orchestrator.py",
     '"restartPolicy": "Never"', '"restartPolicy": "Always"'),
]
REFERENCE_MUTANTS = [
    ("control-admission-check-skipped", "receipt_gate.py",
     "failures = self.admission_failures(admission_receipt)", "failures = []"),
    ("control-restart-policy-always", "receipt_gate.py",
     '"restartPolicy": "Never"', '"restartPolicy": "Always"'),
]


def run(cmd, cwd, env, timeout=900):
    begin = time.perf_counter()
    done = subprocess.run(cmd, cwd=cwd, env=env, capture_output=True, text=True, timeout=timeout,
                          creationflags=NO_WINDOW)
    return done, round(time.perf_counter() - begin, 1)


def junit(path: Path) -> dict:
    root = ET.parse(path).getroot()
    suites = root.findall(".//testsuite") or [root]
    out = {k: sum(int(s.attrib.get(k, "0")) for s in suites) for k in ("tests", "failures", "errors", "skipped")}
    out["failed_cases"] = sorted(c.attrib["name"] for c in root.iter("testcase") if c.find("failure") is not None)
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--output", type=Path, required=True)
    ap.add_argument("--evaluated-repo", type=Path)
    ap.add_argument("--commit", action="append", default=[])
    ap.add_argument("--private-logs", type=Path,
                    help="pytest logs and XML for evaluated commits quote evaluated test source, so they go "
                         "here and never into --output (omit to discard them)")
    a = ap.parse_args()
    out = a.output.resolve()
    if out.exists() and any(out.iterdir()):
        raise SystemExit("Use a new, empty output directory.")
    out.mkdir(parents=True, exist_ok=True)
    scratch = Path(tempfile.mkdtemp(prefix="rgs-rerun-"))
    base_env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1", "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1"}
    base_env.pop("PYTHONPATH", None)
    scrub_pairs = [(str(scratch), "<scratch>"), (str(HERE), "<experiments>"), (str(out), "<output>"),
                   (str(Path(sys.executable).parent), "<python>"), (str(Path.home()), "<home>")]
    if a.evaluated_repo:
        scrub_pairs.append((str(a.evaluated_repo.resolve()), "<evaluated-repo>"))

    def scrub(text: str) -> str:
        for real, label in sorted(scrub_pairs, key=lambda p: -len(p[0])):
            for form in {real, real.replace("\\", "/"), real.replace("\\", "\\\\")}:
                text = re.sub(re.escape(form), label, text, flags=re.IGNORECASE)
        return re.sub(r'hostname="[^"]*"', 'hostname="<host>"', text)

    def save(name: str, text: str, private: bool = False):
        if not private:
            (out / name).write_text(scrub(text), encoding="utf-8")
        elif a.private_logs:
            a.private_logs.mkdir(parents=True, exist_ok=True)
            (a.private_logs / name).write_text(scrub(text), encoding="utf-8")

    def pytest_run(label, cwd, env, selectors, private=False):
        xml = scratch / f"{label}.xml"
        cmd = [sys.executable, "-B", "-m", "pytest", "-p", "no:cacheprovider", "-p", "pytest_asyncio.plugin",
               "-q", "--tb=short", "--basetemp=" + str(scratch / (label + "-tmp")), "--junitxml=" + str(xml),
               *selectors]
        done, secs = run(cmd, cwd, env)
        save(f"{label}.log", done.stdout + "\nSTDERR\n" + done.stderr, private)
        summary = [ln for ln in done.stdout.splitlines() if re.match(r"^\d+ (passed|failed)", ln)]
        rec = {"label": label, "exit_code": done.returncode, "duration_seconds": secs,
               "command": "python -m pytest " + " ".join(selectors), "pytest_summary": summary[-1:]}
        if xml.exists():
            save(f"{label}.xml", xml.read_text(encoding="utf-8"), private)
            rec.update(junit(xml))
        print(json.dumps({k: rec.get(k) for k in ("label", "exit_code", "tests", "failures", "errors")}), flush=True)
        return rec

    def experiments(label, cwd, env):
        recs = []
        done, secs = run([sys.executable, "-B", str(HERE / "boundary_experiment.py")], cwd, env)
        save(f"{label}-boundary.json", done.stdout or done.stderr)
        recs.append({"label": f"{label}-boundary", "exit_code": done.returncode, "duration_seconds": secs,
                     "command": "python boundary_experiment.py"})
        for variant in ("durable", "stateless", "memory-ledger", "admission-predecessor"):
            done, secs = run([sys.executable, "-B", str(HERE / "controller_experiment.py"), "run",
                              str(scratch / f"{label}-{variant}"), variant], cwd, env)
            save(f"{label}-controller-{variant}.json", done.stdout or done.stderr)
            try:
                res = json.loads(done.stdout)
            except json.JSONDecodeError:
                res = {}
            recs.append({"label": f"{label}-controller-{variant}", "exit_code": done.returncode,
                         "duration_seconds": secs, "cases_passed": res.get("cases_passed"),
                         "cases_total": res.get("cases_total"), "criterion_met": res.get("criterion_met"),
                         "failed_cases": [c["case"] for c in res.get("cases", []) if not c["ok"]],
                         "rollback_limit_restored_ledger_replay_routes_again":
                             res.get("rollback_limit_restored_ledger_replay_routes_again"),
                         "command": f"python controller_experiment.py run <scratch> {variant}"})
            print(json.dumps({k: recs[-1][k] for k in ("label", "exit_code", "cases_passed")}), flush=True)
        return recs

    targets = []
    # Reference implementation.
    ref_env = {**base_env, "RGS_BACKEND": "reference"}
    t = {"target": "reference", "runs": []}
    t["runs"].append(pytest_run("reference-baseline", HERE / "reference", ref_env, ["test_receipt_gate.py"]))
    for name, file, old, new in REFERENCE_MUTANTS:
        root = scratch / f"reference-{name}"
        shutil.copytree(HERE / "reference", root)
        text = (root / file).read_text(encoding="utf-8")
        assert text.count(old) == 1, name
        (root / file).write_text(text.replace(old, new), encoding="utf-8")
        rec = pytest_run(f"reference-{name}", root, ref_env, ["test_receipt_gate.py"])
        rec["mutation"] = {"file": file, "old": old, "new": new}
        t["runs"].append(rec)
    t["runs"] += experiments("reference", HERE, ref_env)
    targets.append(t)

    # Evaluated planner at each pinned commit.
    for commit in a.commit:
        repo = a.evaluated_repo.resolve()
        full = subprocess.check_output(["git", "-C", str(repo), "rev-parse", commit], text=True,
                                       creationflags=NO_WINDOW).strip()
        label = "pinned-" + full[:7]
        root = scratch / label
        root.mkdir()
        data = subprocess.check_output(["git", "-c", f"safe.directory={repo.as_posix()}", "-C", str(repo),
                                        "archive", full], creationflags=NO_WINDOW)
        with tarfile.open(fileobj=io.BytesIO(data)) as archive:
            archive.extractall(root, filter="data")
        env = {**base_env, "RGS_BACKEND": "pinned", "PYTHONPATH": str(root)}
        t = {"target": label, "commit": full,
             "planner_sha256": hashlib.sha256((root / "level2/orchestrator.py").read_bytes()).hexdigest(),
             "model_host_sha256": hashlib.sha256((root / "level2/model_host.py").read_bytes()).hexdigest(),
             "runs": []}
        sel = ["tests/test_controls.py", "-k", "orchestration"]
        t["runs"].append(pytest_run(f"{label}-baseline", root, env, sel, private=True))
        for name, file, old, new in PINNED_MUTANTS:
            mroot = scratch / f"{label}-{name}"
            shutil.copytree(root, mroot)
            text = (mroot / file).read_text(encoding="utf-8")
            assert text.count(old) == 1, name
            (mroot / file).write_text(text.replace(old, new), encoding="utf-8")
            rec = pytest_run(f"{label}-{name}", mroot, {**env, "PYTHONPATH": str(mroot)}, sel, private=True)
            rec["mutation"] = {"file": file, "old": old, "new": new}
            t["runs"].append(rec)
        t["runs"] += experiments(label, root, env)
        targets.append(t)

    versions = subprocess.run([sys.executable, "-m", "pip", "freeze", "--all"], capture_output=True, text=True,
                              creationflags=NO_WINDOW).stdout.split()
    record = {
        "run": "receipt-gated-model-serving rerun", "finished_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "python": sys.version.split()[0], "platform": platform.platform(), "packages": versions,
        "software_only": True, "targets": targets,
        "harness_sha256": {p.relative_to(HERE).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                           for p in sorted(HERE.rglob("*.py"))},
    }
    save("rerun.json", json.dumps(record, indent=2))
    leftovers = [f.name for f in out.iterdir()
                 if re.search(r"[A-Za-z]:[\\/]+Users|/home/|Users[\\/]+\w+[\\/]", f.read_text(encoding="utf-8"))]
    sums = {f.name: hashlib.sha256(f.read_bytes()).hexdigest() for f in sorted(out.iterdir())}
    (out / "SHA256SUMS.json").write_text(json.dumps(sums, indent=2), encoding="utf-8")
    shutil.rmtree(scratch, ignore_errors=True)
    print(json.dumps({"path_leftovers": leftovers}), flush=True)
    raise SystemExit(1 if leftovers else 0)


if __name__ == "__main__":
    main()
