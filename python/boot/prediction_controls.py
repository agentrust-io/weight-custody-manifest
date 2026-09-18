"""Predict built launch artifacts and require sensitivity to each input.

Software evidence only: no report, firmware approval or custody claim is made.
Each prediction runs in a fresh isolated interpreter with the pinned tool.
"""
import argparse
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

PREDICTOR = Path(__file__).with_name("predict_measurement.py")


def require_difference(baseline, changed, case):
    if baseline["expected_measurement_hex"] == changed["expected_measurement_hex"]:
        raise AssertionError(f"prediction ignored {case} substitution")


def predict(options):
    command = [sys.executable, "-I", "-B", "-S", str(PREDICTOR)]
    for name, value in options.items():
        command += ["--" + name, str(value)]
    return json.loads(subprocess.check_output(command, text=True, timeout=120))


def run(args):
    args.output.mkdir(parents=True, exist_ok=False)
    # Snapshot once so every control changes exactly one baseline input.
    with tempfile.TemporaryDirectory(prefix="wcm-launch-controls-") as directory:
        root = Path(directory)
        options = {"tool-source": args.tool_source.resolve(), "vcpus": args.vcpus,
                   "vcpu-type": args.vcpu_type, "guest-features": args.guest_features}
        for role in ("firmware", "kernel", "initrd", "command-line"):
            path = root / role
            shutil.copyfile(getattr(args, role.replace("-", "_")), path)
            options[role] = path
        baseline = predict(options)
        repeated = predict(options)
        if baseline != repeated:
            raise AssertionError("same-input prediction did not repeat")
        (args.output / "prediction.json").write_text(json.dumps(baseline, indent=2) + "\n")
        observations = []
        changes = {"vcpus": args.changed_vcpus, "vcpu-type": args.changed_vcpu_type,
                   "guest-features": args.changed_guest_features}
        for case in ("firmware", "kernel", "initrd", "command-line", *changes):
            altered = dict(options)
            if case in changes:
                if changes[case] == options[case]:
                    raise ValueError(f"{case} control must differ from baseline")
                altered[case] = changes[case]
            else:
                data = bytearray(options[case].read_bytes())
                if case == "command-line":
                    data += b" wcm_prediction_control=1"
                else:
                    # Preserve sizes and firmware metadata at the image suffix.
                    data[0] ^= 1
                path = root / (case + "-changed")
                path.write_bytes(data)
                altered[case] = path
            result = predict(altered)
            require_difference(baseline, result, case)
            observations.append({"case": case, "prediction": result})
            print("PASS", case, flush=True)
        receipt = {"kind": "wcm/built-launch-prediction-controls/v1",
                   "hardware_validated": False, "firmware_enforcement_validated": False,
                   "application_identity_established": False,
                   "same_input_repeat": True, "baseline": baseline,
                   "substitutions": observations}
        (args.output / "controls.json").write_text(json.dumps(receipt, indent=2) + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("tool-source", "firmware", "kernel", "initrd", "command-line", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("vcpus", "changed-vcpus"):
        parser.add_argument("--" + name, type=int, required=True)
    for name in ("vcpu-type", "guest-features", "changed-vcpu-type", "changed-guest-features"):
        parser.add_argument("--" + name, required=True)
    run(parser.parse_args())
