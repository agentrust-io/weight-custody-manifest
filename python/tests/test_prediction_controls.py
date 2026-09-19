"""A predictor that ignores changed inputs must fail the control oracle."""
import importlib.util
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "boot" / "prediction_controls.py"
spec = importlib.util.spec_from_file_location("prediction_controls", SCRIPT)
controls = importlib.util.module_from_spec(spec)
spec.loader.exec_module(controls)


@pytest.mark.parametrize("case", ["firmware", "kernel", "initrd", "command-line",
                                  "vcpus", "vcpu-type", "guest-features"])
def test_ignored_input_fails_even_when_receipt_changes(case):
    baseline = {"expected_measurement_hex": "12" * 48}
    with pytest.raises(AssertionError, match="ignored"):
        controls.require_difference(baseline, {**baseline, "artifacts": {case: "changed"}}, case)
    controls.require_difference(baseline, {"expected_measurement_hex": "34" * 48}, case)
