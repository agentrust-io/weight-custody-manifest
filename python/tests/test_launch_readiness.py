import importlib.util
import json
from pathlib import Path


MODULE = Path(__file__).parents[1] / "tools" / "launch_readiness.py"
SPEC = importlib.util.spec_from_file_location("launch_readiness", MODULE)
assert SPEC and SPEC.loader
launch_readiness = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(launch_readiness)


def test_test_sets_cover_release_and_refusal_invariants() -> None:
    assert any("channel_binding_required_seals" in test for test in launch_readiness.HAPPY_TESTS)
    assert any("verify_provenance_round_trip" in test for test in launch_readiness.HAPPY_TESTS)
    assert any("test_kbs.py" == test.rsplit("/", 1)[-1] for test in launch_readiness.NEGATIVE_TESTS)
    assert any("tampered_model" in test for test in launch_readiness.NEGATIVE_TESTS)
    assert any("wrong_nonce" in test for test in launch_readiness.NEGATIVE_TESTS)


def test_write_reports_marks_software_boundary(tmp_path: Path) -> None:
    result = {
        "kind": "wcm-launch-readiness/v1",
        "mode": "happy",
        "hardware_claim": False,
        "release_candidate": "abc123",
        "started_at": "2026-08-12T00:00:00+00:00",
        "finished_at": "2026-08-12T00:00:01+00:00",
        "command": ["python", "-m", "pytest"],
        "tests": ["example"],
        "passed": True,
        "exit_code": 0,
        "stdout": "1 passed",
        "stderr": "",
    }
    launch_readiness.write_reports(result, tmp_path)
    receipt = json.loads((tmp_path / "happy.json").read_text(encoding="utf-8"))
    assert receipt["hardware_claim"] is False
    assert receipt["record_sha256"]
    assert "Hardware claim: `false`" in (tmp_path / "happy.md").read_text(encoding="utf-8")
