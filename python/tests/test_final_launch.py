import importlib.util
import json
from pathlib import Path


MODULE = Path(__file__).parents[1] / "tools" / "final_launch.py"
SPEC = importlib.util.spec_from_file_location("final_launch", MODULE)
assert SPEC and SPEC.loader
final_launch = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(final_launch)


def test_validate_pack_accepts_sanitized_json(tmp_path: Path) -> None:
    (tmp_path / "receipt.json").write_text(
        json.dumps({"hardware_claim": False, "classification": "OPAQUE internal"}),
        encoding="utf-8",
    )
    result = final_launch.validate_pack(tmp_path)
    assert len(result) == 1 and result[0]["passed"]


def test_validate_pack_rejects_private_key(tmp_path: Path) -> None:
    (tmp_path / "bad.pem").write_text(
        "-----BEGIN PRIVATE KEY-----\nnot-real\n-----END PRIVATE KEY-----", encoding="utf-8"
    )
    assert not final_launch.validate_pack(tmp_path)[0]["passed"]


def test_validate_pack_rejects_invalid_json(tmp_path: Path) -> None:
    (tmp_path / "bad.json").write_text("{", encoding="utf-8")
    assert not final_launch.validate_pack(tmp_path)[0]["passed"]
