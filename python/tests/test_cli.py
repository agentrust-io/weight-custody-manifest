from __future__ import annotations

import json
import shutil
from pathlib import Path

from wcm.cli import main
from tests.conftest import EXAMPLES


def _keygen_files(tmp_path: Path, name: str) -> tuple[str, str]:
    """Generate a key pair to files; return (private_path, public_path)."""
    prefix = str(tmp_path / name)
    assert main(["keygen", "--out", prefix]) == 0
    return prefix, prefix + ".pub"


def test_keygen_stdout_json(capsys):
    assert main(["keygen"]) == 0
    k = json.loads(capsys.readouterr().out)
    assert set(k) == {"key_id", "public_key_b64url", "private_key_b64url"}
    assert len(k["key_id"]) == 64


def test_keygen_writes_files(tmp_path: Path):
    priv, pub = _keygen_files(tmp_path, "b")
    assert Path(priv).exists() and Path(pub).exists()
    # Files hold a single stripped base64url token.
    assert "\n" not in Path(priv).read_text().strip()


def test_sign_then_verify_roundtrip(tmp_path: Path, capsys):
    manifest = tmp_path / "m.json"
    shutil.copy(EXAMPLES / "manifest.example.json", manifest)

    b_priv, b_pub = _keygen_files(tmp_path, "builder")
    c_priv, c_pub = _keygen_files(tmp_path, "custodian")

    signed = tmp_path / "signed.json"
    assert (
        main(
            ["sign", str(manifest), "--role", "builder", "--signer", "example-builder",
             "--key-file", b_priv, "--out", str(signed)]
        )
        == 0
    )
    assert (
        main(
            ["sign", str(signed), "--role", "custodian", "--signer", "example-custodian",
             "--key-file", c_priv, "--out", str(signed)]
        )
        == 0
    )

    capsys.readouterr()  # drain
    rc = main(["verify", str(signed), "--key-file", b_pub, "--key-file", c_pub])
    report = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert report["ok"] is True


def test_verify_fails_missing_role(tmp_path: Path, capsys):
    manifest = tmp_path / "m.json"
    shutil.copy(EXAMPLES / "manifest.example.json", manifest)
    b_priv, b_pub = _keygen_files(tmp_path, "builder")

    signed = tmp_path / "signed.json"
    main(
        ["sign", str(manifest), "--role", "builder", "--signer", "example-builder",
         "--key-file", b_priv, "--out", str(signed)]
    )
    capsys.readouterr()
    rc = main(["verify", str(signed), "--key-file", b_pub])
    report = json.loads(capsys.readouterr().out)
    assert rc == 1
    assert report["ok"] is False
    assert "custodian" in report["missing_roles"]


def test_sign_missing_manifest_reports_one_line_error(tmp_path: Path, capsys):
    missing = tmp_path / "missing.json"
    rc = main(
        ["sign", str(missing), "--role", "builder", "--signer", "builder",
         "--key-file", str(tmp_path / "unused-key")]
    )
    output = capsys.readouterr()
    assert rc == 1
    assert output.out == ""
    assert output.err.startswith(f"error: {missing}: ")
    assert output.err.count("\n") == 1
    assert "Traceback" not in output.err


def test_sign_missing_key_reports_one_line_error(tmp_path: Path, capsys):
    manifest = tmp_path / "manifest.json"
    shutil.copy(EXAMPLES / "manifest.example.json", manifest)
    missing = tmp_path / "missing-key"
    rc = main(
        ["sign", str(manifest), "--role", "builder", "--signer", "builder",
         "--key-file", str(missing)]
    )
    output = capsys.readouterr()
    assert rc == 1
    assert output.out == ""
    assert output.err.startswith(f"error: {missing}: ")
    assert output.err.count("\n") == 1
    assert "Traceback" not in output.err


def test_verify_missing_key_reports_one_line_error(tmp_path: Path, capsys):
    manifest = tmp_path / "manifest.json"
    shutil.copy(EXAMPLES / "manifest.example.json", manifest)
    missing = tmp_path / "missing-key.pub"
    rc = main(["verify", str(manifest), "--key-file", str(missing)])
    output = capsys.readouterr()
    assert rc == 1
    assert output.out == ""
    assert output.err.startswith(f"error: {missing}: ")
    assert output.err.count("\n") == 1
    assert "Traceback" not in output.err


def test_verify_invalid_json_reports_one_line_error(tmp_path: Path, capsys):
    manifest = tmp_path / "bad.json"
    manifest.write_text("{bad", encoding="utf-8")
    rc = main(["verify", str(manifest), "--key-file", str(tmp_path / "unused-key")])
    output = capsys.readouterr()
    assert rc == 1
    assert output.out == ""
    assert output.err.startswith(f"error: {manifest}: ")
    assert output.err.count("\n") == 1
    assert "Traceback" not in output.err


def test_cli_rejects_duplicate_json_keys_in_manifest(tmp_path: Path, capsys):
    import pytest
    from wcm.cli import _read_json
    from wcm.provisioning_wire import json_object

    raw = (EXAMPLES / "manifest.example.json").read_text(encoding="utf-8").strip()
    dup = tmp_path / "dup.json"
    dup.write_text(raw[:-1] + ', "manifest_version": "0.1"}', encoding="utf-8")
    rc = main(["inspect", str(dup)])
    output = capsys.readouterr()
    assert rc == 1
    assert "duplicate JSON object key" in output.err

    for idx, bad in enumerate(('{"a": 1, "a": 2}', '{"a": NaN}', '{"a": Infinity}', '{"a": -Infinity}', '{"a": 1e400}', '{"a": -1e400}')):
        p = tmp_path / f"bad_{idx}.json"
        p.write_text(bad, encoding="utf-8")
        assert main(["inspect", str(p)]) == 1
        capsys.readouterr()
        with pytest.raises(Exception):
            _read_json(str(p))
        with pytest.raises(ValueError):
            json_object(bad)
