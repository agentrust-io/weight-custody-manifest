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
            ["sign", str(signed), "--role", "custodian", "--signer", "opaque-systems",
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
