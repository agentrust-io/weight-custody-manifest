from __future__ import annotations

import json
import shutil
from pathlib import Path

from wcm.cli import main
from tests.conftest import EXAMPLES


def _keygen(capsys) -> dict:
    assert main(["keygen"]) == 0
    return json.loads(capsys.readouterr().out)


def test_keygen(capsys):
    k = _keygen(capsys)
    assert set(k) == {"key_id", "public_key_b64url", "private_key_b64url"}
    assert len(k["key_id"]) == 64


def test_sign_then_verify_roundtrip(tmp_path: Path, capsys):
    manifest = tmp_path / "m.json"
    shutil.copy(EXAMPLES / "manifest.example.json", manifest)

    builder = _keygen(capsys)
    custodian = _keygen(capsys)

    signed = tmp_path / "signed.json"
    assert (
        main(
            [
                "sign",
                str(manifest),
                "--role",
                "builder",
                "--signer",
                "example-builder",
                "--key",
                builder["private_key_b64url"],
                "--out",
                str(signed),
            ]
        )
        == 0
    )
    assert (
        main(
            [
                "sign",
                str(signed),
                "--role",
                "custodian",
                "--signer",
                "opaque-systems",
                "--key",
                custodian["private_key_b64url"],
                "--out",
                str(signed),
            ]
        )
        == 0
    )

    capsys.readouterr()  # drain
    rc = main(
        [
            "verify",
            str(signed),
            "--key",
            builder["public_key_b64url"],
            "--key",
            custodian["public_key_b64url"],
        ]
    )
    report = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert report["ok"] is True


def test_verify_fails_missing_role(tmp_path: Path, capsys):
    manifest = tmp_path / "m.json"
    shutil.copy(EXAMPLES / "manifest.example.json", manifest)
    builder = _keygen(capsys)

    signed = tmp_path / "signed.json"
    main(
        [
            "sign",
            str(manifest),
            "--role",
            "builder",
            "--signer",
            "example-builder",
            "--key",
            builder["private_key_b64url"],
            "--out",
            str(signed),
        ]
    )
    capsys.readouterr()
    rc = main(["verify", str(signed), "--key", builder["public_key_b64url"]])
    report = json.loads(capsys.readouterr().out)
    assert rc == 1
    assert report["ok"] is False
    assert "custodian" in report["missing_roles"]
