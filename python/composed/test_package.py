"""Bundle corruption and ambiguous source identities must fail before fetching."""
import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location("reproduce", Path(__file__).with_name("reproduce.py"))
reproduce = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reproduce)


@pytest.fixture
def bundle(tmp_path):
    files = {"reproduce.py": b"launcher", "requirements.txt": b"pytest==8.0.0", "README.md": b"limits"}
    manifest = {
        "format": "wcm-composed-source-bundle-v1",
        "sources": {name: "a" * 40 for name in reproduce.REPOSITORIES},
        "files": {name: hashlib.sha256(data).hexdigest() for name, data in files.items()},
    }
    for name, data in files.items():
        (tmp_path / name).write_bytes(data)
    (tmp_path / "bundle.json").write_text(json.dumps(manifest), encoding="utf-8")
    return tmp_path, manifest


def test_bundle_identity_and_files(bundle):
    root, expected = bundle
    assert reproduce.validate_bundle(root) == expected


@pytest.mark.parametrize("name", ["reproduce.py", "requirements.txt", "README.md"])
def test_modified_bundle_file_is_refused(bundle, name):
    root, _ = bundle
    (root / name).write_bytes(b"changed")
    with pytest.raises(ValueError, match="digest mismatch"):
        reproduce.validate_bundle(root)


@pytest.mark.parametrize("revision", ["main", "a" * 39, "--upload-pack=other"])
def test_mutable_or_invalid_source_is_refused(bundle, revision):
    root, manifest = bundle
    manifest["sources"]["cmcp"] = revision
    (root / "bundle.json").write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(ValueError, match="immutable Git revision"):
        reproduce.validate_bundle(root)


def test_extra_file_path_is_refused(bundle):
    root, manifest = bundle
    manifest["files"]["../outside"] = "a" * 64
    (root / "bundle.json").write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(ValueError, match="unexpected bundle files"):
        reproduce.validate_bundle(root)
