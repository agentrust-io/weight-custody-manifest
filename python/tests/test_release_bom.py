import importlib.util
import json
from pathlib import Path

import pytest


MODULE = Path(__file__).parents[1] / "tools" / "release_bom.py"
SPEC = importlib.util.spec_from_file_location("release_bom", MODULE)
assert SPEC and SPEC.loader
release_bom = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release_bom)


def _metadata(version="0.25.0"):
    return {
        "info": {"version": version, "requires_dist": ["pydantic<3,>=2.7"]},
        "urls": [{
            "filename": "package.whl", "packagetype": "bdist_wheel", "size": 12,
            "digests": {"sha256": "a" * 64}, "url": "https://files.example/package.whl",
            "upload_time_iso_8601": "2026-08-12T00:00:00Z",
        }],
    }


def test_build_bom_binds_release_inputs(tmp_path: Path, monkeypatch) -> None:
    (tmp_path / "python/docker").mkdir(parents=True)
    (tmp_path / "python/docker/Dockerfile").write_text(
        "ARG BASE_DIGEST=sha256:" + "b" * 64 + "\n", encoding="utf-8"
    )
    monkeypatch.setattr(release_bom, "_tag_commit", lambda *a, **k: "c" * 40)
    bom = release_bom.build_bom(_metadata(), tmp_path, "0.25.0")
    assert bom["specVersion"] == "1.6"
    assert bom["metadata"]["component"]["version"] == "0.25.0"
    assert "requirement:pydantic<3,>=2.7" in bom["dependencies"][0]["dependsOn"]


def test_build_bom_rejects_wrong_version(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="instead of"):
        release_bom.build_bom(_metadata("0.24.0"), tmp_path, "0.25.0")


def test_write_bom_emits_parseable_cyclonedx(tmp_path: Path, monkeypatch) -> None:
    root = tmp_path / "root"
    (root / "python/docker").mkdir(parents=True)
    (root / "python/docker/Dockerfile").write_text(
        "ARG BASE_DIGEST=sha256:" + "b" * 64 + "\n", encoding="utf-8"
    )
    monkeypatch.setattr(release_bom, "_tag_commit", lambda *a, **k: "c" * 40)
    bom = release_bom.build_bom(_metadata(), root, "0.25.0")
    output = tmp_path / "out"
    release_bom.write_bom(bom, output)
    assert json.loads((output / "release-bom.cdx.json").read_text())["bomFormat"] == "CycloneDX"
    assert "public release metadata" in (output / "README.md").read_text()
