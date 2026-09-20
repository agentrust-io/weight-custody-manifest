"""Bundle corruption and ambiguous source identities must fail before fetching."""

import hashlib
import importlib.metadata
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location(
    "reproduce", Path(__file__).with_name("reproduce.py")
)
reproduce = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reproduce)


@pytest.fixture
def bundle(tmp_path):
    files = {
        "reproduce.py": b"launcher",
        "requirements.txt": b"pytest==8.0.0",
        "README.md": b"limits",
        "LICENSE": b"license",
        "NOTICE": b"notice",
    }
    manifest = {
        "format": "wcm-composed-source-bundle-v1",
        "sources": {name: "a" * 40 for name in reproduce.REPOSITORIES},
        "files": {
            name: hashlib.sha256(data).hexdigest() for name, data in files.items()
        },
    }
    for name, data in files.items():
        (tmp_path / name).write_bytes(data)
    (tmp_path / "bundle.json").write_text(json.dumps(manifest), encoding="utf-8")
    return tmp_path, manifest


def test_bundle_identity_and_files(bundle):
    root, expected = bundle
    assert reproduce.validate_bundle(root) == expected


@pytest.mark.parametrize(
    "name", ["reproduce.py", "requirements.txt", "README.md", "LICENSE", "NOTICE"]
)
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


@pytest.fixture
def evaluated_checkout(tmp_path):
    root = tmp_path / "wcm"
    harness = root / "python/composed"
    harness.mkdir(parents=True)
    (root / ".gitignore").write_text("__pycache__/\n", encoding="utf-8")
    original = Path(__file__).parent
    for name in ("LICENSE", "NOTICE"):
        (root / name).write_bytes((original.parents[1] / name).read_bytes())
    for name in ["package.py", "reproduce.py", "run.py", "BUNDLE.md", "Dockerfile"]:
        (harness / name).write_bytes((original / name).read_bytes())
    for command in [
        ["git", "init", root],
        ["git", "-C", root, "add", "."],
        [
            "git",
            "-C",
            root,
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.com",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-m",
            "fixture",
        ],
    ]:
        subprocess.run(list(map(str, command)), check=True, capture_output=True)
    revision = subprocess.check_output(
        ["git", "-C", str(root), "rev-parse", "HEAD"], text=True
    ).strip()
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    manifest = {
        "exit_code": 0,
        "profile": "wcm-composed-software-v1",
        "sources": {
            "wcm": revision,
            "cmcp": "2cdb168ce52020406ff0ef6cbc34447f0ea55aee",
            "ca2a": "fc22c644846111c7f375446399e9097a73f93214",
            "confinement": "bad751becca0ec5c42d70062e5c9fe5ee1380e85",
        },
        "wcm_tracked_diff_sha256": hashlib.sha256(b"").hexdigest(),
        "harness_files": {
            p.name: hashlib.sha256(p.read_bytes()).hexdigest()
            for p in [*harness.glob("*.py"), harness / "Dockerfile"]
        },
        "dependencies": [
            {"name": d.metadata["Name"], "version": d.version}
            for d in importlib.metadata.distributions()
        ],
    }
    return root, evidence, manifest


def invoke_package(evaluated_checkout, output):
    root, evidence, manifest = evaluated_checkout
    (evidence / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    return subprocess.run(
        [
            sys.executable,
            str(root / "python/composed/package.py"),
            "--evidence",
            str(evidence),
            "--output",
            str(output),
        ],
        capture_output=True,
        text=True,
        check=False,
    )


def test_build_is_deterministic_and_validated(evaluated_checkout, tmp_path):
    import zipfile

    first, second = tmp_path / "first.zip", tmp_path / "second.zip"
    for output in [first, second]:
        result = invoke_package(evaluated_checkout, output)
        assert result.returncode == 0, result.stdout + result.stderr
    assert first.read_bytes() == second.read_bytes()
    with zipfile.ZipFile(first) as archive:
        archive.extractall(tmp_path / "extracted")
    manifest = reproduce.validate_bundle(tmp_path / "extracted")
    assert manifest["sources"] == evaluated_checkout[2]["sources"]


@pytest.mark.parametrize(
    "fault, message",
    [
        ("failed", "successful evidence"),
        ("revision", "successful evidence"),
        ("edited", "tracked WCM edits"),
        ("bytes", "current harness bytes"),
        ("native", "reviewed confined profile"),
        ("dependencies", "same dependency environment"),
    ],
)
def test_builder_refuses_unmatched_evidence(
    evaluated_checkout, tmp_path, fault, message
):
    manifest = evaluated_checkout[2]
    if fault == "failed":
        manifest["exit_code"] = 1
    elif fault == "revision":
        manifest["sources"]["wcm"] = "a" * 40
    elif fault == "edited":
        manifest["wcm_tracked_diff_sha256"] = "a" * 64
    elif fault == "bytes":
        manifest["harness_files"]["reproduce.py"] = "a" * 64
    elif fault == "native":
        del manifest["sources"]["confinement"]
    else:
        manifest["dependencies"] = []
    output = tmp_path / "refused.zip"
    result = invoke_package(evaluated_checkout, output)
    assert result.returncode != 0
    assert message in result.stderr
    assert not output.exists()
