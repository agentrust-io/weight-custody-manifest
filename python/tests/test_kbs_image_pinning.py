"""Offline checks on the KBS image's pinning.

The reproducibility guarantee is only tested end-to-end in CI, which needs Docker.
What can be checked cheaply and offline is that the pieces still agree with each
other, which is where this drifts in practice: bumping the interpreter in the
Dockerfile without bumping it in the lock generator leaves the locks resolved for
the wrong Python, and the CI failure that follows points at Docker rather than at
the real cause.

Deliberately no network here. ``tools/gen_kbs_lock.py --check`` talks to PyPI and
belongs in a maintainer's hands, not in the unit suite.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import gen_kbs_lock  # noqa: E402

DOCKER_DIR = Path(__file__).resolve().parents[1] / "docker"
DOCKERFILE = (DOCKER_DIR / "Dockerfile").read_text(encoding="utf-8")
LOCKS = ("requirements.lock", "requirements-build.lock")


def _arg(name: str) -> str:
    match = re.search(rf"^ARG {name}=(.+)$", DOCKERFILE, re.MULTILINE)
    assert match, f"Dockerfile has no ARG {name}"
    return match.group(1).strip()


@pytest.mark.parametrize("lock", LOCKS)
def test_lock_exists_and_is_fully_hashed(lock: str) -> None:
    """Every requirement carries at least one hash, or --require-hashes fails."""
    text = (DOCKER_DIR / lock).read_text(encoding="utf-8")
    requirements = re.findall(r"^([A-Za-z0-9._-]+)==", text, re.MULTILINE)
    assert requirements, f"{lock} pins nothing"
    blocks = [b for b in text.split("\n\n") if "==" in b]
    assert len(blocks) == len(requirements)
    for block in blocks:
        name = block.split("==")[0].strip().splitlines()[-1]
        assert "--hash=sha256:" in block, f"{lock}: {name} has no hash"


@pytest.mark.parametrize("lock", LOCKS)
def test_lock_has_no_unpinned_or_ranged_requirement(lock: str) -> None:
    text = (DOCKER_DIR / lock).read_text(encoding="utf-8")
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", "--hash")):
            continue
        assert "==" in stripped, f"{lock}: not an exact pin: {stripped}"
        for operator in (">=", "<=", "~=", ">", "<"):
            head = stripped.split(";")[0]
            assert operator not in head, f"{lock}: range in {stripped}"


def test_base_image_is_pinned_by_digest() -> None:
    digest = _arg("BASE_DIGEST")
    assert re.fullmatch(r"sha256:[0-9a-f]{64}", digest), digest
    # Both stages must use the digest, not the bare tag.
    from_lines = re.findall(r"^FROM (.+)$", DOCKERFILE, re.MULTILINE)
    assert from_lines, "no FROM lines"
    for line in from_lines:
        assert "@${BASE_DIGEST}" in line, f"FROM without the digest pin: {line}"


def test_interpreter_version_agrees_across_the_build() -> None:
    """The Dockerfile base, the site-packages path, and the lock generator.

    Three places name the interpreter version, and they have to match or the locks
    are resolved for a Python the image does not run.
    """
    version = gen_kbs_lock.PYTHON_VERSION
    assert f"python:{version}-slim" in _arg("BASE_IMAGE")
    assert f"/python{version}/" in _arg("SITE_PACKAGES")


def test_source_date_epoch_is_fixed_and_used_for_normalization() -> None:
    epoch = _arg("SOURCE_DATE_EPOCH")
    assert epoch.isdigit(), epoch
    # The normalization step is the reason the build is reproducible at all; if it
    # is dropped, the CI layer-parity check fails with no hint as to why.
    assert "-newermt" in DOCKERFILE and "touch" in DOCKERFILE


def _instructions() -> list[str]:
    """Dockerfile lines with comments stripped, so prose cannot satisfy a test."""
    return [
        line for line in DOCKERFILE.splitlines() if line.strip() and not line.lstrip().startswith("#")
    ]


def test_every_pip_install_is_hash_checked_or_local() -> None:
    installs = [line for line in _instructions() if "pip install" in line]
    assert len(installs) == 3, installs  # build lock, runtime lock, the wheel
    hash_checked = [line for line in installs if "--require-hashes" in line]
    assert len(hash_checked) == 2, (
        "both the builder and the runtime stage must install from a lock with "
        f"--require-hashes; got {installs}"
    )
    # Installing the wheel with resolution enabled would reintroduce an unpinned
    # fetch and undo the point of the locks.
    wheel_install = next(line for line in installs if ".whl" in line)
    assert "--no-deps" in wheel_install and "--no-index" in wheel_install


def test_every_pip_install_disables_byte_compilation() -> None:
    """pip's compile pass is the subtlest way to lose reproducibility.

    A .pyc embeds the source mtime, so normalizing mtimes afterwards leaves
    bytecode holding the old value: the sources look reproducible and the image is
    not. PYTHONDONTWRITEBYTECODE does not help, since it governs the interpreter
    rather than pip.
    """
    for line in _instructions():
        if "pip install" in line:
            assert "--no-compile" in line, line


def test_lock_roots_come_from_pyproject_not_a_restatement() -> None:
    """Guards against the bug this had: bare package names in the generator.

    Listing the packages in the tool let the lock resolve a version pyproject
    declares incompatible (cryptography 50 against a <50 bound). Nothing caught
    it, because the runtime stage installs the wheel with --no-deps.
    """
    source = (Path(gen_kbs_lock.__file__)).read_text(encoding="utf-8")
    assert "tomllib" in source
    assert "optional-dependencies" in source
    roots = gen_kbs_lock.runtime_roots()
    assert any(root.startswith("cryptography") and "<" in root for root in roots), roots
    assert gen_kbs_lock.build_roots() == ("hatchling",)


def test_locked_versions_satisfy_the_project_constraints() -> None:
    """The pins actually inside the declared bounds, not merely sourced from them."""
    bounds: dict[str, tuple[int, ...]] = {}
    for root in gen_kbs_lock.runtime_roots():
        match = re.match(r"^([A-Za-z0-9._-]+)[^<]*<([0-9.]+)", root)
        if match:
            name = re.sub(r"[-_.]+", "-", match.group(1)).lower()
            bounds[name] = tuple(int(p) for p in match.group(2).split("."))
    assert bounds, "expected at least one upper-bounded dependency to check"

    text = (DOCKER_DIR / "requirements.lock").read_text(encoding="utf-8")
    pinned = dict(re.findall(r"^([A-Za-z0-9._-]+)==([0-9][^ \\\n;]*)", text, re.MULTILINE))
    for name, upper in bounds.items():
        assert name in pinned, f"{name} is declared but not in the lock"
        version = tuple(int(p) for p in re.findall(r"\d+", pinned[name])[: len(upper)])
        assert version < upper, f"{name}=={pinned[name]} violates the <{'.'.join(map(str, upper))} bound"


def test_reproducibility_check_is_wired_into_ci() -> None:
    script = DOCKER_DIR / "verify-reproducible.sh"
    assert script.is_file()
    body = script.read_text(encoding="utf-8")
    # --no-cache on the second build is the whole point: a cached rebuild would
    # pass trivially.
    assert "--no-cache" in body
    assert "sha256sum" in body
    workflow = (
        Path(__file__).resolve().parents[2] / ".github" / "workflows" / "kbs-image.yml"
    ).read_text(encoding="utf-8")
    assert "verify-reproducible.sh" in workflow


def test_runtime_stage_does_not_carry_build_tooling() -> None:
    """hatchling is installed in the builder stage only."""
    builder, _, runtime = DOCKERFILE.partition("# Runtime:")
    assert "requirements-build.lock" in builder
    assert "requirements-build.lock" not in runtime
    assert "hatchling" not in runtime
