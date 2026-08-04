#!/usr/bin/env python3
"""Regenerate the hash-locked requirement files for the reference KBS image.

Writes ``docker/requirements.lock`` (runtime) and
``docker/requirements-build.lock`` (builder stage). Both are installed with
``pip --require-hashes``, so an unpinned or substituted artifact fails the image
build instead of silently changing the image measurement, which is the whole
point: a measurement you cannot reproduce cannot be pinned in a manifest's
``custody.kbs_image.measurement``.

Two things make this work from any machine, including a Windows one:

- **Resolution targets Linux, not the host.** ``pip download`` runs with explicit
  ``--platform``/``--python-version`` for the image's interpreter, so the version
  set is the one the image will actually get.
- **Every distribution of a pinned version is hashed, not just the one file this
  machine would pick.** ``--require-hashes`` accepts multiple hashes per
  requirement and matches whichever file pip selects, so the lock is not tied to
  one wheel tag.

Environment markers are the one thing ``pip download`` gets wrong here: it
evaluates them against the *host*, so a Windows host resolves ``colorama`` in and
``uvloop`` out, which is backwards for a Linux image. Rather than trust that,
``EXTRA_RUNTIME`` and ``EXCLUDE`` state the corrections explicitly and
``MARKERS`` carries the marker into the lock, where pip evaluates it on the
target.

Usage (from ``python/``):

    python tools/gen_kbs_lock.py
    python tools/gen_kbs_lock.py --check    # exit 1 if a lock is stale
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
DOCKER_DIR = HERE.parent / "docker"

#: The image's interpreter. Must match the base image in docker/Dockerfile.
PYTHON_VERSION = "3.12"

#: Several tags, because projects target different manylinux baselines and a
#: single tag makes resolution fail on whichever one does not match.
PLATFORMS = (
    "manylinux2014_x86_64",
    "manylinux_2_17_x86_64",
    "manylinux_2_28_x86_64",
    "manylinux_2_34_x86_64",
)

#: What the runtime stage installs: the server extra's dependency closure.
RUNTIME_ROOTS = ("pydantic", "cryptography", "fastapi", "uvicorn[standard]")

#: What the builder stage needs to build the wheel with --no-build-isolation.
BUILD_ROOTS = ("hatchling",)

#: Resolved separately because a non-Linux host evaluates their markers away.
EXTRA_RUNTIME = ("uvloop",)

#: Pulled in by a host-only marker; not wanted in a Linux image.
EXCLUDE = frozenset({"colorama"})

#: Markers carried into the lock, so pip evaluates them on the target platform.
MARKERS = {
    "uvloop": "sys_platform != 'win32' and platform_python_implementation != 'PyPy'",
}


def _canonical(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _resolve(roots: tuple[str, ...]) -> dict[str, str]:
    """Resolve *roots* for the image's platform; return {canonical_name: version}."""
    platform_args: list[str] = []
    for tag in PLATFORMS:
        platform_args += ["--platform", tag]
    with tempfile.TemporaryDirectory() as tmp:
        subprocess.run(
            [
                sys.executable, "-m", "pip", "download", "--quiet", "--dest", tmp,
                *platform_args,
                "--python-version", PYTHON_VERSION,
                "--implementation", "cp",
                "--only-binary=:all:",
                *roots,
            ],
            check=True,
        )
        resolved: dict[str, str] = {}
        for path in sorted(Path(tmp).iterdir()):
            name, version = path.name.split("-")[0], path.name.split("-")[1]
            resolved[_canonical(name)] = version
    return resolved


def _hashes(name: str, version: str) -> list[str]:
    """Every sha256 PyPI publishes for this exact version."""
    url = f"https://pypi.org/pypi/{name}/{version}/json"
    with urllib.request.urlopen(url, timeout=30) as response:  # noqa: S310
        data = json.load(response)
    digests = sorted({f["digests"]["sha256"] for f in data["urls"]})
    if not digests:
        raise SystemExit(f"PyPI lists no files for {name}=={version}")
    return digests


def _render(pins: dict[str, str], title: str, note: list[str]) -> str:
    lines = [f"# {title}", "#"]
    lines += [f"# {line}" for line in note]
    lines += ["#", "# Regenerate with tools/gen_kbs_lock.py. Do not hand-edit.", ""]
    for name in sorted(pins):
        requirement = f"{name}=={pins[name]}"
        marker = MARKERS.get(name)
        if marker:
            requirement += f" ; {marker}"
        digests = _hashes(name, pins[name])
        lines.append(f"{requirement} \\")
        for index, digest in enumerate(digests):
            trailer = "" if index == len(digests) - 1 else " \\"
            lines.append(f"    --hash=sha256:{digest}{trailer}")
        lines.append("")
    return "\n".join(lines)


def build_locks() -> dict[Path, str]:
    runtime = _resolve(RUNTIME_ROOTS)
    runtime.update(_resolve(EXTRA_RUNTIME))
    for name in EXCLUDE:
        runtime.pop(name, None)

    return {
        DOCKER_DIR / "requirements.lock": _render(
            runtime,
            "Hash-locked RUNTIME dependencies for the reference KBS image.",
            [
                "Every distribution pip may select for a pinned version is listed, so the",
                "set is platform-independent: pip matches whichever file it picks. Installed",
                "with --require-hashes, so an unpinned or substituted artifact fails the",
                "build rather than silently changing the image measurement.",
            ],
        ),
        DOCKER_DIR / "requirements-build.lock": _render(
            _resolve(BUILD_ROOTS),
            "Hash-locked BUILD dependencies for the reference KBS image.",
            [
                "Only used in the builder stage, to build the wcm wheel with",
                "--no-build-isolation. Keeping these hash-locked closes the last unpinned",
                "network fetch in the build; keeping them out of the runtime stage keeps",
                "build tooling off the KBS's attack surface.",
            ],
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check", action="store_true", help="do not write; exit 1 if a lock is stale"
    )
    args = parser.parse_args()

    stale = []
    for path, rendered in build_locks().items():
        if args.check:
            current = path.read_text(encoding="utf-8") if path.exists() else ""
            if current != rendered:
                stale.append(path)
            continue
        path.write_text(rendered, encoding="utf-8")
        print(f"wrote {path}")

    if args.check:
        if stale:
            names = ", ".join(str(p) for p in stale)
            print(f"stale: {names}; run 'python tools/gen_kbs_lock.py'", file=sys.stderr)
            return 1
        print("locks are up to date")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
