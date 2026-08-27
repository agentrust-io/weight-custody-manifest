"""Deterministic content digest for a model artifact on disk.

A manifest binds ``weights_hash``, and something has to compute it. That
computation is not in ``SPEC.md``: the specification takes the digest as given
and says nothing about how a directory of shards, indexes and tokenizer assets
collapses into one value. Every consumer therefore invented it, and by
2026-08-27 the same construction existed in three places (the examples
repository's open-model walkthrough and two Marketplace integrations) with
nothing keeping them in step.

The failure mode of a recipe existing several times is not that one is wrong.
It is that they drift, a manifest produced by one path stops verifying on
another, and the mismatch surfaces as ``weights_hash`` not matching, which reads
as tampered weights. This module exists so there is one implementation to point
at.

**This is a convention, not specification.** ``RECIPE_ID`` names it so a
mismatch can be attributed to the recipe rather than to the bytes, and so a
future construction can be ``/v2`` without either silently replacing the other.
A deployment that computes ``weights_hash`` some other way is not
non-conforming; it simply must not expect this function to agree.

The construction, in full:

  - Files sorted by POSIX relative path, so the order does not depend on the
    filesystem's readdir order or on the platform's separator.
  - Per file: the relative path's byte length as 8 bytes big-endian, then those
    path bytes, then the file size as 8 bytes big-endian, then the contents.
  - Length prefixing is the part that matters. Without it, ``a/bc`` + ``d`` and
    ``a/b`` + ``cd`` flatten to the same byte stream, so two different directory
    layouts would produce one digest.
  - ``.cache``, ``.git``, ``.gitattributes`` and ``.huggingface`` are excluded.
    They differ between two caches holding byte-identical weights, so including
    them would make a digest depend on how the model was fetched.

Symlinks are refused rather than followed. A link is a name that resolves
somewhere else, so following one lets a digest cover bytes outside the tree, and
lets the covered bytes change without anything in the tree changing. Pass
``follow_symlinks=True`` to accept that deliberately.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Iterable, Optional, Sequence

from ._types import HashValue

__all__ = [
    "RECIPE_ID",
    "EXCLUDED_NAMES",
    "ArtifactDigestError",
    "artifact_files",
    "artifact_digest",
]

#: Names this recipe, so a mismatch is attributable and a successor can coexist.
RECIPE_ID = "wcm-artifact-digest/v1"

#: Path components that are fetch bookkeeping rather than part of the model.
EXCLUDED_NAMES = frozenset({".cache", ".git", ".gitattributes", ".huggingface"})

_CHUNK = 1 << 20


class ArtifactDigestError(ValueError):
    """Raised rather than returning a digest that covers the wrong bytes."""


def artifact_files(
    path: Path, *, follow_symlinks: bool = False
) -> list[Path]:
    """The deterministic file inventory this recipe covers.

    Ordered by POSIX relative path. A single file is its own inventory, which is
    the case where a manifest binds one consolidated checkpoint.
    """
    if not path.exists():
        raise ArtifactDigestError(f"model artifact does not exist: {path}")

    if path.is_file():
        if path.is_symlink() and not follow_symlinks:
            raise ArtifactDigestError(_SYMLINK_MESSAGE.format(path=path))
        return [path]

    if not path.is_dir():
        raise ArtifactDigestError(
            f"{path} is neither a file nor a directory. A digest over a socket, "
            "device or FIFO would depend on what was read at the time."
        )

    files: list[Path] = []
    for candidate in path.rglob("*"):
        relative = candidate.relative_to(path)
        if EXCLUDED_NAMES.intersection(relative.parts):
            continue
        if candidate.is_symlink() and not follow_symlinks:
            raise ArtifactDigestError(_SYMLINK_MESSAGE.format(path=candidate))
        if candidate.is_file():
            files.append(candidate)

    if not files:
        raise ArtifactDigestError(
            f"model artifact contains no files: {path}. Hashing an empty inventory "
            "would produce a well-formed digest that binds nothing."
        )
    return sorted(files, key=lambda item: item.relative_to(path).as_posix())


_SYMLINK_MESSAGE = (
    "{path} is a symbolic link. Following one lets the digest cover bytes outside "
    "the artifact, and lets those bytes change without anything in the artifact "
    "changing. Pass follow_symlinks=True to accept that deliberately."
)


def artifact_digest(
    path: Path,
    *,
    include: Optional[Sequence[str]] = None,
    follow_symlinks: bool = False,
) -> HashValue:
    """Digest a file or a complete model directory. See the module docstring.

    ``include`` restricts the inventory to an explicit list of POSIX relative
    paths, for the case where a builder bound only the weight shards rather than
    the whole directory. Argument order is ignored; the recipe sorts. A named
    file that is absent raises, because hashing fewer files than the manifest
    bound produces a digest matching nothing and an error blaming the weights.

    Returns a ``HashValue``, so the result drops straight into ``weights_hash``
    or a serving-image measurement without restringing.
    """
    root = path if path.is_dir() else path.parent
    files = artifact_files(path, follow_symlinks=follow_symlinks)

    if include is not None:
        wanted = set(include)
        by_relative = {item.relative_to(root).as_posix(): item for item in files}
        missing = sorted(wanted - by_relative.keys())
        if missing:
            raise ArtifactDigestError(
                f"named files are absent from the artifact: {', '.join(missing)}. "
                "Hashing the remaining files would produce a digest that matches "
                "nothing, and an error that blames the weights."
            )
        files = [by_relative[name] for name in sorted(wanted)]

    digest = hashlib.sha256()
    for item in files:
        relative = item.relative_to(root).as_posix().encode("utf-8")
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        # The size is bound as well as the contents. A truncated read would
        # otherwise produce a digest indistinguishable from one over a genuinely
        # shorter file.
        digest.update(item.stat().st_size.to_bytes(8, "big"))
        with item.open("rb") as handle:
            for chunk in iter(lambda: handle.read(_CHUNK), b""):
                digest.update(chunk)
    return HashValue("sha256:" + digest.hexdigest())
