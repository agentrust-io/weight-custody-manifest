"""Tests for the artifact digest recipe.

Two things are being pinned. The construction itself, because three copies of it
already exist outside this repository and this one is now the reference they
converge on. And the refusals, because every one of them exists to stop a digest
that covers the wrong bytes while looking well-formed.
"""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

import pytest

from wcm import (
    ARTIFACT_DIGEST_RECIPE,
    ArtifactDigestError,
    HashValue,
    artifact_digest,
    artifact_files,
)
from wcm.artifact_digest import EXCLUDED_NAMES


def write(directory: Path, files: dict[str, bytes]) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    for name, payload in files.items():
        target = directory / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(payload)
    return directory


MODEL = {"model.safetensors": b"weights", "config.json": b"{}"}


def test_recipe_is_named_so_a_mismatch_is_attributable() -> None:
    assert ARTIFACT_DIGEST_RECIPE == "wcm-artifact-digest/v1"


def test_digest_is_a_hash_value_usable_as_weights_hash(tmp_path: Path) -> None:
    """The result drops into a manifest without restringing."""
    digest = artifact_digest(write(tmp_path / "m", MODEL))

    assert isinstance(digest, HashValue)
    assert digest.algorithm == "sha256"
    assert len(digest.hex_digest) == 64


def test_construction_is_exactly_the_documented_one(tmp_path: Path) -> None:
    """Recomputed by hand. Three copies of this live outside the repository.

    If this assertion ever has to be updated, every one of them breaks, which is
    the point: the recipe is versioned so a successor becomes /v2 rather than
    silently replacing this.
    """
    directory = write(tmp_path / "m", MODEL)

    expected = hashlib.sha256()
    for name, payload in sorted(MODEL.items()):
        relative = name.encode("utf-8")
        expected.update(len(relative).to_bytes(8, "big"))
        expected.update(relative)
        expected.update(len(payload).to_bytes(8, "big"))
        expected.update(payload)

    assert artifact_digest(directory) == "sha256:" + expected.hexdigest()


def test_a_single_file_is_its_own_inventory(tmp_path: Path) -> None:
    directory = write(tmp_path / "m", {"consolidated.safetensors": b"weights"})
    single = directory / "consolidated.safetensors"

    assert artifact_digest(single) == artifact_digest(directory)


def test_content_change_changes_the_digest(tmp_path: Path) -> None:
    one = artifact_digest(write(tmp_path / "a", MODEL))
    two = artifact_digest(write(tmp_path / "b", {**MODEL, "config.json": b"{ }"}))

    assert one != two


def test_added_file_changes_the_digest(tmp_path: Path) -> None:
    one = artifact_digest(write(tmp_path / "a", MODEL))
    two = artifact_digest(write(tmp_path / "b", {**MODEL, "adapter.safetensors": b"x"}))

    assert one != two


def test_removed_file_changes_the_digest(tmp_path: Path) -> None:
    one = artifact_digest(write(tmp_path / "a", MODEL))
    two = artifact_digest(write(tmp_path / "b", {"model.safetensors": b"weights"}))

    assert one != two


def test_rename_changes_the_digest(tmp_path: Path) -> None:
    """The path is bound, not only the contents."""
    one = artifact_digest(write(tmp_path / "a", {"shard-0.safetensors": b"w"}))
    two = artifact_digest(write(tmp_path / "b", {"shard-1.safetensors": b"w"}))

    assert one != two


def test_length_prefixing_separates_layouts_that_would_otherwise_collide(
    tmp_path: Path,
) -> None:
    """Without the length prefix these two flatten to one byte stream.

    "a" + "bc" and "ab" + "c" concatenate identically. This is the specific
    reason the construction is not a plain concatenation, so it gets its own
    case rather than being implied by the rename test.
    """
    one = artifact_digest(write(tmp_path / "one", {"a": b"z", "bc": b"z"}))
    two = artifact_digest(write(tmp_path / "two", {"ab": b"z", "c": b"z"}))

    assert one != two


def test_digest_is_stable_across_repeated_runs(tmp_path: Path) -> None:
    directory = write(tmp_path / "m", MODEL)

    assert artifact_digest(directory) == artifact_digest(directory)


def test_nested_directories_are_covered(tmp_path: Path) -> None:
    directory = write(tmp_path / "m", {"a.bin": b"1", "sub/b.bin": b"2"})

    assert len(artifact_files(directory)) == 2


def test_nesting_is_bound_not_flattened(tmp_path: Path) -> None:
    one = artifact_digest(write(tmp_path / "a", {"sub/b.bin": b"2"}))
    two = artifact_digest(write(tmp_path / "b", {"b.bin": b"2"}))

    assert one != two


@pytest.mark.parametrize("excluded", sorted(EXCLUDED_NAMES))
def test_fetch_bookkeeping_does_not_change_the_digest(
    tmp_path: Path, excluded: str
) -> None:
    """Two caches holding identical weights must produce identical digests."""
    clean = write(tmp_path / "clean", MODEL)
    fetched = write(tmp_path / "fetched", MODEL)
    (fetched / excluded).mkdir()
    (fetched / excluded / "state").write_bytes(b"how this was downloaded")

    assert artifact_digest(clean) == artifact_digest(fetched)


def test_excluded_name_nested_deeper_is_also_skipped(tmp_path: Path) -> None:
    clean = write(tmp_path / "clean", MODEL)
    fetched = write(tmp_path / "fetched", {**MODEL, "sub/.cache/blob": b"junk"})

    assert artifact_digest(clean) == artifact_digest(fetched)


def test_include_selects_an_explicit_inventory(tmp_path: Path) -> None:
    directory = write(tmp_path / "m", {**MODEL, "README.md": b"docs"})

    assert artifact_digest(directory, include=["model.safetensors"]) != artifact_digest(
        directory
    )


def test_include_order_is_ignored(tmp_path: Path) -> None:
    directory = write(tmp_path / "m", MODEL)

    forward = artifact_digest(directory, include=["config.json", "model.safetensors"])
    backward = artifact_digest(directory, include=["model.safetensors", "config.json"])

    assert forward == backward


def test_include_matching_everything_equals_the_plain_digest(tmp_path: Path) -> None:
    directory = write(tmp_path / "m", MODEL)

    assert artifact_digest(directory, include=list(MODEL)) == artifact_digest(directory)


def test_named_file_absent_raises_rather_than_hashing_fewer(tmp_path: Path) -> None:
    directory = write(tmp_path / "m", MODEL)

    with pytest.raises(ArtifactDigestError, match="absent from the artifact"):
        artifact_digest(directory, include=["model.safetensors", "not-there.bin"])


def test_empty_directory_raises(tmp_path: Path) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()

    with pytest.raises(ArtifactDigestError, match="contains no files"):
        artifact_digest(empty)


def test_directory_of_only_excluded_names_raises(tmp_path: Path) -> None:
    """An inventory emptied by exclusion is still an empty inventory."""
    directory = tmp_path / "m"
    (directory / ".cache").mkdir(parents=True)
    (directory / ".cache" / "blob").write_bytes(b"junk")

    with pytest.raises(ArtifactDigestError, match="contains no files"):
        artifact_digest(directory)


def test_missing_path_raises(tmp_path: Path) -> None:
    with pytest.raises(ArtifactDigestError, match="does not exist"):
        artifact_digest(tmp_path / "nowhere")


@pytest.mark.skipif(sys.platform == "win32", reason="symlink creation needs privilege")
def test_symlinked_file_is_refused_by_default(tmp_path: Path) -> None:
    """A link lets covered bytes change without the artifact changing."""
    outside = tmp_path / "outside.bin"
    outside.write_bytes(b"not part of the model")
    directory = write(tmp_path / "m", MODEL)
    (directory / "linked.safetensors").symlink_to(outside)

    with pytest.raises(ArtifactDigestError, match="symbolic link"):
        artifact_digest(directory)


@pytest.mark.skipif(sys.platform == "win32", reason="symlink creation needs privilege")
def test_symlinks_can_be_followed_deliberately(tmp_path: Path) -> None:
    outside = tmp_path / "outside.bin"
    outside.write_bytes(b"pulled in on purpose")
    directory = write(tmp_path / "m", MODEL)
    (directory / "linked.safetensors").symlink_to(outside)

    digest = artifact_digest(directory, follow_symlinks=True)

    assert digest != artifact_digest(write(tmp_path / "plain", MODEL))


@pytest.mark.skipif(sys.platform == "win32", reason="symlink creation needs privilege")
def test_symlink_target_change_is_what_the_refusal_prevents(tmp_path: Path) -> None:
    outside = tmp_path / "outside.bin"
    outside.write_bytes(b"before")
    directory = write(tmp_path / "m", MODEL)
    (directory / "linked.safetensors").symlink_to(outside)

    before = artifact_digest(directory, follow_symlinks=True)
    outside.write_bytes(b"after!")
    after = artifact_digest(directory, follow_symlinks=True)

    assert before != after, "nothing inside the artifact changed, yet the digest did"


def test_inventory_is_sorted_by_posix_relative_path(tmp_path: Path) -> None:
    """Not by readdir order, and not by the platform separator."""
    directory = write(tmp_path / "m", {"b.bin": b"2", "a/z.bin": b"1", "a.bin": b"0"})

    names = [item.relative_to(directory).as_posix() for item in artifact_files(directory)]

    assert names == sorted(names)
    assert names == ["a.bin", "a/z.bin", "b.bin"]
