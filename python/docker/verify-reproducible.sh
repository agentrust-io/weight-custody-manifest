#!/usr/bin/env bash
#
# Verify the reference KBS image is reproducible: build it twice, the second time
# with --no-cache, and require the two images to have identical filesystem
# CONTENT.
#
# Why content and not layer digests. A layer's digest covers tar metadata, and
# BuildKit sets some of that from wall-clock regardless of what the Dockerfile
# does: the destination directory entry a COPY creates gets a build-time mtime,
# which no amount of in-image normalization can reach. Comparing layer digests
# therefore fails on metadata noise that has nothing to do with what the image
# contains. What a KBS measurement is actually about is the content: which files
# are present, with what permissions, holding what bytes. So that is what this
# compares, and it is the stronger claim of the two to be able to make.
#
# Run from the REPO ROOT:
#   ./python/docker/verify-reproducible.sh
#
# Needs docker and sudo (a container filesystem contains files the invoking user
# cannot read).

set -euo pipefail

DOCKERFILE="python/docker/Dockerfile"
WORK="$(mktemp -d)"
trap 'sudo rm -rf "$WORK"' EXIT

if [[ ! -f "$DOCKERFILE" ]]; then
    echo "run this from the repository root (no $DOCKERFILE here)" >&2
    exit 2
fi

# Snapshot an image's filesystem as two sorted, mtime-free manifests:
#   .meta  type, permissions, and path for every entry (catches a changed mode,
#          a file appearing or vanishing, a symlink becoming a regular file)
#   .files sha256 of every regular file's contents
snapshot() {
    local tag="$1" out="$2" root="$WORK/$2.root" cid
    mkdir -p "$root"
    cid="$(docker create "$tag")"
    docker export "$cid" | sudo tar -x -C "$root" 2>/dev/null || true
    docker rm -f "$cid" >/dev/null

    ( cd "$root" && sudo find . -mindepth 1 -printf '%y %m %P\n' ) \
        | LC_ALL=C sort > "$WORK/$out.meta"
    ( cd "$root" && sudo find . -type f -print0 \
        | LC_ALL=C sort -z \
        | sudo xargs -0 -r sha256sum ) \
        | LC_ALL=C sort -k2 > "$WORK/$out.files"

    echo "  $out: $(wc -l < "$WORK/$out.meta") entries, $(wc -l < "$WORK/$out.files") files"
}

echo "==> build 1"
docker build -f "$DOCKERFILE" -t wcm-kbs:repro1 . >/dev/null
echo "==> build 2 (--no-cache, so every step genuinely reruns)"
docker build --no-cache -f "$DOCKERFILE" -t wcm-kbs:repro2 . >/dev/null

echo "==> snapshotting filesystems"
snapshot wcm-kbs:repro1 one
snapshot wcm-kbs:repro2 two

status=0
if ! diff -u "$WORK/one.meta" "$WORK/two.meta" | head -50; then
    echo "FAIL: the two images differ in structure or permissions" >&2
    status=1
fi
if ! diff -u "$WORK/one.files" "$WORK/two.files" | head -50; then
    echo "FAIL: the two images differ in file contents" >&2
    status=1
fi

if [[ "$status" -ne 0 ]]; then
    echo >&2
    echo "The image is NOT reproducible. Something in the build depends on when it" >&2
    echo "ran. Usual suspects: an unpinned dependency, a byte-compile pass writing" >&2
    echo "mtime-stamped .pyc files, or a generated file carrying a timestamp." >&2
    exit 1
fi

echo
echo "PASS: two independent builds produced byte-identical filesystem content"
echo "      ($(wc -l < "$WORK/one.files") files, $(wc -l < "$WORK/one.meta") entries)"
echo
echo "Content digest (stable across builds, usable as a reference value):"
cat "$WORK/one.meta" "$WORK/one.files" | sha256sum | cut -d' ' -f1
