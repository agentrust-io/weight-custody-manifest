#!/usr/bin/env bash
# Compare two builds' exported filesystem and effective image runtime Config.
# This is same-runner repeatability, not hardware attestation or an OCI digest.
set -euo pipefail

TARGET=reference
OUTPUT_DIR=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --target) TARGET="${2:?missing target}"; shift 2 ;;
        --output-dir) OUTPUT_DIR="${2:?missing output directory}"; shift 2 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done
case "$TARGET" in reference|provisioned) ;; *) echo "unsupported target" >&2; exit 2 ;; esac

DOCKERFILE=python/docker/Dockerfile
SNAPSHOT=python/docker/image_snapshot.py
[[ -f "$DOCKERFILE" && -f "$SNAPSHOT" ]] || { echo "run from repository root" >&2; exit 2; }
TMP_BASE="$(cd "${TMPDIR:-/tmp}" && pwd -P)"
WORK="$(mktemp -d "$TMP_BASE/wcm-repro.XXXXXXXX")"
CID=""
FIRST="wcm-kbs:repro-${TARGET}-one-$$"
SECOND="wcm-kbs:repro-${TARGET}-two-$$"
cleanup() {
    [[ -z "$CID" ]] || docker rm -f "$CID" >/dev/null 2>&1 || true
    docker image rm "$FIRST" "$SECOND" >/dev/null 2>&1 || true
    case "$WORK" in
        "$TMP_BASE"/wcm-repro.*) rm -rf -- "$WORK" ;;
        *) echo "refusing cleanup outside temporary root" >&2 ;;
    esac
}
trap cleanup EXIT

snapshot_image() {
    local tag="$1" name="$2"
    CID="$(docker create "$tag")"
    # Separate commands: an export failure must abort before any comparison.
    docker export "$CID" --output "$WORK/$name.tar"
    docker rm "$CID" >/dev/null
    CID=""
    docker image inspect "$tag" > "$WORK/$name.inspect.json"
    python3 "$SNAPSHOT" "$WORK/$name.tar" "$WORK/$name.inspect.json" "$WORK/$name.snapshot.json"
}

echo "==> build $TARGET twice (second without cache)"
docker build --target "$TARGET" -f "$DOCKERFILE" -t "$FIRST" . >/dev/null
docker build --no-cache --target "$TARGET" -f "$DOCKERFILE" -t "$SECOND" . >/dev/null
snapshot_image "$FIRST" one
snapshot_image "$SECOND" two
if ! cmp -s "$WORK/one.snapshot.json" "$WORK/two.snapshot.json"; then
    echo "FAIL: filesystem content, metadata or image runtime configuration differs" >&2
    exit 1
fi

DIGEST="$(sha256sum "$WORK/one.snapshot.json" | cut -d' ' -f1)"
echo "PASS: same-runner filesystem and runtime configuration match ($TARGET)"
echo "Reference snapshot SHA256: $DIGEST (not a hardware launch measurement)"
if [[ -n "$OUTPUT_DIR" ]]; then
    mkdir -p "$OUTPUT_DIR"
    cp "$WORK/one.snapshot.json" "$OUTPUT_DIR/image-snapshot.json"
    printf '%s\n' "$DIGEST" > "$OUTPUT_DIR/sha256.txt"
fi
