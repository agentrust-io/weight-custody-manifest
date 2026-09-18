#!/usr/bin/env bash
# Export the reviewed dependency closure from the existing hash-locked image.
# Run from repository root; output is a new, empty task directory.
set -euo pipefail
output="${1:?output directory required}"
mkdir -p "$output"
test ! -e "$output/runtime.tar"
docker build --target provisioned -f python/docker/Dockerfile -t wcm-boot-runtime:local .
docker run --rm --network none --read-only --user 0 --entrypoint tar \
  wcm-boot-runtime:local --create --file=- --format=ustar --sort=name \
  --mtime=@0 --owner=0 --group=0 --numeric-owner --mode=u=rwX,go=rX \
  --dereference --hard-dereference --directory=/ \
  usr/local/bin/python3 usr/local/lib lib/x86_64-linux-gnu lib64 \
  etc/ld.so.cache etc/ssl/certs > "$output/runtime.tar"
cc -static -O2 -Wall -Wextra -Werror python/boot/init.c -o "$output/init"
python -m wcm.boot_bundle "$output/runtime.tar" "$output/init" --output "$output/initrd.cpio"
python -m wcm.boot_bundle "$output/runtime.tar" "$output/init" --verify "$output/initrd.cpio"
