"""Deterministic, uncompressed initramfs assembly for the provisional loader.

This is packaging, not an SNP measurement calculator or runtime security proof.
Inputs must be frozen, independently reviewed build artifacts.
"""
from __future__ import annotations

import argparse
import io
from pathlib import Path
import re
import stat
import struct
import tarfile

MAX_BUNDLE = 512 * 1024 * 1024
MAX_FILES = 30000
_RESERVED = {"dev", "run", "proc", "sys", "tmp"}


def _static_loader(data: bytes) -> None:
    # ELF64, little endian, x86-64 executable. No interpreter or dynamic segment.
    if (len(data) < 64 or data[:7] != b"\x7fELF\x02\x01\x01"
            or struct.unpack_from("<HH", data, 16) != (2, 62)):
        raise ValueError("static x86-64 ELF loader required")
    offset = struct.unpack_from("<Q", data, 32)[0]
    width, count = struct.unpack_from("<HH", data, 54)
    if width != 56 or not 1 <= count <= 128 or offset + width * count > len(data):
        raise ValueError("invalid loader program headers")
    kinds = [struct.unpack_from("<I", data, offset + width * i)[0] for i in range(count)]
    if 1 not in kinds or 2 in kinds or 3 in kinds:
        raise ValueError("dynamic loader rejected")


def _cpio(entries: dict[str, tuple[int, bytes]]) -> bytes:
    output = bytearray()
    for inode, (name, (mode, data)) in enumerate(
        [*sorted(entries.items()), ("TRAILER!!!", (0, b""))], 1
    ):
        encoded = name.encode("ascii") + b"\0"
        fields = (inode, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(encoded), 0)
        output.extend(b"070701" + "".join(f"{value:08x}" for value in fields).encode("ascii"))
        output.extend(encoded)
        output.extend(bytes(-len(output) % 4))
        output.extend(data)
        output.extend(bytes(-len(output) % 4))
    return bytes(output)


def build_initramfs(runtime_tar: bytes, loader: bytes) -> bytes:
    """Embed the complete runtime under /runtime and the supplied loader at /init.

    No extraction to the build host. Links, devices, special files, ambiguous
    paths and privilege bits are rejected. TAR timestamps/owners/order are not
    execution inputs; file bytes and executable bits are retained.
    """
    if not runtime_tar or len(runtime_tar) + len(loader) > MAX_BUNDLE:
        raise ValueError("boot inputs exceed size limit")
    _static_loader(loader)
    entries: dict[str, tuple[int, bytes]] = {
        name: (stat.S_IFDIR | 0o555, b"")
        for name in ("dev", "sys", "runtime", "runtime/dev", "runtime/run")
    }
    entries["init"] = (stat.S_IFREG | 0o555, loader)
    seen: set[str] = set()
    total = len(loader)
    with tarfile.open(fileobj=io.BytesIO(runtime_tar), mode="r:") as archive:
        for item in archive:
            name = item.name
            if (not re.fullmatch(r"[A-Za-z0-9_+.,@/-]+", name)
                    or any(part in ("", ".", "..") for part in name.split("/"))
                    or name.split("/")[0] in _RESERVED or name in seen):
                raise ValueError(f"unsafe, reserved or duplicate runtime path: {name!r}")
            seen.add(name)
            if len(seen) > MAX_FILES or item.mode & 0o7022:
                raise ValueError("runtime count or permission policy violated")
            if not (item.isdir() or item.isreg()) or item.pax_headers:
                raise ValueError("only plain regular files and directories allowed")
            total += item.size
            if total > MAX_BUNDLE or item.size < 0 or (item.isdir() and item.size):
                raise ValueError("runtime size policy violated")
            path = "runtime/" + name
            if item.isdir():
                entries[path] = (stat.S_IFDIR | 0o555, b"")
            else:
                stream = archive.extractfile(item)
                if stream is None:
                    raise ValueError("missing runtime file")
                data = stream.read()
                if len(data) != item.size:
                    raise ValueError("truncated runtime file")
                entries[path] = (stat.S_IFREG | (0o555 if item.mode & 0o111 else 0o444), data)
    for path in list(entries):
        parts = path.split("/")
        for depth in range(1, len(parts)):
            parent = "/".join(parts[:depth])
            if parent in entries and not stat.S_ISDIR(entries[parent][0]):
                raise ValueError("runtime parent is not a directory")
            entries.setdefault(parent, (stat.S_IFDIR | 0o555, b""))
    interpreter = entries.get("runtime/usr/local/bin/python3")
    if interpreter is None or not interpreter[0] & 0o111 or not interpreter[1]:
        raise ValueError("fixed Python entry point missing")
    return _cpio(entries)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("runtime", type=Path)
    parser.add_argument("loader", type=Path)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--output", type=Path)
    group.add_argument("--verify", type=Path)
    args = parser.parse_args()
    try:
        bundle = build_initramfs(args.runtime.read_bytes(), args.loader.read_bytes())
        if args.verify is not None:
            if args.verify.read_bytes() != bundle:
                raise ValueError("initramfs differs from approved runtime and loader")
        else:
            # Never silently overwrite an independently approved artifact.
            with args.output.open("xb") as output:
                output.write(bundle)
    except Exception as exc:
        parser.exit(1, f"boot bundle rejected ({type(exc).__name__})\n")


if __name__ == "__main__":
    main()
