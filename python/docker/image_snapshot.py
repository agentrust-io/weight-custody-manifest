"""Canonical Docker export + runtime configuration, without extracting the tar.

This is a build comparison format, not an SNP launch measurement or OCI digest.
Timestamps and image history are intentionally excluded; runtime Config and
filesystem ownership, links, permissions, contents and extended headers are not.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import tarfile
from typing import Any


def _path(name: str) -> str:
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts or not name:
        raise ValueError("export contains a noncanonical filesystem path")
    return str(path)


def snapshot(archive: Path, inspection: Path) -> dict[str, Any]:
    inspected = json.loads(inspection.read_bytes())
    if not isinstance(inspected, list) or len(inspected) != 1 or not isinstance(inspected[0], dict):
        raise ValueError("one Docker image inspection object required")
    image = inspected[0]
    if (not isinstance(image.get("Config"), dict)
            or not isinstance(image.get("Architecture"), str) or not image["Architecture"]
            or not isinstance(image.get("Os"), str) or not image["Os"]):
        raise ValueError("image runtime configuration and platform are required")
    runtime = {"architecture": image["Architecture"], "os": image["Os"],
               "variant": image.get("Variant"), "config": image["Config"]}
    entries: dict[str, dict[str, Any]] = {}
    regular_files = 0
    with tarfile.open(archive, mode="r|*") as exported:
        for member in exported:
            name = _path(member.name)
            if name in entries:
                raise ValueError("export contains duplicate filesystem paths")
            entry: dict[str, Any] = {
                "path": name, "mode": member.mode, "uid": member.uid, "gid": member.gid,
                "pax": {key: value for key, value in sorted(member.pax_headers.items())
                        if key not in {"mtime", "atime", "ctime"}},
            }
            if member.isreg():
                entry["type"] = "file"
                entry["size"] = member.size
                digest = hashlib.sha256()
                stream = exported.extractfile(member)
                if stream is None:
                    raise ValueError("regular file has no contents")
                size = 0
                with stream:
                    while chunk := stream.read(1024 * 1024):
                        digest.update(chunk)
                        size += len(chunk)
                if size != member.size:
                    raise ValueError("exported file is truncated")
                entry["sha256"] = digest.hexdigest()
                regular_files += 1
            elif member.isdir():
                entry["type"] = "directory"
            elif member.issym():
                entry.update(type="symlink", target=member.linkname)
            elif member.islnk():
                entry.update(type="hardlink", target=_path(member.linkname))
            elif member.ischr() or member.isblk():
                entry.update(type="character" if member.ischr() else "block",
                             major=member.devmajor, minor=member.devminor)
            elif member.isfifo():
                entry["type"] = "fifo"
            else:
                raise ValueError("unsupported exported filesystem entry")
            entries[name] = entry
    if not regular_files:
        raise ValueError("export contains no regular files")
    for entry in entries.values():
        if entry["type"] == "hardlink":
            target = entry["target"]
            seen = {entry["path"]}
            while True:
                if target in seen or target not in entries:
                    raise ValueError("unresolved or cyclic exported hardlink")
                seen.add(target)
                destination = entries[target]
                if destination["type"] == "file":
                    break
                if destination["type"] != "hardlink":
                    raise ValueError("hardlink does not resolve to a regular file")
                target = destination["target"]
    return {"format": "wcm/image-content-and-config/v1", "runtime": runtime,
            "filesystem": [entries[name] for name in sorted(entries)]}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("inspection", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    result = snapshot(args.archive, args.inspection)
    args.output.write_text(json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
