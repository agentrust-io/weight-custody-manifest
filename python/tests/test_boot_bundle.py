"""Independent newc decoding and malformed archive cases; no boot claim."""
import io
import stat
import struct
import subprocess
import sys
import tarfile

import pytest

from wcm.boot_bundle import build_initramfs


def loader():
    data = bytearray(120)
    data[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HH", data, 16, 2, 62)
    struct.pack_into("<Q", data, 32, 64)
    struct.pack_into("<HH", data, 54, 56, 1)
    struct.pack_into("<I", data, 64, 1)
    return bytes(data)


def runtime(items=None, *, mtime=0):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name, data, mode, kind in items or [("usr/local/bin/python3", b"interpreter", 0o755, tarfile.REGTYPE)]:
            item = tarfile.TarInfo(name)
            item.mode, item.type, item.mtime = mode, kind, mtime
            item.size = len(data) if kind == tarfile.REGTYPE else 0
            item.linkname = "outside" if kind in (tarfile.LNKTYPE, tarfile.SYMTYPE) else ""
            archive.addfile(item, io.BytesIO(data))
    return output.getvalue()


def decode(blob):
    records = {}
    offset = 0
    while True:
        assert blob[offset:offset + 6] == b"070701"
        values = [int(blob[i:i + 8], 16) for i in range(offset + 6, offset + 110, 8)]
        mode, uid, gid, mtime, size, namesize = (values[i] for i in (1, 2, 3, 5, 6, 11))
        assert (uid, gid, mtime) == (0, 0, 0)
        name = blob[offset + 110:offset + 110 + namesize - 1].decode()
        offset = (offset + 110 + namesize + 3) & ~3
        content = blob[offset:offset + size]
        offset = (offset + size + 3) & ~3
        if name == "TRAILER!!!":
            assert offset == len(blob)
            break
        assert name not in records
        parent = name.rpartition("/")[0]
        assert not parent or stat.S_ISDIR(records[parent][0])
        records[name] = (mode, content)
    return records


def test_complete_runtime_and_loader_are_contained_deterministically():
    items = [("usr/local/bin/python3", b"python", 0o755, tarfile.REGTYPE),
             ("usr/local/lib/dependency.so", b"dependency", 0o644, tarfile.REGTYPE)]
    image = build_initramfs(runtime(items), loader())
    assert image == build_initramfs(runtime(list(reversed(items)), mtime=99), loader())
    records = decode(image)
    assert records["init"] == (stat.S_IFREG | 0o555, loader())
    assert records["runtime/usr/local/lib/dependency.so"] == (stat.S_IFREG | 0o444, b"dependency")
    assert "runtime/run/config.json" not in records
    changed = items.copy()
    changed[1] = (changed[1][0], b"substitution", 0o644, tarfile.REGTYPE)
    assert build_initramfs(runtime(changed), loader()) != image


@pytest.mark.parametrize("name", ["/absolute", "../escape", "a/../b", "a//b", "./a", "a\\b", "run/config", "dev/null", "sys/x", "proc/x", "tmp/x", "non ascii\u00e9"])
def test_unsafe_and_reserved_names_rejected(name):
    with pytest.raises(ValueError):
        build_initramfs(runtime([(name, b"x", 0o644, tarfile.REGTYPE)]), loader())


@pytest.mark.parametrize("kind", [tarfile.LNKTYPE, tarfile.SYMTYPE, tarfile.CHRTYPE, tarfile.BLKTYPE, tarfile.FIFOTYPE])
def test_links_and_special_files_rejected(kind):
    with pytest.raises(ValueError):
        build_initramfs(runtime([("usr/escape", b"", 0o644, kind)]), loader())


@pytest.mark.parametrize("kind", [tarfile.LNKTYPE, tarfile.SYMTYPE])
def test_link_with_existing_empty_target_is_rejected(kind):
    # Avoid missing-target or size guards masking the explicit link rule.
    items = [("usr/local/bin/python3", b"python", 0o755, tarfile.REGTYPE),
             ("outside", b"", 0o644, tarfile.REGTYPE),
             ("usr/outside", b"", 0o644, tarfile.REGTYPE),
             ("usr/escape", b"", 0o644, kind)]
    with pytest.raises(ValueError, match="plain regular"):
        build_initramfs(runtime(items), loader())


@pytest.mark.parametrize("mode", [0o4755, 0o2755, 0o1755, 0o777, 0o664])
def test_privilege_and_writable_modes_rejected(mode):
    with pytest.raises(ValueError):
        build_initramfs(runtime([("usr/local/bin/python3", b"x", mode, tarfile.REGTYPE)]), loader())


def test_duplicates_parent_conflicts_missing_interpreter_and_dynamic_loader():
    good = ("usr/local/bin/python3", b"x", 0o755, tarfile.REGTYPE)
    for items in ([good, good], [good, ("usr", b"file", 0o644, tarfile.REGTYPE)],
                  [("other", b"x", 0o644, tarfile.REGTYPE)]):
        with pytest.raises(ValueError):
            build_initramfs(runtime(items), loader())
    for data in (b"shell script", loader()[:80], loader()[:64] + struct.pack("<I", 3) + loader()[68:]):
        with pytest.raises(ValueError):
            build_initramfs(runtime(), data)


def test_cli_verifies_containment_and_refuses_overwrite(tmp_path):
    source, init, output = (tmp_path / name for name in ("runtime.tar", "init", "image"))
    source.write_bytes(runtime())
    init.write_bytes(loader())
    command = [sys.executable, "-m", "wcm.boot_bundle", str(source), str(init)]
    subprocess.run([*command, "--output", str(output)], check=True)
    subprocess.run([*command, "--verify", str(output)], check=True)
    assert subprocess.run([*command, "--output", str(output)], capture_output=True).returncode == 1
    output.write_bytes(output.read_bytes() + b"second unapproved archive")
    assert subprocess.run([*command, "--verify", str(output)], capture_output=True).returncode == 1
