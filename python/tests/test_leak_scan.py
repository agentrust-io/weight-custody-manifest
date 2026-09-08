"""Regression cover for tools/leak_scan.py.

The scanner shipped with ALLOWLIST keys written using forward slashes while
iter_files yielded os.path-native strings. On Windows every exemption missed
and the scan failed against a clean tree. CI runs on Linux, so the only person
who could hit it was a maintainer running the check by hand before a manual
publish, which is the case the scanner exists to cover. These tests pin the
separator contract so the same gap cannot reopen silently.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

MODULE = Path(__file__).parents[2] / "tools" / "leak_scan.py"
SPEC = importlib.util.spec_from_file_location("leak_scan", MODULE)
assert SPEC and SPEC.loader
leak_scan = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(leak_scan)


def test_iter_files_yields_posix_relative_paths() -> None:
    """Backslashes here would silently disable every ALLOWLIST entry."""
    rels = [rel for _, rel in leak_scan.iter_files()]
    assert rels, "scanner walked no files"
    assert not any("\\" in rel for rel in rels)


def test_every_allowlist_key_matches_something() -> None:
    """A key that matches nothing is either a typo or stale debt."""
    rels = {rel for _, rel in leak_scan.iter_files()}
    for key in leak_scan.ALLOWLIST:
        matched = key in rels or (
            key.endswith("/") and any(r.startswith(key) for r in rels)
        )
        assert matched, f"ALLOWLIST key matches no file: {key}"


def test_exempt_honours_prefix_and_exact_keys() -> None:
    assert not leak_scan.exempt("tools/leak_scan.py", "cloud-access-key")
    assert leak_scan.exempt("conformance/vectors/gate/x.json", "private-key-block")
    assert not leak_scan.exempt("conformance/vectors/gate/x.json", "cloud-access-key")
    assert not leak_scan.exempt("python/src/wcm/__init__.py", "private-key-block")


# Synthetic identifiers exercise disclosure detection without exposing real values.
SYNTHETIC_PACK = """
- Azure subscription: `Example` (`00000000-0000-4000-8000-000000000000`)
- Resource group: `rg-example-placeholder`
- VM: `vm-example-placeholder`
- Leaf subject: `CN=Example,2.5.4.5=00000000000000000000000000000000000000AB`
"""


def test_patterns_catch_infrastructure_identifiers() -> None:
    """Infrastructure identifiers must block publication."""
    fired = {name for name, rx, _ in leak_scan.BLOCKING if rx.search(SYNTHETIC_PACK)}
    assert fired == {
        "azure-subscription-or-tenant-guid",
        "cloud-resource-name",
        "device-certificate-serial",
    }


def test_scanner_reports_the_tree_clean() -> None:
    """Includes this file, which is allowlisted precisely because it must
    carry pattern-shaped strings to test the patterns at all."""
    assert leak_scan.main() == 0


def test_exceptions_never_allow_known_open_findings() -> None:
    assert not any("OPEN" in reason for patterns in leak_scan.ALLOWLIST.values()
                   for reason in patterns.values())


def test_findings_do_not_print_matched_values(tmp_path, monkeypatch, capsys) -> None:
    source = tmp_path / "example.txt"
    source.write_text("OPAQUE internal")
    monkeypatch.setattr(leak_scan, "iter_files", lambda: iter([(source, "example.txt")]))
    assert leak_scan.main() == 1
    output = capsys.readouterr().out
    assert "internal-classification-label" in output
    assert "OPAQUE internal" not in output


def test_unreadable_input_fails_closed(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(leak_scan, "iter_files", lambda: iter([(tmp_path / "missing", "missing")]))
    assert leak_scan.main() == 1


def test_wheel_scans_content_and_limits_synthetic_exceptions(tmp_path) -> None:
    import zipfile
    archive = tmp_path / "example.whl"
    key = "-----BEGIN " + "PRIVATE KEY-----"
    with zipfile.ZipFile(archive, "w") as z:
        z.writestr("wcm/_conformance/vectors/example.json", key)
    assert leak_scan.main(["--archives", str(archive)]) == 0
    with zipfile.ZipFile(archive, "a") as z:
        z.writestr("wcm/credentials.txt", key)
    assert leak_scan.main(["--archives", str(archive)]) == 1


def test_sdist_blocks_internal_content(tmp_path) -> None:
    import io
    import tarfile
    archive = tmp_path / "example.tar.gz"
    data = b"OPAQUE internal"
    with tarfile.open(archive, "w:gz") as t:
        member = tarfile.TarInfo("weight_custody_manifest-0.0.0/README.md")
        member.size = len(data)
        t.addfile(member, io.BytesIO(data))
    assert leak_scan.main(["--archives", str(archive)]) == 1


def test_corrupt_archive_fails_closed(tmp_path) -> None:
    archive = tmp_path / "broken.whl"
    archive.write_bytes(b"not a zip file")
    assert leak_scan.main(["--archives", str(archive)]) == 1


def test_workspace_path_is_blocked() -> None:
    assert leak_scan.findings("README.md", "C:/Users/example/private/file.txt")
