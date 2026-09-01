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
    assert leak_scan.exempt("tools/leak_scan.py", "azure-subscription-or-tenant-guid")
    assert leak_scan.exempt("conformance/vectors/gate/x.json", "private-key-block")
    assert not leak_scan.exempt("conformance/vectors/gate/x.json", "cloud-access-key")
    assert not leak_scan.exempt("python/src/wcm/__init__.py", "private-key-block")


# Deliberately synthetic. Asserting on the real values would recommit the exact
# strings #107 removed, and the first draft of this test did precisely that --
# the scanner caught it in CI, which is the control working. What is under test
# is the identifier SHAPE, so the shape is what belongs here.
SYNTHETIC_PACK = """
- Azure subscription: `Example` (`00000000-0000-4000-8000-000000000000`)
- Resource group: `rg-example-placeholder`
- VM: `vm-example-placeholder`
- Leaf subject: `CN=Example,2.5.4.5=00000000000000000000000000000000000000AB`
"""


def test_patterns_catch_the_identifier_classes_that_were_published() -> None:
    """The three classes that reached PyPI in 0.26.0 and 0.27.0 (RCA-0008)."""
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
