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


def test_patterns_catch_the_identifiers_that_were_published() -> None:
    """The four classes that reached PyPI in 0.26.0 and 0.27.0 (RCA-0008)."""
    sample = (
        "- Azure subscription: `Test` (`a5980719-95dc-405d-a853-a29e6946f1a6`)\n"
        "- Resource group: `rg-wcm-h100-eus2`\n"
        "- VM: `vm-wcm-h100-eus2`\n"
        "- Leaf subject: `CN=X,2.5.4.5=6536B34085535E72F1AB025E163C4661AE279CD9`\n"
    )
    fired = {name for name, rx, _ in leak_scan.BLOCKING if rx.search(sample)}
    assert fired == {
        "azure-subscription-or-tenant-guid",
        "cloud-resource-name",
        "device-certificate-serial",
    }
