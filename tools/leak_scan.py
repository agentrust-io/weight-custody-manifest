#!/usr/bin/env python3
"""Pre-release leak scan — runs on every push and pull request.

WHY THIS EXISTS (RCA-0008, 2026-09-01)
======================================
An Azure subscription GUID, a resource group, a VM name and a GPU device
certificate serial were published to PUBLIC PyPI in sdists 0.25.0-0.27.0 while
this repository was still PRIVATE on GitHub. Two manual pre-flip leak scans
(2026-08-06 and 2026-08-13) both reported CLEAN, and both were honest: they
searched a five-term denylist of customer, partner and codename strings, and
those terms genuinely were absent. The leaked material was a different class
entirely -- infrastructure identifiers -- and it landed on 2026-08-16, three
days after the last scan.

Two failures composed, and this script addresses both:

  1. WRONG CLASS. A denylist of named entities cannot catch a GUID. This scans
     for identifier SHAPES, not for a list of known-bad strings.

  2. WRONG SURFACE. Every control guarded the GitHub visibility flip. Nothing
     guarded `python -m build && twine upload`. A repository that publishes a
     package is public AT THE PACKAGE BOUNDARY regardless of its GitHub
     visibility. This runs in CI on every change, not by hand before a flip.

Exit 0 = clean. Exit 1 = findings. No third-party dependencies, by design.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

# Directories that never ship and never need scanning.
SKIP_DIRS = {".git", "node_modules", "__pycache__",
             ".pytest_cache", ".venv", "venv", "dist", "build", ".mypy_cache",
             ".ruff_cache", "htmlcov"}

# Binary / non-text extensions.
SKIP_EXT = {".png", ".jpg", ".jpeg", ".gif", ".pdf", ".ico", ".woff", ".woff2",
            ".zip", ".gz", ".tar", ".whl", ".so", ".dylib", ".bin"}

# --- BLOCKING patterns -------------------------------------------------------
# Calibrated 2026-09-01: each produces ZERO hits on a clean tree, so any hit is
# a real finding rather than noise. Keep it that way -- a check that cries wolf
# gets ignored, which is how the last one failed.
BLOCKING = [
    ("azure-subscription-or-tenant-guid",
     re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"),
     "A bare GUID. Azure subscription/tenant/resource IDs look like this."),
    ("cloud-resource-name",
     re.compile(r"\b(?:rg|vm|nic|nsg|vnet)-[a-z0-9]+(?:-[a-z0-9]+){1,}\b"),
     "An Azure-style resource name (resource group, VM, NIC, NSG, vnet)."),
    ("device-certificate-serial",
     re.compile(r"2\.5\.4\.5\s*=\s*[0-9A-Fa-f]{16,}"),
     "An X.509 serialNumber (OID 2.5.4.5) -- identifies specific hardware."),
    ("private-key-block",
     re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----"),
     "A private key block."),
    ("cloud-access-key",
     re.compile(r"\b(?:AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16})\b"),
     "An AWS access key ID."),
]

# --- WARNING patterns --------------------------------------------------------
# Not blocking, because the label is doing its job when it marks a genuinely
# internal artifact. It becomes a defect only when such an artifact is
# COMMITTED to a repo that publishes -- which the allowlist below makes visible.
WARNING = [
    ("internal-classification-label",
     re.compile(r"OPAQUE internal"),
     "An artifact self-labelled internal. Verify it is not shipped."),
]

# Known, deliberate, reviewed exceptions, as {path-or-prefix: {pattern: reason}}.
# Every entry needs a reason. An empty allowlist is the goal; a growing one is a
# smell. `*` exempts every pattern for that path.
ALLOWLIST = {
    # This scanner documents the patterns it hunts, so it matches itself.
    "tools/leak_scan.py": {"*": "the scanner's own documentation"},

    # Synthetic PKI, and it is stated policy: PUBLIC-RELEASE.md:45 --
    # "synthetic PKI for portability even though the SDK also carries
    # real-silicon fixtures." These keys protect nothing.
    "conformance/vectors/": {
        "private-key-block": "synthetic conformance PKI (PUBLIC-RELEASE.md:45)"},
    # Tests the identifier patterns, so it must contain pattern-shaped strings
    # or it tests nothing. The values there are synthetic placeholders, not the
    # published ones; test_patterns_catch_the_identifier_classes_that_were_published
    # says why. Reviewed 2026-09-01.
    "python/tests/test_leak_scan.py": {
        "azure-subscription-or-tenant-guid": "synthetic all-zero GUID under test",
        "cloud-resource-name": "synthetic rg-/vm-example-placeholder under test",
        "device-certificate-serial": "synthetic all-zero serial under test"},

    "python/tests/test_final_launch.py": {
        "private-key-block": "synthetic test key",
        "internal-classification-label": "asserts on the label value"},

    # The label is the VALUE these tools write, not leaked data. Correct
    # behaviour: they mark internal evidence as internal.
    "python/tools/final_launch.py": {
        "internal-classification-label": "emits the label by design"},
    "python/tools/paired_hardware_release.py": {
        "internal-classification-label": "emits the label by design"},

    # OPEN DEBT, not a decision. This fixture is SHA-256 pinned by
    # tests/test_paired_hardware_receipt.py, so redacting it breaks the
    # integrity pin that proves the receipt is the one the hardware produced.
    # Resolving it means deciding whether evidentiary pinning or publishability
    # wins -- a judgement call, not a cleanup. Owner: Imran. See RCA-0008.
    "python/tests/fixtures/live-validation/weight-custody-manifest/paired-2026-08-20/paired-release.json": {
        "device-certificate-serial": "OPEN: SHA-256 pinned evidence; redaction breaks the pin (RCA-0008)",
        "internal-classification-label": "OPEN: same pinned record (RCA-0008)"},
}


def exempt(rel: str, pattern: str) -> bool:
    """True if `rel` is allowlisted for `pattern` (exact path or prefix)."""
    for key, pats in ALLOWLIST.items():
        if rel == key or (key.endswith("/") and rel.startswith(key)):
            if "*" in pats or pattern in pats:
                return True
    return False


def iter_files():
    for p in REPO.rglob("*"):
        if not p.is_file():
            continue
        rel = p.relative_to(REPO)
        if any(part in SKIP_DIRS for part in rel.parts):
            continue
        if p.suffix.lower() in SKIP_EXT:
            continue
        # as_posix(), not str(): ALLOWLIST keys are written with forward
        # slashes, and str() on Windows yields backslashes, so every exemption
        # silently missed and the scan failed on a clean tree. CI is Linux, so
        # only a maintainer running this locally before a manual publish would
        # have hit it -- which is exactly the case this scanner exists to cover.
        yield p, rel.as_posix()


def main() -> int:
    blocking_hits, warning_hits = [], []
    for path, rel in iter_files():
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for name, rx, why in BLOCKING:
            if exempt(rel, name):
                continue
            for m in rx.finditer(text):
                line = text[:m.start()].count("\n") + 1
                blocking_hits.append((rel, line, name, why, m.group(0)[:60]))
        for name, rx, why in WARNING:
            if exempt(rel, name):
                continue
            for m in rx.finditer(text):
                line = text[:m.start()].count("\n") + 1
                warning_hits.append((rel, line, name, why, m.group(0)[:60]))

    if warning_hits:
        print("WARNINGS (not blocking):")
        for rel, line, name, why, snip in warning_hits:
            print(f"  {rel}:{line}  [{name}]  {why}\n      matched: {snip}")
        print()

    if blocking_hits:
        print("LEAK SCAN FAILED -- do not publish.\n")
        for rel, line, name, why, snip in blocking_hits:
            print(f"  {rel}:{line}  [{name}]\n      {why}\n      matched: {snip}")
        print(f"\n{len(blocking_hits)} blocking finding(s).")
        print("If a match is a deliberate, reviewed exception, add it to "
              "ALLOWLIST in tools/leak_scan.py with a reason and an owner.")
        return 1

    print(f"leak scan clean ({len(ALLOWLIST)} documented exception(s), "
          f"{len(warning_hits)} warning(s))")
    return 0


if __name__ == "__main__":
    sys.exit(main())
