#!/usr/bin/env python3
"""Scan source files and release archives for accidental disclosure.

Exit 0 means no configured pattern matched outside a documented exception.
Exit 1 means a finding or unreadable input. This is not a complete secret audit.
Matched values are never printed.
"""
from __future__ import annotations

import argparse
import re
import tarfile
import zipfile
import sys
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

# Binary / non-text extensions.
SKIP_EXT = {".png", ".jpg", ".jpeg", ".gif", ".pdf", ".ico", ".woff", ".woff2",
            ".zip", ".gz", ".tar", ".whl", ".so", ".dylib", ".bin"}

# Publication-blocking patterns. Synthetic exceptions are scoped below.
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

BLOCKING += [
    ("internal-classification-label", re.compile(r"OPAQUE " + r"internal", re.IGNORECASE),
     "An internal classification label."),
    ("local-workspace-path", re.compile(r"(?:[A-Za-z]:[\\/]Users[\\/](?!Public\b|Default\b)[^\s\"<>]+|/(?:Users|home)/[^/\s]+/)", re.IGNORECASE),
     "A local user workspace path."),
    ("github-token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})\b"),
     "A GitHub access token."),
]

# Exceptions cover synthetic inputs only, never production credentials.
ALLOWLIST = {
    "conformance/vectors/": {"private-key-block": "synthetic conformance PKI; protects no deployed identity"},
    "python/tests/test_leak_scan.py": {
        "azure-subscription-or-tenant-guid": "synthetic test GUID",
        "cloud-resource-name": "synthetic resource names",
        "device-certificate-serial": "synthetic device serial",
        "internal-classification-label": "synthetic negative control",
        "local-workspace-path": "synthetic negative control",
    },
    "python/tests/test_final_launch.py": {"private-key-block": "synthetic test key"},
}


def exempt(rel: str, pattern: str) -> bool:
    """True if `rel` is allowlisted for `pattern` (exact path or prefix)."""
    for key, pats in ALLOWLIST.items():
        if rel == key or (key.endswith("/") and rel.startswith(key)):
            if "*" in pats or pattern in pats:
                return True
    return False


def iter_files():
    paths = subprocess.check_output(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"], cwd=REPO
    ).decode("utf-8").split("\0")
    for rel in sorted(set(paths) - {""}):
        p = REPO / rel
        if p.is_symlink():
            raise ValueError("source symlink requires review")
        if p.suffix.lower() not in SKIP_EXT:
            yield p, rel


def findings(rel: str, text: str) -> list[tuple[str, int, str]]:
    return [(rel, text[:m.start()].count("\n") + 1, name)
            for name, rx, _ in BLOCKING if not exempt(rel, name)
            for m in rx.finditer(text)]


def archive_source_path(name: str, wheel: bool) -> str:
    """Map the package's documented build layout to repository exceptions."""
    if "\\" in name or name.startswith("/") or ".." in Path(name).parts:
        raise ValueError("unsafe archive member path")
    if wheel:
        if name.startswith("wcm/_conformance/"):
            return "conformance/" + name[len("wcm/_conformance/"):]
        return "python/src/" + name
    root, sep, rel = name.partition("/")
    if not sep or not root.startswith("weight_custody_manifest-"):
        raise ValueError("unexpected sdist layout")
    return rel if rel.startswith(("conformance/", "schema/")) else "python/" + rel


def archive_findings(path: Path) -> list[tuple[str, int, str]]:
    hits = []
    if path.suffix == ".whl":
        with zipfile.ZipFile(path) as z:
            for entry in z.infolist():
                if not entry.is_dir():
                    rel = archive_source_path(entry.filename, True)
                    hits.extend(findings(rel, z.read(entry).decode("utf-8", errors="ignore")))
    elif path.name.endswith(".tar.gz"):
        with tarfile.open(path, "r:gz") as t:
            for entry in t:
                if entry.isdir():
                    continue
                if not entry.isfile():
                    raise ValueError("non-regular archive member")
                rel = archive_source_path(entry.name, False)
                f = t.extractfile(entry)
                if f is None:
                    raise ValueError("unreadable archive member")
                with f:
                    hits.extend(findings(rel, f.read().decode("utf-8", errors="ignore")))
    else:
        raise ValueError("expected a wheel or .tar.gz sdist")
    return hits


def main(argv: tuple[str, ...] | list[str] = ()) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archives", nargs="+", type=Path)
    args = parser.parse_args(argv)
    hits = []
    try:
        if args.archives:
            for path in args.archives:
                hits.extend(archive_findings(path))
        else:
            for path, rel in iter_files():
                hits.extend(findings(rel, path.read_text(encoding="utf-8", errors="ignore")))
    except (OSError, ValueError, subprocess.CalledProcessError, tarfile.TarError, zipfile.BadZipFile):
        print("LEAK SCAN FAILED: an input could not be scanned.")
        return 1
    for rel, line, name in hits:
        print(f"{rel}:{line} [{name}]")
    if hits:
        print(f"LEAK SCAN FAILED: {len(hits)} finding(s). Values withheld.")
        return 1
    print(f"No configured disclosure patterns matched ({len(ALLOWLIST)} scoped exception(s)).")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
