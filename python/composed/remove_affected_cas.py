"""Remove the two affected roots from a pinned Debian image's system store.

Both the KBS image and the confined-agent image use the same Debian base.  The
base's CA package still selects these roots.  Deselection must update both the
concatenated bundle and OpenSSL's hashed CA directory, because clients can use
either source.  This script uses only Python's standard library and the
``update-ca-certificates`` program already present in the pinned base image.
"""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import re
import ssl
import subprocess


# Debian DLA-4845-1 removes both anchors: compromised eMudhra intermediates
# also chain through the cross-signed Comodo AAA root.  The fingerprints below
# were checked against Debian's 20250419~deb12u1 package, and both files are
# absent from Debian's 20250419~deb12u2 package.
REMOVED_ROOTS = {
    "mozilla/emSign_ECC_Root_CA_-_G3.crt": "86a1ecba089c4a8d3bbe2734c612ba341d813e043cf9e8a862cd5c57a36bbe6b",
    "mozilla/Comodo_AAA_Services_root.crt": "d7a7a0fb5d7e2731d771e9484ebcdef71d5f0c3e0a2948782bc83ee0ea699ef4",
}
REMOVED_FINGERPRINTS = frozenset(REMOVED_ROOTS.values())
PEM_CERT = re.compile(rb"-----BEGIN CERTIFICATE-----\s+.*?-----END CERTIFICATE-----", re.DOTALL)


def fingerprints(path: Path) -> set[str]:
    """SHA-256 fingerprints of every PEM certificate in *path*."""
    return {
        hashlib.sha256(ssl.PEM_cert_to_DER_cert(block.decode("ascii"))).hexdigest()
        for block in PEM_CERT.findall(path.read_bytes())
    }


def verify_anchors(anchors_dir: Path) -> None:
    for name, digest in REMOVED_ROOTS.items():
        if fingerprints(anchors_dir / name) != {digest}:
            raise RuntimeError(f"pinned base has an unexpected certificate: {name}")


def disable_roots(config: Path, anchors_dir: Path) -> None:
    verify_anchors(anchors_dir)
    lines = config.read_text(encoding="utf-8").splitlines(keepends=True)
    for name in REMOVED_ROOTS:
        selected = [index for index, line in enumerate(lines) if line.rstrip("\r\n") == name]
        if len(selected) != 1:
            raise RuntimeError(f"expected exactly one selected root: {name}")
        lines[selected[0]] = "!" + lines[selected[0]]
    config.write_text("".join(lines), encoding="utf-8")


def check_store(config: Path, anchors_dir: Path, cert_dir: Path, *, check_ssl: bool) -> None:
    verify_anchors(anchors_dir)
    lines = config.read_text(encoding="utf-8").splitlines()
    for name in REMOVED_ROOTS:
        if name in lines or lines.count("!" + name) != 1:
            raise RuntimeError(f"affected root is still selected: {name}")

    bundle = cert_dir / "ca-certificates.crt"
    bundle_fingerprints = fingerprints(bundle)
    if not bundle_fingerprints or bundle_fingerprints & REMOVED_FINGERPRINTS:
        raise RuntimeError("an affected root is present in, or no roots remain in, the CA bundle")

    # OpenSSL can use CApath even when its CAfile is clean.  Inspect its linked
    # certificates as well, including hashed links that do not name the root.
    for entry in cert_dir.iterdir():
        if entry == bundle or not entry.is_file():
            continue
        if fingerprints(entry) & REMOVED_FINGERPRINTS:
            raise RuntimeError(f"an affected root remains trusted through {entry}")

    if check_ssl:
        loaded = ssl.create_default_context().get_ca_certs(binary_form=True)
        if {hashlib.sha256(cert).hexdigest() for cert in loaded} & REMOVED_FINGERPRINTS:
            raise RuntimeError("Python/OpenSSL still loads an affected root by default")


def normalize_timestamps(paths: list[Path]) -> None:
    epoch = int(os.environ.get("SOURCE_DATE_EPOCH", "1700000000"))
    for path in paths:
        os.utime(path, (epoch, epoch), follow_symlinks=False)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="verify only; do not modify the store")
    args = parser.parse_args()
    config = Path("/etc/ca-certificates.conf")
    anchors_dir = Path("/usr/share/ca-certificates")
    cert_dir = Path("/etc/ssl/certs")

    if not args.check:
        disable_roots(config, anchors_dir)
        subprocess.run(["update-ca-certificates", "--fresh"], check=True)
        normalize_timestamps([config, cert_dir, *cert_dir.iterdir()])
    check_store(config, anchors_dir, cert_dir, check_ssl=True)


if __name__ == "__main__":
    main()
