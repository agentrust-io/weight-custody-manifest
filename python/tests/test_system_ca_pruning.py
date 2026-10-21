"""Offline checks for the pinned Debian system-CA root deselection."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "remove_affected_cas", ROOT / "composed" / "remove_affected_cas.py"
)
assert SPEC and SPEC.loader
ca = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ca)
G3_PEM = (Path(__file__).parent / "fixtures" / "emsign-ecc-root-g3.pem").read_text()
COMODO_PEM = (Path(__file__).parent / "fixtures" / "comodo-aaa-services-root.pem").read_text()
SAFE_PEM = "-----BEGIN CERTIFICATE-----\nQUJD\n-----END CERTIFICATE-----\n"
G3_NAME, COMODO_NAME = ca.REMOVED_ROOTS


def test_affected_root_fingerprint_and_both_trust_store_forms(tmp_path: Path) -> None:
    config = tmp_path / "ca-certificates.conf"
    config.write_text("mozilla/ISRG_Root_X1.crt\n" + G3_NAME + "\n" + COMODO_NAME + "\n")
    anchors_dir = tmp_path / "anchors"
    (anchors_dir / "mozilla").mkdir(parents=True)
    (anchors_dir / G3_NAME).write_text(G3_PEM)
    (anchors_dir / COMODO_NAME).write_text(COMODO_PEM)
    cert_dir = tmp_path / "certs"
    cert_dir.mkdir()
    bundle = cert_dir / "ca-certificates.crt"
    bundle.write_text(G3_PEM + COMODO_PEM + SAFE_PEM)

    for name, digest in ca.REMOVED_ROOTS.items():
        assert ca.fingerprints(anchors_dir / name) == {digest}
    ca.disable_roots(config, anchors_dir)
    assert config.read_text().splitlines() == [
        "mozilla/ISRG_Root_X1.crt", "!" + G3_NAME, "!" + COMODO_NAME
    ]
    with pytest.raises(RuntimeError, match="CA bundle"):
        ca.check_store(config, anchors_dir, cert_dir, check_ssl=False)

    bundle.write_text(COMODO_PEM + SAFE_PEM)
    with pytest.raises(RuntimeError, match="CA bundle"):
        ca.check_store(config, anchors_dir, cert_dir, check_ssl=False)

    bundle.write_text(SAFE_PEM)
    for name in ca.REMOVED_ROOTS:
        link = cert_dir / (Path(name).stem + ".pem")
        link.symlink_to(anchors_dir / name)
        with pytest.raises(RuntimeError, match="remains trusted through"):
            ca.check_store(config, anchors_dir, cert_dir, check_ssl=False)
        link.unlink()

    ca.check_store(config, anchors_dir, cert_dir, check_ssl=False)


def test_unexpected_pinned_anchor_is_refused(tmp_path: Path) -> None:
    config = tmp_path / "ca-certificates.conf"
    config.write_text(G3_NAME + "\n" + COMODO_NAME + "\n")
    anchors_dir = tmp_path / "anchors"
    (anchors_dir / "mozilla").mkdir(parents=True)
    (anchors_dir / G3_NAME).write_text(SAFE_PEM)
    (anchors_dir / COMODO_NAME).write_text(COMODO_PEM)
    with pytest.raises(RuntimeError, match="unexpected certificate"):
        ca.disable_roots(config, anchors_dir)


def test_both_image_builds_prune_the_shared_pinned_base() -> None:
    kbs = (ROOT / "docker" / "Dockerfile").read_text()
    agent = (ROOT / "composed" / "Dockerfile").read_text()
    assert "FROM ca_base AS builder" in kbs
    assert "FROM ca_base AS runtime" in kbs
    assert "PIP_CERT=/etc/ssl/certs/ca-certificates.crt" in kbs
    assert "python /tmp/remove_affected_cas.py" in kbs
    assert "python /tmp/remove_affected_cas.py" in agent
