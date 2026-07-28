"""NVIDIA CC GPU-report verification.

Primary validation: a REAL H100 NVL confidential-compute attestation captured on
live silicon (`fixtures/gpu_h100_attestation.json`, cross-checked with NVIDIA's
own local verifier) is verified OFFLINE against the pinned NVIDIA Device Identity
CA root (`fixtures/nvidia_device_identity_ca.pem`): cert chain + ECDSA-P384/SHA384
report signature + raw-nonce-at-offset-4 binding.

The KBS-integration and nonce-binding tests use a synthetic NVIDIA-format report
(same layout: 4-byte header, raw nonce at offset 4, ECDSA-P384 raw r||s over
report[:-96]) so they can bind an arbitrary KBS challenge nonce; the real report
is fixed to its captured nonce.
"""
from __future__ import annotations

import base64
import json
import pathlib
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.x509.oid import NameOID

from wcm import (
    CompositeEvidence,
    CpuQuote,
    GpuReport,
    KeyBrokerService,
    NvidiaGpuVerifier,
    build_gpu_verifier,
    parse_gpu_report,
)

FIXTURES = pathlib.Path(__file__).parent / "fixtures"
NOW = datetime(2026, 7, 28, 12, 0, 0, tzinfo=timezone.utc)


def _real_bundle() -> dict:
    return json.loads((FIXTURES / "gpu_h100_attestation.json").read_text())


def _real_root_pem() -> str:
    return (FIXTURES / "nvidia_device_identity_ca.pem").read_text()


def _evidence_b64(report_b64: str, cert_chain_pem: str) -> str:
    doc = {"report_b64": report_b64, "cert_chain_pem": cert_chain_pem}
    return base64.b64encode(json.dumps(doc).encode()).decode()


# -- REAL captured H100 attestation (the point) --------------------------------


def test_real_h100_attestation_verifies_offline():
    b = _real_bundle()
    v = build_gpu_verifier(_real_root_pem())
    result = v.verify(
        _evidence_b64(b["report_b64"], b["cert_chain_pem"]),
        expected_nonce=b["nonce"],
        now=NOW,
    )
    assert result.verified, result.reason
    assert "GSP FMC LF" in (result.leaf_subject or "")


def test_real_h100_raw_nonce_at_offset_4():
    b = _real_bundle()
    report = base64.b64decode(b["report_b64"])
    parsed = parse_gpu_report(report)
    assert parsed.raw_nonce == bytes.fromhex(b["nonce"])
    assert len(parsed.signature) == 96


def test_real_h100_wrong_nonce_fails():
    b = _real_bundle()
    v = build_gpu_verifier(_real_root_pem())
    result = v.verify(
        _evidence_b64(b["report_b64"], b["cert_chain_pem"]),
        expected_nonce="cd" * 32,
        now=NOW,
    )
    assert not result.verified
    assert "nonce" in (result.reason or "").lower()


def test_real_h100_tampered_report_fails_signature():
    b = _real_bundle()
    report = bytearray(base64.b64decode(b["report_b64"]))
    report[100] ^= 0xFF  # flip a byte inside the signed body
    v = build_gpu_verifier(_real_root_pem())
    result = v.verify(
        _evidence_b64(base64.b64encode(bytes(report)).decode(), b["cert_chain_pem"]),
        expected_nonce=b["nonce"],
        now=NOW,
    )
    assert not result.verified
    assert "signature" in (result.reason or "")


def test_real_h100_untrusted_root_fails():
    b = _real_bundle()
    v = build_gpu_verifier(_pem(_Pki().root))  # a stranger root
    result = v.verify(
        _evidence_b64(b["report_b64"], b["cert_chain_pem"]),
        expected_nonce=b["nonce"],
        now=NOW,
    )
    assert not result.verified
    assert "trusted root" in (result.reason or "")


# -- synthetic NVIDIA-format helpers (controllable nonce) ----------------------


def _p384():
    return ec.generate_private_key(ec.SECP384R1())


def _cert(subject, issuer_name, subj_key, issuer_key, *, ca=False, nb=None, na=None):
    b = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_name)]))
        .public_key(subj_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(nb or (NOW - timedelta(days=1)))
        .not_valid_after(na or (NOW + timedelta(days=365)))
    )
    if ca:
        b = b.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    return b.sign(issuer_key, hashes.SHA384())


def _pem(cert) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode()


class _Pki:
    """Synthetic NVIDIA-like device chain (all P-384): root -> inter -> leaf."""

    def __init__(self):
        self.root_key = _p384()
        self.root = _cert("nv-test-root", "nv-test-root", self.root_key, self.root_key, ca=True)
        self.inter_key = _p384()
        self.inter = _cert("nv-test-inter", "nv-test-root", self.inter_key, self.root_key, ca=True)
        self.leaf_key = _p384()
        self.leaf = _cert("nv-test-gsp-fmc-lf", "nv-test-inter", self.leaf_key, self.inter_key)

    def chain_pem(self) -> str:
        return _pem(self.leaf) + _pem(self.inter) + _pem(self.root)


def _nv_report(nonce_hex: str, leaf_key, measurements: bytes = b"synthetic-gpu-measurements") -> bytes:
    """Build a report in the real NVIDIA layout signed by leaf_key."""
    signed_body = b"\x11\xe0\x01\xff" + bytes.fromhex(nonce_hex) + measurements
    der = leaf_key.sign(signed_body, ec.ECDSA(hashes.SHA384()))
    r, s = decode_dss_signature(der)
    raw = r.to_bytes(48, "big") + s.to_bytes(48, "big")
    return signed_body + raw


def _synth_evidence(pki: _Pki, nonce_hex: str) -> str:
    report = _nv_report(nonce_hex, pki.leaf_key)
    return _evidence_b64(base64.b64encode(report).decode(), pki.chain_pem())


def test_synthetic_report_verifies():
    pki = _Pki()
    v = build_gpu_verifier(_pem(pki.root))
    r = v.verify(_synth_evidence(pki, "ab" * 32), expected_nonce="ab" * 32, now=NOW)
    assert r.verified, r.reason


def test_build_gpu_verifier_shape():
    assert isinstance(build_gpu_verifier(_pem(_Pki().root)), NvidiaGpuVerifier)


# -- KBS integration -----------------------------------------------------------


def _evidence(nonce, *, gpu_quote_b64, current, rim):
    return CompositeEvidence(
        cpu=CpuQuote(
            platform="amd-sev-snp",
            assurance_tier="hardware-attested",
            serving_image_measurement=current,
            nonce_echo=nonce,
            attestation_key_id="vcek:test",
        ),
        gpu=GpuReport(
            platform="nvidia-cc-gpu", measurement=rim, nonce_echo=nonce, quote_b64=gpu_quote_b64
        ),
    )


def _measurements(m):
    ams = m.release_policy.required_serving_image.accepted_measurements
    current = next(x.measurement for x in ams if x.status.value == "current")
    rim = m.release_policy.required_gpu_measurement.rim_pin
    return current, rim


def test_kbs_releases_with_verified_gpu(example_manifest):
    pki = _Pki()
    current, rim = _measurements(example_manifest)
    kbs = KeyBrokerService(
        {example_manifest.weights_hash: b"KEY"},
        now=lambda: NOW,
        gpu_report_verifier=build_gpu_verifier(_pem(pki.root)),
    )
    challenge = kbs.issue_challenge()
    ev = _evidence(challenge.nonce, gpu_quote_b64=_synth_evidence(pki, challenge.nonce), current=current, rim=rim)
    decision = kbs.verify_and_release(example_manifest, ev)
    assert decision.released
    assert any(c.name == "gpu_report_verified" and c.passed for c in decision.checks)


def test_kbs_denies_untrusted_gpu(example_manifest):
    pki = _Pki()
    current, rim = _measurements(example_manifest)
    kbs = KeyBrokerService(
        {example_manifest.weights_hash: b"KEY"},
        now=lambda: NOW,
        gpu_report_verifier=build_gpu_verifier(_pem(_Pki().root)),  # different root
    )
    challenge = kbs.issue_challenge()
    ev = _evidence(challenge.nonce, gpu_quote_b64=_synth_evidence(pki, challenge.nonce), current=current, rim=rim)
    decision = kbs.verify_and_release(example_manifest, ev)
    assert not decision.released
    assert any(c.name == "gpu_report_verified" and not c.passed for c in decision.checks)


def test_kbs_denies_gpu_verifier_set_but_no_quote(example_manifest):
    current, rim = _measurements(example_manifest)
    kbs = KeyBrokerService(
        {example_manifest.weights_hash: b"KEY"},
        now=lambda: NOW,
        gpu_report_verifier=build_gpu_verifier(_pem(_Pki().root)),
    )
    challenge = kbs.issue_challenge()
    ev = _evidence(challenge.nonce, gpu_quote_b64=None, current=current, rim=rim)
    decision = kbs.verify_and_release(example_manifest, ev)
    assert not decision.released
    assert any(c.name == "gpu_report_verified" and not c.passed for c in decision.checks)


def test_kbs_without_gpu_verifier_notes_structural_only(example_manifest):
    current, rim = _measurements(example_manifest)
    kbs = KeyBrokerService({example_manifest.weights_hash: b"KEY"}, now=lambda: NOW)
    challenge = kbs.issue_challenge()
    ev = _evidence(challenge.nonce, gpu_quote_b64=None, current=current, rim=rim)
    decision = kbs.verify_and_release(example_manifest, ev)
    assert decision.released
    chk = [c for c in decision.checks if c.name == "gpu_report_verified"][0]
    assert chk.passed and "structural trust only" in (chk.detail or "")


def test_kbs_gpu_must_bind_this_nonce(example_manifest):
    """A crypto-valid GPU report bound to a different nonce than this challenge
    fails: the raw nonce echoed in the report must equal the KBS challenge."""
    pki = _Pki()
    current, rim = _measurements(example_manifest)
    kbs = KeyBrokerService(
        {example_manifest.weights_hash: b"KEY"},
        now=lambda: NOW,
        gpu_report_verifier=build_gpu_verifier(_pem(pki.root)),
    )
    challenge = kbs.issue_challenge()
    # report bound to a stale nonce, though the structured nonce_echo is set to this challenge
    stale = _synth_evidence(pki, "cd" * 32)
    ev = _evidence(challenge.nonce, gpu_quote_b64=stale, current=current, rim=rim)
    decision = kbs.verify_and_release(example_manifest, ev)
    assert not decision.released
    assert any(c.name == "gpu_report_verified" and not c.passed for c in decision.checks)
