"""NVIDIA CC GPU-report verification against a synthetic device PKI.

Mirrors test_quote_verify: a real device-root -> device -> attestation-key chain
signs a GPU report body whose REPORT_DATA binds the KBS nonce, driving
``nvidia.build_gpu_verifier`` and the KBS ``gpu_report_verifier`` hook through the
happy path and the failure modes. The real NVIDIA device root and binary SPDM
offsets are not needed here; this validates the verification machinery with real
cryptography, exactly as the CPU-quote path is validated.
"""
from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from wcm import (
    CompositeEvidence,
    CpuQuote,
    GpuReport,
    KeyBrokerService,
    NvidiaCcReportParser,
    QuoteVerifier,
    build_gpu_verifier,
)

NOW = datetime(2026, 7, 20, 12, 0, 0, tzinfo=timezone.utc)
NONCE = "ab" * 32


def _key():
    return ec.generate_private_key(ec.SECP256R1())


def _cert(subject, issuer_name, subject_key, issuer_key, *, ca=False, nb=None, na=None):
    b = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_name)]))
        .public_key(subject_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(nb or (NOW - timedelta(days=1)))
        .not_valid_after(na or (NOW + timedelta(days=365)))
    )
    if ca:
        b = b.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    return b.sign(issuer_key, hashes.SHA256())


def _pem(cert) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode()


class DevicePki:
    """Stand-in for NVIDIA's device-identity chain: root -> device -> attestation."""

    def __init__(self):
        self.root_key = _key()
        self.root = _cert(
            "nvidia-test-device-root", "nvidia-test-device-root", self.root_key, self.root_key, ca=True
        )
        self.dev_key = _key()
        self.dev = _cert(
            "nvidia-test-device", "nvidia-test-device-root", self.dev_key, self.root_key, ca=True
        )
        self.leaf_key = _key()
        self.leaf = _cert("gpu-attestation-key", "nvidia-test-device", self.leaf_key, self.dev_key)


def _gpu_report_body(nonce_hex: str, offset: int = 0) -> bytes:
    digest = hashlib.sha256(bytes.fromhex(nonce_hex)).digest()
    return bytes(offset) + digest + bytes(32) + b"gpu-measurements-rim"


def _gpu_container(pki: DevicePki, report_body: bytes, *, offset: int = 0, sign_key=None) -> str:
    signer = sign_key or pki.leaf_key
    signature = signer.sign(report_body, ec.ECDSA(hashes.SHA256()))
    doc = {
        "report_b64": base64.b64encode(report_body).decode(),
        "signature_b64": base64.b64encode(signature).decode(),
        "leaf_pem": _pem(pki.leaf),
        "intermediates_pem": [_pem(pki.dev)],
        "report_data_offset": offset,
    }
    return base64.b64encode(json.dumps(doc).encode()).decode()


def _verifier(pki: DevicePki) -> QuoteVerifier:
    return build_gpu_verifier(_pem(pki.root))


# -- verifier unit tests -------------------------------------------------------


def test_valid_gpu_report_verifies():
    pki = DevicePki()
    q = _gpu_container(pki, _gpu_report_body(NONCE))
    result = _verifier(pki).verify(q, expected_nonce=NONCE, now=NOW)
    assert result.verified
    assert "gpu-attestation-key" in (result.leaf_subject or "")


def test_untrusted_device_root_fails():
    pki = DevicePki()
    q = _gpu_container(pki, _gpu_report_body(NONCE))
    other = build_gpu_verifier(_pem(DevicePki().root))  # a different device root
    result = other.verify(q, expected_nonce=NONCE, now=NOW)
    assert not result.verified
    assert "trusted root" in (result.reason or "")


def test_tampered_gpu_report_fails_signature():
    pki = DevicePki()
    q = _gpu_container(pki, _gpu_report_body(NONCE))
    doc = json.loads(base64.b64decode(q))
    tampered = bytearray(base64.b64decode(doc["report_b64"]))
    tampered[-1] ^= 0xFF
    doc["report_b64"] = base64.b64encode(bytes(tampered)).decode()
    q2 = base64.b64encode(json.dumps(doc).encode()).decode()
    result = _verifier(pki).verify(q2, expected_nonce=NONCE, now=NOW)
    assert not result.verified
    assert "signature" in (result.reason or "")


def test_gpu_nonce_mismatch_fails_binding():
    pki = DevicePki()
    q = _gpu_container(pki, _gpu_report_body(NONCE))
    result = _verifier(pki).verify(q, expected_nonce="cd" * 32, now=NOW)
    assert not result.verified
    assert "REPORT_DATA" in (result.reason or "")


def test_build_gpu_verifier_shape():
    root_pem = _pem(DevicePki().root)
    assert isinstance(build_gpu_verifier(root_pem), QuoteVerifier)
    assert isinstance(build_gpu_verifier(root_pem, parser=NvidiaCcReportParser()), QuoteVerifier)


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
    pki = DevicePki()
    current, rim = _measurements(example_manifest)
    kbs = KeyBrokerService(
        {example_manifest.weights_hash: b"KEY"},
        now=lambda: NOW,
        gpu_report_verifier=_verifier(pki),
    )
    challenge = kbs.issue_challenge()
    gq = _gpu_container(pki, _gpu_report_body(challenge.nonce))
    ev = _evidence(challenge.nonce, gpu_quote_b64=gq, current=current, rim=rim)

    decision = kbs.verify_and_release(example_manifest, ev)
    assert decision.released
    assert any(c.name == "gpu_report_verified" and c.passed for c in decision.checks)


def test_kbs_denies_untrusted_gpu(example_manifest):
    pki = DevicePki()
    current, rim = _measurements(example_manifest)
    kbs = KeyBrokerService(
        {example_manifest.weights_hash: b"KEY"},
        now=lambda: NOW,
        gpu_report_verifier=build_gpu_verifier(_pem(DevicePki().root)),  # different root
    )
    challenge = kbs.issue_challenge()
    gq = _gpu_container(pki, _gpu_report_body(challenge.nonce))
    ev = _evidence(challenge.nonce, gpu_quote_b64=gq, current=current, rim=rim)

    decision = kbs.verify_and_release(example_manifest, ev)
    assert not decision.released
    assert any(c.name == "gpu_report_verified" and not c.passed for c in decision.checks)


def test_kbs_denies_gpu_verifier_set_but_no_quote(example_manifest):
    pki = DevicePki()
    current, rim = _measurements(example_manifest)
    kbs = KeyBrokerService(
        {example_manifest.weights_hash: b"KEY"},
        now=lambda: NOW,
        gpu_report_verifier=_verifier(pki),
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


def test_kbs_gpu_must_be_bound_to_this_nonce(example_manifest):
    """A crypto-valid GPU report built over a different nonce than this challenge
    fails: cryptographic verification requires the shared KBS nonce, not just the
    structured nonce_echo string."""
    pki = DevicePki()
    current, rim = _measurements(example_manifest)
    kbs = KeyBrokerService(
        {example_manifest.weights_hash: b"KEY"},
        now=lambda: NOW,
        gpu_report_verifier=_verifier(pki),
    )
    challenge = kbs.issue_challenge()
    # Report cryptographically bound to a stale/other nonce, though nonce_echo is
    # set to this challenge (so the structural _check_gpu would pass).
    gq = _gpu_container(pki, _gpu_report_body("cd" * 32))
    ev = _evidence(challenge.nonce, gpu_quote_b64=gq, current=current, rim=rim)

    decision = kbs.verify_and_release(example_manifest, ev)
    assert not decision.released
    assert any(c.name == "gpu_report_verified" and not c.passed for c in decision.checks)
