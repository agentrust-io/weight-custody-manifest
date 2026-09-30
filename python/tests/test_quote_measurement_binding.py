"""The key broker must compare the serving-image measurement with the SIGNED report.

``QuoteVerifier.verify`` received ``expected_workload_measurement`` and discarded
it, so the release decision rested on ``serving_image_measurement``, a structured
field whoever builds the evidence controls. A genuine report from an unapproved
image could name an approved measurement there and receive the key.
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import json
import struct
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.x509.oid import NameOID

from wcm import (
    KeyBrokerService,
    QuoteVerifier,
    SnpQuoteParser,
    TrustStore,
    WeightCustodyManifest,
    generate_transport_keypair,
    manifest_identity,
)
from wcm.attestation import CompositeEvidence, CpuQuote

NOW = datetime.datetime.now(datetime.timezone.utc)
EXAMPLE = Path(__file__).resolve().parents[1] / "examples" / "manifest.example.json"


def _p384() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP384R1())


def _cert(subject, issuer, subject_key, issuer_key, ca=False):
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer)]))
        .public_key(subject_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - datetime.timedelta(days=1))
        .not_valid_after(NOW + datetime.timedelta(days=30))
    )
    if ca:
        builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    return builder.sign(issuer_key, hashes.SHA384())


ROOT_KEY = _p384()
ROOT = _cert("ark", "ark", ROOT_KEY, ROOT_KEY, ca=True)
VCEK_KEY = _p384()
VCEK = _cert("vcek", "ark", VCEK_KEY, ROOT_KEY)


def _snp_report(nonce_hex: str, transport_key_hex: str, measurement: bytes) -> bytes:
    body = bytearray(0x2A0)
    struct.pack_into("<I", body, 0, 3)
    body[0x50:0x70] = hashlib.sha256(bytes.fromhex(nonce_hex) + bytes.fromhex(transport_key_hex)).digest()
    body[0x90 : 0x90 + 48] = measurement
    r, s = decode_dss_signature(VCEK_KEY.sign(bytes(body), ec.ECDSA(hashes.SHA384())))
    sig = bytearray(512)
    sig[0:48] = r.to_bytes(48, "little")
    sig[72:120] = s.to_bytes(48, "little")
    return bytes(body) + bytes(sig)


def _manifest() -> WeightCustodyManifest:
    doc = json.loads(EXAMPLE.read_text(encoding="utf-8"))
    doc["release_policy"]["required_hw_platform"] = ["amd-sev-snp"]
    doc["release_policy"].pop("required_gpu_measurement")
    return WeightCustodyManifest.model_validate(doc)


def _release(signed_measurement: bytes, claimed: str, manifest: WeightCustodyManifest | None = None):
    manifest = manifest or _manifest()
    trust = TrustStore()
    trust.add_root(ROOT)
    kbs = KeyBrokerService(
        {manifest.weights_hash: b"K" * 32},
        cpu_quote_verifier=QuoteVerifier(SnpQuoteParser(VCEK, []), trust),
        require_channel_binding=True,
        require_cpu_quote_verification=True,
        require_gpu_report_verification=True,
        trusted_manifest_identities={manifest_identity(manifest)},
    )
    challenge = kbs.issue_challenge()
    _, transport_key = generate_transport_keypair()
    evidence = CompositeEvidence(
        cpu=CpuQuote(
            platform="amd-sev-snp",
            assurance_tier="hardware-attested",
            serving_image_measurement=claimed,
            nonce_echo=challenge.nonce,
            attestation_key_id="vcek:test",
            quote_b64=base64.b64encode(_snp_report(challenge.nonce, transport_key, signed_measurement)).decode(),
            transport_public_key=transport_key,
        )
    )
    return kbs.verify_and_release(manifest, evidence)


def _current(manifest: WeightCustodyManifest) -> str:
    accepted = manifest.release_policy.required_serving_image.accepted_measurements
    return next(a.measurement for a in accepted if a.status.value == "current")


def test_policy_under_test_is_not_empty():
    assert _manifest().release_policy.required_serving_image.accepted_measurements


def test_unapproved_signed_measurement_is_refused_even_when_the_claim_names_an_approved_one():
    unapproved = b"\xee" * 48
    decision = _release(unapproved, claimed=_current(_manifest()))
    assert not decision.released
    assert decision.sealed_key is None
    detail = {c.name: c.detail for c in decision.failures}
    assert "measurement" in detail["cpu_quote_verified"]


def test_matching_signed_measurement_still_releases():
    """Control: a genuine approved image is not refused by the new check."""
    launch = b"" * 48
    digest = "sha256:" + hashlib.sha256(launch).hexdigest()
    doc = json.loads(EXAMPLE.read_text(encoding="utf-8"))
    doc["release_policy"]["required_hw_platform"] = ["amd-sev-snp"]
    doc["release_policy"].pop("required_gpu_measurement")
    accepted = doc["release_policy"]["required_serving_image"]["accepted_measurements"]
    next(a for a in accepted if a["status"] == "current")["measurement"] = digest
    decision = _release(launch, claimed=digest, manifest=WeightCustodyManifest.model_validate(doc))
    assert decision.released, [(c.name, c.detail) for c in decision.failures]


@pytest.mark.parametrize("expected", ["sha256:" + "00" * 32, "sha256:" + hashlib.sha256(b"\xee" * 48).hexdigest()])
def test_verifier_compares_the_signed_measurement(expected):
    trust = TrustStore()
    trust.add_root(ROOT)
    nonce = "ab" * 32
    report = _snp_report(nonce, "", b"\xee" * 48)
    result = QuoteVerifier(SnpQuoteParser(VCEK, []), trust).verify(
        base64.b64encode(report).decode(), expected_nonce=nonce, expected_workload_measurement=expected
    )
    assert result.verified is expected.endswith(hashlib.sha256(b"\xee" * 48).hexdigest())
