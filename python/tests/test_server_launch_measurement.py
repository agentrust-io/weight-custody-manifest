"""The environment-built server takes the serving-image measurement from the signed report.

``build_kbs_from_env`` used ``JsonQuoteParser()`` with no launch-measurement
offset, so ``QuoteVerifier`` had no signed measurement to compare and the
serving-image gate rested on the evidence's structured
``serving_image_measurement`` field. These tests drive the HTTP surface the
container runs.
"""
from __future__ import annotations

import base64
import datetime
import hashlib
import json
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from wcm import (  # noqa: E402
    JsonQuoteParser,
    QuoteVerifier,
    TrustStore,
    WeightCustodyManifest,
    generate_transport_keypair,
    manifest_identity,
)
from wcm.attestation import CompositeEvidence, CpuQuote  # noqa: E402
from wcm.server import build_kbs_from_env, create_app  # noqa: E402

NOW = datetime.datetime.now(datetime.timezone.utc)
EXAMPLE = Path(__file__).resolve().parents[1] / "examples" / "manifest.example.json"
KEY = b"K" * 32
SNP_MEASUREMENT_OFFSET = 0x90
UNAPPROVED = b"\xee" * 48
APPROVED = b"\x11" * 48


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
        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True
        )
    return builder.sign(issuer_key, hashes.SHA256())


ROOT_KEY = ec.generate_private_key(ec.SECP256R1())
ROOT = _cert("root", "root", ROOT_KEY, ROOT_KEY, ca=True)
LEAF_KEY = ec.generate_private_key(ec.SECP256R1())
LEAF = _cert("leaf", "root", LEAF_KEY, ROOT_KEY)


def _digest(measurement: bytes) -> str:
    return "sha256:" + hashlib.sha256(measurement).hexdigest()


def _manifest(current: str | None = None) -> WeightCustodyManifest:
    doc = json.loads(EXAMPLE.read_text(encoding="utf-8"))
    doc["release_policy"]["required_hw_platform"] = ["amd-sev-snp"]
    doc["release_policy"].pop("required_gpu_measurement")
    if current is not None:
        accepted = doc["release_policy"]["required_serving_image"]["accepted_measurements"]
        next(a for a in accepted if a["status"] == "current")["measurement"] = current
    return WeightCustodyManifest.model_validate(doc)


def _current(manifest: WeightCustodyManifest) -> str:
    accepted = manifest.release_policy.required_serving_image.accepted_measurements
    return next(a.measurement for a in accepted if a.status.value == "current")


def _quote(nonce_hex: str, transport_key_hex: str, measurement: bytes) -> str:
    """A signed JSON reference container: REPORT_DATA at 0, measurement at 0x90."""
    body = bytearray(0x2A0)
    body[0:32] = hashlib.sha256(
        bytes.fromhex(nonce_hex) + bytes.fromhex(transport_key_hex)
    ).digest()
    body[SNP_MEASUREMENT_OFFSET : SNP_MEASUREMENT_OFFSET + 48] = measurement
    signature = LEAF_KEY.sign(bytes(body), ec.ECDSA(hashes.SHA256()))
    document = {
        "report_b64": base64.b64encode(bytes(body)).decode(),
        "signature_b64": base64.b64encode(signature).decode(),
        "leaf_pem": LEAF.public_bytes(serialization.Encoding.PEM).decode(),
        "intermediates_pem": [],
    }
    return base64.b64encode(json.dumps(document).encode()).decode()


def _env(tmp_path, monkeypatch, manifest, *, offset: str | None = "0x90") -> None:
    root = tmp_path / "cpu-root.pem"
    root.write_bytes(ROOT.public_bytes(serialization.Encoding.PEM))
    keystore = tmp_path / "keystore.json"
    keystore.write_text(json.dumps({manifest.weights_hash: base64.b64encode(KEY).decode()}))
    identities = tmp_path / "manifest-identities.json"
    identities.write_text(json.dumps([manifest_identity(manifest)]))
    monkeypatch.setenv("WCM_CPU_TRUST_ROOT_FILE", str(root))
    monkeypatch.setenv("WCM_KEYSTORE_FILE", str(keystore))
    monkeypatch.setenv("WCM_TRUSTED_MANIFEST_IDENTITIES_FILE", str(identities))
    monkeypatch.delenv("WCM_GPU_TRUST_ROOT_FILE", raising=False)
    if offset is None:
        monkeypatch.delenv("WCM_CPU_LAUNCH_MEASUREMENT_OFFSET", raising=False)
    else:
        monkeypatch.setenv("WCM_CPU_LAUNCH_MEASUREMENT_OFFSET", offset)


def _post_release(manifest, signed_measurement: bytes, claimed: str) -> dict:
    client = TestClient(create_app(build_kbs_from_env()))
    nonce = client.post("/challenge").json()["nonce"]
    _, transport_key = generate_transport_keypair()
    evidence = CompositeEvidence(
        cpu=CpuQuote(
            platform="amd-sev-snp",
            assurance_tier="hardware-attested",
            serving_image_measurement=claimed,
            nonce_echo=nonce,
            attestation_key_id="leaf:test",
            quote_b64=_quote(nonce, transport_key, signed_measurement),
            transport_public_key=transport_key,
        )
    )
    response = client.post(
        "/release",
        json={
            "manifest": manifest.model_dump(mode="json", by_alias=True, exclude_none=True),
            "evidence": evidence.model_dump(mode="json", by_alias=True, exclude_none=True),
        },
    )
    assert response.status_code == 200, response.text
    return response.json()


def test_unapproved_signed_image_naming_an_approved_measurement_is_refused(
    tmp_path, monkeypatch
):
    manifest = _manifest()
    _env(tmp_path, monkeypatch, manifest)
    body = _post_release(manifest, UNAPPROVED, claimed=_current(manifest))
    assert body["released"] is False
    assert body["sealed_key_b64"] is None
    failed = {c["name"]: c["detail"] for c in body["checks"] if not c["passed"]}
    assert failed["cpu_quote_verified"] == "signed workload launch measurement mismatch"


def test_approved_signed_image_still_releases(tmp_path, monkeypatch):
    manifest = _manifest(current=_digest(APPROVED))
    _env(tmp_path, monkeypatch, manifest)
    body = _post_release(manifest, APPROVED, claimed=_digest(APPROVED))
    assert body["released"] is True, [c for c in body["checks"] if not c["passed"]]
    assert body["sealed_key_b64"]


def test_trust_root_without_launch_offset_refuses_to_start(tmp_path, monkeypatch):
    _env(tmp_path, monkeypatch, _manifest(), offset=None)
    with pytest.raises(ValueError, match="WCM_CPU_LAUNCH_MEASUREMENT_OFFSET"):
        build_kbs_from_env()


@pytest.mark.parametrize("value", ["", "  ", "abc", "-1", "0x"])
def test_malformed_launch_offset_refuses_to_start(tmp_path, monkeypatch, value):
    _env(tmp_path, monkeypatch, _manifest(), offset=value)
    with pytest.raises(ValueError, match="WCM_CPU_LAUNCH_MEASUREMENT_OFFSET"):
        build_kbs_from_env()


@pytest.mark.parametrize("value", ["0x90", "144"])
def test_launch_offset_accepts_hex_and_decimal(tmp_path, monkeypatch, value):
    manifest = _manifest()
    _env(tmp_path, monkeypatch, manifest, offset=value)
    body = _post_release(manifest, UNAPPROVED, claimed=_current(manifest))
    assert body["released"] is False


def test_offset_past_the_report_is_refused(tmp_path, monkeypatch):
    manifest = _manifest(current=_digest(APPROVED))
    _env(tmp_path, monkeypatch, manifest, offset="0x2A0")
    body = _post_release(manifest, APPROVED, claimed=_digest(APPROVED))
    assert body["released"] is False


def test_no_trust_root_still_starts_without_offset(monkeypatch):
    monkeypatch.delenv("WCM_CPU_TRUST_ROOT_FILE", raising=False)
    monkeypatch.delenv("WCM_CPU_LAUNCH_MEASUREMENT_OFFSET", raising=False)
    assert build_kbs_from_env()._cpu_quote_verifier is None  # type: ignore[attr-defined]


def test_required_launch_measurement_refuses_a_parser_that_yields_none():
    trust = TrustStore()
    trust.add_root(ROOT)
    nonce = "ab" * 32
    quote = _quote(nonce, "", UNAPPROVED)
    expected = _digest(APPROVED)
    lenient = QuoteVerifier(JsonQuoteParser(), trust)
    # Library default unchanged: a parser with no offset skips the comparison.
    assert lenient.verify(
        quote, expected_nonce=nonce, expected_workload_measurement=expected
    ).verified
    strict = QuoteVerifier(JsonQuoteParser(), trust, require_launch_measurement=True)
    result = strict.verify(quote, expected_nonce=nonce, expected_workload_measurement=expected)
    assert not result.verified
    assert result.reason == "quote carries no signed workload launch measurement"
    # No expected measurement: nothing to compare, so the flag does not refuse.
    assert strict.verify(quote, expected_nonce=nonce).verified
