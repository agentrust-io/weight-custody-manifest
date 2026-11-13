"""GPU evidence parsing and the KBS boundary before revocation queries.

Synthetic certificates and scripted status answers exercise software admission,
not NVIDIA OCSP signature validation or a live GPU.
"""

from __future__ import annotations

import base64
import json
from datetime import datetime, timedelta, timezone
from unittest.mock import Mock

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from wcm._quote_verify import QuoteVerification
from wcm._seal import generate_transport_keypair
from wcm.attestation import CompositeEvidence, CpuQuote, GpuReport
from wcm.gpu_revocation import Answer, NvidiaOcspClient, chain_from_evidence
from wcm.kbs import KeyBrokerService
from wcm.renewal import manifest_identity

from tests.conftest import waive
from tests.test_certificate_policy import _non_positive_serial_pem

NOW = datetime(2026, 11, 1, tzinfo=timezone.utc)


@pytest.fixture
def certificates():
    result = []
    for name in ("synthetic-leaf", "synthetic-brom", "synthetic-ica", "synthetic-root"):
        key = ec.generate_private_key(ec.SECP384R1())
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
        result.append(
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(NOW - timedelta(days=1))
            .not_valid_after(NOW + timedelta(days=1))
            .sign(key, hashes.SHA384())
        )
    return result


def pem_chain(certificates):
    return b"".join(
        c.public_bytes(serialization.Encoding.PEM) for c in certificates
    ).decode()


def encode(document):
    return base64.b64encode(json.dumps(document).encode()).decode()


def duplicate_document(pem):
    return (
        '{"report_b64":"AAAA","cert_chain_pem":'
        + json.dumps(pem)
        + ',"cert_chain_pem":'
        + json.dumps(pem)
        + "}"
    )


def test_valid_chain_bytes_and_order_are_preserved(certificates):
    parsed = chain_from_evidence(
        encode({"report_b64": "AAAA", "cert_chain_pem": pem_chain(certificates)})
    )
    assert [c.public_bytes(serialization.Encoding.DER) for c in parsed] == [
        c.public_bytes(serialization.Encoding.DER) for c in certificates
    ]


@pytest.mark.parametrize("field", ["cert_chain_pem", "report_b64", "unrelated"])
def test_duplicate_members_are_refused(certificates, field):
    document = json.dumps(
        {
            "report_b64": "AAAA",
            "cert_chain_pem": pem_chain(certificates),
            "unrelated": 1,
        }
    )
    repeated = (
        pem_chain(certificates)
        if field == "cert_chain_pem"
        else "AAAA"
        if field == "report_b64"
        else 2
    )
    document = (
        document[:-1] + "," + json.dumps(field) + ":" + json.dumps(repeated) + "}"
    )
    with pytest.raises(ValueError, match="duplicate"):
        chain_from_evidence(base64.b64encode(document.encode()).decode())


@pytest.mark.parametrize(
    "document",
    [
        [],
        None,
        1,
        "text",
        {},
        {"cert_chain_pem": None},
        {"cert_chain_pem": 1},
        {"cert_chain_pem": []},
        {"cert_chain_pem": ""},
        {"cert_chain_pem": " "},
        {"cert_chain_pem": "not PEM"},
    ],
)
def test_nonobject_or_invalid_chain_is_refused(document):
    with pytest.raises(ValueError):
        chain_from_evidence(encode(document))


@pytest.mark.parametrize("suffix", ["\n", " ", "!", "@"])
def test_non_base64_characters_are_not_ignored(certificates, suffix):
    valid = encode({"cert_chain_pem": pem_chain(certificates)})
    assert len(chain_from_evidence(valid)) == 4
    with pytest.raises(ValueError):
        chain_from_evidence(valid[:4] + suffix + valid[4:])


def broker_and_evidence(manifest, certificates, verifier):
    manifest = waive(manifest)
    _, public = generate_transport_keypair()
    client = Mock(spec=NvidiaOcspClient)
    client.status.return_value = Answer(
        "GOOD", "scripted test answer", NOW + timedelta(minutes=5)
    )
    broker = KeyBrokerService(
        {manifest.weights_hash: b"KEY"},
        now=lambda: NOW,
        gpu_report_verifier=verifier,
        gpu_revocation_client=client,
        trusted_manifest_identities={manifest_identity(manifest)},
    )
    nonce = broker.issue_challenge().nonce
    current = next(
        x.measurement
        for x in manifest.release_policy.required_serving_image.accepted_measurements
        if x.status.value == "current"
    )
    evidence = CompositeEvidence(
        cpu=CpuQuote(
            platform="amd-sev-snp",
            assurance_tier="hardware-attested",
            serving_image_measurement=current,
            nonce_echo=nonce,
            transport_public_key=public,
            attestation_key_id="synthetic-key",
        ),
        gpu=GpuReport(
            platform="nvidia-cc-gpu",
            nonce_echo=nonce,
            measurement=manifest.release_policy.required_gpu_measurement.rim_pin,
            quote_b64=encode(
                {"report_b64": "AAAA", "cert_chain_pem": pem_chain(certificates)}
            ),
        ),
    )
    return broker, manifest, evidence, client


def test_valid_software_twin_reaches_revocation_queries(example_manifest, certificates):
    verifier = Mock()
    verifier.verify.return_value = QuoteVerification(
        True,
        "scripted test verifier",
        gpu_measurement=example_manifest.release_policy.required_gpu_measurement.rim_pin,
    )
    broker, manifest, evidence, client = broker_and_evidence(
        example_manifest, certificates, verifier
    )
    decision = broker.verify_and_release(manifest, evidence)
    assert decision.released is True
    assert client.status.call_count == 2
    assert client.status.call_args_list[0].args[:2] == (
        certificates[1],
        certificates[2],
    )
    assert client.status.call_args_list[1].args[:2] == (
        certificates[2],
        certificates[3],
    )


@pytest.mark.parametrize("raise_error", [False, True])
def test_rejected_gpu_report_never_queries_revocation(
    example_manifest, certificates, raise_error
):
    verifier = Mock()
    if raise_error:
        verifier.verify.side_effect = ValueError("scripted verifier error")
    else:
        verifier.verify.return_value = QuoteVerification(False, "scripted denial")
    broker, manifest, evidence, client = broker_and_evidence(
        example_manifest, certificates, verifier
    )
    decision = broker.verify_and_release(manifest, evidence)
    assert decision.released is False
    assert decision.key is None and decision.sealed_key is None
    client.status.assert_not_called()
    assert (
        next(c for c in decision.checks if c.name == "attestation_revocation").passed
        is False
    )


def test_ambiguous_json_never_reaches_revocation_even_under_waiver(
    example_manifest, certificates
):
    broker, manifest, evidence, client = broker_and_evidence(
        example_manifest, certificates, None
    )
    evidence.gpu.quote_b64 = base64.b64encode(
        duplicate_document(pem_chain(certificates)).encode()
    ).decode()
    decision = broker.verify_and_release(manifest, evidence)
    assert decision.released is False
    assert decision.key is None and decision.sealed_key is None
    client.status.assert_not_called()
    assert (
        next(c for c in decision.checks if c.name == "attestation_revocation").passed
        is False
    )


def test_zero_serial_chain_is_refused_before_query_even_under_waiver(
    example_manifest, certificates
):
    broker, manifest, evidence, client = broker_and_evidence(
        example_manifest, certificates, None
    )
    pem = _non_positive_serial_pem().decode() + pem_chain(certificates[1:])
    quote = encode({"report_b64": "AAAA", "cert_chain_pem": pem})
    with pytest.raises(ValueError, match="certificate"):
        chain_from_evidence(quote)
    evidence.gpu.quote_b64 = quote
    decision = broker.verify_and_release(manifest, evidence)
    assert decision.released is False
    assert decision.key is None and decision.sealed_key is None
    assert not next(c for c in decision.checks if c.name == "attestation_revocation").passed
    client.status.assert_not_called()


def test_explicit_verification_waiver_still_queries_valid_chain(
    example_manifest, certificates
):
    broker, manifest, evidence, client = broker_and_evidence(
        example_manifest, certificates, None
    )
    decision = broker.verify_and_release(manifest, evidence)
    assert decision.released is True
    assert client.status.call_count == 2


@pytest.mark.parametrize("tamper", [False, True])
def test_captured_gpu_verifier_controls_revocation_admission(
    example_manifest, certificates, tamper
):
    from pathlib import Path
    from unittest.mock import patch

    from wcm.nvidia import build_gpu_verifier

    fixtures = Path(__file__).parent / "fixtures"
    bundle = json.loads((fixtures / "gpu_h100_attestation.json").read_text())
    verifier = build_gpu_verifier(
        (fixtures / "nvidia_device_identity_ca.pem").read_text()
    )
    verified = verifier.verify(encode(bundle), expected_nonce=bundle["nonce"], now=NOW)
    assert verified.verified is True
    assert verified.gpu_measurement is not None
    policy = example_manifest.release_policy
    manifest = example_manifest.model_copy(
        update={
            "release_policy": policy.model_copy(
                update={
                    "required_gpu_measurement": policy.required_gpu_measurement.model_copy(
                        update={"rim_pin": verified.gpu_measurement}
                    )
                }
            )
        }
    )
    with patch("wcm._challenge.secrets.token_hex", return_value=bundle["nonce"]):
        broker, manifest, evidence, client = broker_and_evidence(
            manifest, certificates, verifier
        )
    if tamper:
        report = bytearray(base64.b64decode(bundle["report_b64"]))
        report[-1] ^= 1
        bundle["report_b64"] = base64.b64encode(report).decode()
    evidence.gpu.quote_b64 = encode(bundle)
    decision = broker.verify_and_release(manifest, evidence)
    if tamper:
        assert decision.released is False
        assert decision.key is None and decision.sealed_key is None
        client.status.assert_not_called()
    else:
        assert decision.released is True
        assert client.status.call_count == len(chain_from_evidence(encode(bundle))) - 2
