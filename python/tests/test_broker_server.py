"""HTTP boot-to-provision-to-release using synthetic native-SNP signatures."""
import base64
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
import json

import pytest
pytest.importorskip("fastapi")
from fastapi.testclient import TestClient
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from wcm import open_sealed
from wcm._hw_providers import SevSnpProvider
from wcm.broker_receiver import BrokerReceiver
from wcm.broker_server import app_from_env, create_app
from wcm.providers import AttestationUnavailableError
from tests.test_broker_receiver import KEY, setup, signed_report, workload_evidence  # noqa: F401


def challenge_json(challenge):
    return {"nonce": challenge.nonce, "issued_at": challenge.issued_at.isoformat(),
            "expires_at": challenge.expires_at.isoformat()}


def envelope_json(envelope):
    return {"nonce": envelope.nonce,
            "ciphertext_b64": base64.b64encode(envelope.ciphertext).decode(),
            "owner_signature_b64": base64.b64encode(envelope.owner_signature).decode()}


def http_envelope(setup, client, monkeypatch):
    _, owner, _, _, _, vcek, signing_key, _ = setup
    monkeypatch.setattr(SevSnpProvider, "_fetch_report", lambda self, data: signed_report(signing_key, data))
    challenge = owner.issue_challenge()
    response = client.post("/provisioning/report", json=challenge_json(challenge))
    assert response.status_code == 200, response.text
    report = response.json()
    assert set(report) == {"report_b64", "transport_public_key"}
    envelope = owner.provision(nonce=challenge.nonce, report=base64.b64decode(report["report_b64"]),
                               vcek=vcek, intermediates=[], transport_public_key=report["transport_public_key"],
                               model_key=KEY)
    return envelope_json(envelope), challenge


def test_http_provision_install_release_and_install_replay(setup, monkeypatch):
    receiver, _, _, _, manifest, _, _, _ = setup
    client = TestClient(create_app(receiver))
    assert client.get("/health").json() == {"status": "ok"}
    assert client.post("/challenge").status_code == 409
    envelope, challenge = http_envelope(setup, client, monkeypatch)
    assert client.post("/provisioning/install", json=envelope).json() == {"installed": True}
    assert client.post("/challenge").status_code == 200
    evidence, private = workload_evidence(setup)
    body = {"manifest": manifest.model_dump(mode="json"), "evidence": evidence.model_dump(mode="json")}
    result = client.post("/release", json=body)
    assert result.status_code == 200
    assert set(result.json()) == {"released", "sealed_key_b64", "checks"}
    assert result.json()["released"]
    assert open_sealed(base64.b64decode(result.json()["sealed_key_b64"]), private) == KEY
    assert KEY.decode() not in result.text and "key_b64" not in result.json()
    assert client.post("/provisioning/install", json=envelope).status_code == 409
    assert client.post("/provisioning/report", json=challenge_json(challenge)).status_code == 409


def test_missing_native_hardware_never_falls_back(setup, monkeypatch):
    receiver, owner, _, _, _, _, _, _ = setup
    def unavailable(self, report_data):
        raise AttestationUnavailableError("sensitive internal device diagnostics")
    monkeypatch.setattr(SevSnpProvider, "_fetch_report", unavailable)
    client = TestClient(create_app(receiver))
    result = client.post("/provisioning/report", json=challenge_json(owner.issue_challenge()))
    assert result.status_code == 503
    assert "sensitive" not in result.text
    assert "report_b64" not in result.json()
    assert client.post("/challenge").status_code == 409


@pytest.mark.parametrize("change", ["naive", "nonutc", "extra", "badnonce", "expired", "reversed"])
def test_invalid_challenge_is_rejected_before_device_access(setup, monkeypatch, change):
    receiver, owner, _, _, _, _, _, _ = setup
    monkeypatch.setattr(SevSnpProvider, "_fetch_report", lambda *args: pytest.fail("invalid request reached device"))
    body = challenge_json(owner.issue_challenge())
    if change == "naive":
        body["issued_at"] = "2026-09-17T00:00:00"
    elif change == "nonutc":
        body["issued_at"] = "2026-09-17T00:00:00+01:00"
    elif change == "extra":
        body["model_key"] = "accidental-plaintext-secret"
    elif change == "badnonce":
        body["nonce"] = "accidental-plaintext-secret"
    elif change == "expired":
        body["issued_at"] = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
        body["expires_at"] = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
    else:
        body["expires_at"] = body["issued_at"]
    result = TestClient(create_app(receiver)).post("/provisioning/report", json=body)
    assert result.status_code in (400, 422)
    assert "accidental-plaintext-secret" not in result.text


@pytest.mark.parametrize("attack", ["signature", "nonce", "ciphertext", "extra", "bad-base64"])
def test_invalid_envelope_cannot_enable_release(setup, monkeypatch, attack):
    receiver = setup[0]
    client = TestClient(create_app(receiver))
    body, _ = http_envelope(setup, client, monkeypatch)
    if attack == "signature":
        body["owner_signature_b64"] = base64.b64encode(bytes(64)).decode()
    elif attack == "nonce":
        body["nonce"] = "00" * 32
    elif attack == "ciphertext":
        body["ciphertext_b64"] = base64.b64encode(bytes(93)).decode()
    elif attack == "extra":
        body["model_key"] = "accidental-plaintext-secret"
    else:
        body["owner_signature_b64"] = "!" * 88
    result = client.post("/provisioning/install", json=body)
    assert result.status_code in (400, 422)
    assert "accidental-plaintext-secret" not in result.text
    assert client.post("/challenge").status_code == 409


def test_http_restart_rejects_previous_boot_envelope(setup, monkeypatch):
    _, _, config, policy, _, _, _, _ = setup
    initial = TestClient(create_app(setup[0]))
    body, challenge = http_envelope(setup, initial, monkeypatch)
    restarted = TestClient(create_app(BrokerReceiver(config, policy)))
    assert restarted.post("/provisioning/report", json=challenge_json(challenge)).status_code == 200
    assert restarted.post("/provisioning/install", json=body).status_code == 400
    assert restarted.post("/challenge").status_code == 409


def test_malformed_release_does_not_echo_input(setup):
    result = TestClient(create_app(setup[0])).post("/release", json={
        "manifest": {"accidental-plaintext-secret": "sensitive"}, "evidence": {},
    })
    assert result.status_code == 422
    assert "accidental-plaintext-secret" not in result.text


def test_env_factory_requires_config_and_has_no_keystore_fallback(monkeypatch):
    monkeypatch.delenv("WCM_BROKER_CONFIG_FILE", raising=False)
    monkeypatch.setenv("WCM_KEYSTORE_FILE", "must-not-be-read.json")
    with pytest.raises(ValueError, match="WCM_BROKER_CONFIG_FILE"):
        app_from_env()


def test_env_factory_reads_effective_inputs_and_rejects_plaintext_key_config(setup, tmp_path, monkeypatch):
    _, _, config, policy, _, _, _, _ = setup
    (tmp_path / "cpu-root.pem").write_bytes(x509.load_der_x509_certificate(config.cpu_root_der).public_bytes(serialization.Encoding.PEM))
    (tmp_path / "cpu-vcek.pem").write_bytes(x509.load_der_x509_certificate(config.cpu_vcek_der).public_bytes(serialization.Encoding.PEM))
    (tmp_path / "owner.pub").write_bytes(config.owner_public_key)
    policy_json = asdict(policy)
    for field in ("required_platform_fields", "forbidden_platform_fields"):
        policy_json[field] = sorted(policy_json[field])
    data = {"configuration": {
        "cpu_root_file": "cpu-root.pem", "cpu_vcek_file": "cpu-vcek.pem",
        "cpu_intermediate_files": [], "trusted_manifest_identities": sorted(config.trusted_manifest_identities),
        "owner_public_key_file": "owner.pub",
    }, "policy": policy_json}
    path = tmp_path / "broker.json"
    path.write_text(json.dumps(data))
    monkeypatch.setenv("WCM_BROKER_CONFIG_FILE", str(path))
    monkeypatch.setenv("WCM_KEYSTORE_FILE", "must-not-be-read.json")
    app = app_from_env()
    assert TestClient(app).post("/challenge").status_code == 409
    data["configuration"]["model_key"] = "accidental-plaintext-secret"
    path.write_text(json.dumps(data))
    with pytest.raises(ValueError, match="unrecognized"):
        app_from_env()
