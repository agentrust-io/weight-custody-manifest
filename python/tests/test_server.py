"""KBS HTTP server (reference surface). Skipped if fastapi isn't installed."""
from __future__ import annotations

import base64

import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from wcm import (  # noqa: E402
    KeyBrokerService,
    SoftwareProvider,
    generate_transport_keypair,
    open_sealed,
)
from wcm.server import create_app  # noqa: E402

KEY = b"served-decryption-key-32bytes-xx"


@pytest.fixture
def client_and_manifest(example_manifest):
    # The reference server requires channel binding (SPEC 3.2): the key leaves
    # only sealed to the enclave's attested transport key.
    kbs = KeyBrokerService(
        {example_manifest.weights_hash: KEY}, require_channel_binding=True
    )
    return TestClient(create_app(kbs)), kbs, example_manifest


def _measurements(m):
    ams = m.release_policy.required_serving_image.accepted_measurements
    current = next(x.measurement for x in ams if x.status.value == "current")
    rim = m.release_policy.required_gpu_measurement.rim_pin
    return current, rim


def test_health(client_and_manifest):
    client, _, _ = client_and_manifest
    r = client.get("/health")
    assert r.status_code == 200 and r.json()["status"] == "ok"


def test_challenge_issues_nonce(client_and_manifest):
    client, _, _ = client_and_manifest
    r = client.post("/challenge")
    assert r.status_code == 200
    assert len(r.json()["nonce"]) == 64


def test_release_happy_path(client_and_manifest):
    client, kbs, manifest = client_and_manifest
    current, rim = _measurements(manifest)
    nonce = client.post("/challenge").json()["nonce"]
    # Reconstruct the challenge object's nonce for the provider via a direct issue
    # is not possible over HTTP; instead build evidence bound to the issued nonce.
    from wcm._challenge import Challenge
    from datetime import datetime, timezone

    priv, pub = generate_transport_keypair()
    ch = Challenge(nonce=nonce, issued_at=datetime.now(timezone.utc), expires_at=datetime.now(timezone.utc))
    evidence = SoftwareProvider().produce(
        ch, serving_image_measurement=current, gpu_measurement=rim, transport_public_key=pub
    )
    body = {
        "manifest": manifest.model_dump(mode="json", exclude_none=True),
        "evidence": evidence.model_dump(mode="json", exclude_none=True),
    }
    r = client.post("/release", json=body)
    assert r.status_code == 200
    data = r.json()
    assert data["released"] is True
    # The server never returns a raw key; only the enclave's transport key opens it.
    assert "key_b64" not in data
    assert open_sealed(base64.b64decode(data["sealed_key_b64"]), priv) == KEY


def test_release_without_transport_key_denied(client_and_manifest):
    client, _, manifest = client_and_manifest
    current, rim = _measurements(manifest)
    nonce = client.post("/challenge").json()["nonce"]
    from wcm._challenge import Challenge
    from datetime import datetime, timezone

    ch = Challenge(nonce=nonce, issued_at=datetime.now(timezone.utc), expires_at=datetime.now(timezone.utc))
    # No transport key: the channel-binding gate denies release.
    evidence = SoftwareProvider().produce(
        ch, serving_image_measurement=current, gpu_measurement=rim
    )
    body = {
        "manifest": manifest.model_dump(mode="json", exclude_none=True),
        "evidence": evidence.model_dump(mode="json", exclude_none=True),
    }
    data = client.post("/release", json=body).json()
    assert data["released"] is False and data["sealed_key_b64"] is None
    assert any(c["name"] == "channel_binding" and not c["passed"] for c in data["checks"])


def test_release_denies_bad_evidence(client_and_manifest):
    client, _, manifest = client_and_manifest
    current, _ = _measurements(manifest)
    nonce = client.post("/challenge").json()["nonce"]
    from wcm._challenge import Challenge
    from datetime import datetime, timezone

    _, pub = generate_transport_keypair()
    ch = Challenge(nonce=nonce, issued_at=datetime.now(timezone.utc), expires_at=datetime.now(timezone.utc))
    # No GPU report -> gpu check fails.
    evidence = SoftwareProvider().produce(
        ch, serving_image_measurement=current, include_gpu=False, transport_public_key=pub
    )
    body = {
        "manifest": manifest.model_dump(mode="json", exclude_none=True),
        "evidence": evidence.model_dump(mode="json", exclude_none=True),
    }
    r = client.post("/release", json=body)
    assert r.status_code == 200
    data = r.json()
    assert data["released"] is False and data["sealed_key_b64"] is None


def test_release_malformed_manifest_422(client_and_manifest):
    client, _, _ = client_and_manifest
    r = client.post("/release", json={"manifest": {"bogus": 1}, "evidence": {"cpu": {}}})
    assert r.status_code == 422


def test_app_from_env_empty_keystore(monkeypatch):
    monkeypatch.delenv("WCM_KEYSTORE_FILE", raising=False)
    from wcm.server import app_from_env

    client = TestClient(app_from_env())
    assert client.get("/health").json()["status"] == "ok"


def test_app_from_env_loads_keystore(tmp_path, monkeypatch, example_manifest):
    import json

    ks = tmp_path / "keystore.json"
    ks.write_text(json.dumps({example_manifest.weights_hash: base64.b64encode(KEY).decode()}))
    monkeypatch.setenv("WCM_KEYSTORE_FILE", str(ks))
    from wcm.server import build_kbs_from_env

    kbs = build_kbs_from_env()
    # The key loaded for the example weights_hash decodes back to KEY.
    assert kbs._keystore[example_manifest.weights_hash] == KEY  # type: ignore[attr-defined]
