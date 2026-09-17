"""Wire and owner-client controls with independently signed synthetic reports."""
import base64
from dataclasses import asdict
from datetime import datetime
import json
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from wcm import owner_provision
from wcm._challenge import Challenge
from wcm.broker_receiver import BrokerReceiver
from wcm.provisioning import ProvisioningEnvelope
from wcm.provisioning_wire import json_object, load_broker_inputs
from tests.test_broker_receiver import signed_report
from tests.test_provisioning import POLICY, KEY
from tests.test_snp import _vcek_chain


@pytest.fixture
def bundle(tmp_path):
    root, vcek, signing = _vcek_chain()
    owner_key = Ed25519PrivateKey.generate()
    (tmp_path / "root.pem").write_bytes(root.public_bytes(serialization.Encoding.PEM))
    (tmp_path / "vcek.pem").write_bytes(vcek.public_bytes(serialization.Encoding.PEM))
    (tmp_path / "owner-public").write_bytes(owner_key.public_key().public_bytes_raw())
    (tmp_path / "owner-private").write_bytes(owner_key.private_bytes_raw())
    (tmp_path / "model-key").write_bytes(KEY)
    policy = asdict(POLICY)
    for field in ("required_platform_fields", "forbidden_platform_fields"):
        policy[field] = sorted(policy[field])
    broker = {
        "configuration": {"cpu_root_file": "root.pem", "cpu_vcek_file": "vcek.pem",
            "cpu_intermediate_files": [], "trusted_manifest_identities": ["sha256:" + "33" * 32],
            "owner_public_key_file": "owner-public"},
        "policy": policy,
    }
    broker_path = tmp_path / "broker.json"
    broker_path.write_text(json.dumps(broker))
    config, _ = load_broker_inputs(broker_path)
    policy["configuration_sha256"] = config.digest()
    broker_path.write_text(json.dumps(broker))
    (tmp_path / "policy.json").write_text(json.dumps(policy))
    owner = {"policy_file": "policy.json", "owner_signing_key_file": "owner-private",
        "amd_root_file": "root.pem", "broker_vcek_file": "vcek.pem", "broker_intermediate_files": [],
        "model_key_file": "model-key", "epoch_database": "owner.sqlite", "epoch_namespace": "broker",
        "broker_url": "https://broker.example"}
    owner_path = tmp_path / "owner.json"
    owner_path.write_text(json.dumps(owner))
    return broker_path, owner_path, signing


def wire_receiver(bundle, monkeypatch, *, attack=None):
    broker_path, _, signing = bundle
    receiver = BrokerReceiver(*load_broker_inputs(broker_path))
    calls = []

    def post(url, payload):
        calls.append((url, payload))
        if url.endswith("/report"):
            challenge = Challenge(payload["nonce"], datetime.fromisoformat(payload["issued_at"]),
                                  datetime.fromisoformat(payload["expires_at"]))
            report = signed_report(signing, receiver.provisioning_report_data(challenge))
            public = receiver.transport_public_key
            if attack == "key":
                public = "99" * 32
            elif attack == "report":
                report = report[:100] + bytes([report[100] ^ 1]) + report[101:]
            return {"report_b64": base64.b64encode(report).decode(), "transport_public_key": public}
        receiver.install(ProvisioningEnvelope(payload["nonce"], base64.b64decode(payload["ciphertext_b64"]),
                                             base64.b64decode(payload["owner_signature_b64"])))
        return {"installed": True}

    monkeypatch.setattr(owner_provision, "_post", post)
    return receiver, calls


def test_owner_client_provisions_receiver_without_transmitting_plaintext_key(bundle, monkeypatch):
    receiver, calls = wire_receiver(bundle, monkeypatch)
    receipt = owner_provision.provision_from_file(bundle[1])
    assert receiver.issue_challenge().nonce
    assert len(calls) == 2
    assert KEY not in base64.b64decode(calls[1][1]["ciphertext_b64"])
    assert base64.b64encode(KEY).decode() not in json.dumps(calls)
    assert KEY.hex() not in json.dumps(calls)
    assert receipt["broker_acknowledged"] is True
    assert receipt["installation_proven"] is False


def test_owner_and_service_over_real_http_with_synthetic_snp(bundle, monkeypatch):
    import uvicorn
    from wcm._hw_providers import SevSnpProvider
    from wcm.broker_server import create_app

    receiver = BrokerReceiver(*load_broker_inputs(bundle[0]))
    monkeypatch.setattr(SevSnpProvider, "provisioning_report",
                        lambda self, data: signed_report(bundle[2], data))
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    service = uvicorn.Server(uvicorn.Config(create_app(receiver), log_level="critical", access_log=False))
    thread = threading.Thread(target=service.run, kwargs={"sockets": [listener]}, daemon=True)
    thread.start()
    try:
        deadline = time.monotonic() + 5
        while not service.started and thread.is_alive() and time.monotonic() < deadline:
            time.sleep(0.01)
        assert service.started
        raw = json.loads(bundle[1].read_text())
        raw["broker_url"] = f"http://127.0.0.1:{listener.getsockname()[1]}"
        bundle[1].write_text(json.dumps(raw))
        receipt = owner_provision.provision_from_file(bundle[1], allow_loopback_http=True)
        assert receipt["broker_acknowledged"] is True
        assert receipt["installation_proven"] is False
        assert receiver.issue_challenge().nonce
    finally:
        service.should_exit = True
        thread.join(5)
        listener.close()
        assert not thread.is_alive()


@pytest.mark.parametrize("attack", ["key", "report"])
def test_bad_attestation_never_sends_install_request(bundle, monkeypatch, attack):
    receiver, calls = wire_receiver(bundle, monkeypatch, attack=attack)
    with pytest.raises(ValueError, match="attestation rejected"):
        owner_provision.provision_from_file(bundle[1])
    assert len(calls) == 1
    with pytest.raises(RuntimeError):
        receiver.issue_challenge()


def test_owner_restart_cannot_admit_older_policy_before_network(bundle, monkeypatch):
    wire_receiver(bundle, monkeypatch)
    owner_provision.provision_from_file(bundle[1])
    policy_path = bundle[1].parent / "policy.json"
    policy = json.loads(policy_path.read_text())
    policy["epoch"] -= 1
    policy_path.write_text(json.dumps(policy))
    monkeypatch.setattr(owner_provision, "_post", lambda *args: pytest.fail("network on rollback"))
    with pytest.raises(ValueError, match="rollback"):
        owner_provision.provision_from_file(bundle[1])


def test_untrusted_certificate_root_cannot_cause_install(bundle, monkeypatch):
    _, calls = wire_receiver(bundle, monkeypatch)
    wrong_root, _, _ = _vcek_chain()
    (bundle[1].parent / "root.pem").write_bytes(wrong_root.public_bytes(serialization.Encoding.PEM))
    with pytest.raises(ValueError, match="attestation rejected"):
        owner_provision.provision_from_file(bundle[1])
    assert len(calls) == 1


def test_loaded_configuration_cannot_accept_plaintext_keystore_field(bundle):
    raw = json.loads(bundle[0].read_text())
    raw["configuration"]["model_key_file"] = "model-key"
    bundle[0].write_text(json.dumps(raw))
    with pytest.raises(ValueError, match="unrecognized"):
        load_broker_inputs(bundle[0])


def test_configuration_uses_actual_file_bytes_and_snapshots_them(bundle):
    config, policy = load_broker_inputs(bundle[0])
    (bundle[0].parent / "owner-public").write_bytes(Ed25519PrivateKey.generate().public_key().public_bytes_raw())
    other, _ = load_broker_inputs(bundle[0])
    assert config.digest() == policy.configuration_sha256
    assert other.digest() != config.digest()
    with pytest.raises(ValueError, match="configuration"):
        BrokerReceiver(other, policy)


@pytest.mark.parametrize("data", ['{"a":1,"a":2}', '{"inner":{"a":1,"a":2}}', '[]'])
def test_ambiguous_json_rejected(data):
    with pytest.raises(ValueError):
        json_object(data)


@pytest.mark.parametrize("url", ["http://broker.example", "file:///tmp/x", "https://u:p@broker.example",
    "https://broker.example?a=b", "https://broker.example#x", "http://127.0.0.1"])
def test_default_client_rejects_unapproved_urls(url):
    with pytest.raises(ValueError):
        owner_provision.validate_url(url)


@pytest.mark.parametrize("url", ["http://127.0.0.1:8443", "http://[::1]:8000", "http://localhost"])
def test_loopback_http_requires_explicit_opt_in(url):
    assert owner_provision.validate_url(url, allow_loopback_http=True) == url


@pytest.mark.parametrize("oversized", [False, True])
def test_network_redirect_and_oversized_response_are_rejected(oversized):
    requests = []
    class Redirect(BaseHTTPRequestHandler):
        def do_POST(self):
            requests.append(self.path)
            if oversized:
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"x" * 131073)
                return
            self.send_response(307)
            self.send_header("Location", "/redirected")
            self.end_headers()
        def log_message(self, *args):
            pass
    server = ThreadingHTTPServer(("127.0.0.1", 0), Redirect)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with pytest.raises(Exception) as error:
            owner_provision._post(f"http://127.0.0.1:{server.server_port}/first", {})
        if oversized:
            assert isinstance(error.value, ValueError)
            assert "size limit" in str(error.value)
        else:
            assert error.value.code == 307
        assert requests == ["/first"]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(2)


def test_cli_failure_does_not_echo_private_exception(bundle, monkeypatch, capsys):
    monkeypatch.setattr("sys.argv", ["owner_provision", str(bundle[1])])
    def fail(*args, **kwargs):
        raise ValueError("private-model-key-canary")
    monkeypatch.setattr(owner_provision, "provision_from_file", fail)
    with pytest.raises(SystemExit) as error:
        owner_provision.main()
    assert error.value.code == 1
    output = capsys.readouterr()
    assert "private-model-key-canary" not in output.err + output.out
    assert "outcome unknown" in output.err


def test_digest_cli_reports_loaded_configuration_without_approving_it(bundle, monkeypatch, capsys):
    from wcm import provisioning_wire
    monkeypatch.setattr("sys.argv", ["provisioning_wire", str(bundle[0])])
    config, _ = load_broker_inputs(bundle[0])
    provisioning_wire.main()
    assert capsys.readouterr().out.strip() == config.digest()
