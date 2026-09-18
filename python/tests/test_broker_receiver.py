"""Receiver boot-to-release checks with synthetic native-SNP signatures."""
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import base64
import hashlib
import struct

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from wcm import SoftwareProvider, generate_transport_keypair, open_sealed
from wcm._hw_providers import SevSnpProvider
from wcm.broker_receiver import BrokerEffectiveConfiguration, BrokerReceiver
from wcm.provisioning import OwnerProvisioner
from wcm.renewal import manifest_identity
from tests.test_provisioning import POLICY
from tests.test_snp import _vcek_chain

KEY = b"x" * 32
WORKLOAD = b"\x55" * 48


def signed_report(key, report_data, measurement=b"\x11" * 48, *, debug=False, vmpl=0):
    body = bytearray(0x2A0)
    struct.pack_into("<I", body, 0, 3)
    struct.pack_into("<Q", body, 8, (1 << 19) if debug else 0)
    struct.pack_into("<Q", body, 0x40, 0x30)
    struct.pack_into("<I", body, 0x30, vmpl)
    body[0x50:0x90] = report_data
    body[0x90:0xC0] = measurement
    body[0x180:0x188] = bytes.fromhex("0101000000000101")
    r, s = decode_dss_signature(key.sign(bytes(body), ec.ECDSA(hashes.SHA384())))
    signature = bytearray(512)
    signature[:48] = r.to_bytes(48, "little")
    signature[72:120] = s.to_bytes(48, "little")
    return bytes(body + signature)


@pytest.fixture
def setup(example_manifest):
    manifest = example_manifest.model_copy(deep=True)
    manifest.release_policy.required_gpu_measurement = None
    manifest.release_policy.required_serving_image.accepted_measurements[0].measurement = (
        "sha256:" + hashlib.sha256(WORKLOAD).hexdigest()
    )
    root, vcek, signing_key = _vcek_chain()
    owner_key = ed25519.Ed25519PrivateKey.generate()
    config = BrokerEffectiveConfiguration(
        root.public_bytes(serialization.Encoding.DER), vcek.public_bytes(serialization.Encoding.DER),
        (), frozenset({manifest_identity(manifest)}), owner_key.public_key().public_bytes_raw(),
    )
    policy = replace(POLICY, configuration_sha256=config.digest(), weights_hash=manifest.weights_hash)
    owner = OwnerProvisioner(policy, owner_signing_key=owner_key, trusted_root=root)
    receiver = BrokerReceiver(config, policy)
    return receiver, owner, config, policy, manifest, vcek, signing_key, owner_key


def provision(setup, monkeypatch):
    receiver, owner, _, _, _, vcek, signing_key, _ = setup
    challenge = owner.issue_challenge()
    report_data = receiver.provisioning_report_data(challenge)
    provider = SevSnpProvider()
    monkeypatch.setattr(provider, "_fetch_report", lambda data: signed_report(signing_key, data))
    report = provider.provisioning_report(report_data)
    envelope = owner.provision(
        nonce=challenge.nonce, report=report, vcek=vcek, intermediates=[],
        transport_public_key=receiver.transport_public_key, model_key=KEY,
    )
    receiver.install(envelope)
    return envelope, challenge


def workload_evidence(setup, *, measurement=WORKLOAD, debug=False, vmpl=0):
    receiver, _, _, _, manifest, _, signing_key, _ = setup
    challenge = receiver.issue_challenge()
    private, public = generate_transport_keypair()
    expected = manifest.release_policy.required_serving_image.accepted_measurements[0].measurement
    evidence = SoftwareProvider().produce(challenge, serving_image_measurement=expected,
                                          include_gpu=False, transport_public_key=public)
    rd = hashlib.sha256(bytes.fromhex(challenge.nonce) + bytes.fromhex(public)).digest() + bytes(32)
    evidence.cpu.quote_b64 = base64.b64encode(signed_report(signing_key, rd, measurement, debug=debug, vmpl=vmpl)).decode()
    return evidence, private


def test_boot_owner_provisioning_and_strict_workload_release(setup, monkeypatch):
    receiver, _, _, _, manifest, _, _, _ = setup
    with pytest.raises(RuntimeError, match="not provisioned"):
        receiver.issue_challenge()
    envelope, _ = provision(setup, monkeypatch)
    evidence, private = workload_evidence(setup)
    decision = receiver.verify_and_release(manifest, evidence)
    assert decision.released, decision.failures
    assert decision.key is None
    assert open_sealed(decision.sealed_key, private) == KEY
    with pytest.raises(RuntimeError):
        receiver.install(envelope)


@pytest.mark.parametrize("field", ["cpu_root_der", "cpu_vcek_der", "owner_public_key", "trusted_manifest_identities", "gpu_root_der"])
def test_changed_effective_inputs_fail_owner_digest(setup, field):
    _, _, config, policy, _, _, _, _ = setup
    other_root, other_vcek, _ = _vcek_chain()
    changed = {
        "cpu_root_der": other_root.public_bytes(serialization.Encoding.DER),
        "cpu_vcek_der": other_vcek.public_bytes(serialization.Encoding.DER),
        "owner_public_key": ed25519.Ed25519PrivateKey.generate().public_key().public_bytes_raw(),
        "trusted_manifest_identities": frozenset({"sha256:" + "99" * 32}),
        "gpu_root_der": other_root.public_bytes(serialization.Encoding.DER),
    }[field]
    with pytest.raises(ValueError, match="configuration"):
        BrokerReceiver(replace(config, **{field: changed}), policy)


def test_restart_cannot_install_old_boot_envelope(setup, monkeypatch):
    receiver, _, config, policy, _, _, _, _ = setup
    envelope, challenge = provision(setup, monkeypatch)
    restarted = BrokerReceiver(config, policy)
    assert restarted.transport_public_key != receiver.transport_public_key
    restarted.provisioning_report_data(challenge)
    with pytest.raises(InvalidSignature):
        restarted.install(envelope)
    with pytest.raises(RuntimeError, match="not provisioned"):
        restarted.issue_challenge()


@pytest.mark.parametrize("attack", ["measurement", "debug", "vmpl", "missing-quote", "malformed-quote", "recipient-key", "manifest"])
def test_unapproved_workload_cannot_receive_installed_key(setup, monkeypatch, attack):
    receiver, _, _, _, manifest, _, _, _ = setup
    provision(setup, monkeypatch)
    evidence, _ = workload_evidence(setup, measurement=b"\x66" * 48 if attack == "measurement" else WORKLOAD,
                                    debug=attack == "debug", vmpl=1 if attack == "vmpl" else 0)
    if attack == "missing-quote":
        evidence.cpu.quote_b64 = None
    elif attack == "malformed-quote":
        evidence.cpu.quote_b64 = "!not-base64!"
    elif attack == "recipient-key":
        evidence.cpu.transport_public_key = generate_transport_keypair()[1]
    elif attack == "manifest":
        manifest = manifest.model_copy(deep=True)
        manifest.release_policy.required_serving_image.accepted_measurements[0].measurement = "sha256:" + "77" * 32
    decision = receiver.verify_and_release(manifest, evidence)
    assert not decision.released
    assert decision.key is None and decision.sealed_key is None


def test_retirement_stops_release_and_reprovision(setup, monkeypatch):
    receiver, _, _, _, manifest, _, _, _ = setup
    envelope, challenge = provision(setup, monkeypatch)
    evidence, _ = workload_evidence(setup)
    receiver.retire()
    for operation in (lambda: receiver.issue_challenge(), lambda: receiver.install(envelope),
                      lambda: receiver.provisioning_report_data(challenge),
                      lambda: receiver.verify_and_release(manifest, evidence)):
        with pytest.raises(RuntimeError):
            operation()


def test_native_collector_rejects_wrong_report_data_without_device_call(monkeypatch):
    provider = SevSnpProvider()
    monkeypatch.setattr(provider, "_fetch_report", lambda _: pytest.fail("device call on invalid input"))
    with pytest.raises(ValueError, match="64 bytes"):
        provider.provisioning_report(b"bad")


def test_expired_and_repeated_provisioning_requests_denied(setup):
    receiver, owner, _, _, _, _, _, _ = setup
    challenge = owner.issue_challenge()
    with pytest.raises(ValueError, match="expired"):
        receiver.provisioning_report_data(replace(challenge, expires_at=datetime.now(timezone.utc) - timedelta(seconds=1)))
    receiver.provisioning_report_data(challenge)
    with pytest.raises(ValueError, match="already requested"):
        receiver.provisioning_report_data(replace(challenge, expires_at=datetime.now(timezone.utc) + timedelta(days=1)))


def test_failed_install_consumes_pending_request_without_enabling_release(setup):
    receiver, owner, _, _, _, vcek, signing_key, _ = setup
    challenge = owner.issue_challenge()
    data = receiver.provisioning_report_data(challenge)
    envelope = owner.provision(nonce=challenge.nonce, report=signed_report(signing_key, data),
                               vcek=vcek, intermediates=[], transport_public_key=receiver.transport_public_key,
                               model_key=KEY)
    with pytest.raises(InvalidSignature):
        receiver.install(replace(envelope, owner_signature=bytes(64)))
    with pytest.raises(RuntimeError, match="not awaiting"):
        receiver.install(envelope)
    with pytest.raises(RuntimeError, match="not provisioned"):
        receiver.issue_challenge()
