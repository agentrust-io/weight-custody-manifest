"""Software lifecycle observations; synthetic signatures are not hardware evidence."""
import asyncio
import base64
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import shutil
import threading

import pytest

from wcm import owner_provision, open_sealed
from wcm._challenge import Challenge, ChallengeError
from wcm.broker_receiver import BrokerReceiver
from wcm.custody import EnclaveSession, KeyWipedError, ServingShutdown, SessionState, TimeFloor
from wcm.provisioning import OwnerProvisioner, ProvisioningEnvelope
from wcm.provisioning_state import OwnerEpochStore
from wcm.provisioning_wire import load_broker_inputs
from tests.test_broker_receiver import (
    KEY, provision, setup, signed_report, workload_evidence,
)
from tests.test_owner_provision import bundle, wire_receiver


@pytest.mark.parametrize("installed", [False, True])
def test_lost_http_ack_is_unknown_and_install_is_not_retried(bundle, installed):
    """The same dropped connection can precede or follow actual installation."""
    receiver = BrokerReceiver(*load_broker_inputs(bundle[0]))
    paths, errors = [], []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            try:
                paths.append(self.path)
                payload = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                if self.path == "/provisioning/report":
                    challenge = Challenge(payload["nonce"], datetime.fromisoformat(payload["issued_at"]),
                                          datetime.fromisoformat(payload["expires_at"]))
                    report = signed_report(bundle[2], receiver.provisioning_report_data(challenge))
                    body = json.dumps({"report_b64": base64.b64encode(report).decode(),
                                       "transport_public_key": receiver.transport_public_key}).encode()
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                else:
                    assert self.path == "/provisioning/install"
                    if installed:
                        receiver.install(ProvisioningEnvelope(
                            payload["nonce"], base64.b64decode(payload["ciphertext_b64"]),
                            base64.b64decode(payload["owner_signature_b64"])))
                    # Complete request read, but deliberately send no HTTP response.
                    self.close_connection = True
            except Exception as exc:
                errors.append(exc)
                self.close_connection = True

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    config = json.loads(bundle[1].read_text())
    config["broker_url"] = f"http://127.0.0.1:{server.server_port}"
    bundle[1].write_text(json.dumps(config))
    try:
        from http.client import RemoteDisconnected
        with pytest.raises(RemoteDisconnected):
            owner_provision.provision_from_file(bundle[1], allow_loopback_http=True)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(2)
    assert errors == []
    assert paths == ["/provisioning/report", "/provisioning/install"]
    if installed:
        assert receiver.issue_challenge().nonce
    else:
        with pytest.raises(RuntimeError, match="not provisioned"):
            receiver.issue_challenge()


def test_false_http_ack_does_not_prove_installation(bundle, monkeypatch):
    receiver, calls = wire_receiver(bundle, monkeypatch)
    real_post = owner_provision._post

    def post(url, payload):
        if url.endswith("/install"):
            return {"installed": True}  # A lying intermediary never calls install.
        return real_post(url, payload)

    monkeypatch.setattr(owner_provision, "_post", post)
    receipt = owner_provision.provision_from_file(bundle[1])
    assert len(calls) == 1
    assert receipt["broker_acknowledged"] is True
    assert receipt["installation_proven"] is False
    with pytest.raises(RuntimeError, match="not provisioned"):
        receiver.issue_challenge()


def test_owner_restart_loses_pending_nonce_but_can_start_fresh(setup, tmp_path):
    receiver, _, _, policy, _, vcek, signing, owner_key = setup
    from cryptography import x509
    root = x509.load_der_x509_certificate(setup[2].cpu_root_der)

    def owner():
        return OwnerProvisioner(policy, owner_signing_key=owner_key, trusted_root=root,
                                epoch_store=OwnerEpochStore(tmp_path / "owner.sqlite", "broker"))

    first = owner()
    challenge = first.issue_challenge()
    report = signed_report(signing, receiver.provisioning_report_data(challenge))
    restarted = owner()
    with pytest.raises(ChallengeError, match="unknown"):
        restarted.provision(nonce=challenge.nonce, report=report, vcek=vcek, intermediates=[],
                            transport_public_key=receiver.transport_public_key, model_key=KEY)
    fresh = restarted.issue_challenge()
    assert fresh.nonce != challenge.nonce
    report = signed_report(signing, receiver.provisioning_report_data(fresh))
    receiver.install(restarted.provision(nonce=fresh.nonce, report=report, vcek=vcek, intermediates=[],
                                        transport_public_key=receiver.transport_public_key, model_key=KEY))
    assert receiver.issue_challenge().nonce


def test_policy_advance_does_not_retract_an_already_sealed_envelope(setup):
    receiver, owner, _, policy, manifest, vcek, signing, _ = setup
    challenge = owner.issue_challenge()
    report = signed_report(signing, receiver.provisioning_report_data(challenge))
    envelope = owner.provision(nonce=challenge.nonce, report=report, vcek=vcek, intermediates=[],
                               transport_public_key=receiver.transport_public_key, model_key=KEY)
    owner.update_policy(replace(policy, epoch=policy.epoch + 1))
    # Policy admission and HTTP delivery are separate operations. The old receiver
    # cannot learn an owner-side update from a previously valid envelope.
    receiver.install(envelope)
    evidence, private = workload_evidence(setup)
    decision = receiver.verify_and_release(manifest, evidence)
    assert decision.released, decision.failures
    assert open_sealed(decision.sealed_key, private) == KEY


@pytest.mark.parametrize("failure", ["replaced", "expired", "clock-failure", "retired"])
def test_pending_install_failure_requires_fresh_provisioning(setup, monkeypatch, failure):
    receiver, owner, config, policy, _, vcek, signing, _ = setup
    current = datetime.now(timezone.utc)
    broken = False

    class Clock:
        @staticmethod
        def now(_):
            if broken:
                raise RuntimeError("clock unavailable")
            return current

    monkeypatch.setattr("wcm.broker_receiver.datetime", Clock)
    challenge = owner.issue_challenge()
    # Unauthenticated timestamps cannot extend the receiver's local 60s cap.
    offered = replace(challenge, expires_at=current + timedelta(days=1))
    report = signed_report(signing, receiver.provisioning_report_data(offered))
    envelope = owner.provision(nonce=challenge.nonce, report=report, vcek=vcek, intermediates=[],
                               transport_public_key=receiver.transport_public_key, model_key=KEY)
    if failure == "replaced":
        receiver.provisioning_report_data(owner.issue_challenge())
    elif failure == "expired":
        current += timedelta(seconds=61)
    elif failure == "clock-failure":
        broken = True
    else:
        receiver.retire()
    with pytest.raises((ValueError, RuntimeError)):
        receiver.install(envelope)
    broken = False
    with pytest.raises(RuntimeError, match="not awaiting"):
        receiver.install(envelope)
    with pytest.raises(RuntimeError, match="not provisioned"):
        receiver.issue_challenge()
    current = datetime.now(timezone.utc)
    if failure == "retired":
        receiver = BrokerReceiver(config, policy)
        assert receiver.transport_public_key != setup[0].transport_public_key
    fresh = owner.issue_challenge()
    report = signed_report(signing, receiver.provisioning_report_data(fresh))
    receiver.install(owner.provision(nonce=fresh.nonce, report=report, vcek=vcek, intermediates=[],
                                     transport_public_key=receiver.transport_public_key, model_key=KEY))
    assert receiver.issue_challenge().nonce


@pytest.mark.parametrize("tamper", ["snapshot", "delete", "substitute", "namespace", "clone"])
def test_owner_storage_tampering_is_an_external_assumption(tmp_path, tamper):
    path = tmp_path / "owner.sqlite"
    store = OwnerEpochStore(path, "broker")
    with store.guard(1, b"first", admit=True):
        pass
    snapshot = tmp_path / "snapshot.sqlite"
    shutil.copyfile(path, snapshot)  # All connections closed; no WAL copying.
    with store.guard(2, b"next", admit=True):
        pass
    with pytest.raises(ValueError, match="rollback"):
        with store.guard(1, b"first", admit=True):
            pass
    namespace = "broker"
    if tamper == "snapshot":
        shutil.copyfile(snapshot, path)
    elif tamper == "delete":
        path.unlink()
    elif tamper == "substitute":
        other = tmp_path / "other.sqlite"
        OwnerEpochStore(other, "other-lineage")
        shutil.copyfile(other, path)
    elif tamper == "namespace":
        namespace = "new-lineage"
    else:
        path = snapshot  # A concurrent owner using a stale clone is independent.
    restarted = OwnerEpochStore(path, namespace)
    # Counterexample, deliberately expected to succeed: SQLite does not supply
    # trusted storage identity, anti-rollback or a distributed owner consensus.
    with restarted.guard(1, b"first", admit=True):
        pass


@pytest.mark.parametrize("mode", ["idle", "resume", "clock-failure"])
def test_retirement_leaves_loaded_worker_until_its_local_stop(setup, monkeypatch, mode):
    receiver, _, _, _, manifest, _, _, _ = setup
    provision(setup, monkeypatch)
    evidence, private = workload_evidence(setup)
    decision = receiver.verify_and_release(manifest, evidence)
    assert decision.released, decision.failures
    key = open_sealed(decision.sealed_key, private)
    assert key == KEY
    current = datetime.now(timezone.utc)
    broken = False
    events = []
    worker = {"admission": True, "inflight": True, "loaded": True, "alive": True}

    def clock():
        if broken:
            raise RuntimeError("clock unavailable")
        return current

    def stop_admission():
        assert session.is_wiped
        events.append("stop")
        worker["admission"] = False

    def cancel():
        events.append("cancel")
        worker["inflight"] = False

    def unload():
        assert not worker["inflight"]
        events.append("unload")
        worker["loaded"] = False

    def terminate():
        events.append("terminate")
        worker["alive"] = False

    session = EnclaveSession(key, cadence_seconds=10, now=clock, on_stop=ServingShutdown(
        stop_admission=stop_admission, cancel_inflight=cancel, unload_weights=unload, terminate=terminate))
    assert session.time_floor is TimeFloor.none
    receiver.retire()
    with pytest.raises(RuntimeError, match="retired"):
        receiver.issue_challenge()
    session.authorize_operation()  # Retirement cannot recall an earlier release.
    assert all(worker.values())
    assert session.remaining_seconds() == 10

    async def sleep(_):
        nonlocal current, broken
        if mode == "clock-failure":
            broken = True
        else:
            current += timedelta(seconds=10 if mode == "idle" else 3600)

    monkeypatch.setattr("wcm.custody.asyncio.sleep", sleep)
    if mode == "clock-failure":
        with pytest.raises(RuntimeError, match="clock unavailable"):
            asyncio.run(session.monitor())
    else:
        asyncio.run(session.monitor())
    assert session.state is SessionState.wiped
    assert not any(worker.values())
    assert events == ["stop", "cancel", "unload", "terminate"]
    with pytest.raises(KeyWipedError):
        session.authorize_operation()
    session.zeroize()
    assert len(events) == 4


def test_stalled_clock_does_not_supply_a_real_time_bound():
    current = datetime.now(timezone.utc)
    session = EnclaveSession(KEY, cadence_seconds=10, now=lambda: current)
    assert session.time_floor is TimeFloor.none
    current -= timedelta(hours=1)
    session.authorize_operation()
    assert session.remaining_seconds() == 3610
    session.zeroize()
