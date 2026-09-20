"""Restart and stale-process controls using signed synthetic SNP evidence."""
from dataclasses import replace
from concurrent.futures import ThreadPoolExecutor
import threading

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from wcm import generate_transport_keypair
from wcm._seal import seal_to_public_key
from wcm.provisioning import OwnerProvisioner, open_provisioned_key
from wcm.provisioning_state import OwnerEpochStore
from tests.test_provisioning import POLICY, KEY, report_for
from tests.test_snp import NOW, _vcek_chain


def test_restart_floor_and_stale_live_owner_rejected_before_sealing(tmp_path, monkeypatch):
    root, vcek, signing = _vcek_chain()
    owner_key = Ed25519PrivateKey.generate()
    path = tmp_path / "owner.sqlite"

    def owner(policy):
        return OwnerProvisioner(policy, owner_signing_key=owner_key, trusted_root=root,
                                now=lambda: NOW, epoch_store=OwnerEpochStore(path, "broker"))

    first = owner(POLICY)
    nonce = first.issue_challenge().nonce
    private, public = generate_transport_keypair()
    args = dict(nonce=nonce, report=report_for(signing, nonce, public), vcek=vcek,
                intermediates=[], transport_public_key=public, model_key=KEY)
    envelope = first.provision(**args)
    assert open_provisioned_key(envelope, policy=POLICY, transport_private_key=private,
                               trusted_owner=owner_key.public_key()) == KEY
    args["nonce"] = first.issue_challenge().nonce
    args["report"] = report_for(signing, args["nonce"], public)
    second = owner(POLICY)
    second.update_policy(replace(POLICY, epoch=2))
    with pytest.raises(ValueError, match="rollback"):
        owner(POLICY)
    with pytest.raises(ValueError, match="rollback"):
        first.issue_challenge()
    sealed = []
    def observed_seal(*args, **kwargs):
        sealed.append(1)
        return seal_to_public_key(*args, **kwargs)
    monkeypatch.setattr("wcm.provisioning.seal_to_public_key", observed_seal)
    with pytest.raises(ValueError, match="rollback"):
        first.provision(**args)
    assert sealed == []
    assert owner(replace(POLICY, epoch=2)).issue_challenge().nonce


def test_same_epoch_configuration_substitution_rejected(tmp_path):
    root, _, _ = _vcek_chain()
    store = OwnerEpochStore(tmp_path / "owner.sqlite", "broker")
    args = dict(owner_signing_key=Ed25519PrivateKey.generate(), trusted_root=root,
                now=lambda: NOW, epoch_store=store)
    OwnerProvisioner(POLICY, **args)
    with pytest.raises(ValueError, match="substitution"):
        OwnerProvisioner(replace(POLICY, configuration_sha256="44" * 32), **args)


def test_failed_admission_does_not_advance_floor(tmp_path):
    store = OwnerEpochStore(tmp_path / "owner.sqlite", "broker")
    with store.guard(1, b"first", admit=True):
        pass
    with pytest.raises(RuntimeError):
        with store.guard(2, b"next", admit=True):
            raise RuntimeError("abort")
    with store.guard(1, b"first"):
        pass
    with pytest.raises(ValueError, match="not admitted"):
        with store.guard(2, b"next"):
            pass


def test_missing_floor_is_not_silently_readmitted(tmp_path):
    store = OwnerEpochStore(tmp_path / "owner.sqlite", "broker")
    with pytest.raises(ValueError, match="missing"):
        with store.guard(1, b"first"):
            pass


def test_policy_advance_serializes_with_inflight_release(tmp_path):
    path = tmp_path / "owner.sqlite"
    first = OwnerEpochStore(path, "broker")
    second = OwnerEpochStore(path, "broker")
    started, admitted = threading.Event(), threading.Event()

    def advance():
        started.set()
        with second.guard(2, b"next", admit=True):
            admitted.set()

    with first.guard(1, b"first", admit=True):
        pass
    with ThreadPoolExecutor(max_workers=1) as pool:
        with first.guard(1, b"first"):
            future = pool.submit(advance)
            assert started.wait(2)
            assert not admitted.wait(0.05)
        future.result(timeout=2)
    assert admitted.is_set()
    with pytest.raises(ValueError, match="rollback"):
        with first.guard(1, b"first"):
            pass


@pytest.mark.parametrize("path, namespace", [(":memory:", "broker"), ("owner.sqlite", "")])
def test_nonpersistent_configuration_rejected(path, namespace):
    with pytest.raises(ValueError):
        OwnerEpochStore(path, namespace)
