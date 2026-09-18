"""Synthetic SNP PKI tests; no assertion of live broker isolation."""
from dataclasses import replace
from datetime import timedelta
import hashlib
import json
import struct

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from wcm import generate_transport_keypair
from wcm._challenge import ChallengeError
from wcm.provisioning import (
    BrokerProvisioningPolicy, OwnerProvisioner, open_provisioned_key,
)
from tests.test_snp import NOW, _vcek_chain

KEY = b"k" * 32
POLICY = BrokerProvisioningPolicy(
    "11" * 48, "22" * 32, "sha256:" + "33" * 32, 1,
    guest_policy=0, minimum_tcb_le_hex="0101000000000101",
    required_platform_fields=frozenset({"ciphertext_hiding_en", "alias_check_complete"}),
    forbidden_platform_fields=frozenset({"smt_en"}),
)


def report_for(key, nonce, public_key, policy=POLICY, measurement=None,
               guest_policy=0, platform_info=0x30, tcb="0101000000000101", version=3, vmpl=0):
    # Build the wire binding independently from the implementation helper.
    context = b"wcm/broker-provisioning/v1\x00" + json.dumps({
        "measurement_hex": policy.measurement_hex,
        "configuration_sha256": policy.configuration_sha256,
        "weights_hash": policy.weights_hash,
        "epoch": policy.epoch,
        "guest_policy": policy.guest_policy,
        "minimum_tcb_le_hex": policy.minimum_tcb_le_hex,
        "required_platform_fields": sorted(policy.required_platform_fields),
        "forbidden_platform_fields": sorted(policy.forbidden_platform_fields),
    }, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    binding = b"wcm/broker-provisioning/v1\x00" + bytes.fromhex(public_key) + hashlib.sha256(context).digest()
    body = bytearray(0x2A0)
    struct.pack_into("<I", body, 0, version)
    struct.pack_into("<Q", body, 8, guest_policy)
    struct.pack_into("<I", body, 0x30, vmpl)
    struct.pack_into("<Q", body, 0x40, platform_info)
    body[0x180:0x188] = bytes.fromhex(tcb)
    body[0x50:0x70] = hashlib.sha256(bytes.fromhex(nonce) + binding).digest()
    body[0x90:0xC0] = measurement or bytes.fromhex(policy.measurement_hex)
    r, s = decode_dss_signature(key.sign(bytes(body), ec.ECDSA(hashes.SHA384())))
    signature = bytearray(512)
    signature[:48] = r.to_bytes(48, "little")
    signature[72:120] = s.to_bytes(48, "little")
    return bytes(body + signature)


@pytest.mark.parametrize("changes", [
    {"guest_policy": 1 << 19}, {"guest_policy": 1}, {"vmpl": 1},
    {"platform_info": 0x20}, {"platform_info": 0x10}, {"platform_info": 0x31},
    {"tcb": "0002000000000202"},  # larger scalar value hides lower boot-loader SVN
    {"tcb": "0200000000000202"}, {"tcb": "0202000000000002"},
    {"tcb": "0202000000000200"}, {"version": 2},
])
def test_signed_unsuitable_platform_cannot_receive_keys(setup, changes):
    owner, args, _, _, _, key = setup
    args["report"] = report_for(key, args["nonce"], args["transport_public_key"], **changes)
    with pytest.raises(ValueError, match="broker"):
        owner.provision(**args)


@pytest.fixture
def setup():
    root, vcek, key = _vcek_chain()
    signer = ed25519.Ed25519PrivateKey.generate()
    clock = [NOW]
    owner = OwnerProvisioner(POLICY, owner_signing_key=signer, trusted_root=root, now=lambda: clock[0])
    private, public = generate_transport_keypair()
    nonce = owner.issue_challenge().nonce
    args = dict(nonce=nonce, report=report_for(key, nonce, public), vcek=vcek,
                intermediates=[], transport_public_key=public, model_key=KEY)
    return owner, args, private, signer, clock, key


def test_approved_broker_can_open_owner_authenticated_key(setup):
    owner, args, private, signer, _, _ = setup
    envelope = owner.provision(**args)
    assert envelope.ciphertext != KEY
    assert open_provisioned_key(envelope, policy=POLICY, transport_private_key=private,
                               trusted_owner=signer.public_key()) == KEY


@pytest.mark.parametrize("attack", ["image", "config", "epoch", "key-label", "transport", "tamper", "root"])
def test_substitution_is_denied_before_provisioning(setup, attack):
    owner, args, _, _, _, key = setup
    if attack == "image":
        args["report"] = report_for(key, args["nonce"], args["transport_public_key"], measurement=b"\x99" * 48)
    elif attack in ("config", "epoch", "key-label"):
        changes = {"config": {"configuration_sha256": "44" * 32}, "epoch": {"epoch": 0},
                   "key-label": {"weights_hash": "different-model"}}[attack]
        args["report"] = report_for(key, args["nonce"], args["transport_public_key"], replace(POLICY, **changes))
    elif attack == "transport":
        args["transport_public_key"] = generate_transport_keypair()[1]
    elif attack == "tamper":
        report = bytearray(args["report"])
        report[0x40] ^= 1
        args["report"] = bytes(report)
    else:
        _, args["vcek"], other_key = _vcek_chain()
        args["report"] = report_for(other_key, args["nonce"], args["transport_public_key"])
    with pytest.raises(ValueError, match="broker"):
        owner.provision(**args)
    with pytest.raises(ChallengeError, match="already used"):
        owner.provision(**args)


def test_challenge_replay_and_expiry(setup):
    owner, args, _, _, clock, key = setup
    owner.provision(**args)
    with pytest.raises(ChallengeError, match="already used"):
        owner.provision(**args)
    args["nonce"] = owner.issue_challenge().nonce
    args["report"] = report_for(key, args["nonce"], args["transport_public_key"])
    clock[0] += timedelta(seconds=61)
    with pytest.raises(ChallengeError, match="expired"):
        owner.provision(**args)


def test_policy_update_revokes_pending_requests_and_rejects_rollback(setup):
    owner, args, private, signer, _, key = setup
    updated = replace(POLICY, epoch=2, configuration_sha256="44" * 32)
    owner.update_policy(updated)
    with pytest.raises(ChallengeError, match="unknown"):
        owner.provision(**args)
    for rejected in (POLICY, updated):
        with pytest.raises(ValueError, match="advance"):
            owner.update_policy(rejected)
    args["nonce"] = owner.issue_challenge().nonce
    args["report"] = report_for(key, args["nonce"], args["transport_public_key"], updated)
    envelope = owner.provision(**args)
    assert open_provisioned_key(envelope, policy=updated, transport_private_key=private,
                               trusted_owner=signer.public_key()) == KEY
    with pytest.raises(InvalidSignature):
        open_provisioned_key(envelope, policy=POLICY, transport_private_key=private,
                             trusted_owner=signer.public_key())


@pytest.mark.parametrize("attack", ["owner", "recipient", "ciphertext", "nonce"])
def test_broker_rejects_substituted_envelope(setup, attack):
    owner, args, private, signer, _, _ = setup
    envelope = owner.provision(**args)
    if attack == "owner":
        signer = ed25519.Ed25519PrivateKey.generate()
    elif attack == "recipient":
        private = generate_transport_keypair()[0]
    elif attack == "ciphertext":
        envelope = replace(envelope, ciphertext=envelope.ciphertext[:-1] + bytes([envelope.ciphertext[-1] ^ 1]))
    else:
        envelope = replace(envelope, nonce="00" * 32)
    with pytest.raises(InvalidSignature):
        open_provisioned_key(envelope, policy=POLICY, transport_private_key=private,
                             trusted_owner=signer.public_key())


def test_one_challenge_cannot_provision_twice_concurrently(setup):
    from concurrent.futures import ThreadPoolExecutor

    owner, args, _, _, _, _ = setup
    def attempt():
        try:
            return owner.provision(**args)
        except ChallengeError:
            return None
    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(lambda _: attempt(), range(2)))
    assert sum(outcome is not None for outcome in outcomes) == 1


@pytest.mark.parametrize("changes", [
    {"guest_policy": 1 << 19}, {"guest_policy": -1}, {"epoch": True},
    {"minimum_tcb_le_hex": "00"},
    {"required_platform_fields": frozenset({"unknown"})},
    {"forbidden_platform_fields": frozenset({"alias_check_complete"})},
])
def test_bad_owner_policy_is_rejected(changes):
    with pytest.raises(ValueError):
        replace(POLICY, **changes)


def test_report_is_snapshotted_before_authentication(setup, monkeypatch):
    from wcm._quote_verify import QuoteVerifier

    owner, args, _, _, _, key = setup
    mutable = bytearray(report_for(key, args["nonce"], args["transport_public_key"], measurement=b"\x99" * 48))
    args["report"] = mutable
    original_verify = QuoteVerifier.verify
    def verify_then_swap(self, *positional, **kwargs):
        result = original_verify(self, *positional, **kwargs)
        mutable[0x90:0xC0] = bytes.fromhex(POLICY.measurement_hex)
        return result
    monkeypatch.setattr(QuoteVerifier, "verify", verify_then_swap)
    with pytest.raises(ValueError, match="image measurement"):
        owner.provision(**args)


def test_envelope_is_snapshotted_before_owner_verification(setup):
    owner, args, private, signer, _, _ = setup
    envelope = owner.provision(**args)
    mutable = bytearray(envelope.ciphertext)
    envelope = replace(envelope, ciphertext=mutable)
    class VerifyThenSwap:
        def verify(self, signature, payload):
            signer.public_key().verify(signature, payload)
            mutable[:] = bytes(len(mutable))
    assert open_provisioned_key(envelope, policy=POLICY, transport_private_key=private,
                               trusted_owner=VerifyThenSwap()) == KEY
