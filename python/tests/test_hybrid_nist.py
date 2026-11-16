"""Official primitive vectors and an independent envelope-format oracle.

These are software tests, not CAVP/CMVP validation. The oracle intentionally
uses hashlib rather than the production ConcatKDFHash adapter.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM768PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import wcm.hybrid_seal as hs
from wcm import (
    HybridTransportPrivateKey, SealError, generate_hybrid_transport_keypair,
    open_hybrid_sealed, seal_to_hybrid_public_key,
)

VECTORS = json.loads(
    (Path(__file__).parent / "fixtures/mlkem768-nist-keygen.json").read_text()
)["vectors"]


@pytest.mark.parametrize("vector", VECTORS, ids=lambda v: str(v["tcId"]))
def test_nist_acvp_mlkem768_keygen(vector):
    seed = bytes.fromhex(vector["d"] + vector["z"])
    native = MLKEM768PrivateKey.from_seed_bytes(seed)
    assert native.public_key().public_bytes_raw().hex() == vector["ek"].lower()
    restored = HybridTransportPrivateKey(b"WCMK\x02" + seed + bytes(range(32)))
    assert bytes.fromhex(restored.public_key_hex())[5:1189] == bytes.fromhex(vector["ek"])


def test_rfc7748_section_6_1_x25519_vector():
    alice = X25519PrivateKey.from_private_bytes(bytes.fromhex(
        "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"))
    bob = X25519PublicKey.from_public_bytes(bytes.fromhex(
        "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"))
    assert alice.exchange(bob).hex() == (
        "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")


def test_aes256_gcm_known_answer():
    # NIST AES_GCM.pdf, GCM-AES256 Example #2 (128-bit tag, 96-bit IV).
    key = bytes.fromhex("feffe9928665731c6d6a8f9467308308" * 2)
    nonce = bytes.fromhex("cafebabefacedbaddecaf888")
    plaintext = bytes.fromhex(
        "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
        "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255")
    expected = bytes.fromhex(
        "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa"
        "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad"
        "b094dac5d93471bdec1a502270e3cc6c")
    assert AESGCM(key).encrypt(nonce, plaintext, b"") == expected
    assert AESGCM(key).decrypt(nonce, expected, b"") == plaintext


def reference_key(ss_m, ss_x, descriptor, encapsulation):
    # SP 800-56C one-step SHA3-256: counter || Z || FixedInfo.
    # This literal encoding is deliberately independent of production constants.
    return hashlib.sha3_256(
        bytes.fromhex("00000001") + ss_m + ss_x + encapsulation + descriptor
        + b"wcm/sealed-key/mlkem768-x25519-sha3-256-aes256gcm/v1\x00"
        + bytes.fromhex("00000100")
    ).digest()


def test_one_step_kdf_matches_independent_oracle_and_binds_all_fields():
    ss_m, ss_x = bytes(range(32)), bytes(range(32, 64))
    descriptor = b"WCMH\x02" + bytes(i % 256 for i in range(1216))
    encapsulation = bytes(i % 251 for i in range(1120))
    expected = reference_key(ss_m, ss_x, descriptor, encapsulation)
    assert hs._derive_key(ss_m + ss_x, descriptor, encapsulation) == expected
    for part in range(4):
        fields = [ss_m, ss_x, descriptor, encapsulation]
        fields[part] = bytes([fields[part][0] ^ 1]) + fields[part][1:]
        assert hs._derive_key(fields[0] + fields[1], fields[2], fields[3]) != expected
    # Both public components and both encapsulation components are covered.
    for offset in (5, 1189):
        changed = bytearray(descriptor)
        changed[offset] ^= 1
        assert hs._derive_key(ss_m + ss_x, bytes(changed), encapsulation) != expected
    for offset in (0, 1088):
        changed = bytearray(encapsulation)
        changed[offset] ^= 1
        assert hs._derive_key(ss_m + ss_x, descriptor, bytes(changed)) != expected


def test_reference_sender_to_sdk_and_sdk_sender_to_reference():
    # Fixed non-secret component seeds, fresh native ML-KEM encapsulation.
    seed = bytes(range(64))
    x_seed = bytes(range(32))
    receiver = HybridTransportPrivateKey(b"WCMK\x02" + seed + x_seed)
    native_m = MLKEM768PrivateKey.from_seed_bytes(seed)
    native_x = X25519PrivateKey.from_private_bytes(x_seed)
    descriptor = bytes.fromhex(receiver.public_key_hex())
    ss_m, ct_m = native_m.public_key().encapsulate()
    ephemeral = X25519PrivateKey.from_private_bytes(bytes(range(32, 64)))
    ct_x = ephemeral.public_key().public_bytes_raw()
    ss_x = ephemeral.exchange(native_x.public_key())
    enc = ct_m + ct_x
    nonce, aad, payload = bytes(range(12)), b"holder:model:transaction", b"test-share"
    header = b"WCMH\x02" + enc + nonce
    key = reference_key(ss_m, ss_x, descriptor, enc)
    blob = header + AESGCM(key).encrypt(nonce, payload, header + descriptor + aad)
    assert open_hybrid_sealed(blob, receiver, aad) == payload

    blob = seal_to_hybrid_public_key(receiver.public_key_hex(), payload, aad)
    assert blob[:5] == b"WCMH\x02"
    enc, nonce, header = blob[5:1125], blob[1125:1137], blob[:1137]
    ss_m = native_m.decapsulate(enc[:1088])
    ss_x = native_x.exchange(X25519PublicKey.from_public_bytes(enc[1088:]))
    key = reference_key(ss_m, ss_x, descriptor, enc)
    assert AESGCM(key).decrypt(nonce, blob[1137:], header + descriptor + aad) == payload


def test_prior_xwing_profile_and_private_encoding_are_not_accepted():
    private, public = generate_hybrid_transport_keypair()
    raw = bytes.fromhex(public)
    with pytest.raises(SealError):
        seal_to_hybrid_public_key((b"WCMH\x01" + raw[5:]).hex(), b"share")
    blob = seal_to_hybrid_public_key(public, b"share")
    with pytest.raises(SealError):
        open_hybrid_sealed(b"WCMH\x01" + blob[5:], private)
    with pytest.raises(SealError):
        HybridTransportPrivateKey(bytes(32))
    assert hs.HYBRID_TRANSPORT_PROFILE == "mlkem768-x25519-sha3-256-aes256gcm-v1"


def test_private_import_backend_failure(monkeypatch):
    from cryptography.hazmat.primitives.asymmetric import mlkem

    class Unavailable:
        @staticmethod
        def from_seed_bytes(seed):
            raise UnsupportedAlgorithm("test")

    monkeypatch.setattr(mlkem, "MLKEM768PrivateKey", Unavailable)
    with pytest.raises(SealError, match="unavailable"):
        HybridTransportPrivateKey(b"WCMK\x02" + bytes(96))
