"""Object-sealing to an attested transport key (SPEC 3.2 channel binding)."""
from __future__ import annotations

import pytest

from wcm import (
    SealError,
    generate_transport_keypair,
    open_sealed,
    seal_to_public_key,
)
from wcm._seal import _HEADER_LEN, _VERSION

PAYLOAD = b"decryption-key-for-these-weights"


def test_roundtrip():
    priv, pub = generate_transport_keypair()
    blob = seal_to_public_key(pub, PAYLOAD)
    assert open_sealed(blob, priv) == PAYLOAD


def test_wrong_key_cannot_open():
    _, pub = generate_transport_keypair()
    other_priv, _ = generate_transport_keypair()
    blob = seal_to_public_key(pub, PAYLOAD)
    with pytest.raises(SealError):
        open_sealed(blob, other_priv)


def test_tampered_ciphertext_fails_closed():
    priv, pub = generate_transport_keypair()
    blob = bytearray(seal_to_public_key(pub, PAYLOAD))
    blob[-1] ^= 0x01  # flip a ciphertext/tag bit
    with pytest.raises(SealError):
        open_sealed(bytes(blob), priv)


def test_aad_must_match():
    priv, pub = generate_transport_keypair()
    blob = seal_to_public_key(pub, PAYLOAD, aad=b"context-a")
    assert open_sealed(blob, priv, aad=b"context-a") == PAYLOAD
    with pytest.raises(SealError):
        open_sealed(blob, priv, aad=b"context-b")


def test_fresh_ephemeral_each_seal():
    _, pub = generate_transport_keypair()
    a = seal_to_public_key(pub, PAYLOAD)
    b = seal_to_public_key(pub, PAYLOAD)
    # Distinct ephemeral key + nonce every time, so two seals never collide.
    assert a != b
    assert a[1 : _HEADER_LEN] != b[1 : _HEADER_LEN]


def test_malformed_blob_rejected():
    priv, _ = generate_transport_keypair()
    with pytest.raises(SealError):
        open_sealed(b"too-short", priv)
    with pytest.raises(SealError):
        open_sealed(bytes([_VERSION + 9]) + bytes(_HEADER_LEN + 16), priv)


def test_seal_rejects_bad_recipient_key():
    with pytest.raises(SealError):
        seal_to_public_key("not-hex", PAYLOAD)
    with pytest.raises(SealError):
        seal_to_public_key("00" * 8, PAYLOAD)  # wrong length for X25519
