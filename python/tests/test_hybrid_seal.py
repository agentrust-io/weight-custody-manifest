"""Hybrid transport software checks; no hardware or quantum-resistance claim."""
from __future__ import annotations

import random

import pytest
from cryptography.exceptions import UnsupportedAlgorithm

import wcm.hybrid_seal as hs
from wcm import (
    SealError, HybridTransportPrivateKey, generate_hybrid_transport_keypair,
    generate_transport_keypair, hybrid_transport_binding, open_hybrid_sealed,
    open_sealed, seal_to_hybrid_public_key, seal_to_public_key,
)

@pytest.mark.parametrize("length", [0, 1, 32, 33, 64, 1024, 65536])
def test_roundtrip_sizes_and_serialization(length):
    private, public = generate_hybrid_transport_keypair()
    payload = bytes(i % 256 for i in range(length))
    sealed = seal_to_hybrid_public_key(public, payload, b"holder:model:transaction")
    restored = HybridTransportPrivateKey(private.private_bytes_raw())
    assert restored.public_key_hex() == public
    assert len(bytes.fromhex(public)) == 1221
    assert len(sealed) == length + 1153
    assert open_hybrid_sealed(sealed, restored, b"holder:model:transaction") == payload
    assert private.private_bytes_raw().hex() not in repr(private)


@pytest.mark.parametrize("component", ["_mlkem", "_x25519"])
def test_each_private_component_is_required(component):
    private, public = generate_hybrid_transport_keypair()
    other, _ = generate_hybrid_transport_keypair()
    sealed = seal_to_hybrid_public_key(public, b"secret")
    object.__setattr__(private, component, getattr(other, component))
    with pytest.raises(SealError):
        open_hybrid_sealed(sealed, private)


@pytest.mark.parametrize("offset", [0, 4, 5, 105, 1092, 1093, 1124, 1125, 1136, 1137, -1])
def test_each_envelope_component_tampered(offset):
    private, public = generate_hybrid_transport_keypair()
    blob = bytearray(seal_to_hybrid_public_key(public, b"test-share", b"context"))
    blob[offset] ^= 1
    with pytest.raises(SealError):
        open_hybrid_sealed(bytes(blob), private, b"context")


def test_context_wrong_recipient_and_fresh_encapsulation():
    private, public = generate_hybrid_transport_keypair()
    wrong, _ = generate_hybrid_transport_keypair()
    first = seal_to_hybrid_public_key(public, b"share", b"holder-A:model-A:nonce-A")
    second = seal_to_hybrid_public_key(public, b"share", b"holder-A:model-A:nonce-A")
    assert first[5:1125] != second[5:1125]
    assert first[1125:1137] != second[1125:1137]
    for key, aad in [(wrong,b"holder-A:model-A:nonce-A"), (private,b"holder-B:model-A:nonce-A"),
                     (private,b"holder-A:model-B:nonce-A"), (private,b"holder-A:model-A:nonce-B")]:
        with pytest.raises(SealError):
            open_hybrid_sealed(first,key,aad)


@pytest.mark.parametrize("bad", [None, 1, b"", "", "00", "00"*1221, "A"*2442, "0"*2441, "0"*2443])
def test_bad_public_descriptor(bad):
    with pytest.raises(SealError):
        hybrid_transport_binding(bad)
    with pytest.raises(SealError):
        seal_to_hybrid_public_key(bad,b"share")


def test_noncanonical_descriptor_and_wrong_profile():
    _, public = generate_hybrid_transport_keypair()
    for bad in [public.upper(), public+"\n", " "+public, public[:8]+"01"+public[10:]]:
        with pytest.raises(SealError):
            seal_to_hybrid_public_key(bad,b"share")


@pytest.mark.parametrize("bad_x", [bytes(32), b"\x01"+bytes(31)])
def test_low_order_x25519_recipient_and_encapsulation(bad_x):
    private, public = generate_hybrid_transport_keypair()
    raw = bytes.fromhex(public)
    with pytest.raises(SealError):
        seal_to_hybrid_public_key((raw[:-32]+bad_x).hex(),b"share")
    blob=seal_to_hybrid_public_key(public,b"share")
    with pytest.raises(SealError):
        open_hybrid_sealed(blob[:1093]+bad_x+blob[1125:],private)


def test_noncanonical_mlkem_public_coefficients():
    _, public = generate_hybrid_transport_keypair()
    raw=bytes.fromhex(public)
    # Packed 12-bit coefficients 4095 exceed q=3329; encapsulation must reject.
    invalid=raw[:5]+b"\xff"*1152+raw[5+1152:]
    with pytest.raises(SealError):
        seal_to_hybrid_public_key(invalid.hex(),b"share")


def test_neither_api_accepts_the_other_profile():
    classical, cp = generate_transport_keypair()
    hybrid, hp = generate_hybrid_transport_keypair()
    with pytest.raises(SealError): seal_to_public_key(hp,b"share")
    with pytest.raises(SealError): seal_to_hybrid_public_key(cp,b"share")
    with pytest.raises(SealError): open_hybrid_sealed(seal_to_public_key(cp,b"share"),hybrid)
    with pytest.raises(SealError): open_sealed(seal_to_hybrid_public_key(hp,b"share"),classical)
    with pytest.raises(SealError): open_hybrid_sealed(seal_to_hybrid_public_key(hp,b"share"),classical)


@pytest.mark.parametrize("bad", [None, 1, "text", bytearray(b"abc"), b"x"*65537], ids=["none","int","str","bytearray","oversized"])
def test_wrong_types_and_bounded_inputs(bad):
    private, public = generate_hybrid_transport_keypair()
    for payload,aad in [(bad,b""),(b"share",bad)]:
        with pytest.raises(SealError): seal_to_hybrid_public_key(public,payload,aad)
    with pytest.raises(SealError): open_hybrid_sealed(bad,private)
    with pytest.raises(SealError): open_hybrid_sealed(b"",private,bad)


@pytest.mark.parametrize("seed", [None, b"", b"x"*32, b"x"*100, b"x"*102, "x"*101, b"WCMK\x01"+bytes(96), b"WCMH\x02"+bytes(96)])
def test_invalid_seed(seed):
    with pytest.raises(SealError): HybridTransportPrivateKey(seed)


def test_backend_unavailable_never_falls_back(monkeypatch):
    _, public = generate_hybrid_transport_keypair()
    def unavailable(*args): raise UnsupportedAlgorithm("test")
    monkeypatch.setattr(hs,"_encapsulate",unavailable)
    with pytest.raises(SealError): seal_to_hybrid_public_key(public,b"share")


def test_random_malformed_envelopes_fail_closed():
    rng=random.Random(20261112)
    private, public=generate_hybrid_transport_keypair()
    blob=seal_to_hybrid_public_key(public,b"a non-secret test share",b"context")
    for _ in range(2000):
        candidate=bytearray(blob)
        idx=rng.randrange(len(candidate)); candidate[idx]^=rng.randrange(1,256)
        with pytest.raises(SealError): open_hybrid_sealed(bytes(candidate),private,b"context")
    for n in [0,1,4,5,100,1124,1136,1152,len(blob)-1]:
        with pytest.raises(SealError): open_hybrid_sealed(blob[:n],private,b"context")
    with pytest.raises(SealError): open_hybrid_sealed(blob+b"extra",private,b"context")
    with pytest.raises(SealError): open_hybrid_sealed(bytes(70000),private)


def test_key_generation_backend_unavailable(monkeypatch):
    from cryptography.hazmat.primitives.asymmetric import mlkem
    class Unavailable:
        @staticmethod
        def generate():
            raise UnsupportedAlgorithm("disabled for this test")
    monkeypatch.setattr(mlkem,"MLKEM768PrivateKey",Unavailable)
    with pytest.raises(SealError,match="unavailable"):
        generate_hybrid_transport_keypair()


def test_maximum_aad_and_bad_kem_length():
    private,public=generate_hybrid_transport_keypair()
    aad=b"a"*65536
    blob=seal_to_hybrid_public_key(public,b"share",aad)
    assert open_hybrid_sealed(blob,private,aad)==b"share"
    with pytest.raises(SealError): private._decapsulate(b"short")


def test_x25519_equivalent_ciphertext_encoding_still_refuses():
    # RFC 7748 masks the high bit of an X25519 input coordinate. Changing that
    # bit leaves ECDH unchanged, but must not produce an accepted hybrid alias.
    private, public = generate_hybrid_transport_keypair()
    blob = seal_to_hybrid_public_key(public, b"test-share", b"context")
    changed = bytearray(blob)
    changed[1124] ^= 0x80  # Last byte of the ephemeral X25519 public key.
    original_secret = private._decapsulate(blob[5:1125])
    alias_secret = private._decapsulate(bytes(changed[5:1125]))
    assert original_secret == alias_secret
    descriptor = bytes.fromhex(public)
    assert hs._derive_key(original_secret, descriptor, blob[5:1125]) != hs._derive_key(
        alias_secret, descriptor, bytes(changed[5:1125]),
    )
    with pytest.raises(SealError):
        open_hybrid_sealed(bytes(changed), private, b"context")
