"""Object-sealing a released key to an enclave's attested transport key.

This is WCM's channel binding for Layer 2 (SPEC.md section 3.2). Nonce binding
(``_quote_verify``) closes quote *replay*: a captured quote cannot be presented
later. It does not close quote *relay*: a network adversary who terminates the
enclave's channel can forward a live, valid quote and have the key released onto
its own channel instead of the enclave's (the intra-handshake binding gap,
CVE-2026-33697). Attested-TLS binds evidence to the ephemeral key, not to the
whole channel, so relay survives it.

The fix is to stop returning the key on the channel at all. The enclave vouches
for a transport public key inside the hardware quote (its bytes are folded into
REPORT_DATA under the challenge nonce, so a relay cannot substitute its own), and
the KBS seals the key *to that key* before it leaves. A relayed release then
yields only ciphertext the relay cannot open; only the enclave holding the
transport private key can.

The scheme mirrors ``ca2a_runtime.channel.sealed`` so the family stays one
implementation: ephemeral-static X25519 ECDH, HKDF-SHA256 to a ChaCha20-Poly1305
key, AEAD over the payload. Stdlib crypto (``cryptography``), no new dependency.
Fail-closed: every open error raises ``SealError`` and no path returns
unauthenticated plaintext.
"""
from __future__ import annotations

import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

_VERSION = 1
_HKDF_INFO = b"wcm/sealed-key/v1"
_EPH_LEN = 32
_NONCE_LEN = 12
_HEADER_LEN = 1 + _EPH_LEN + _NONCE_LEN  # version || ephemeral pub || AEAD nonce
_TAG_LEN = 16


class SealError(Exception):
    """Sealing or opening failed. Opening never returns unauthenticated bytes."""


def generate_transport_keypair() -> tuple[X25519PrivateKey, str]:
    """Generate an enclave transport keypair; return (private key, public hex).

    The public hex is what the enclave binds into its attestation quote and hands
    to the KBS; the private key never leaves the enclave.
    """
    priv = X25519PrivateKey.generate()
    return priv, priv.public_key().public_bytes_raw().hex()


def _derive_key(shared: bytes, eph_pub: bytes, peer_pub: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=_HKDF_INFO).derive(
        eph_pub + peer_pub + shared
    )


def seal_to_public_key(recipient_pub_hex: str, payload: bytes, aad: bytes = b"") -> bytes:
    """Seal *payload* so only the holder of *recipient_pub_hex*'s key can open it.

    Returns ``version || ephemeral_pub || nonce || ciphertext``. The recipient
    public key is the transport key the enclave attested; a relay that lacks the
    matching private key cannot open the result.
    """
    try:
        recipient = X25519PublicKey.from_public_bytes(bytes.fromhex(recipient_pub_hex))
    except ValueError as exc:
        raise SealError(f"invalid recipient transport public key: {exc}") from exc

    eph = X25519PrivateKey.generate()
    eph_pub = eph.public_key().public_bytes_raw()
    shared = eph.exchange(recipient)
    key = _derive_key(shared, eph_pub, bytes.fromhex(recipient_pub_hex))
    nonce = os.urandom(_NONCE_LEN)
    ct = ChaCha20Poly1305(key).encrypt(nonce, payload, aad)
    return bytes([_VERSION]) + eph_pub + nonce + ct


def open_sealed(blob: bytes, private_key: X25519PrivateKey, aad: bytes = b"") -> bytes:
    """Open a blob from :func:`seal_to_public_key`. Fail-closed on any error."""
    if len(blob) < _HEADER_LEN + _TAG_LEN:
        raise SealError("sealed blob too short")
    if blob[0] != _VERSION:
        raise SealError(f"unsupported sealed-blob version {blob[0]}")
    eph_pub = blob[1 : 1 + _EPH_LEN]
    nonce = blob[1 + _EPH_LEN : _HEADER_LEN]
    ct = blob[_HEADER_LEN:]
    peer_pub = private_key.public_key().public_bytes_raw()
    try:
        shared = private_key.exchange(X25519PublicKey.from_public_bytes(eph_pub))
        key = _derive_key(shared, eph_pub, peer_pub)
        return ChaCha20Poly1305(key).decrypt(nonce, ct, aad)
    except (InvalidTag, ValueError) as exc:
        raise SealError("could not open sealed key (wrong key or tampered blob)") from exc
