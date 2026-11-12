"""Opt-in ML-KEM-768 + X25519 sealing using finalized NIST guidance.

SP 800-227 section 4.6 / SP 800-56C Rev. 2 one-step SHA3-256 derivation,
then AES-256-GCM. The versioned WCM envelope is experimental, not a NIST
standard or a FIPS-validated module. See docs/hybrid-key-sealing.md.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from cryptography.exceptions import InvalidTag, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash

from ._seal import SealError

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM768PrivateKey

HYBRID_TRANSPORT_PROFILE = "mlkem768-x25519-sha3-256-aes256gcm-v1"
# The version identifies the algorithm AND the envelope encoding. It is included
# in the recipient descriptor, quote binding, KDF context and authenticated data.
_PREFIX = b"WCMH\x02"
_PRIVATE_PREFIX = b"WCMK\x02"
_INFO = b"wcm/sealed-key/mlkem768-x25519-sha3-256-aes256gcm/v1\x00"
_OUTPUT_BITS = (256).to_bytes(4, "big")
_PK_M_LEN = 1184
_CT_M_LEN = 1088
_PK_LEN = 1216
_CT_LEN = 1120
_NONCE_LEN = 12
_TAG_LEN = 16
_DESCRIPTOR_LEN = len(_PREFIX) + _PK_LEN
_HEADER_LEN = len(_PREFIX) + _CT_LEN + _NONCE_LEN
# This interface protects keys/shares, not model files or unbounded messages.
MAX_HYBRID_PAYLOAD_BYTES = 65536
MAX_HYBRID_AAD_BYTES = 65536


def _bytes(value: bytes, name: str, maximum: int) -> None:
    if not isinstance(value, bytes) or len(value) > maximum:
        raise SealError(f"{name} must be bytes of at most {maximum} bytes")


@dataclass(frozen=True, repr=False, init=False)
class HybridTransportPrivateKey:
    """Opaque hybrid key. Versioned private encoding: prefix + ML-KEM seed + X key.

    Never transmit or log this encoding or the component private keys.
    Python does not guarantee zeroization of these objects or temporary bytes.
    """

    _mlkem: MLKEM768PrivateKey = field(repr=False)
    _x25519: X25519PrivateKey = field(repr=False)
    _public: bytes = field(repr=False)

    def __init__(self, encoded: bytes) -> None:
        if (not isinstance(encoded, bytes) or len(encoded) != 101
                or not encoded.startswith(_PRIVATE_PREFIX)):
            raise SealError("invalid hybrid private key length or profile/version")
        try:
            from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM768PrivateKey

            mlkem = MLKEM768PrivateKey.from_seed_bytes(encoded[5:69])
            x25519 = X25519PrivateKey.from_private_bytes(encoded[69:])
            public = (mlkem.public_key().public_bytes_raw()
                      + x25519.public_key().public_bytes_raw())
        except (ImportError, UnsupportedAlgorithm, ValueError) as exc:
            raise SealError("hybrid key generation unavailable or invalid") from exc
        object.__setattr__(self, "_mlkem", mlkem)
        object.__setattr__(self, "_x25519", x25519)
        object.__setattr__(self, "_public", public)

    def __repr__(self) -> str:
        return "HybridTransportPrivateKey(<redacted>)"

    def public_key_hex(self) -> str:
        """Versioned public descriptor; bind ALL decoded bytes in attestation."""
        return (_PREFIX + self._public).hex()

    def private_bytes_raw(self) -> bytes:
        """Export secret material only for protected caller-managed storage."""
        return (_PRIVATE_PREFIX + self._mlkem.private_bytes_raw()
                + self._x25519.private_bytes_raw())

    def _decapsulate(self, ciphertext: bytes) -> bytes:
        if len(ciphertext) != _CT_LEN:
            raise SealError("invalid hybrid encapsulation length")
        ss_m = self._mlkem.decapsulate(ciphertext[:_CT_M_LEN])
        ct_x = ciphertext[_CT_M_LEN:]
        ss_x = self._x25519.exchange(X25519PublicKey.from_public_bytes(ct_x))
        return ss_m + ss_x


def generate_hybrid_transport_keypair() -> tuple[HybridTransportPrivateKey, str]:
    """Generate each component independently using the native backend RNG."""
    try:
        from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM768PrivateKey

        mlkem = MLKEM768PrivateKey.generate()
        x25519 = X25519PrivateKey.generate()
        private = HybridTransportPrivateKey(
            _PRIVATE_PREFIX + mlkem.private_bytes_raw() + x25519.private_bytes_raw(),
        )
        return private, private.public_key_hex()
    except (ImportError, UnsupportedAlgorithm, ValueError) as exc:
        raise SealError("hybrid key generation unavailable or invalid") from exc


def hybrid_transport_binding(public_key_hex: str) -> bytes:
    """Validate the descriptor encoding; return bytes to bind under the nonce.

    Encoding validation is not authentication or full mathematical key
    validation. ML-KEM encapsulation and X25519 exchange validate those inputs
    before any ciphertext is released.
    """
    if (not isinstance(public_key_hex, str)
            or len(public_key_hex) != 2 * _DESCRIPTOR_LEN
            or any(c not in "0123456789abcdef" for c in public_key_hex)):
        raise SealError("hybrid transport key must be canonical fixed-length lowercase hex")
    raw = bytes.fromhex(public_key_hex)
    if not raw.startswith(_PREFIX):
        raise SealError("unsupported hybrid transport profile/version")
    return raw


def _encapsulate(public: bytes) -> tuple[bytes, bytes]:
    from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM768PublicKey

    # exchange() rejects low-order/all-zero shared secrets in OpenSSL.
    ephemeral = X25519PrivateKey.generate()
    ct_x = ephemeral.public_key().public_bytes_raw()
    pk_x = public[_PK_M_LEN:]
    ss_x = ephemeral.exchange(X25519PublicKey.from_public_bytes(pk_x))
    peer = MLKEM768PublicKey.from_public_bytes(public[:_PK_M_LEN])
    ss_m, ct_m = peer.encapsulate()
    return ss_m + ss_x, ct_m + ct_x


def _derive_key(shared: bytes, descriptor: bytes, encapsulation: bytes) -> bytes:
    # SP 800-56C Rev. 2 section 4.1, Option 1: one 256-bit block.
    # Z = ss_M || ss_X, ML-KEM first. FixedInfo binds BOTH ciphertext/public
    # components, the WCM suite/version and output length (SP 800-227 4.6).
    # ConcatKDFHash prepends the required big-endian 32-bit counter 00000001.
    return ConcatKDFHash(
        algorithm=hashes.SHA3_256(), length=32,
        otherinfo=encapsulation + descriptor + _INFO + _OUTPUT_BITS,
    ).derive(shared)


def seal_to_hybrid_public_key(
    recipient_pub_hex: str, payload: bytes, aad: bytes = b"",
) -> bytes:
    """Seal a key/share to BOTH recipient key components; no classical fallback.

    Layout: WCMH || 0x02 || ML-KEM ct + X ephemeral (1120) || nonce (12) || AEAD.
    Caller-supplied AAD should bind the holder, model and transaction context.
    """
    _bytes(payload, "payload", MAX_HYBRID_PAYLOAD_BYTES)
    _bytes(aad, "aad", MAX_HYBRID_AAD_BYTES)
    descriptor = hybrid_transport_binding(recipient_pub_hex)
    try:
        shared, encapsulation = _encapsulate(descriptor[len(_PREFIX):])
        key = _derive_key(shared, descriptor, encapsulation)
        nonce = os.urandom(_NONCE_LEN)
        header = _PREFIX + encapsulation + nonce
        ciphertext = AESGCM(key).encrypt(nonce, payload, header + descriptor + aad)
        return header + ciphertext
    except (ImportError, UnsupportedAlgorithm, ValueError, TypeError) as exc:
        raise SealError("could not seal hybrid key (invalid key or unavailable backend)") from exc


def open_hybrid_sealed(
    blob: bytes, private_key: HybridTransportPrivateKey, aad: bytes = b"",
) -> bytes:
    """Authenticate and open a hybrid envelope; never accept a classical blob.

    Replay/expiry and sender authorization MUST be checked separately. Reopening
    an unchanged envelope is intentionally possible at this stateless layer.
    """
    _bytes(blob, "blob", _HEADER_LEN + _TAG_LEN + MAX_HYBRID_PAYLOAD_BYTES)
    _bytes(aad, "aad", MAX_HYBRID_AAD_BYTES)
    if not isinstance(private_key, HybridTransportPrivateKey):
        raise SealError("hybrid private key required")
    if len(blob) < _HEADER_LEN + _TAG_LEN or not blob.startswith(_PREFIX):
        raise SealError("invalid hybrid envelope length or profile/version")
    encapsulation = blob[len(_PREFIX):len(_PREFIX) + _CT_LEN]
    nonce = blob[len(_PREFIX) + _CT_LEN:_HEADER_LEN]
    descriptor = _PREFIX + private_key._public
    try:
        shared = private_key._decapsulate(encapsulation)
        key = _derive_key(shared, descriptor, encapsulation)
        return AESGCM(key).decrypt(
            nonce, blob[_HEADER_LEN:], blob[:_HEADER_LEN] + descriptor + aad,
        )
    except (InvalidTag, UnsupportedAlgorithm, ValueError, TypeError) as exc:
        raise SealError("could not open hybrid key (wrong key, context or tampered blob)") from exc
