"""Ed25519 signing and verification for the WCM reference SDK.

Standard profile: Ed25519 (RFC 8032). A post-quantum profile (ML-DSA-65) is
on the roadmap and intentionally out of scope for the Layer 1 preview.

A Weight Custody Manifest is signed JOINTLY: the builder and the custodian
each contribute a signature over the same pre-image (SPEC.md section 3.1).
Under ``sovereign_profile`` a quorum that includes the sovereign signer is
also required. Each signer produces one signature block tagged with its
``role`` and ``signer`` identity; verification (``_verify``) checks that the
required roles are present and that every block is cryptographically valid.

Signing pre-image: RFC 8785 canonical JSON of the manifest's WCM_SIGNED_FIELDS.
Key identifiers: sha256 hex-digest of the raw public key bytes.
Signatures: base64url-encoded (no padding).

Ed25519 validation notes: PyCA/OpenSSL enforces the cofactorless equation,
rejects non-canonical point encodings, and rejects small-order keys. The
eight torsion points are additionally rejected at load time here.

Adapted from the agentrust-io/agent-manifest SDK (Apache-2.0).
"""
from __future__ import annotations

import base64
import hashlib
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from ._canonicalize import canonicalize

# Fields covered by the joint signature. Everything the builder and custodian
# commit to at issuance, and nothing appended afterward: the ``signatures``
# array is excluded because it is built from these signatures. This tuple is
# normative for the reference SDK and MUST NOT be varied by an implementation.
WCM_SIGNED_FIELDS: tuple[str, ...] = (
    "manifest_version",
    "weights_hash",
    "builder",
    "release_terms",
    "release_policy",
    "custody",
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


_B64URL_RE = re.compile(r"^[A-Za-z0-9\-_]*$")


def _b64url_decode(s: str) -> bytes:
    # Reject standard base64 (+/); only URL-safe alphabet is allowed.
    if not _B64URL_RE.match(s):
        raise ValueError(
            "Invalid base64url: contains non-URL-safe characters (use - and _ not + and /)"
        )
    pad = 4 - len(s) % 4
    return base64.urlsafe_b64decode(s + ("=" * pad if pad != 4 else ""))


def _key_id(public_key_bytes: bytes) -> str:
    """sha256 hex of raw public key bytes."""
    return hashlib.sha256(public_key_bytes).hexdigest()


def _signed_at_now() -> str:
    """ISO 8601 UTC timestamp for a signature block's ``signed_at``."""
    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )


def signing_pre_image(manifest_dict: dict[str, Any]) -> bytes:
    """Return the RFC 8785 canonical bytes that are signed.

    Extracts only the WCM_SIGNED_FIELDS subset from *manifest_dict* and
    canonicalizes it. Absent optional fields are omitted (null-exclusion is
    applied by ``canonicalize``). This is the single source of truth for the
    pre-image: signers and verifiers MUST both call it so their byte
    sequences are identical.
    """
    subset = {k: manifest_dict[k] for k in WCM_SIGNED_FIELDS if k in manifest_dict}
    return canonicalize(subset)


# ---------------------------------------------------------------------------
# Ed25519
# ---------------------------------------------------------------------------

# All eight low-order (torsion) points of the Ed25519 curve (cofactor 8). A key
# equal to any of these enables signature forgery; reject at load time.
_SMALL_ORDER_POINTS: frozenset[bytes] = frozenset(
    {
        bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000000"),
        bytes.fromhex("0100000000000000000000000000000000000000000000000000000000000000"),
        bytes.fromhex("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"),
        bytes.fromhex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"),
        bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000080"),
        bytes.fromhex("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
        bytes.fromhex("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85"),
        bytes.fromhex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa"),
    }
)


@dataclass(frozen=True)
class Ed25519KeyPair:
    private_key: Ed25519PrivateKey
    public_key: Ed25519PublicKey

    def __repr__(self) -> str:
        return f"Ed25519KeyPair(key_id={self.key_id!r}, private_key=<REDACTED>)"

    def __str__(self) -> str:
        return self.__repr__()

    @property
    def public_bytes(self) -> bytes:
        return self.public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)

    @property
    def key_id(self) -> str:
        return _key_id(self.public_bytes)

    def public_b64url(self) -> str:
        return _b64url_encode(self.public_bytes)

    def private_b64url(self) -> str:
        raw = self.private_key.private_bytes(
            Encoding.Raw, PrivateFormat.Raw, NoEncryption()
        )
        return _b64url_encode(raw)


def generate_ed25519() -> Ed25519KeyPair:
    """Generate a fresh Ed25519 key pair."""
    priv = Ed25519PrivateKey.generate()
    return Ed25519KeyPair(private_key=priv, public_key=priv.public_key())


def ed25519_from_private_bytes(raw: bytes) -> Ed25519KeyPair:
    priv = Ed25519PrivateKey.from_private_bytes(raw)
    return Ed25519KeyPair(private_key=priv, public_key=priv.public_key())


def ed25519_from_private_b64url(s: str) -> Ed25519KeyPair:
    return ed25519_from_private_bytes(_b64url_decode(s))


class Ed25519Signer:
    """Signs a manifest dict for one party (builder, custodian, or a quorum signer)."""

    def __init__(self, keypair: Ed25519KeyPair) -> None:
        self._kp = keypair

    @property
    def key_id(self) -> str:
        return self._kp.key_id

    def sign(self, manifest_dict: dict[str, Any], *, role: str, signer: str) -> dict[str, Any]:
        """Return a signature block for the ``signatures`` array.

        Args:
            manifest_dict: The manifest as a plain dict (unsigned fields ok).
            role: The signing party's role, e.g. ``builder``, ``custodian``,
                ``sovereign``, or ``additional`` (SPEC.md section 3.1).
            signer: The signer's stable identity string (matches
                ``builder.identity`` / ``custody.custodian`` where applicable).
        """
        pre_image = signing_pre_image(manifest_dict)
        sig_bytes = self._kp.private_key.sign(pre_image)
        return {
            "role": role,
            "signer": signer,
            "algorithm": "Ed25519",
            "key_id": self._kp.key_id,
            "key_type": "software",
            "signed_at": _signed_at_now(),
            "signature_value": _b64url_encode(sig_bytes),
            "signed_fields": list(WCM_SIGNED_FIELDS),
        }


class Ed25519Verifier:
    """Verifies an Ed25519 signature over a manifest's signed fields."""

    def __init__(self, public_key_bytes: bytes) -> None:
        # Reject all eight torsion (small-order) subgroup elements. cryptography
        # >=44 defers this to verify() time, so enforce it here at load.
        if len(public_key_bytes) != 32 or public_key_bytes in _SMALL_ORDER_POINTS:
            raise ValueError(
                "Invalid Ed25519 public key: key is a small-order subgroup element "
                "(torsion point) and MUST be rejected."
            )
        self._pub: Ed25519PublicKey = Ed25519PublicKey.from_public_bytes(
            public_key_bytes
        )
        self._key_id = _key_id(public_key_bytes)

    @classmethod
    def from_b64url(cls, s: str) -> "Ed25519Verifier":
        return cls(_b64url_decode(s))

    @property
    def key_id(self) -> str:
        return self._key_id

    def verify(self, manifest_dict: dict[str, Any], signature_value: str) -> None:
        """Verify *signature_value* over *manifest_dict*'s signed fields.

        Raises:
            InvalidSignature: Verification failed or the signature is the
                wrong length.
            ValueError: The signature string is not valid base64url.
        """
        pre_image = signing_pre_image(manifest_dict)
        sig_bytes = _b64url_decode(signature_value)
        if len(sig_bytes) != 64:
            raise InvalidSignature(
                f"Ed25519 signature must be 64 bytes, got {len(sig_bytes)}"
            )
        self._pub.verify(sig_bytes, pre_image)  # raises InvalidSignature on failure
