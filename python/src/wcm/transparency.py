"""Transparency log: making equivocation and suppressed revocations detectable
(SPEC.md section 3.7).

Joint signatures prove *who* authorized a manifest; they do not prove there is
only *one*. An append-only transparency log with signed tree heads and inclusion
proofs turns a split view into something a monitor can catch: re-attestation
binds to an inclusion proof, so a manifest absent from the log or superseded does
not verify, and because revocations publish to the same log, a suppressed
revocation is a *missing expected entry* rather than a silent non-event.

This is the log operator's side (a SCITT Transparency Service, or a Rekor-style
log). The mechanism choice and who runs the witnesses/monitors is open question
10; this ships the RFC 9162 substrate both are built on. It makes the authority
layer honest; it does not make adversary-owned silicon honest (open question 8.8).
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from ._canonicalize import canonicalize
from ._merkle import InclusionProof, MerkleTree, compute_root_from_proof, verify_consistency
from ._merkle import _sha256  # domain-separated leaf hashing
from ._signing import Ed25519KeyPair, _b64url_decode, _b64url_encode


class EntryType(str, Enum):
    manifest = "manifest"
    revocation = "revocation"
    measurement_set_change = "measurement-set-change"


def make_leaf_preimage(statement: dict[str, Any], entry_type: EntryType) -> bytes:
    """Deterministic leaf preimage for a logged statement (RFC 8785 canonical)."""
    return canonicalize({"type": entry_type.value, "statement": statement})


@dataclass(frozen=True)
class SignedTreeHead:
    tree_size: int
    root: str  # "sha256:<hex>"
    signed_at: str
    key_id: str
    signature_b64: str

    def root_bytes(self) -> bytes:
        return bytes.fromhex(self.root.split(":", 1)[1])


def _sth_preimage(tree_size: int, root: str, signed_at: str) -> bytes:
    return canonicalize({"tree_size": tree_size, "root": root, "signed_at": signed_at})


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class TransparencyLog:
    """An append-only, signed transparency log for manifests and revocations."""

    def __init__(
        self,
        keypair: Ed25519KeyPair,
        *,
        now: Optional[Callable[[], datetime]] = None,
    ) -> None:
        self._kp = keypair
        self._tree = MerkleTree("sha256")
        self._preimages: list[bytes] = []
        self._now = now or _utcnow

    @property
    def size(self) -> int:
        return len(self._preimages)

    def append(self, statement: dict[str, Any], *, entry_type: EntryType) -> int:
        """Register *statement*; returns its 0-based leaf index."""
        preimage = make_leaf_preimage(statement, entry_type)
        self._tree.add_leaf(preimage)
        self._preimages.append(preimage)
        return len(self._preimages) - 1

    def signed_tree_head(self) -> SignedTreeHead:
        root = self._tree.root_hex()
        signed_at = self._now().isoformat(timespec="seconds").replace("+00:00", "Z")
        size = len(self._tree)
        preimage = _sth_preimage(size, root, signed_at)
        sig = self._kp.private_key.sign(preimage)
        return SignedTreeHead(
            tree_size=size,
            root=root,
            signed_at=signed_at,
            key_id=self._kp.key_id,
            signature_b64=_b64url_encode(sig),
        )

    def inclusion_proof(self, index: int) -> InclusionProof:
        return self._tree.inclusion_proof(index)

    def consistency_proof(self, first_size: int) -> list[bytes]:
        return self._tree.consistency_proof(first_size)

    def find(self, statement: dict[str, Any], entry_type: EntryType) -> Optional[int]:
        """Return the index of a matching entry, or None. A monitor uses this to
        detect a *missing* expected entry (e.g. a suppressed revocation)."""
        target = make_leaf_preimage(statement, entry_type)
        for i, preimage in enumerate(self._preimages):
            if preimage == target:
                return i
        return None


# ---------------------------------------------------------------------------
# Monitor-side verification (no access to the log's store)
# ---------------------------------------------------------------------------


def verify_sth(sth: SignedTreeHead, log_public_key: bytes) -> bool:
    """Verify a signed tree head's signature under the log's public key."""
    preimage = _sth_preimage(sth.tree_size, sth.root, sth.signed_at)
    try:
        Ed25519PublicKey.from_public_bytes(log_public_key).verify(
            _b64url_decode(sth.signature_b64), preimage
        )
        return True
    except (InvalidSignature, ValueError):
        return False


def verify_inclusion(
    statement: dict[str, Any],
    entry_type: EntryType,
    proof: InclusionProof,
    sth: SignedTreeHead,
) -> bool:
    """Verify *statement* is included in the tree the *sth* commits to."""
    preimage = make_leaf_preimage(statement, entry_type)
    leaf_hash = _sha256(b"\x00" + preimage)
    if proof.leaf_hash != leaf_hash:
        return False
    if proof.tree_size != sth.tree_size:
        return False
    computed = compute_root_from_proof(
        leaf_hash, proof.leaf_index, proof.tree_size, proof.audit_path, _sha256
    )
    return computed == sth.root_bytes()


def verify_log_consistency(
    old: SignedTreeHead, new: SignedTreeHead, proof: list[bytes]
) -> bool:
    """Verify the log grew append-only from *old* to *new* (no history rewrite)."""
    return verify_consistency(
        old.root_bytes(), new.root_bytes(), old.tree_size, new.tree_size, proof
    )
