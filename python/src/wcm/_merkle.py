"""RFC 9162 Merkle tree with domain separation.

Reference: https://www.rfc-editor.org/rfc/rfc9162

The substrate for the transparency log (SPEC.md section 3.7): an append-only
tree with signed tree heads, inclusion proofs, and consistency proofs, the same
primitive both IETF SCITT and Rekor-style logs are built on.

Domain separation prevents second-preimage attacks:
  Leaf node:     H(0x00 || leaf_data)
  Internal node: H(0x01 || left_child || right_child)

Ported from the agentrust-io/agent-manifest SDK (Apache-2.0), kept in sync with
the family. Consistency-proof logic is subtle; reusing the proven implementation
rather than re-deriving it.
"""
from __future__ import annotations

import hashlib
from typing import Callable, NamedTuple


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _shake256(data: bytes) -> bytes:
    return hashlib.shake_256(data).digest(32)  # 256-bit = 32 bytes, fixed


_HASH_FNS: dict[str, Callable[[bytes], bytes]] = {
    "sha256": _sha256,
    "shake256": _shake256,
}

EMPTY_TREE: dict[str, bytes] = {
    "sha256": _sha256(b""),
    "shake256": _shake256(b""),
}


class InclusionProof(NamedTuple):
    """Merkle inclusion proof for a single leaf."""

    leaf_index: int
    tree_size: int
    leaf_hash: bytes
    audit_path: list[bytes]  # sibling hashes from leaf to root


class MerkleTree:
    """Left-balanced RFC 9162 Merkle tree with domain-separated hashing."""

    def __init__(self, algorithm: str = "sha256") -> None:
        if algorithm not in _HASH_FNS:
            raise ValueError(
                f"Unsupported algorithm {algorithm!r}. Use 'sha256' or 'shake256'."
            )
        self._h = _HASH_FNS[algorithm]
        self._algorithm = algorithm
        self._leaf_hashes: list[bytes] = []

    def add_leaf(self, leaf_preimage: bytes) -> bytes:
        """Hash *leaf_preimage* with domain byte 0x00 and append. Returns the leaf hash."""
        leaf_hash = self._h(b"\x00" + leaf_preimage)
        self._leaf_hashes.append(leaf_hash)
        return leaf_hash

    def __len__(self) -> int:
        return len(self._leaf_hashes)

    def root(self) -> bytes:
        if not self._leaf_hashes:
            return EMPTY_TREE[self._algorithm]
        return self._mth(self._leaf_hashes)

    def root_hex(self) -> str:
        return f"{self._algorithm}:{self.root().hex()}"

    def inclusion_proof(self, leaf_index: int) -> InclusionProof:
        n = len(self._leaf_hashes)
        if leaf_index < 0 or leaf_index >= n:
            raise IndexError(f"leaf_index {leaf_index} out of range for {n} leaves")
        audit_path = self._audit_path(self._leaf_hashes, leaf_index)
        return InclusionProof(leaf_index, n, self._leaf_hashes[leaf_index], audit_path)

    def verify_inclusion(self, proof: InclusionProof) -> bool:
        computed = compute_root_from_proof(
            proof.leaf_hash, proof.leaf_index, proof.tree_size, proof.audit_path, self._h
        )
        return computed == self.root()

    def consistency_proof(self, first_size: int) -> list[bytes]:
        n = len(self._leaf_hashes)
        if not 0 < first_size <= n:
            raise ValueError(f"first_size {first_size} out of range 1..{n}")
        if first_size == n:
            return []
        return self._subproof(first_size, self._leaf_hashes, True)

    def _subproof(self, m: int, hashes: list[bytes], b: bool) -> list[bytes]:
        n = len(hashes)
        if m == n:
            return [] if b else [self._mth(hashes)]
        k = _split_point(n)
        if m <= k:
            return self._subproof(m, hashes[:k], b) + [self._mth(hashes[k:])]
        return self._subproof(m - k, hashes[k:], False) + [self._mth(hashes[:k])]

    def _mth(self, hashes: list[bytes]) -> bytes:
        n = len(hashes)
        if n == 1:
            return hashes[0]
        k = _split_point(n)
        return self._h(b"\x01" + self._mth(hashes[:k]) + self._mth(hashes[k:]))

    def _audit_path(self, hashes: list[bytes], index: int) -> list[bytes]:
        n = len(hashes)
        if n == 1:
            return []
        k = _split_point(n)
        if index < k:
            path = self._audit_path(hashes[:k], index)
            path.append(self._mth(hashes[k:]))
        else:
            path = self._audit_path(hashes[k:], index - k)
            path.append(self._mth(hashes[:k]))
        return path


def _split_point(n: int) -> int:
    """Largest power of 2 strictly less than n (RFC 9162 section 2.1)."""
    k = 1
    while k < n:
        k <<= 1
    return k >> 1


def compute_root_from_proof(
    leaf_hash: bytes,
    index: int,
    tree_size: int,
    audit_path: list[bytes],
    h_fn: Callable[[bytes], bytes],
) -> bytes:
    """Reconstruct the root from an inclusion proof (RFC 9162 section 2.1.3.2).

    Returns ``b""`` on a malformed proof (more path nodes than the tree needs),
    which will not equal any real root.
    """
    fn = index
    sn = tree_size - 1
    r = leaf_hash
    for step in audit_path:
        if sn == 0:
            return b""  # over-long proof: malformed
        if (fn & 1) or fn == sn:
            r = h_fn(b"\x01" + step + r)
            if (fn & 1) == 0:
                while (fn & 1) == 0 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            r = h_fn(b"\x01" + r + step)
        fn >>= 1
        sn >>= 1
    return r


def verify_consistency(
    first_root: bytes,
    second_root: bytes,
    first_size: int,
    second_size: int,
    proof: list[bytes],
    *,
    algorithm: str = "sha256",
) -> bool:
    """Verify an RFC 9162 section 2.1.4.2 consistency proof.

    True iff the size-*first_size* tree (root *first_root*) is an append-only
    positional prefix of the size-*second_size* tree (root *second_root*). Uses
    only the roots, sizes, and proof - never the leaf data - so a monitor without
    the store can check a log advance. Tampered or truncated proofs return False.
    """
    h = _HASH_FNS[algorithm]
    if first_size > second_size:
        return False
    if first_size == second_size:
        return not proof and first_root == second_root
    if first_size == 0:
        return not proof
    terms = list(proof)
    if first_size & (first_size - 1) == 0:  # power of two
        terms = [first_root] + terms
    if not terms:
        return False
    fn, sn = first_size - 1, second_size - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    fr, sr, sn = _fold_consistency_terms(terms, fn, sn, h)
    return fr is not None and fr == first_root and sr == second_root and sn == 0


def _fold_consistency_terms(
    terms: list[bytes], fn: int, sn: int, h: Callable[[bytes], bytes]
) -> tuple[bytes | None, bytes | None, int]:
    fr = sr = terms[0]
    for c in terms[1:]:
        if sn == 0:
            return None, None, -1
        if (fn & 1) or fn == sn:
            fr = h(b"\x01" + c + fr)
            sr = h(b"\x01" + c + sr)
            while (fn & 1) == 0 and fn != 0:
                fn >>= 1
                sn >>= 1
        else:
            sr = h(b"\x01" + sr + c)
        fn >>= 1
        sn >>= 1
    return fr, sr, sn
