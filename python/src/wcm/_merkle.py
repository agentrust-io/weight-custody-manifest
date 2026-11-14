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
from typing import Callable, NamedTuple, Sequence

Buffer = bytes | bytearray | memoryview
HashPath = Sequence[Buffer]  # runtime accepts list/tuple containers only


def _is_integer(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _digest_bytes(value: object, size: int) -> bytes | None:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        return None
    try:
        result = bytes(value)
    except ValueError:  # a released memoryview
        return None
    return result if len(result) == size else None


def _digest_path(value: object, size: int) -> list[bytes] | None:
    if not isinstance(value, (list, tuple)):
        return None
    result: list[bytes] = []
    for node in value:
        digest = _digest_bytes(node, size)
        if digest is None:
            return None
        result.append(digest)
    return result


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
    leaf_hash: Buffer
    audit_path: HashPath  # sibling hashes from leaf to root


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

    def add_leaf(self, leaf_preimage: Buffer) -> bytes:
        """Hash *leaf_preimage* with domain byte 0x00 and append. Returns the leaf hash."""
        if not isinstance(leaf_preimage, (bytes, bytearray, memoryview)):
            raise TypeError("leaf_preimage must be bytes-like")
        leaf_hash = self._h(b"\x00" + bytes(leaf_preimage))
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
        if not _is_integer(leaf_index):
            raise TypeError("leaf_index must be an integer")
        n = len(self._leaf_hashes)
        if leaf_index < 0 or leaf_index >= n:
            raise IndexError(f"leaf_index {leaf_index} out of range for {n} leaves")
        audit_path = self._audit_path(self._leaf_hashes, leaf_index)
        return InclusionProof(leaf_index, n, self._leaf_hashes[leaf_index], audit_path)

    def verify_inclusion(self, proof: InclusionProof) -> bool:
        n = len(self._leaf_hashes)
        if proof.tree_size != n:
            return False
        computed = compute_root_from_proof(
            proof.leaf_hash, proof.leaf_index, proof.tree_size, proof.audit_path, self._h
        )
        return bool(computed) and computed == self.root()

    def consistency_proof(self, first_size: int) -> list[bytes]:
        if not _is_integer(first_size):
            raise TypeError("first_size must be an integer")
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


def _expected_audit_path_length(n: int, index: int) -> int:
    if n == 1:
        return 0
    k = _split_point(n)
    if index < k:
        return 1 + _expected_audit_path_length(k, index)
    return 1 + _expected_audit_path_length(n - k, index - k)


def compute_root_from_proof(
    leaf_hash: Buffer,
    index: int,
    tree_size: int,
    audit_path: HashPath,
    h_fn: Callable[[bytes], bytes],
) -> bytes:
    """Reconstruct the root from an inclusion proof (RFC 9162 section 2.1.3.2).

    Returns ``b""`` on a malformed proof (more path nodes than the tree needs),
    which will not equal any real root.
    """
    if not _is_integer(index) or not _is_integer(tree_size) or not 0 <= index < tree_size:
        return b""  # a position outside the tree is not a position
    digest_size = len(h_fn(b""))
    leaf = _digest_bytes(leaf_hash, digest_size)
    if not isinstance(audit_path, (list, tuple)) or len(audit_path) > tree_size.bit_length():
        return b""
    path = _digest_path(audit_path, digest_size)
    if leaf is None or path is None:
        return b""
    fn = index
    sn = tree_size - 1
    r = leaf
    for step in path:
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
    if sn != 0:
        return b""  # short proof: did not reach the root
    return r


def verify_consistency(
    first_root: Buffer,
    second_root: Buffer,
    first_size: int,
    second_size: int,
    proof: HashPath,
    *,
    algorithm: str = "sha256",
) -> bool:
    """Verify an RFC 9162 section 2.1.4.2 consistency proof.

    True iff the size-*first_size* tree (root *first_root*) is an append-only
    positional prefix of the size-*second_size* tree (root *second_root*). Uses
    only the roots, sizes, and proof - never the leaf data - so a monitor without
    the store can check a log advance. Tampered or truncated proofs return False.
    """
    if not isinstance(algorithm, str) or algorithm not in _HASH_FNS:
        return False
    h = _HASH_FNS[algorithm]
    digest_size = len(EMPTY_TREE[algorithm])
    if (
        not _is_integer(first_size)
        or not _is_integer(second_size)
        or first_size < 0
        or second_size < 0
    ):
        return False
    if (
        not isinstance(proof, (list, tuple))
        or len(proof) > second_size.bit_length() + 1
    ):
        return False
    # A consistency path contributes at most one sibling per tree level,
    # plus one seed subtree hash. The (m=3, n=5) regression reaches this bound.
    first = _digest_bytes(first_root, digest_size)
    second = _digest_bytes(second_root, digest_size)
    nodes = _digest_path(proof, digest_size)
    if first is None or second is None or nodes is None:
        return False
    if first_size > second_size:
        return False
    if first_size == second_size:
        return not nodes and first == second
    if first_size == 0:
        return not nodes
    terms = nodes
    if first_size & (first_size - 1) == 0:  # power of two
        terms = [first] + terms
    if not terms:
        return False
    fn, sn = first_size - 1, second_size - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    fr, sr, sn = _fold_consistency_terms(terms, fn, sn, h)
    return fr is not None and fr == first and sr == second and sn == 0


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
