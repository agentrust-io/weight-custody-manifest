from __future__ import annotations

from wcm._merkle import MerkleTree, verify_consistency


def _tree(n: int) -> MerkleTree:
    t = MerkleTree("sha256")
    for i in range(n):
        t.add_leaf(f"leaf-{i}".encode())
    return t


def test_single_leaf_root_is_leaf_hash():
    t = MerkleTree("sha256")
    h = t.add_leaf(b"only")
    assert t.root() == h


def test_inclusion_proofs_verify_all_indices():
    for n in range(1, 17):
        t = _tree(n)
        for i in range(n):
            assert t.verify_inclusion(t.inclusion_proof(i)), f"n={n} i={i}"


def test_inclusion_fails_on_tampered_leaf():
    t = _tree(5)
    proof = t.inclusion_proof(2)
    bad = proof._replace(leaf_hash=b"\x00" * 32)
    assert not t.verify_inclusion(bad)


def test_consistency_proofs_verify():
    for n in range(2, 17):
        full = _tree(n)
        full_root = full.root()
        for m in range(1, n):
            first_root = _tree(m).root()
            proof = full.consistency_proof(m)
            assert verify_consistency(first_root, full_root, m, n, proof), f"n={n} m={m}"


def test_consistency_rejects_non_prefix():
    full = _tree(8)
    # A different size-4 tree that is NOT the prefix of `full`.
    other = MerkleTree("sha256")
    for i in range(4):
        other.add_leaf(f"OTHER-{i}".encode())
    proof = full.consistency_proof(4)
    assert not verify_consistency(other.root(), full.root(), 4, 8, proof)


def test_consistency_same_size_needs_matching_root():
    t = _tree(4)
    assert verify_consistency(t.root(), t.root(), 4, 4, [])
    assert not verify_consistency(b"\x00" * 32, t.root(), 4, 4, [])


def test_shake256_tree():
    t = MerkleTree("shake256")
    t.add_leaf(b"a")
    t.add_leaf(b"b")
    assert t.root_hex().startswith("shake256:")


def test_verify_inclusion_binds_tree_size_and_validates_types():
    import pytest
    from wcm._merkle import InclusionProof

    t = _tree(4)
    proof = t.inclusion_proof(0)
    assert t.verify_inclusion(proof)
    # Forged tree_size (8 or 3) with the same audit_path must not verify
    for bad_size in (8, 3, True):
        assert not t.verify_inclusion(
            InclusionProof(proof.leaf_index, bad_size, proof.leaf_hash, proof.audit_path)
        )
    assert not t.verify_inclusion(
        InclusionProof(True, proof.tree_size, proof.leaf_hash, proof.audit_path)
    )
    with pytest.raises(TypeError):
        t.add_leaf("not-bytes")  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        t.inclusion_proof(True)
    with pytest.raises(TypeError):
        t.consistency_proof(True)


def test_verify_consistency_validates_algorithm_roots_sizes_and_proof():
    m, n = 5, 9
    small, big = _tree(m), _tree(n)
    proof = big.consistency_proof(m)
    assert verify_consistency(small.root(), big.root(), m, n, proof, algorithm="md5") is False
    assert verify_consistency(b"\xab", b"\xab", 3, 3, []) is False
    assert verify_consistency(small.root(), big.root(), True, n, proof) is False
    assert verify_consistency(small.root(), big.root(), -1, n, proof) is False
    assert verify_consistency("not-bytes", big.root(), m, n, proof) is False  # type: ignore[arg-type]
    assert verify_consistency(small.root(), big.root(), m, n, ["not-bytes"]) is False  # type: ignore[list-item]
