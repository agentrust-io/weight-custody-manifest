from dataclasses import replace
from enum import IntEnum

import pytest

from wcm import EntryType, TransparencyLog, generate_ed25519, verify_inclusion
from wcm._merkle import InclusionProof, MerkleTree, verify_consistency


class Count(int):
    pass


class Position(IntEnum):
    ZERO = 0
    ONE = 1


def tree(n, algorithm="sha256", buffer=bytes):
    result = MerkleTree(algorithm)
    for i in range(n):
        result.add_leaf(buffer(str(i).encode()))
    return result


@pytest.mark.parametrize("algorithm", ["sha256", "shake256"])
@pytest.mark.parametrize("buffer", [bytes, bytearray, memoryview])
@pytest.mark.parametrize("container", [list, tuple])
def test_compatible_inclusion_and_consistency(algorithm, buffer, container):
    small, big = tree(3, algorithm, buffer), tree(5, algorithm, buffer)
    proof = big.inclusion_proof(Position.ONE)
    shaped = InclusionProof(
        Count(proof.leaf_index), Count(proof.tree_size), buffer(proof.leaf_hash),
        container(buffer(p) for p in proof.audit_path),
    )
    assert big.verify_inclusion(shaped)
    assert not big.verify_inclusion(shaped._replace(tree_size=Count(6)))
    consistency = container(buffer(p) for p in big.consistency_proof(Count(3)))
    assert verify_consistency(buffer(small.root()), buffer(big.root()), Count(3), Count(5), consistency, algorithm=algorithm)


def test_consistency_bound_preserves_honest_paths():
    margin = -100
    for n in range(1, 33):
        big = tree(n)
        for m in range(1, n + 1):
            proof = big.consistency_proof(m)
            margin = max(margin, len(proof) - (n.bit_length() + 1))
            assert verify_consistency(tree(m).root(), big.root(), m, n, proof)
    assert margin == 0
    assert len(tree(5).consistency_proof(3)) == (5).bit_length() + 1


def fixture_log():
    log = TransparencyLog(generate_ed25519())
    for i in range(4):
        log.append({"v": i}, entry_type=EntryType.manifest)
    return log, log.inclusion_proof(0), log.signed_tree_head()


@pytest.mark.parametrize("path", [["x"], [None], [b"short"], None, "not-a-path"])
def test_exported_verifier_refuses_malformed_paths(path):
    _, proof, head = fixture_log()
    assert not verify_inclusion({"v": 0}, EntryType.manifest, proof._replace(audit_path=path), head)


@pytest.mark.parametrize("index", [True, -1, 4])
def test_exported_verifier_never_accepts_failure_as_empty_root(index):
    _, proof, head = fixture_log()
    assert not verify_inclusion(
        {"v": 0}, EntryType.manifest, proof._replace(leaf_index=index),
        replace(head, root="sha256:"),
    )


@pytest.mark.parametrize("buffer", [bytes, bytearray, memoryview])
def test_exported_verifier_accepts_compatible_proofs(buffer):
    _, proof, head = fixture_log()
    shaped = proof._replace(
        leaf_index=Position.ZERO, tree_size=Count(4),
        leaf_hash=buffer(proof.leaf_hash), audit_path=tuple(buffer(p) for p in proof.audit_path),
    )
    assert verify_inclusion({"v": 0}, EntryType.manifest, shaped, head)
    assert not verify_inclusion({"v": 0}, EntryType.manifest, shaped._replace(tree_size=True), replace(head, tree_size=True))


def test_boolean_head_size_does_not_equal_single_leaf_size():
    log = TransparencyLog(generate_ed25519())
    log.append({"v": 0}, entry_type=EntryType.manifest)
    assert not verify_inclusion({"v": 0}, EntryType.manifest, log.inclusion_proof(0), replace(log.signed_tree_head(), tree_size=True))


@pytest.mark.parametrize("root", [b"", b"x", b"x" * 31, b"x" * 33])
def test_malformed_consistency_roots_stay_rejected(root):
    assert not verify_consistency(root, root, 3, 3, [])


def test_boolean_inputs_and_truncated_paths_stay_rejected():
    t = tree(4)
    p = t.inclusion_proof(0)
    for field in ("leaf_index", "tree_size"):
        assert not t.verify_inclusion(p._replace(**{field: True}))
    assert not t.verify_inclusion(p._replace(audit_path=p.audit_path[:-1]))
    assert not t.verify_inclusion(p._replace(audit_path=list(p.audit_path) + [b"x" * 32]))
    with pytest.raises(TypeError):
        t.inclusion_proof(True)
    with pytest.raises(TypeError):
        t.consistency_proof(True)
    assert not verify_consistency(t.root(), t.root(), True, 4, [])
