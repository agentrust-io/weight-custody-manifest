from __future__ import annotations

from wcm import (
    EntryType,
    TransparencyLog,
    generate_ed25519,
    verify_inclusion,
    verify_log_consistency,
    verify_sth,
)

MANIFEST = {"weights_hash": "sha256:" + "aa" * 32, "sovereign_profile": False}
REVOCATION = {"weights_hash": "sha256:" + "aa" * 32, "reason": "compromise"}


def _log():
    return TransparencyLog(generate_ed25519())


def test_append_increments_size():
    log = _log()
    assert log.size == 0
    assert log.append(MANIFEST, entry_type=EntryType.manifest) == 0
    assert log.append(REVOCATION, entry_type=EntryType.revocation) == 1
    assert log.size == 2


def test_sth_signature_verifies():
    kp = generate_ed25519()
    log = TransparencyLog(kp)
    log.append(MANIFEST, entry_type=EntryType.manifest)
    sth = log.signed_tree_head()
    assert verify_sth(sth, kp.public_bytes)
    # Wrong key fails.
    assert not verify_sth(sth, generate_ed25519().public_bytes)


def test_inclusion_proof_verifies():
    log = _log()
    log.append(MANIFEST, entry_type=EntryType.manifest)
    idx = log.append(REVOCATION, entry_type=EntryType.revocation)
    log.append({"x": 1}, entry_type=EntryType.measurement_set_change)
    sth = log.signed_tree_head()
    proof = log.inclusion_proof(idx)
    assert verify_inclusion(REVOCATION, EntryType.revocation, proof, sth)


def test_inclusion_fails_for_wrong_statement():
    log = _log()
    idx = log.append(MANIFEST, entry_type=EntryType.manifest)
    sth = log.signed_tree_head()
    proof = log.inclusion_proof(idx)
    # Same proof, different claimed statement.
    assert not verify_inclusion({"weights_hash": "sha256:" + "bb" * 32}, EntryType.manifest, proof, sth)


def test_inclusion_fails_wrong_entry_type():
    log = _log()
    idx = log.append(REVOCATION, entry_type=EntryType.revocation)
    sth = log.signed_tree_head()
    proof = log.inclusion_proof(idx)
    # Right statement, wrong type: preimage differs, so it must not verify.
    assert not verify_inclusion(REVOCATION, EntryType.manifest, proof, sth)


def test_find_detects_presence_and_absence():
    log = _log()
    log.append(MANIFEST, entry_type=EntryType.manifest)
    assert log.find(MANIFEST, EntryType.manifest) == 0
    # A revocation that was never logged: a monitor flags this missing entry.
    assert log.find(REVOCATION, EntryType.revocation) is None


def test_log_consistency_verifies_append_only_growth():
    log = _log()
    for i in range(3):
        log.append({"n": i}, entry_type=EntryType.manifest)
    old = log.signed_tree_head()
    for i in range(3, 7):
        log.append({"n": i}, entry_type=EntryType.manifest)
    new = log.signed_tree_head()
    proof = log.consistency_proof(old.tree_size)
    assert verify_log_consistency(old, new, proof)


def test_log_consistency_rejects_forged_head():
    log = _log()
    for i in range(4):
        log.append({"n": i}, entry_type=EntryType.manifest)
    old = log.signed_tree_head()
    for i in range(4, 8):
        log.append({"n": i}, entry_type=EntryType.manifest)
    new = log.signed_tree_head()
    proof = log.consistency_proof(old.tree_size)
    forged = new.__class__(
        tree_size=new.tree_size,
        root="sha256:" + "00" * 32,
        signed_at=new.signed_at,
        key_id=new.key_id,
        signature_b64=new.signature_b64,
    )
    assert not verify_log_consistency(old, forged, proof)
