from __future__ import annotations

from dataclasses import replace

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from wcm.runtime_records import (
    RuntimeEvent,
    runtime_public_key,
    sign_runtime_record,
    verify_runtime_record_chain,
)


def _chain(boundary: RuntimeEvent = RuntimeEvent.lapse_detected):
    key = Ed25519PrivateKey.generate()
    records = []
    for event in (
        RuntimeEvent.lease_started,
        RuntimeEvent.renewal_succeeded,
        boundary,
        RuntimeEvent.wipe_requested,
        RuntimeEvent.wipe_completed,
        RuntimeEvent.process_terminated,
    ):
        records.append(
            sign_runtime_record(
                signing_key=key,
                sequence=len(records),
                event=event,
                occurred_at=f"2026-08-21T22:00:0{len(records)}Z",
                weights_hash="sha256:" + "11" * 32,
                manifest_hash="sha256:" + "22" * 32,
                lease_id="sha256:" + "33" * 32,
                previous=records[-1] if records else None,
            )
        )
    return key, records


def test_complete_lapse_and_revocation_chains_verify():
    for boundary in (RuntimeEvent.lapse_detected, RuntimeEvent.revocation_detected):
        key, records = _chain(boundary)
        assert verify_runtime_record_chain(records, runtime_public_key(key)) == (
            True,
            "valid terminal runtime record chain",
        )


def test_tampering_reordering_and_cross_lease_splice_fail():
    key, records = _chain()
    public = runtime_public_key(key)
    tampered = records.copy()
    tampered[3] = replace(tampered[3], detail={"completed": True})
    assert not verify_runtime_record_chain(tampered, public)[0]
    assert not verify_runtime_record_chain([records[0], records[2], *records[3:]], public)[0]
    spliced = records.copy()
    spliced[2] = replace(spliced[2], lease_id="different")
    assert not verify_runtime_record_chain(spliced, public)[0]


def test_requested_without_completed_or_termination_is_not_terminal_proof():
    key, records = _chain()
    assert verify_runtime_record_chain(records[:4], runtime_public_key(key)) == (
        False,
        "boundary must be followed by wipe requested, wipe completed, and termination",
    )
    assert verify_runtime_record_chain(
        records[:4], runtime_public_key(key), require_terminal_sequence=False
    )[0]


def test_wrong_signer_and_invalid_creation_order_fail():
    key, records = _chain()
    other = Ed25519PrivateKey.generate()
    assert not verify_runtime_record_chain(records, runtime_public_key(other))[0]
    try:
        sign_runtime_record(
            signing_key=key,
            sequence=1,
            event=RuntimeEvent.lease_started,
            occurred_at="2026-08-21T22:00:00Z",
            weights_hash="sha256:" + "11" * 32,
            manifest_hash="sha256:" + "22" * 32,
            lease_id="lease",
        )
    except ValueError as exc:
        assert "first record" in str(exc)
    else:
        raise AssertionError("nonzero first record was accepted")


def _resign_sequence(key, record, sequence):
    from wcm._canonicalize import canonicalize
    from wcm._signing import _b64url_encode

    unsigned = replace(record, sequence=sequence)
    return replace(
        unsigned,
        signature_b64url=_b64url_encode(key.sign(canonicalize(unsigned.signing_payload()))),
    )


def test_non_integer_sequences_are_refused_even_with_authentic_signatures():
    key, records = _chain()
    public = runtime_public_key(key)
    for index, malformed in ((0, False), (1, True), (0, 0.0), (1, 1.0),
                             (0, "0"), (1, "1"), (0, None), (0, -1)):
        bad = _resign_sequence(key, records[index], malformed)
        assert not bad.verify(public), repr(malformed)
        assert not verify_runtime_record_chain(
            [*records[:index], bad], public, require_terminal_sequence=False
        )[0], repr(malformed)
    assert verify_runtime_record_chain(records[:2], public, require_terminal_sequence=False)[0]
    assert verify_runtime_record_chain(records, public)[0]


def test_signer_rejects_non_integer_sequences_and_malformed_previous():
    import pytest

    key, records = _chain()
    common = dict(signing_key=key, event=RuntimeEvent.renewal_succeeded,
                  occurred_at="2026-11-05T00:00:00Z", weights_hash=records[0].weights_hash,
                  manifest_hash=records[0].manifest_hash, lease_id=records[0].lease_id)
    for malformed, previous in ((False, None), (True, records[0]), (0.0, None),
                                (1.0, records[0]), ("0", None), (None, None), (-1, None)):
        with pytest.raises(ValueError, match="non-negative integer"):
            sign_runtime_record(sequence=malformed, previous=previous, **common)
    for malformed in (False, 0.0, "0", None, -1):
        with pytest.raises(ValueError, match="previous.*non-negative integer"):
            sign_runtime_record(sequence=1, previous=replace(records[0], sequence=malformed), **common)
    valid = sign_runtime_record(sequence=1, previous=records[0], **common)
    assert valid.verify(runtime_public_key(key))
