from __future__ import annotations

from dataclasses import asdict, replace
from enum import IntEnum

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import pytest

from wcm.runtime_records import (
    RuntimeEvent,
    RuntimeRecord,
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


@pytest.mark.parametrize("sequence", [True, False])
def test_boolean_sequence_is_rejected_during_creation_and_verification(sequence):
    key, records = _chain()
    public = runtime_public_key(key)
    common = dict(
        signing_key=key,
        event=RuntimeEvent.renewal_succeeded,
        occurred_at="2026-08-21T22:00:06Z",
        weights_hash=records[0].weights_hash,
        manifest_hash=records[0].manifest_hash,
        lease_id=records[0].lease_id,
        previous=records[0],
    )

    with pytest.raises(TypeError, match="non-boolean integer"):
        sign_runtime_record(sequence=sequence, **common)
    with pytest.raises(TypeError, match="non-boolean integer"):
        replace(records[0], sequence=sequence)

    invalid = replace(records[0])
    object.__setattr__(invalid, "sequence", sequence)
    assert invalid.verify(public) is False
    assert verify_runtime_record_chain([invalid, *records[1:]], public)[0] is False


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


@pytest.mark.parametrize("index,bad", [(0, False), (1, True), (0, 0.0), (1, 1.0),
                                      (0, "0"), (0, None), (0, -1)])
def test_authentically_signed_malformed_sequences_are_refused(index, bad):
    from wcm._canonicalize import canonicalize
    from wcm._signing import _b64url_encode

    key, records = _chain()
    invalid = replace(records[index])
    object.__setattr__(invalid, "sequence", bad)
    object.__setattr__(invalid, "signature_b64url",
                       _b64url_encode(key.sign(canonicalize(invalid.signing_payload()))))
    # The malformed payload has a valid signature, so only shape checks refuse it.
    key.public_key().verify(key.sign(canonicalize(invalid.signing_payload())),
                            canonicalize(invalid.signing_payload()))
    public = runtime_public_key(key)
    assert not invalid.verify(public)
    assert not verify_runtime_record_chain([*records[:index], invalid], public,
                                           require_terminal_sequence=False)[0]


@pytest.mark.parametrize("bad,error", [(False, TypeError), (True, TypeError),
                                       (0.0, TypeError), ("0", TypeError),
                                       (None, TypeError), (-1, ValueError)])
def test_signer_refuses_malformed_predecessor_before_arithmetic(bad, error):
    key, records = _chain()
    previous = replace(records[0])
    object.__setattr__(previous, "sequence", bad)
    with pytest.raises(error, match="previous runtime record sequence"):
        sign_runtime_record(signing_key=key, sequence=1,
                            event=RuntimeEvent.renewal_succeeded,
                            occurred_at="2026-08-21T22:00:06Z",
                            weights_hash=records[0].weights_hash,
                            manifest_hash=records[0].manifest_hash,
                            lease_id=records[0].lease_id, previous=previous)


@pytest.mark.parametrize("bad,error", [(False, TypeError), (True, TypeError),
                                       (0.0, TypeError), ("0", TypeError),
                                       (None, TypeError), (-1, ValueError)])
def test_constructor_replace_and_deserialization_refuse_bad_sequences(bad, error):
    _, records = _chain()
    payload = asdict(records[0])
    payload["sequence"] = bad
    with pytest.raises(error):
        RuntimeRecord(**payload)
    with pytest.raises(error):
        replace(records[0], sequence=bad)


def test_non_boolean_integer_subclasses_retain_valid_signed_bytes():
    class Sequence(IntEnum):
        zero = 0
        one = 1

    key, records = _chain()
    successor = sign_runtime_record(
        signing_key=key, sequence=Sequence.one, event=RuntimeEvent.renewal_succeeded,
        occurred_at="2026-08-21T22:00:01Z", weights_hash=records[0].weights_hash,
        manifest_hash=records[0].manifest_hash, lease_id=records[0].lease_id,
        previous=records[0])
    assert successor.verify(runtime_public_key(key))
    first = replace(records[0], sequence=Sequence.zero)
    assert first.verify(runtime_public_key(key))
    assert first.signing_payload() == records[0].signing_payload()
    assert verify_runtime_record_chain([first], runtime_public_key(key),
                                       require_terminal_sequence=False)[0]
