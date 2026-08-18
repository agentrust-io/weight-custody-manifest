"""The protected-memory sweep itself (SPEC.md 3.1, 3.6; issue #79).

These test the mechanism, not the policy plumbing around it: that the sweep
writes and reads real storage, that a region which aliases is caught, that
everything is derived from the challenge nonce, and that the commitment binds
what it claims to. The gate's use of all this is in ``test_kbs.py``, and the
end-to-end attestation binding is in ``test_quote_verify.py``.

The last test in this file asserts a *limitation*: an alias confined to granules
the probe set never touches is not detected. That is the honest coverage
statement from ``docs/memory-fingerprint.md``, and it is here so that a change
which quietly widens the claim has to change a test that says otherwise.
"""
from __future__ import annotations

import pytest

from wcm.memory_sweep import (
    DEFAULT_PROBE_COUNT,
    MAX_PROBE_COUNT,
    PROBE_BYTES,
    AliasedRegion,
    BufferRegion,
    ProtectedRange,
    SweepError,
    colliding_pairs,
    expected_readback_hash,
    fingerprint_commitment,
    plan_probes,
    probe_value,
    run_sweep,
)

BASE = 0x4000_0000
SIZE = 1 << 20  # 1 MiB, 256 granules
NONCE_A = "ab" * 32
NONCE_B = "cd" * 32


def _range(**kwargs) -> ProtectedRange:
    args = {"base_address": BASE, "size_bytes": SIZE, "probe_count": 64}
    args.update(kwargs)
    return ProtectedRange(**args)


class _RecordingRegion(BufferRegion):
    """A real region that also records the traffic, so a test can assert the
    sweep touched memory rather than assuming it did."""

    def __init__(self, declared: ProtectedRange) -> None:
        super().__init__(declared)
        self.writes: list[tuple[int, int]] = []
        self.reads: list[int] = []

    def write(self, address: int, data: bytes) -> None:
        self.writes.append((address, len(data)))
        super().write(address, data)

    def read(self, address: int, length: int) -> bytes:
        self.reads.append(address)
        return super().read(address, length)


class _PairAliasRegion(BufferRegion):
    """Aliases exactly one pair of addresses onto one cell, leaving the rest of
    the range honest. Narrower than ``AliasedRegion`` so a test can place the
    collision precisely."""

    def __init__(self, declared: ProtectedRange, victim: int, onto: int) -> None:
        super().__init__(declared)
        self._victim = victim
        self._onto = onto

    def _offset(self, address: int, length: int) -> int:
        if address == self._victim:
            address = self._onto
        return super()._offset(address, length)


# -- the sweep runs over real memory ------------------------------------------


def test_clean_sweep_reports_no_aliasing_and_the_hash_the_gate_expects():
    declared = _range()
    result = run_sweep(NONCE_A, declared)
    assert result.aliasing_detected is False
    assert result.mismatched_addresses == ()
    assert result.readback_hash == expected_readback_hash(NONCE_A, declared)


def test_the_sweep_actually_writes_and_reads_the_declared_range():
    declared = _range()
    region = _RecordingRegion(declared)
    run_sweep(NONCE_A, declared, region)

    plan = plan_probes(NONCE_A, declared)
    assert len(region.writes) == declared.probe_count
    assert len(region.reads) == declared.probe_count
    assert {address for address, _ in region.writes} == set(plan.addresses)
    assert set(region.reads) == set(plan.addresses)
    assert {length for _, length in region.writes} == {PROBE_BYTES}
    # Every probe lands inside the range it declared, aligned to a granule.
    for address, length in region.writes:
        assert BASE <= address and address + length <= BASE + SIZE
        assert (address - BASE) % declared.granule_bytes == 0


def test_readback_carries_the_values_that_were_written():
    declared = _range()
    region = BufferRegion(declared)
    run_sweep(NONCE_A, declared, region)
    for address in plan_probes(NONCE_A, declared).addresses:
        assert region.read(address, PROBE_BYTES) == probe_value(
            NONCE_A, declared, address
        )


# -- aliasing is detected ------------------------------------------------------


def test_aliased_region_is_detected():
    declared = _range()
    physical = SIZE // 2
    result = run_sweep(NONCE_A, declared, AliasedRegion(declared, physical))
    assert result.aliasing_detected is True
    assert result.readback_hash != expected_readback_hash(NONCE_A, declared)


def test_every_probed_collision_produces_a_mismatch():
    """The detection is not probabilistic once a colliding pair is probed: the
    surviving value is one of the two, so the other address reads wrong."""
    declared = _range()
    physical = SIZE // 2
    pairs = colliding_pairs(
        plan_probes(NONCE_A, declared).addresses, physical, base=BASE
    )
    assert pairs, "the fixture must actually collide something"
    result = run_sweep(NONCE_A, declared, AliasedRegion(declared, physical))
    assert len(result.mismatched_addresses) == len(pairs)
    for low, high in pairs:
        assert low in result.mismatched_addresses or high in result.mismatched_addresses


def test_a_single_aliased_pair_is_enough():
    declared = _range()
    victim, onto = plan_probes(NONCE_A, declared).addresses[:2]
    result = run_sweep(NONCE_A, declared, _PairAliasRegion(declared, victim, onto))
    assert result.aliasing_detected is True
    assert result.mismatched_addresses


# -- everything is derived from the challenge ---------------------------------


def test_the_probe_plan_is_deterministic_for_a_given_challenge():
    declared = _range()
    assert plan_probes(NONCE_A, declared) == plan_probes(NONCE_A, declared)


def test_a_different_challenge_probes_different_addresses():
    declared = _range()
    a = set(plan_probes(NONCE_A, declared).addresses)
    b = set(plan_probes(NONCE_B, declared).addresses)
    assert a != b


def test_write_and_read_run_in_different_orders():
    plan = plan_probes(NONCE_A, _range())
    assert plan.write_order != plan.read_order
    assert sorted(plan.write_order) == sorted(plan.read_order) == list(
        range(len(plan.addresses))
    )


def test_a_single_probe_range_still_sweeps():
    """The degenerate range: one granule, one probe, nothing to permute."""
    declared = ProtectedRange(base_address=BASE, size_bytes=4096, probe_count=1)
    plan = plan_probes(NONCE_A, declared)
    assert plan.addresses == (BASE,)
    assert plan.write_order == plan.read_order == (0,)
    result = run_sweep(NONCE_A, declared)
    assert result.aliasing_detected is False
    assert result.probes_run == 1


def test_probe_values_are_nonce_derived():
    declared = _range()
    address = plan_probes(NONCE_A, declared).addresses[0]
    assert probe_value(NONCE_A, declared, address) != probe_value(
        NONCE_B, declared, address
    )


def test_a_readback_from_another_challenge_does_not_satisfy_this_one():
    """The replay case as a property: a clean sweep is clean only under its own
    nonce."""
    declared = _range()
    stale = run_sweep(NONCE_B, declared)
    assert stale.aliasing_detected is False
    assert stale.readback_hash != expected_readback_hash(NONCE_A, declared)


def test_the_readback_hash_binds_the_declared_range():
    wide = _range()
    narrow = _range(size_bytes=SIZE // 2, probe_count=64)
    assert expected_readback_hash(NONCE_A, wide) != expected_readback_hash(
        NONCE_A, narrow
    )


# -- the commitment ------------------------------------------------------------


def test_the_commitment_binds_challenge_range_result_and_outcome():
    declared = _range()
    other = _range(size_bytes=SIZE // 2, probe_count=64)
    result_hash = expected_readback_hash(NONCE_A, declared)
    base = fingerprint_commitment(NONCE_A, declared, result_hash, False)

    assert len(base) == 32
    assert base != fingerprint_commitment(NONCE_B, declared, result_hash, False)
    assert base != fingerprint_commitment(NONCE_A, other, result_hash, False)
    assert base != fingerprint_commitment(
        NONCE_A, declared, "sha256:" + "00" * 32, False
    )
    assert base != fingerprint_commitment(NONCE_A, declared, result_hash, True)


# -- ranges and regions fail closed on nonsense -------------------------------


@pytest.mark.parametrize(
    "kwargs",
    [
        {"base_address": -1},
        {"size_bytes": 0},
        {"size_bytes": SIZE + 1},  # not a whole number of granules
        {"granule_bytes": PROBE_BYTES - 1},
        {"probe_count": 0},
        {"probe_count": (SIZE // 4096) + 1},  # more probes than granules
    ],
)
def test_unsweepable_ranges_are_rejected(kwargs):
    with pytest.raises(SweepError):
        _range(**kwargs)


def test_an_absurd_probe_count_is_refused_before_any_work_happens():
    """The range arrives in evidence and the gate re-derives every probe from it,
    so an unbounded count is a denial of service on the release path."""
    huge = MAX_PROBE_COUNT + 1
    with pytest.raises(SweepError, match="ceiling"):
        ProtectedRange(
            base_address=BASE,
            size_bytes=4096 * huge,
            probe_count=huge,
        )


def test_default_probe_count_needs_a_range_with_room_for_it():
    with pytest.raises(SweepError):
        ProtectedRange(base_address=BASE, size_bytes=4096 * (DEFAULT_PROBE_COUNT - 1))


def test_a_region_refuses_addresses_outside_the_declared_range():
    declared = _range()
    region = BufferRegion(declared)
    with pytest.raises(SweepError):
        region.write(BASE + SIZE, b"\x00" * PROBE_BYTES)
    with pytest.raises(SweepError):
        region.read(BASE - 1, PROBE_BYTES)


@pytest.mark.parametrize("physical", [0, SIZE, SIZE + 4096, 4097])
def test_an_aliased_region_must_actually_alias(physical):
    with pytest.raises(SweepError):
        AliasedRegion(_range(), physical)


def test_a_non_hex_nonce_is_rejected_rather_than_swept():
    with pytest.raises(SweepError):
        run_sweep("not-hex", _range())


# -- what the sweep does not establish ----------------------------------------


def test_an_alias_outside_the_probed_granules_is_missed():
    """The coverage limit, asserted rather than described.

    Probes cover ``probe_count`` of ``granules``; an alias that folds only
    granules nobody probed produces a clean readback. This is why the honest
    claim is about the probed granules and why probe density is a deployment
    parameter, not a constant that makes the sweep exhaustive.
    """
    declared = _range()
    probed = set(plan_probes(NONCE_A, declared).addresses)
    unprobed = [
        BASE + index * declared.granule_bytes
        for index in range(declared.granules)
        if BASE + index * declared.granule_bytes not in probed
    ]
    assert len(unprobed) >= 2

    result = run_sweep(
        NONCE_A, declared, _PairAliasRegion(declared, unprobed[0], unprobed[1])
    )
    assert result.aliasing_detected is False
    assert result.readback_hash == expected_readback_hash(NONCE_A, declared)
