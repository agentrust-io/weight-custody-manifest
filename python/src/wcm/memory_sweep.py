"""The protected-memory fingerprint sweep (SPEC.md sections 3.1, 3.6).

This is the mechanism behind ``memory_fingerprint_challenge``, the WCM-level
detection for the measurement-forgery half of open question 8.8 (BadRAM-class:
DRAM aliased through a misreported SPD size, so a measurement reads clean while
the guest runs from aliased addresses and the signing key never leaves the chip).

The shape of the check, per the spec: the KBS sends a random value, the enclave
writes derived values across its full declared DRAM range, reads them back, and
returns a hash of the readback pattern. Aliased memory collides in a way a
genuine full-size installation cannot, so the readback does not match what was
written.

Four properties this module has to get right, because each is load-bearing:

**Address selection is nonce-derived, not fixed.** With a fixed probe set an
operator who controls the memory map can arrange for the aliased granules to be
ones nobody probes. Addresses come from the KBS nonce, so nobody knows which
granules will be touched until the challenge arrives.

**Values are unpredictable before the challenge.** ``probe_value`` is derived
from the nonce, so a readback captured under an earlier nonce is worthless: it
carries the wrong values everywhere. This is what makes a replayed sweep fail
rather than merely look stale.

**Write and read run in two different nonce-derived orders.** Writing in address
order would let a partial emulation answer from the most recent write. Two
independent permutations mean the surviving value in an aliased pair is not the
one a naive emulator would guess, and a genuine region is unaffected because
every granule is distinct storage.

**The result commits to the range it swept.** A sweep over one page and a sweep
over 64 GiB are not the same evidence, so the declared range is inside the hash
and inside the commitment the quote binds (``fingerprint_commitment``).

What this establishes, precisely, is in ``docs/memory-fingerprint.md``. The short
version: a clean sweep says the address space the enclave reached behaves like
distinct storage at the probed granules. It says nothing about physical memory
protection, and on its own it does not prove the enclave ran it at all. Only the
attestation binding does that, and only against an adversary who has not lifted
the attestation key (the open half of 8.8).
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Iterable, Mapping, Optional, Protocol

from ._canonicalize import canonical_hash, canonicalize

#: Probe alignment. One probe per granule; 4 KiB is the smallest page a
#: BadRAM-class alias can fold at, so probing per granule matches the grain of
#: the attack rather than a grain we chose for convenience.
GRANULE_BYTES = 4096

#: Bytes written and read back per probe. 32 bytes makes an accidental match
#: between two distinct probe values a 2^-256 event, so a collision the sweep
#: misses is not a collision that plausibly happened.
PROBE_BYTES = 32

#: Default probe count when a caller does not choose one. Deliberately modest:
#: the sweep is paid for inside the release path, and the honest coverage
#: statement (docs/memory-fingerprint.md) is about the ratio of probes to
#: granules, which a deployment tunes for its own range.
DEFAULT_PROBE_COUNT = 256

#: Hard ceiling on probes, because the gate re-derives the plan from a range the
#: evidence declares. Without it a response claiming a billion probes makes the
#: verifier allocate and hash its way through them before it can decide anything,
#: which is a denial of service written into the release path. A range wanting
#: more coverage than this raises its granule size.
MAX_PROBE_COUNT = 1 << 16

_DOMAIN_ADDRESS = b"wcm/memory-fingerprint/address/v1"
_DOMAIN_VALUE = b"wcm/memory-fingerprint/value/v1"
_DOMAIN_WRITE_ORDER = b"wcm/memory-fingerprint/write-order/v1"
_DOMAIN_READ_ORDER = b"wcm/memory-fingerprint/read-order/v1"


class SweepError(Exception):
    """The sweep could not be run as specified (bad range, bad region)."""


@dataclass(frozen=True)
class ProtectedRange:
    """The protected-memory range an enclave declares and sweeps.

    ``base_address`` and ``size_bytes`` are what the enclave says its protected
    region is; the sweep is only as meaningful as that declaration, which is why
    the gate carries a floor on ``size_bytes`` rather than accepting any range an
    enclave cares to name.
    """

    base_address: int
    size_bytes: int
    granule_bytes: int = GRANULE_BYTES
    probe_count: int = DEFAULT_PROBE_COUNT

    def __post_init__(self) -> None:
        if self.base_address < 0:
            raise SweepError("base_address must not be negative")
        if self.size_bytes <= 0:
            raise SweepError("size_bytes must be positive")
        if self.granule_bytes < PROBE_BYTES:
            raise SweepError(
                f"granule_bytes must be at least the probe width ({PROBE_BYTES})"
            )
        if self.size_bytes % self.granule_bytes:
            raise SweepError("size_bytes must be a whole number of granules")
        if self.probe_count <= 0:
            raise SweepError("probe_count must be positive")
        if self.probe_count > MAX_PROBE_COUNT:
            raise SweepError(
                f"probe_count {self.probe_count} exceeds the {MAX_PROBE_COUNT} ceiling; "
                "a verifier re-derives every probe, so an unbounded count is a "
                "denial of service"
            )
        if self.probe_count > self.granules:
            raise SweepError(
                f"probe_count {self.probe_count} exceeds the {self.granules} granules "
                "in the declared range"
            )

    @property
    def granules(self) -> int:
        return self.size_bytes // self.granule_bytes

    def as_dict(self) -> dict[str, int]:
        """The canonical form that goes into hashes and commitments."""
        return {
            "base_address": self.base_address,
            "size_bytes": self.size_bytes,
            "granule_bytes": self.granule_bytes,
            "probe_count": self.probe_count,
        }


class MemoryRegion(Protocol):
    """The protected memory a sweep runs over.

    Deliberately this narrow: an enclave implementation backs it with its real
    protected allocation, and the negative fixtures back it with a region that
    aliases. Nothing else about the memory is assumed.
    """

    def write(self, address: int, data: bytes) -> None: ...

    def read(self, address: int, length: int) -> bytes: ...


class BufferRegion:
    """A real allocation, swept for real.

    Every write and read below lands in an actual ``bytearray`` of the declared
    size. It is not a model of memory: the sweep does the writes, does the reads,
    and reports what came back. On a host whose mappings are honest that is the
    same code path a production enclave runs, which is why it lives here rather
    than in the tests.
    """

    def __init__(self, declared: ProtectedRange) -> None:
        self._base = declared.base_address
        self._size = declared.size_bytes
        self._buffer = bytearray(declared.size_bytes)

    def _offset(self, address: int, length: int) -> int:
        offset = address - self._base
        if offset < 0 or offset + length > self._size:
            raise SweepError(
                f"address {address:#x} (+{length}) falls outside the declared range"
            )
        return offset

    def write(self, address: int, data: bytes) -> None:
        offset = self._offset(address, len(data))
        self._buffer[offset : offset + len(data)] = data

    def read(self, address: int, length: int) -> bytes:
        offset = self._offset(address, length)
        return bytes(self._buffer[offset : offset + length])


class AliasedRegion(BufferRegion):
    """A region whose physical storage is smaller than it reports.

    The BadRAM-class shape reduced to its essential: the SPD says one size, the
    DRAM behind it is smaller, and the top address bits fold. Two declared
    addresses congruent modulo ``physical_bytes`` are one cell, so the second
    write destroys the first and the readback says so.

    It exists so detection can be exercised as a negative fixture rather than
    asserted. Nothing in the sweep knows it is being lied to.
    """

    def __init__(self, declared: ProtectedRange, physical_bytes: int) -> None:
        super().__init__(declared)
        if physical_bytes <= 0 or physical_bytes >= declared.size_bytes:
            raise SweepError(
                "physical_bytes must be positive and smaller than the declared size, "
                "otherwise nothing aliases"
            )
        if physical_bytes % declared.granule_bytes:
            raise SweepError("physical_bytes must be a whole number of granules")
        self._physical = physical_bytes
        self._buffer = bytearray(physical_bytes)

    def _offset(self, address: int, length: int) -> int:
        offset = super()._offset(address, length)
        return offset % self._physical


@dataclass(frozen=True)
class ProbePlan:
    """Which granules get probed, and in what order they are written and read."""

    addresses: tuple[int, ...]
    write_order: tuple[int, ...]
    read_order: tuple[int, ...]


@dataclass(frozen=True)
class SweepResult:
    """What the enclave returns, and what the gate re-derives and compares."""

    declared_range: ProtectedRange
    readback_hash: str
    aliasing_detected: bool
    #: Addresses whose readback did not match what was written there. Reported
    #: for diagnosis; the gate decides on ``aliasing_detected`` and the hash.
    mismatched_addresses: tuple[int, ...] = field(default=())

    @property
    def probes_run(self) -> int:
        return self.declared_range.probe_count


def _xof(domain: bytes, nonce: str, extra: bytes, length: int) -> bytes:
    """SHAKE256 over a domain-separated input.

    Domain separation keeps the address stream, the value stream and the two
    orderings from ever coinciding for the same nonce.
    """
    try:
        nonce_bytes = bytes.fromhex(nonce)
    except ValueError as exc:
        raise SweepError(f"challenge nonce is not hex: {exc}") from exc
    shake = hashlib.shake_256()
    shake.update(domain)
    shake.update(len(nonce_bytes).to_bytes(4, "big"))
    shake.update(nonce_bytes)
    shake.update(extra)
    return shake.digest(length)


def _range_tag(declared: ProtectedRange) -> bytes:
    """The declared range as bytes, so every derivation is range-specific."""
    return canonicalize(declared.as_dict())


def probe_value(nonce: str, declared: ProtectedRange, address: int) -> bytes:
    """The value that belongs at *address* under this challenge.

    Nonce-derived, so it cannot be known before the challenge is issued, and
    address-derived, so a cell holding another address's value is detectable.
    """
    return _xof(
        _DOMAIN_VALUE,
        nonce,
        _range_tag(declared) + address.to_bytes(8, "big"),
        PROBE_BYTES,
    )


def _permutation(
    domain: bytes, nonce: str, declared: ProtectedRange, count: int
) -> tuple[int, ...]:
    """A nonce-derived permutation of ``range(count)`` (Fisher-Yates)."""
    order = list(range(count))
    if count < 2:
        return tuple(order)
    # 8 bytes per swap is far more than the modulus needs; the bias from taking
    # it modulo i+1 is bounded by count * 2^-64 and is not security-relevant
    # here, where the requirement is unpredictability, not a uniform draw.
    stream = _xof(domain, nonce, _range_tag(declared), 8 * count)
    for i in range(count - 1, 0, -1):
        draw = int.from_bytes(stream[8 * i : 8 * i + 8], "big")
        j = draw % (i + 1)
        order[i], order[j] = order[j], order[i]
    return tuple(order)


def plan_probes(nonce: str, declared: ProtectedRange) -> ProbePlan:
    """Derive the probe addresses and the write/read orders for this challenge.

    Both sides call this: the enclave to run the sweep, the gate to know what an
    honest sweep must have produced. Same inputs, same plan, no negotiation.
    """
    granules = declared.granules
    chosen: list[int] = []
    seen: set[int] = set()
    # Draw granule indices until enough distinct ones are collected. Drawn in
    # blocks so a range whose granule count is close to the probe count does not
    # turn into one XOF call per retry.
    block = max(declared.probe_count, 16)
    counter = 0
    while len(chosen) < declared.probe_count:
        stream = _xof(
            _DOMAIN_ADDRESS,
            nonce,
            _range_tag(declared) + counter.to_bytes(4, "big"),
            8 * block,
        )
        for i in range(block):
            index = int.from_bytes(stream[8 * i : 8 * i + 8], "big") % granules
            if index not in seen:
                seen.add(index)
                chosen.append(index)
                if len(chosen) == declared.probe_count:
                    break
        counter += 1
        if counter > 1024:  # pragma: no cover - unreachable for a valid range
            raise SweepError("could not select distinct probe granules")

    addresses = tuple(
        declared.base_address + index * declared.granule_bytes for index in chosen
    )
    count = len(addresses)
    return ProbePlan(
        addresses=addresses,
        write_order=_permutation(_DOMAIN_WRITE_ORDER, nonce, declared, count),
        read_order=_permutation(_DOMAIN_READ_ORDER, nonce, declared, count),
    )


def readback_hash(
    nonce: str, declared: ProtectedRange, readback: Mapping[int, bytes]
) -> str:
    """Hash a readback pattern.

    Sorted by address so the hash is a function of what the memory held, not of
    the order it was read in. The read *order* still matters: it decides which
    value survives in an aliased pair, and that shows up in the values.
    """
    return canonical_hash(
        {
            "v": 1,
            "nonce": nonce,
            "range": declared.as_dict(),
            "readback": [
                {"address": address, "value": readback[address].hex()}
                for address in sorted(readback)
            ],
        }
    )


def expected_readback_hash(nonce: str, declared: ProtectedRange) -> str:
    """The hash an honest, non-aliased sweep must produce.

    Computable by the gate from the nonce and the declared range alone, which is
    what turns ``readback_hash`` from a decorative field into a checked one. Note
    what this does *not* buy: the derivation is public, so a host that never
    touched memory can compute the same value. Only the attestation binding
    separates the two, which is why ``fingerprint_commitment`` exists.
    """
    plan = plan_probes(nonce, declared)
    return readback_hash(
        nonce,
        declared,
        {address: probe_value(nonce, declared, address) for address in plan.addresses},
    )


def fingerprint_commitment(
    nonce: str,
    declared: ProtectedRange,
    result_hash: str,
    aliasing_detected: bool,
) -> bytes:
    """The 32 bytes the enclave folds into REPORT_DATA for this sweep.

    Binding the commitment into the quote is what makes the result the enclave's
    rather than the host's: the bytes are covered by the attestation signature,
    so a host that fabricated a clean readback cannot get it into a quote it
    cannot sign. It binds the challenge, the declared range and the outcome
    together, so none of the three can be swapped for another attempt's.
    """
    return hashlib.sha256(
        canonicalize(
            {
                "v": 1,
                "nonce": nonce,
                "range": declared.as_dict(),
                "readback_hash": result_hash,
                "aliasing_detected": aliasing_detected,
            }
        )
    ).digest()


def run_sweep(
    nonce: str,
    declared: ProtectedRange,
    region: Optional[MemoryRegion] = None,
) -> SweepResult:
    """Run the sweep inside the protected boundary and report what came back.

    Writes every probe value in the nonce-derived write order, then reads every
    probe back in a different nonce-derived read order, then compares. A region
    whose granules are distinct storage returns exactly what was written; a
    region that aliases returns another probe's value at one or both of the
    folded addresses.

    ``region`` defaults to a real allocation of the declared size. Callers pass
    their own protected allocation in production, or an ``AliasedRegion`` to
    exercise detection.
    """
    plan = plan_probes(nonce, declared)
    if region is None:
        region = BufferRegion(declared)

    values = {
        address: probe_value(nonce, declared, address) for address in plan.addresses
    }

    for index in plan.write_order:
        address = plan.addresses[index]
        region.write(address, values[address])

    readback: dict[int, bytes] = {}
    for index in plan.read_order:
        address = plan.addresses[index]
        readback[address] = region.read(address, PROBE_BYTES)

    mismatched = tuple(
        sorted(address for address, value in values.items() if readback[address] != value)
    )
    return SweepResult(
        declared_range=declared,
        readback_hash=readback_hash(nonce, declared, readback),
        aliasing_detected=bool(mismatched),
        mismatched_addresses=mismatched,
    )


def colliding_pairs(
    addresses: Iterable[int], physical_bytes: int, base: int = 0
) -> list[tuple[int, int]]:
    """Address pairs that fold together under a modulo-*physical_bytes* alias.

    A helper for reasoning about coverage in tests and documentation: it says
    which probes a given alias would collapse, so a fixture can assert that the
    sweep had something to find rather than assuming it did.
    """
    seen: dict[int, int] = {}
    pairs: list[tuple[int, int]] = []
    for address in sorted(addresses):
        cell = (address - base) % physical_bytes
        if cell in seen:
            pairs.append((seen[cell], address))
        else:
            seen[cell] = address
    return pairs
