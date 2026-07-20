"""Threshold split-key release for sovereign self-custody (SPEC.md 3.5, decision 15).

Single-key self-custody is sound only for a semi-trusted self-custodian. A
hardware-owning sovereign can forge its own KBS quote and self-release, so
sovereign self-custody requires **threshold split-key release**: the decryption
key is split into ``n`` shares such that any ``t`` reconstruct it and any
``t - 1`` reveal nothing, so no single party (the builder included) can assemble
the key alone.

This is Shamir Secret Sharing over GF(256) (the AES field), applied byte-wise:
each secret byte is the constant term of an independent degree ``t-1`` polynomial,
and share ``i`` carries that polynomial evaluated at ``x = i``. Information-
theoretic: fewer than ``t`` shares leave every secret equally likely.

This module is the sharing primitive. Wiring it into a KBS so a quorum of
custodians must combine their shares before release is deployment-specific and
layered on top; the threshold guarantee is the property this provides.
"""
from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import Callable

# GF(256) exp/log tables, generator 0x03 (AES reducing polynomial 0x11b).
_GF_EXP: list[int] = [0] * 512
_GF_LOG: list[int] = [0] * 256


def _xtime(a: int) -> int:
    a <<= 1
    if a & 0x100:
        a ^= 0x11B
    return a & 0xFF


def _init_tables() -> None:
    x = 1
    for i in range(255):
        _GF_EXP[i] = x
        _GF_LOG[x] = i
        x ^= _xtime(x)  # multiply by the generator 0x03
    for i in range(255, 512):
        _GF_EXP[i] = _GF_EXP[i - 255]


_init_tables()


def _mul(a: int, b: int) -> int:
    if a == 0 or b == 0:
        return 0
    return _GF_EXP[_GF_LOG[a] + _GF_LOG[b]]


def _div(a: int, b: int) -> int:
    if b == 0:
        raise ZeroDivisionError("GF(256) division by zero")
    if a == 0:
        return 0
    return _GF_EXP[(_GF_LOG[a] - _GF_LOG[b]) % 255]


@dataclass(frozen=True)
class Share:
    """One Shamir share: the x-coordinate and the per-byte y-values."""

    x: int  # 1..255, distinct per share
    y: bytes  # one GF(256) evaluation per secret byte


def split_secret(
    secret: bytes,
    *,
    threshold: int,
    shares: int,
    rng: Callable[[int], bytes] = secrets.token_bytes,
) -> list[Share]:
    """Split *secret* into *shares* pieces, any *threshold* of which reconstruct it.

    Args:
        rng: source of random coefficient bytes; injectable for deterministic
            tests, defaults to a cryptographic RNG.

    Raises:
        ValueError: on empty secret or out-of-range threshold/shares.
    """
    if not secret:
        raise ValueError("secret must be non-empty")
    if not 2 <= threshold <= shares <= 255:
        raise ValueError("require 2 <= threshold <= shares <= 255")

    xs = list(range(1, shares + 1))
    ys: list[bytearray] = [bytearray() for _ in xs]
    for byte in secret:
        coeffs = [byte] + list(rng(threshold - 1))  # a0 = secret byte, then random
        for idx, x in enumerate(xs):
            acc = 0
            for c in reversed(coeffs):  # Horner evaluation at x
                acc = _mul(acc, x) ^ c
            ys[idx].append(acc)
    return [Share(x=x, y=bytes(y)) for x, y in zip(xs, ys)]


def combine_shares(shares: list[Share]) -> bytes:
    """Reconstruct the secret from *shares* (Lagrange interpolation at x=0).

    Any ``threshold`` correct shares recover the secret; fewer recover a
    different value (this function cannot tell how many are enough, by design of
    the scheme, so the caller must supply at least the threshold).

    Raises:
        ValueError: on no shares, duplicate x, or mismatched share lengths.
    """
    if not shares:
        raise ValueError("need at least one share")
    xs = [s.x for s in shares]
    if len(set(xs)) != len(xs):
        raise ValueError("shares must have distinct x-coordinates")
    length = len(shares[0].y)
    if any(len(s.y) != length for s in shares):
        raise ValueError("all shares must have the same length")

    secret = bytearray()
    for pos in range(length):
        acc = 0
        for i, si in enumerate(shares):
            num, den = 1, 1
            for j, sj in enumerate(shares):
                if i == j:
                    continue
                num = _mul(num, sj.x)  # (0 - x_j) == x_j in GF(256)
                den = _mul(den, si.x ^ sj.x)
            acc ^= _mul(si.y[pos], _div(num, den))
        secret.append(acc)
    return bytes(secret)
