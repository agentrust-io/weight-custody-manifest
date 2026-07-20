from __future__ import annotations

import itertools

import pytest

from wcm import combine_shares, split_secret

SECRET = b"a-32-byte-decryption-key--padxx!"  # 32 bytes


def test_any_threshold_subset_reconstructs():
    shares = split_secret(SECRET, threshold=3, shares=5)
    for subset in itertools.combinations(shares, 3):
        assert combine_shares(list(subset)) == SECRET


def test_all_shares_reconstruct():
    shares = split_secret(SECRET, threshold=3, shares=5)
    assert combine_shares(shares) == SECRET


def test_more_than_threshold_reconstructs():
    shares = split_secret(SECRET, threshold=2, shares=5)
    assert combine_shares(shares[:4]) == SECRET


def test_fewer_than_threshold_does_not_reconstruct():
    shares = split_secret(SECRET, threshold=3, shares=5)
    # Two shares of a 3-of-n split reveal a different value for a 32-byte secret.
    assert combine_shares(shares[:2]) != SECRET


def test_single_byte_secret():
    shares = split_secret(b"\x2a", threshold=2, shares=3)
    assert combine_shares(shares[:2]) == b"\x2a"


def test_deterministic_with_injected_rng():
    rng = lambda n: bytes([7]) * n
    a = split_secret(SECRET, threshold=3, shares=5, rng=rng)
    b = split_secret(SECRET, threshold=3, shares=5, rng=rng)
    assert [s.y for s in a] == [s.y for s in b]
    assert combine_shares(a[1:4]) == SECRET


def test_shares_do_not_equal_secret():
    shares = split_secret(SECRET, threshold=3, shares=5)
    for s in shares:
        assert s.y != SECRET


@pytest.mark.parametrize(
    "kwargs",
    [
        {"threshold": 1, "shares": 3},  # threshold too low
        {"threshold": 4, "shares": 3},  # threshold > shares
        {"threshold": 2, "shares": 256},  # too many shares
    ],
)
def test_invalid_params_raise(kwargs):
    with pytest.raises(ValueError):
        split_secret(SECRET, **kwargs)


def test_empty_secret_raises():
    with pytest.raises(ValueError):
        split_secret(b"", threshold=2, shares=3)


def test_combine_rejects_empty():
    with pytest.raises(ValueError):
        combine_shares([])


def test_combine_rejects_duplicate_x():
    shares = split_secret(SECRET, threshold=2, shares=3)
    with pytest.raises(ValueError):
        combine_shares([shares[0], shares[0]])


def test_combine_rejects_mismatched_lengths():
    from wcm.threshold import Share

    with pytest.raises(ValueError):
        combine_shares([Share(1, b"\x01\x02"), Share(2, b"\x03")])
