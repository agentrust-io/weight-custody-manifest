"""Robustness fuzzing: parsers must fail closed on malformed input.

Each parser is fed random / truncated / adversarial input; it must either handle
it or raise its DOCUMENTED exception type. Any other exception (or a crash) is a
failure. Deterministic via a fixed seed.
"""
from __future__ import annotations

import base64
import random

import pytest
from cryptography.exceptions import InvalidSignature
from pydantic import ValidationError

from wcm import (
    ChallengeStore,
    Ed25519Verifier,
    JsonQuoteParser,
    QuoteVerifier,
    TrustStore,
    WeightCustodyManifest,
    canonicalize,
    combine_shares,
    generate_ed25519,
    parse_cadence,
)
from wcm._quote_verify import QuoteFormatError
from wcm.threshold import Share

SEED = 1337
ITERS = 400


def _rng():
    return random.Random(SEED)


def _rand_bytes(rng, n_max=512):
    return bytes(rng.getrandbits(8) for _ in range(rng.randint(0, n_max)))


def _rand_str(rng, n_max=64):
    return "".join(chr(rng.randint(0, 0x2FFFF)) for _ in range(rng.randint(0, n_max)))


def _rand_json(rng, depth=0):
    if depth > 4:
        return rng.choice([0, "x", True, None])
    kind = rng.randint(0, 6)
    if kind == 0:
        return rng.randint(-(2**40), 2**40)
    if kind == 1:
        return _rand_str(rng)
    if kind == 2:
        return rng.choice([True, False, None])
    if kind == 3:
        return [_rand_json(rng, depth + 1) for _ in range(rng.randint(0, 4))]
    if kind == 4:
        return {_rand_str(rng, 8): _rand_json(rng, depth + 1) for _ in range(rng.randint(0, 4))}
    if kind == 5:
        return rng.uniform(-1e6, 1e6)
    return rng.random()


def test_canonicalize_never_crashes_on_json_like():
    rng = _rng()
    for _ in range(ITERS):
        obj = _rand_json(rng)
        try:
            out = canonicalize(obj)
            assert isinstance(out, bytes)
        except (TypeError, ValueError):
            pass  # documented: non-serializable / NaN / Inf / depth


def test_canonicalize_rejects_nonserializable():
    for bad in [object(), {1, 2}, b"bytes", complex(1, 2)]:
        with pytest.raises((TypeError, ValueError)):
            canonicalize({"k": bad})


def test_json_quote_parser_fails_closed():
    rng = _rng()
    p = JsonQuoteParser()
    for _ in range(ITERS):
        blob = rng.choice([
            base64.b64encode(_rand_bytes(rng)).decode(),
            _rand_str(rng),
            "",
            "not-base64-!@#",
        ])
        with pytest.raises(QuoteFormatError):
            p.parse(blob)


def test_quote_verifier_returns_false_never_crashes():
    rng = _rng()
    ts = TrustStore()
    v = QuoteVerifier(JsonQuoteParser(), ts)
    for _ in range(ITERS):
        blob = base64.b64encode(_rand_bytes(rng)).decode()
        r = v.verify(blob, expected_nonce="ab" * 32)
        assert r.verified is False  # garbage never verifies, never raises


def test_manifest_validation_fails_closed():
    rng = _rng()
    for _ in range(ITERS):
        obj = _rand_json(rng)
        if not isinstance(obj, dict):
            obj = {"x": obj}
        with pytest.raises((ValidationError, TypeError)):
            WeightCustodyManifest.model_validate(obj)


def test_parse_cadence_fails_closed():
    rng = _rng()
    for _ in range(ITERS):
        s = _rand_str(rng, 12)
        try:
            v = parse_cadence(s)
            assert isinstance(v, int) and v > 0
        except ValueError:
            pass


def test_ed25519_verify_fails_closed():
    rng = _rng()
    kp = generate_ed25519()
    v = Ed25519Verifier(kp.public_bytes)
    for _ in range(ITERS):
        sig = base64.urlsafe_b64encode(_rand_bytes(rng, 80)).rstrip(b"=").decode()
        with pytest.raises((InvalidSignature, ValueError)):
            v.verify({"a": 1}, sig)


def test_combine_shares_fails_closed():
    rng = _rng()
    for _ in range(ITERS):
        shares = [Share(rng.randint(0, 300), _rand_bytes(rng, 8)) for _ in range(rng.randint(0, 4))]
        try:
            out = combine_shares(shares)
            assert isinstance(out, bytes)
        except (ValueError, ZeroDivisionError, IndexError):
            pass


def test_challenge_consume_fails_closed():
    from wcm import ChallengeError

    rng = _rng()
    store = ChallengeStore()
    for _ in range(ITERS):
        nonce = _rand_bytes(rng, 32).hex()
        with pytest.raises(ChallengeError):
            store.consume(nonce)  # never issued
