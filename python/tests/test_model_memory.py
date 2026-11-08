"""Loaded-byte checks, not hardware/DMA attack validation."""
from __future__ import annotations

import hashlib
import struct
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pydantic import ValidationError

from wcm import EnclaveSession, KeyBrokerService, KeyWipedError, SoftwareProvider
from wcm._challenge import ChallengeStore
from wcm._seal import generate_transport_keypair
from wcm._signing import _b64url_encode
from wcm._types import HashValue
from wcm.model_memory import (
    BufferDigest, BufferMemoryReader, ModelMemoryBaseline, ModelMemoryError,
    ModelMemoryGuard, ModelMemoryObservation, ModelMemoryVerifier,
    measure_model_buffers, model_memory_baseline_hash, observe_model_memory,
)
from wcm.renewal import manifest_identity


def _hash(value: bytes) -> HashValue:
    return HashValue("sha256:" + hashlib.sha256(value).hexdigest())


@pytest.fixture
def setup():
    data = bytearray(struct.pack("<3f", 2.0, 3.0, 4.0))
    buffers = {"linear.weight": BufferMemoryReader(data)}
    baseline = ModelMemoryBaseline(
        manifest_hash=_hash(b"manifest"), weights_hash=_hash(bytes(data)),
        serving_image_measurement=_hash(b"image"), layout_id="linear-f32le-v1",
        buffers=measure_model_buffers(buffers),
    )
    key = Ed25519PrivateKey.generate()
    _, transport = generate_transport_keypair()
    return data, buffers, baseline, key, transport


def _verifier(setup, **kwargs):
    _, _, baseline, key, transport = setup
    return ModelMemoryVerifier(
        baseline=baseline,
        observer_public_key_b64url=_b64url_encode(key.public_key().public_bytes_raw()),
        transport_public_key=transport, **kwargs,
    )


def _observation(setup, nonce):
    _, buffers, baseline, key, transport = setup
    return observe_model_memory(buffers, baseline=baseline, challenge_nonce=nonce,
                                transport_public_key=transport, signing_key=key)


def test_real_bytes_and_json_round_trip(setup):
    verifier = _verifier(setup)
    nonce = verifier.issue_challenge().nonce
    report = _observation(setup, nonce)
    exported = ModelMemoryObservation.model_validate_json(report.model_dump_json())
    assert verifier.verify(exported, challenge_nonce=nonce)[0]
    assert not verifier.verify(exported, challenge_nonce=nonce)[0]  # replay


def test_disk_unchanged_but_loaded_weight_modified(setup, tmp_path):
    data, _, baseline, _, _ = setup
    artifact = tmp_path / "weights.bin"
    artifact.write_bytes(data)
    verifier = _verifier(setup)
    nonce = verifier.issue_challenge().nonce
    struct.pack_into("<f", data, 0, 20.0)
    assert _hash(artifact.read_bytes()) == baseline.weights_hash
    passed, detail = verifier.verify(_observation(setup, nonce), challenge_nonce=nonce)
    assert not passed and "differ" in detail


@pytest.mark.parametrize("field,value", [
    ("challenge_nonce", "b" * 64), ("transport_public_key", "c" * 64),
    ("baseline_hash", "sha256:" + "d" * 64),
    ("signature_b64url", "A" * 86), ("kind", "unsupported"),
])
def test_altered_or_misbound_observation_fails(setup, field, value):
    verifier = _verifier(setup)
    nonce = verifier.issue_challenge().nonce
    report = _observation(setup, nonce).model_copy(update={field: value})
    assert not verifier.verify(report, challenge_nonce=nonce)[0]
    # Restoring a genuine report cannot reuse the failed attempt's nonce.
    assert not verifier.verify(_observation(setup, nonce), challenge_nonce=nonce)[0]


def test_fresh_challenge_cannot_refresh_old_observation(setup):
    verifier = _verifier(setup)
    old = verifier.issue_challenge().nonce
    report = _observation(setup, old)
    fresh = verifier.issue_challenge().nonce
    assert not verifier.verify(report, challenge_nonce=fresh)[0]


def test_unknown_and_expired_challenge(setup):
    now = [datetime(2026, 11, 4, tzinfo=timezone.utc)]
    store = ChallengeStore(ttl_seconds=5, now=lambda: now[0])
    verifier = _verifier(setup, challenge_store=store)
    assert not verifier.verify(_observation(setup, "f" * 64), challenge_nonce="f" * 64)[0]
    nonce = verifier.issue_challenge().nonce
    report = _observation(setup, nonce)
    now[0] += timedelta(seconds=6)
    assert not verifier.verify(report, challenge_nonce=nonce)[0]


def test_wrong_observer_cannot_self_assert_its_key(setup):
    verifier = _verifier(setup)
    nonce = verifier.issue_challenge().nonce
    data, buffers, baseline, _, transport = setup
    report = _observation((data, buffers, baseline, Ed25519PrivateKey.generate(), transport), nonce)
    assert not verifier.verify(report, challenge_nonce=nonce)[0]
    assert "public_key" not in report.model_dump()


@pytest.mark.parametrize("update", [
    {"manifest_hash": _hash(b"another manifest")},
    {"weights_hash": _hash(b"another model")},
    {"serving_image_measurement": _hash(b"another image")},
    {"layout_id": "another-loader"},
])
def test_baseline_covers_model_manifest_image_and_loader(setup, update):
    data, buffers, baseline, key, transport = setup
    verifier = _verifier(setup)
    nonce = verifier.issue_challenge().nonce
    other = baseline.model_copy(update=update)
    assert model_memory_baseline_hash(baseline) != model_memory_baseline_hash(other)
    assert not verifier.verify(_observation((data, buffers, other, key, transport), nonce),
                               challenge_nonce=nonce)[0]


@pytest.mark.parametrize("case", ["extra", "missing", "renamed", "resized"])
def test_inventory_is_exact(setup, case):
    data, buffers, baseline, key, transport = setup
    altered = dict(buffers)
    if case == "extra":
        altered["adapter.weight"] = BufferMemoryReader(b"adapter")
    elif case == "missing":
        altered = {}
    elif case == "renamed":
        altered = {"other.weight": buffers["linear.weight"]}
    else:
        altered = {"linear.weight": BufferMemoryReader(bytes(data) + b"x")}
    verifier = _verifier(setup)
    nonce = verifier.issue_challenge().nonce
    if not altered:
        with pytest.raises(ModelMemoryError):
            _observation((data, altered, baseline, key, transport), nonce)
    else:
        assert not verifier.verify(_observation((data, altered, baseline, key, transport), nonce),
                                   challenge_nonce=nonce)[0]


def test_buffer_reader_covers_every_chunk_without_writing():
    data = bytearray(b"a" * (2 * 1024 * 1024 + 11))
    reader = BufferMemoryReader(data)
    original = bytes(data)
    result = measure_model_buffers({"weights": reader})
    assert result[0].nbytes == len(data)
    assert result[0].sha256 == hashlib.sha256(data).hexdigest()
    assert bytes(data) == original
    data[-1] = 98
    assert measure_model_buffers({"weights": reader}) != result
    for offset, length in [(-1, 1), (0, -1), (len(data), 1)]:
        with pytest.raises(ValueError):
            reader.read(offset, length)


@pytest.mark.parametrize("name", ["", "../weights", "weights\n", "w eig ht", "w" * 161])
def test_invalid_buffer_names(name):
    with pytest.raises(ValueError):
        measure_model_buffers({name: BufferMemoryReader(b"x")})


def test_empty_and_oversize_inventory():
    with pytest.raises(ValueError):
        measure_model_buffers({})
    with pytest.raises(ValueError):
        measure_model_buffers({f"w{i}": BufferMemoryReader(b"x") for i in range(4097)})


def test_noncontiguous_buffer_rejected():
    with pytest.raises(TypeError):
        BufferMemoryReader(memoryview(bytearray(8))[::2])


def test_callback_required(setup):
    with pytest.raises(TypeError, match="teardown"):
        ModelMemoryGuard(setup[2], on_failure=None)


def test_point_in_time_observation_does_not_attest_future_memory(setup):
    # Honest boundary: a genuine earlier observation cannot see a later write.
    verifier = _verifier(setup)
    nonce = verifier.issue_challenge().nonce
    report = _observation(setup, nonce)
    setup[0][0] ^= 1
    assert verifier.verify(report, challenge_nonce=nonce)[0]
    # A fresh scan sees the mismatch. No continuous-integrity claim is made.
    fresh = verifier.issue_challenge().nonce
    assert not verifier.verify(_observation(setup, fresh), challenge_nonce=fresh)[0]


@pytest.mark.parametrize("bad", [True, 0, -1, 2**53, 3.0, "3"])
def test_invalid_lengths_refused_before_read(bad):
    class BadReader:
        nbytes = bad

        def read(self, *_):
            pytest.fail("invalid reader should never be invoked")
    with pytest.raises(ValueError):
        measure_model_buffers({"weight": BadReader()})


@pytest.mark.parametrize("kind", ["short", "long", "type", "exception", "resize"])
def test_failed_reader_latches_guard_and_calls_stop_once(setup, kind):
    _, _, baseline, _, _ = setup
    calls = []
    class BadReader:
        nbytes = 12

        def read(self, offset, length):
            if kind == "exception":
                raise OSError("device unavailable")
            if kind == "resize":
                self.nbytes = 13
            return {"short": b"x", "long": b"x" * 13,
                    "type": bytearray(12)}.get(kind, b"x" * 12)
    guard = ModelMemoryGuard(baseline, on_failure=lambda: calls.append("stopped"))
    for _ in range(2):
        with pytest.raises(ModelMemoryError):
            guard.check_before_operation({"linear.weight": BadReader()})
    assert calls == ["stopped"]


def test_restored_bytes_do_not_reopen_failed_guard(setup):
    data, buffers, baseline, _, _ = setup
    before = bytes(data)
    calls = []
    guard = ModelMemoryGuard(baseline, on_failure=lambda: calls.append("stopped"))
    guard.check_before_operation(buffers)
    data[0] ^= 1
    with pytest.raises(ModelMemoryError):
        guard.check_before_operation(buffers)
    data[:] = before
    with pytest.raises(ModelMemoryError, match="latched"):
        guard.check_before_operation(buffers)
    assert calls == ["stopped"]


def test_teardown_failure_never_reopens_guard(setup):
    data, buffers, baseline, _, _ = setup
    def broken_stop():
        raise RuntimeError("worker did not acknowledge stop")
    guard = ModelMemoryGuard(baseline, on_failure=broken_stop)
    data[0] ^= 1
    with pytest.raises(ModelMemoryError, match="teardown callback also failed"):
        guard.check_before_operation(buffers)
    with pytest.raises(ModelMemoryError, match="latched"):
        guard.check_before_operation(buffers)


def test_concurrent_replay_only_one_verification_succeeds(setup):
    verifier = _verifier(setup)
    nonce = verifier.issue_challenge().nonce
    report = _observation(setup, nonce)
    with ThreadPoolExecutor(max_workers=8) as pool:
        outcomes = list(pool.map(lambda _: verifier.verify(report, challenge_nonce=nonce)[0], range(16)))
    assert sum(outcomes) == 1


def test_malformed_constructed_model_and_noncanonical_signature_rejected(setup):
    verifier = _verifier(setup)
    nonce = verifier.issue_challenge().nonce
    report = _observation(setup, nonce)
    # Ed25519's 64 bytes leave four unused base64 bits in the last character.
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    index = alphabet.index(report.signature_b64url[-1])
    changed = report.signature_b64url[:-1] + alphabet[index + 1]
    assert not verifier.verify(report.model_copy(update={"signature_b64url": changed}),
                               challenge_nonce=nonce)[0]
    nonce = verifier.issue_challenge().nonce
    invalid = report.model_copy(update={"buffers": [None]})
    assert not verifier.verify(invalid, challenge_nonce=nonce)[0]


@pytest.mark.parametrize("entries", [(), (
    BufferDigest(name="w", nbytes=1, sha256="a" * 64),
    BufferDigest(name="w", nbytes=1, sha256="a" * 64),
), (
    BufferDigest(name="z", nbytes=1, sha256="a" * 64),
    BufferDigest(name="a", nbytes=1, sha256="a" * 64),
)])
def test_invalid_baselines_cannot_bypass_validation(setup, entries):
    _, _, baseline, _, _ = setup
    bad = baseline.model_copy(update={"buffers": entries})
    with pytest.raises(ValidationError):
        ModelMemoryGuard(bad, on_failure=lambda: None)


@pytest.mark.parametrize("key", ["AAAA", "A" * 43, "not-a-key=", ""])
def test_invalid_observer_pin_fails_configuration(setup, key):
    _, _, baseline, _, transport = setup
    with pytest.raises(ValueError):
        ModelMemoryVerifier(baseline=baseline, observer_public_key_b64url=key,
                            transport_public_key=transport)


def test_release_decrypt_load_check_infer_then_mutation_denies_and_wipes(structural_manifest, tmp_path):
    """Real AES-GCM, sealed WCM release and tiny inference; MOCK hardware only."""
    plain = struct.pack("<3f", 2.0, 3.0, 4.0)
    model_hash = _hash(plain)
    manifest = structural_manifest.model_copy(update={"weights_hash": model_hash})
    key = AESGCM.generate_key(bit_length=256)
    iv = b"\x01" * 12  # unique for the fresh per-test key
    artifact = tmp_path / "model.enc"
    artifact.write_bytes(AESGCM(key).encrypt(iv, plain, b"model-v1"))
    original_cipher_hash = _hash(artifact.read_bytes())
    now = [datetime(2026, 7, 19, 12, tzinfo=timezone.utc)]
    kbs = KeyBrokerService({model_hash: key}, now=lambda: now[0],
                           trusted_manifest_identities={manifest_identity(manifest)})
    private, public = generate_transport_keypair()
    policy = manifest.release_policy
    image = next(x.measurement for x in policy.required_serving_image.accepted_measurements
                 if x.status.value == "current")
    evidence = SoftwareProvider().produce(
        kbs.issue_challenge(), serving_image_measurement=image,
        gpu_measurement=policy.required_gpu_measurement.rim_pin,
        transport_public_key=public,
    )
    decision = kbs.verify_and_release(manifest, evidence)
    assert decision.released and decision.key is None and decision.sealed_key is not None
    stopped = []
    session = EnclaveSession.from_release(manifest, decision, transport_private_key=private,
                                          now=lambda: now[0], on_stop=lambda: stopped.append(True))
    loaded = bytearray(AESGCM(session.use_key()).decrypt(iv, artifact.read_bytes(), b"model-v1"))
    baseline = ModelMemoryBaseline(
        manifest_hash=HashValue(manifest_identity(manifest)), weights_hash=model_hash,
        serving_image_measurement=image, layout_id="linear-f32le-v1",
        buffers=measure_model_buffers({"linear.weight": BufferMemoryReader(plain)}),
    )
    guard = ModelMemoryGuard(baseline, on_failure=session.zeroize)
    buffers = {"linear.weight": BufferMemoryReader(loaded)}
    def infer():
        session.authorize_operation()
        guard.check_before_operation(buffers)
        # A long scan must not allow a lease that expired while scanning.
        if session.tick().value == "wiped":
            raise KeyWipedError("lease ended during integrity scan")
        return sum(w * x for w, x in zip(struct.unpack("<3f", loaded), (4, 5, 6)))
    assert infer() == 47
    struct.pack_into("<f", loaded, 0, 20.0)
    assert _hash(artifact.read_bytes()) == original_cipher_hash
    with pytest.raises(ModelMemoryError):
        infer()
    assert session.is_wiped and stopped == [True]
    with pytest.raises(KeyWipedError):
        infer()
