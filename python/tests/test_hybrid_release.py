"""Local hybrid KBS flow with signed synthetic quotes, never hardware evidence."""
from __future__ import annotations

import pytest
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import wcm.hybrid_seal as hs
from wcm import (
    HYBRID_TRANSPORT_PROFILE, KeyBrokerService, SealError,
    generate_hybrid_transport_keypair, generate_transport_keypair,
    open_hybrid_sealed, seal_to_hybrid_public_key,
)
from wcm.renewal import manifest_identity
from wcm.threshold import Share, combine_shares, split_secret
from .test_quote_verify import (
    NOW, Pki, _container, _evidence, _measurements, _report_body_cb, _verifier,
)


def broker(manifest, key, pki, **options):
    return KeyBrokerService(
        {manifest.weights_hash:key}, now=lambda: NOW,
        cpu_quote_verifier=_verifier(pki),
        transport_profile=HYBRID_TRANSPORT_PROFILE,
        trusted_manifest_identities={manifest_identity(manifest)}, **options,
    )


def evidence(kbs, manifest, public, pki, *, bound=None):
    challenge=kbs.issue_challenge()
    current,rim=_measurements(manifest)
    quote=_container(pki,_report_body_cb(challenge.nonce,bytes.fromhex(bound or public)))
    return _evidence(challenge.nonce,quote_b64=quote,current=current,rim=rim,
                     transport_public_key=public)


@pytest.mark.parametrize("options", [{}, {"require_cpu_quote_verification": False}],
                         ids=["default", "explicit-false"])
def test_hybrid_release_and_nonce_replay(structural_manifest, options):
    pki=Pki(); kbs=broker(structural_manifest,b"test-key",pki,**options)
    private,public=generate_hybrid_transport_keypair()
    ev=evidence(kbs,structural_manifest,public,pki)
    decision=kbs.verify_and_release(structural_manifest,ev)
    assert decision.released and decision.key is None
    assert any(c.name == "cpu_quote_verified" and c.passed for c in decision.checks)
    assert open_hybrid_sealed(decision.sealed_key,private)==b"test-key"
    replay=kbs.verify_and_release(structural_manifest,ev)
    assert not replay.released and replay.key is None and replay.sealed_key is None


@pytest.mark.parametrize("options", [{}, {"require_cpu_quote_verification": False}],
                         ids=["default", "explicit-false"])
@pytest.mark.parametrize("include_quote", [False, True], ids=["no-quote", "unverified-quote"])
@pytest.mark.parametrize("renewal", [False, True], ids=["initial", "renewal"])
def test_hybrid_structural_policy_cannot_waive_quote_verifier(
    structural_manifest, options, include_quote, renewal,
):
    assert structural_manifest.release_policy.require_evidence_verification is False
    pki = Pki()
    kbs = KeyBrokerService(
        {structural_manifest.weights_hash: b"test-key"}, now=lambda: NOW,
        transport_profile=HYBRID_TRANSPORT_PROFILE,
        trusted_manifest_identities={manifest_identity(structural_manifest)},
        **options,
    )
    _, public = generate_hybrid_transport_keypair()
    ev = evidence(kbs, structural_manifest, public, pki)
    if not include_quote:
        ev.cpu.quote_b64 = None
    denied = kbs.verify_and_release(structural_manifest, ev, renewal=renewal)
    assert not denied.released and denied.key is None and denied.sealed_key is None
    # Descriptor validation passes; the absent quote verifier alone must deny.
    assert [c.name for c in denied.failures] == ["cpu_quote_verified"]
    assert "required but not configured" in denied.failures[0].detail
    replay = kbs.verify_and_release(structural_manifest, ev, renewal=renewal)
    assert not replay.released and replay.key is None and replay.sealed_key is None
    assert [c.name for c in replay.failures] == ["nonce_fresh"]


@pytest.mark.parametrize("kind", ["missing", "malformed", "untrusted", "wrong-nonce"])
def test_hybrid_requires_successful_quote_verification(structural_manifest, kind):
    pki = Pki()
    kbs = broker(structural_manifest, b"test-key", pki)
    _, public = generate_hybrid_transport_keypair()
    ev = evidence(kbs, structural_manifest, public, pki)
    if kind == "missing":
        ev.cpu.quote_b64 = None
    elif kind == "malformed":
        ev.cpu.quote_b64 = "not-a-quote"
    elif kind == "untrusted":
        ev.cpu.quote_b64 = _container(
            Pki(), _report_body_cb(ev.cpu.nonce_echo, bytes.fromhex(public)),
        )
    else:
        other_nonce = kbs.issue_challenge().nonce
        ev.cpu.quote_b64 = _container(pki, _report_body_cb(other_nonce, bytes.fromhex(public)))
    denied = kbs.verify_and_release(structural_manifest, ev)
    assert not denied.released and denied.key is None and denied.sealed_key is None
    assert [c.name for c in denied.failures] == ["cpu_quote_verified"]


@pytest.mark.parametrize("part", ["mlkem", "x25519", "all"])
def test_quote_binds_both_keys_and_profile(structural_manifest,part):
    pki=Pki(); kbs=broker(structural_manifest,b"test-key",pki)
    _,public=generate_hybrid_transport_keypair(); _,attacker=generate_hybrid_transport_keypair()
    raw=bytes.fromhex(public); other=bytes.fromhex(attacker)
    swapped={"mlkem":raw[:5]+other[5:1189]+raw[1189:],
             "x25519":raw[:1189]+other[1189:],"all":other}[part].hex()
    ev=evidence(kbs,structural_manifest,swapped,pki,bound=public)
    denied=kbs.verify_and_release(structural_manifest,ev)
    assert not denied.released and denied.key is None and denied.sealed_key is None
    assert any(c.name=="cpu_quote_verified" and not c.passed for c in denied.checks)
    # A refused attempt still consumes the challenge.
    ev.cpu.transport_public_key=public
    assert not kbs.verify_and_release(structural_manifest,ev).released


@pytest.mark.parametrize("kind", ["classical", "missing", "version", "uppercase", "truncated", "low-order", "bad-mlkem"])
def test_invalid_or_downgraded_key_never_releases(structural_manifest,kind):
    pki=Pki(); kbs=broker(structural_manifest,b"test-key",pki)
    _,public=generate_hybrid_transport_keypair(); _,classical=generate_transport_keypair()
    raw=bytes.fromhex(public)
    variants={"classical":classical,"missing":None,"version":public[:8]+"01"+public[10:],
              "uppercase":public.upper(),"truncated":public[:-2],
              "low-order":(raw[:-32]+bytes(32)).hex(),
              "bad-mlkem":(raw[:5]+b"\xff"*1152+raw[1157:]).hex()}
    offered=variants[kind]
    ev=evidence(kbs,structural_manifest,offered or public,pki)
    ev.cpu.transport_public_key=offered
    denied=kbs.verify_and_release(structural_manifest,ev)
    assert not denied.released and denied.key is None and denied.sealed_key is None


def test_default_broker_rejects_hybrid_descriptor(structural_manifest):
    pki=Pki()
    kbs=KeyBrokerService({structural_manifest.weights_hash:b"key"},now=lambda:NOW,
        cpu_quote_verifier=_verifier(pki),
        trusted_manifest_identities={manifest_identity(structural_manifest)})
    _,public=generate_hybrid_transport_keypair()
    denied=kbs.verify_and_release(structural_manifest,evidence(kbs,structural_manifest,public,pki))
    assert not denied.released and denied.key is None and denied.sealed_key is None


def test_hybrid_cannot_disable_channel_binding():
    with pytest.raises(ValueError,match="requires channel binding"):
        KeyBrokerService({},transport_profile=HYBRID_TRANSPORT_PROFILE,require_channel_binding=False)
    with pytest.raises(ValueError,match="unsupported"):
        KeyBrokerService({},transport_profile="mlkem-only")


def test_backend_failure_cannot_leak_plaintext(structural_manifest,monkeypatch):
    pki=Pki(); kbs=broker(structural_manifest,b"test-key",pki)
    _,public=generate_hybrid_transport_keypair()
    def unavailable(*args): raise UnsupportedAlgorithm("disabled")
    monkeypatch.setattr(hs,"_encapsulate",unavailable)
    denied=kbs.verify_and_release(structural_manifest,evidence(kbs,structural_manifest,public,pki))
    assert not denied.released and denied.key is None and denied.sealed_key is None
    assert any(c.name=="key_sealed" and not c.passed for c in denied.checks)


def test_two_hop_two_holder_share_transport_and_runtime_rotation(structural_manifest):
    # A software composition test, not a ready-made holder service. The caller
    # still authenticates holders, enforces threshold and authorizes each grant.
    model_key=AESGCM.generate_key(bit_length=256)
    encrypted_model=AESGCM(model_key).encrypt(bytes(12),b"public test model",b"model-v1")
    shares=split_secret(model_key,threshold=2,shares=2)
    holders=[generate_hybrid_transport_keypair() for _ in shares]
    pki=Pki(); runtime, runtime_public=generate_hybrid_transport_keypair()
    recovered=[]; released_blobs=[]
    for i,(share,(holder_private,holder_public)) in enumerate(zip(shares,holders)):
        context=f"holder:{i}:model:{structural_manifest.weights_hash}:provision:1".encode()
        sealed=seal_to_hybrid_public_key(holder_public,bytes([share.x])+share.y,context)
        with pytest.raises(SealError): open_hybrid_sealed(sealed,holders[1-i][0],context)
        payload=open_hybrid_sealed(sealed,holder_private,context)
        kbs=broker(structural_manifest,payload,pki)
        released=kbs.verify_and_release(structural_manifest,
            evidence(kbs,structural_manifest,runtime_public,pki))
        assert released.released and released.key is None
        released_blobs.append(released.sealed_key)
        received=open_hybrid_sealed(released.sealed_key,runtime)
        recovered.append(Share(received[0],received[1:]))
    assert len(recovered)==2 and len({s.x for s in recovered})==2
    key=combine_shares(recovered)
    assert key==model_key
    assert AESGCM(key).decrypt(bytes(12),encrypted_model,b"model-v1")==b"public test model"
    replacement,_=generate_hybrid_transport_keypair()
    for blob in released_blobs:
        with pytest.raises(SealError): open_hybrid_sealed(blob,replacement)


def test_expired_challenge_refuses_hybrid_release(structural_manifest):
    from datetime import timedelta
    clock=[NOW]
    pki=Pki()
    kbs=KeyBrokerService({structural_manifest.weights_hash:b"test-key"},
        now=lambda:clock[0],challenge_ttl_seconds=10,
        cpu_quote_verifier=_verifier(pki),transport_profile=HYBRID_TRANSPORT_PROFILE,
        trusted_manifest_identities={manifest_identity(structural_manifest)})
    _,public=generate_hybrid_transport_keypair()
    ev=evidence(kbs,structural_manifest,public,pki)
    clock[0]+=timedelta(seconds=11)
    denied=kbs.verify_and_release(structural_manifest,ev)
    assert not denied.released and denied.key is None and denied.sealed_key is None
