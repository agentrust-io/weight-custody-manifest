"""An exception from a verifier, its result or the GPU revocation check is a failed check, not a crash.

KeyBrokerService calls its configured CPU and GPU verifiers, and the GPU
revocation check, after consuming the challenge nonce. Verifiers deny rather
than raise, but one that raises or returns an unreadable result must not take
verify_and_release down with it. Each test runs against a release that succeeds
without the fault.
"""
from __future__ import annotations

import base64
import json
from types import SimpleNamespace

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization

import tests.test_gpu_revocation as revocation
import tests.test_gpu_revocation_gate as gate
import tests.test_nvidia as nv
import tests.test_quote_verify as qv
from tests.conftest import waive
from wcm import KeyBrokerService, generate_transport_keypair
from wcm.nvidia import build_gpu_verifier
from wcm.renewal import manifest_identity

_OID_P384 = bytes.fromhex("06052b81040022")


class _Raising:
    def __init__(self, inner):
        self.inner = inner

    def verify(self, *args, **kwargs):
        raise RuntimeError("a verifier bug")


class _Passing:
    def __init__(self, inner):
        self.inner = inner

    def verify(self, *args, **kwargs):
        return self.inner.verify(*args, **kwargs)


class _ReturningNone(_Passing):
    def verify(self, *args, **kwargs):
        return None


class _MissingReason(_Passing):
    def verify(self, *args, **kwargs):
        return SimpleNamespace(verified=True)


def _failed(decision):
    return [c for c in decision.checks if not c.passed]


@pytest.mark.parametrize("wrap, error", [
    (_Passing, None), (_Raising, "RuntimeError"),
    (_ReturningNone, "AttributeError"), (_MissingReason, "AttributeError"),
])
def test_kbs_denies_when_cpu_quote_verification_raises(structural_manifest, wrap, error):
    pki = qv.Pki()
    current, rim = qv._measurements(structural_manifest)
    kbs = KeyBrokerService(
        {structural_manifest.weights_hash: b"KEY"},
        now=lambda: qv.NOW,
        cpu_quote_verifier=wrap(qv._verifier(pki)),
        trusted_manifest_identities={manifest_identity(structural_manifest)},
    )
    challenge = kbs.issue_challenge()
    _, enclave_pub = generate_transport_keypair()
    quote = qv._container(pki, qv._report_body_cb(challenge.nonce, bytes.fromhex(enclave_pub)))
    ev = qv._evidence(challenge.nonce, quote_b64=quote, current=current, rim=rim, transport_public_key=enclave_pub)
    decision = kbs.verify_and_release(structural_manifest, ev)
    if wrap is _Passing:
        assert decision.released, _failed(decision)
        return
    assert not decision.released and decision.key is None and decision.sealed_key is None
    assert [(c.name, c.detail) for c in _failed(decision)] == [
        ("cpu_quote_verified", f"CPU quote verification raised {error}")
    ]
    again = kbs.verify_and_release(structural_manifest, ev)
    assert [c.name for c in _failed(again)] == ["nonce_fresh"]


@pytest.mark.parametrize("wrap, error", [
    (_Passing, None), (_Raising, "RuntimeError"),
    (_ReturningNone, "AttributeError"), (_MissingReason, "AttributeError"),
])
def test_kbs_denies_when_gpu_report_verification_raises(example_manifest, wrap, error):
    manifest = nv._pin_gpu(waive(example_manifest, cc_mode=False), nv.SYNTH_MEASUREMENT)
    pki = nv._Pki()
    current, rim = nv._measurements(manifest)
    kbs = KeyBrokerService(
        {manifest.weights_hash: b"KEY"},
        now=lambda: nv.NOW,
        gpu_report_verifier=wrap(build_gpu_verifier(nv._pem(pki.root))),
        require_gpu_report_verification=True,
        trusted_manifest_identities={manifest_identity(manifest)},
    )
    challenge = kbs.issue_challenge()
    ev = nv._evidence(challenge.nonce, gpu_quote_b64=nv._synth_evidence(pki, challenge.nonce), current=current, rim=rim)
    decision = kbs.verify_and_release(manifest, ev)
    if wrap is _Passing:
        assert decision.released, _failed(decision)
        return
    assert not decision.released and decision.key is None and decision.sealed_key is None
    failed = {c.name: c.detail for c in _failed(decision)}
    assert failed["gpu_report_verified"] == f"GPU report verification raised {error}"
    # require_cc_mode is met only by a verified report, so it fails with it.
    assert set(failed) <= {"gpu_report_verified", "gpu"}
    again = kbs.verify_and_release(manifest, ev)
    assert [c.name for c in _failed(again)] == ["nonce_fresh"]


def _unknown_curve_issuer(links):
    """The committed H100 chain with the issuer at index 2 on an unknown curve.

    The OCSP CertID hashes the issuer's name and key bits, which do not change,
    so NVIDIA's captured answer still matches; checking its signature reads the
    issuer key, which no longer parses.
    """
    links = list(links)
    der = links[2].public_bytes(serialization.Encoding.DER)
    assert der.count(_OID_P384) == 1
    links[2] = x509.load_der_x509_certificate(der.replace(_OID_P384, _OID_P384[:-1] + b"\x7f"))
    return links


def test_kbs_denies_when_the_gpu_revocation_check_raises(example_manifest):
    """The revocation check runs on the chain the GPU evidence carries."""
    manifest = gate.requires_revocation(example_manifest)
    kbs = gate.kbs_for(manifest, revocation.client_for())
    intact = kbs.verify_and_release(manifest, gate.evidence(kbs.issue_challenge().nonce, manifest))
    assert intact.released, _failed(intact)

    kbs = gate.kbs_for(manifest, revocation.client_for())
    challenge = kbs.issue_challenge()
    ev = gate.evidence(challenge.nonce, manifest)
    doc = json.loads(base64.b64decode(ev.gpu.quote_b64))
    doc["cert_chain_pem"] = "".join(
        c.public_bytes(serialization.Encoding.PEM).decode() for c in _unknown_curve_issuer(revocation.chain())
    )
    quote_b64 = base64.b64encode(json.dumps(doc).encode()).decode()
    ev = ev.model_copy(update={"gpu": ev.gpu.model_copy(update={"quote_b64": quote_b64})})
    decision = kbs.verify_and_release(manifest, ev)
    assert not decision.released and decision.key is None and decision.sealed_key is None
    assert [(c.name, c.detail) for c in _failed(decision)] == [
        ("attestation_revocation", "GPU revocation check raised UnsupportedAlgorithm")
    ]
