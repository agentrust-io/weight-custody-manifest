"""Deeply nested JSON evidence is a denial with a reason, never an exception.

json.loads raises RecursionError on deeply nested input, and the evidence JSON
parses in AzureSnpVtpmVerifier (the bundle and the HCL runtime claims),
JsonQuoteParser and NvidiaGpuVerifier did not list it among the errors they
turn into denials. Through a verifier configured in KeyBrokerService the
exception also left verify_and_release, after the challenge nonce had been
consumed.
"""
from __future__ import annotations

import base64
import json

import tests.test_azure_vtpm_verify as snp_vtpm
import tests.test_quote_verify as qv
from wcm import JsonQuoteParser, KeyBrokerService, QuoteVerifier, TrustStore, generate_transport_keypair
from wcm.nvidia import NvidiaGpuVerifier
from wcm.renewal import manifest_identity

DEEP = b"[" * 100_000 + b"]" * 100_000  # past any interpreter's recursion limit
NONCE = "ab" * 32


def _failed(decision):
    return [c for c in decision.checks if not c.passed]


def test_json_quote_parser_denies_deeply_nested_json():
    result = QuoteVerifier(JsonQuoteParser(), TrustStore()).verify(
        base64.b64encode(DEEP).decode(), expected_nonce=NONCE
    )
    assert not result.verified and "unparseable quote container" in result.reason


def test_nvidia_gpu_verifier_denies_deeply_nested_json():
    result = NvidiaGpuVerifier(TrustStore()).verify(base64.b64encode(DEEP).decode(), expected_nonce=NONCE)
    assert not result.verified and result.reason.startswith("unparseable GPU evidence")


def test_azure_snp_vtpm_denies_a_deeply_nested_bundle():
    _, trust = snp_vtpm._bundle()
    result = snp_vtpm._verify(base64.b64encode(DEEP).decode(), trust)
    assert not result.verified and result.reason.startswith("invalid Azure vTPM evidence")


def test_azure_snp_vtpm_denies_deeply_nested_runtime_claims(monkeypatch):
    """The HCL runtime JSON is parsed only after the SNP report binds it, so build a bundle that binds a deep one."""

    class _DeepRuntimeJson:
        @staticmethod
        def dumps(obj, **kwargs):
            if isinstance(obj, dict) and "keys" in obj:
                return DEEP.decode()
            return json.dumps(obj, **kwargs)

    monkeypatch.setattr(snp_vtpm, "json", _DeepRuntimeJson)
    bundle, trust = snp_vtpm._bundle()
    monkeypatch.undo()
    result = snp_vtpm._verify(bundle, trust)
    assert not result.verified and result.reason.startswith("invalid HCLAkPub")


def test_kbs_denies_deeply_nested_evidence_and_the_nonce_stays_spent(structural_manifest):
    """End to end with the reference server's CPU verifier class, against a release that succeeds.

    The inputs canonicalize, so the nonce is consumed before the verifier runs
    and stays spent after the denial.
    """
    pki = qv.Pki()
    current, rim = qv._measurements(structural_manifest)
    kbs = KeyBrokerService(
        {structural_manifest.weights_hash: b"KEY"},
        now=lambda: qv.NOW,
        cpu_quote_verifier=qv._verifier(pki),
        trusted_manifest_identities={manifest_identity(structural_manifest)},
    )

    def evidence(quote_for):
        challenge = kbs.issue_challenge()
        _, enclave_pub = generate_transport_keypair()
        return qv._evidence(
            challenge.nonce, quote_b64=quote_for(challenge.nonce, enclave_pub),
            current=current, rim=rim, transport_public_key=enclave_pub,
        )

    good = evidence(lambda nonce, pub: qv._container(pki, qv._report_body_cb(nonce, bytes.fromhex(pub))))
    assert kbs.verify_and_release(structural_manifest, good).released
    deep = evidence(lambda nonce, pub: base64.b64encode(DEEP).decode())
    decision = kbs.verify_and_release(structural_manifest, deep)
    assert not decision.released and decision.key is None and decision.sealed_key is None
    failed = _failed(decision)
    assert [c.name for c in failed] == ["cpu_quote_verified"]
    assert "unparseable quote container" in failed[0].detail
    again = kbs.verify_and_release(structural_manifest, deep)
    assert [c.name for c in _failed(again)] == ["nonce_fresh"]
