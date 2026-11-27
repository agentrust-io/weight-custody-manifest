"""Strict base64 on the JSON quote container and the NVIDIA GPU evidence (#252).

``base64.b64decode`` without ``validate=True`` skips every character outside the
alphabet, so a report padded with whitespace, line breaks or symbols decoded to
the same bytes as the clean string. The verifiers now refuse those characters.
(Unused pad bits are still not checked, so this is not a canonical-encoding
check.) Each decode site has its own tests, and each test injects one junk
character into the one field under test while every other field stays canonical,
so removing ``validate=True`` at a single site fails that site's tests and no
one else's:

- ``JsonQuoteParser.parse``: outer ``quote_b64``, ``report_b64``, ``signature_b64``
- ``NvidiaGpuVerifier.verify``: outer ``evidence_b64``, inner ``report_b64``
"""
from __future__ import annotations

import base64
import json

import pytest

from tests import test_nvidia as gpu
from tests import test_quote_verify as cpu
from wcm import (
    JsonQuoteParser,
    KeyBrokerService,
    QuoteFormatError,
    build_gpu_verifier,
    generate_transport_keypair,
)
from wcm.renewal import manifest_identity

# Characters the lax decoder drops: line breaks, a space, and two symbols.
JUNK = {"newline": "\n", "space": " ", "bang": "!", "at": "@"}
PLACES = ("leading", "middle", "trailing")

junk_param = pytest.mark.parametrize("junk", JUNK.values(), ids=JUNK.keys())
place_param = pytest.mark.parametrize("place", PLACES)


def _alias(b64: str, junk: str, place: str) -> str:
    """A different wire string that the lax decoder maps to the same bytes."""
    cut = {"leading": 0, "middle": len(b64) // 2, "trailing": len(b64)}[place]
    aliased = b64[:cut] + junk + b64[cut:]
    assert aliased != b64
    assert base64.b64decode(aliased) == base64.b64decode(b64)
    return aliased


def _json_doc(pki: cpu.Pki) -> dict:
    return json.loads(base64.b64decode(cpu._container(pki, cpu._report_body(cpu.NONCE))))


def _repack(doc: dict) -> str:
    return base64.b64encode(json.dumps(doc).encode()).decode()


def _assert_json_quote_refused(pki: cpu.Pki, quote: str) -> None:
    with pytest.raises(QuoteFormatError, match="unparseable quote container"):
        JsonQuoteParser().parse(quote)
    result = cpu._verifier(pki).verify(quote, expected_nonce=cpu.NONCE, now=cpu.NOW)
    assert not result.verified
    assert "unparseable quote container" in (result.reason or "")


# -- JsonQuoteParser / QuoteVerifier -------------------------------------------


def test_clean_json_container_still_verifies():
    pki = cpu.Pki()
    quote = cpu._container(pki, cpu._report_body(cpu.NONCE))
    assert JsonQuoteParser().parse(quote).report_body == cpu._report_body(cpu.NONCE)
    assert cpu._verifier(pki).verify(quote, expected_nonce=cpu.NONCE, now=cpu.NOW).verified


@junk_param
@place_param
def test_json_parser_refuses_junk_in_the_outer_quote(junk, place):
    pki = cpu.Pki()
    quote = _alias(cpu._container(pki, cpu._report_body(cpu.NONCE)), junk, place)
    _assert_json_quote_refused(pki, quote)


@junk_param
@place_param
def test_json_parser_refuses_junk_in_report_b64(junk, place):
    pki = cpu.Pki()
    doc = _json_doc(pki)
    doc["report_b64"] = _alias(doc["report_b64"], junk, place)
    _assert_json_quote_refused(pki, _repack(doc))


@junk_param
@place_param
def test_json_parser_refuses_junk_in_signature_b64(junk, place):
    pki = cpu.Pki()
    doc = _json_doc(pki)
    doc["signature_b64"] = _alias(doc["signature_b64"], junk, place)
    _assert_json_quote_refused(pki, _repack(doc))


def test_kbs_denies_a_cpu_quote_with_a_padded_wire_encoding(structural_manifest):
    pki = cpu.Pki()
    current, rim = cpu._measurements(structural_manifest)
    kbs = KeyBrokerService(
        {structural_manifest.weights_hash: b"KEY"},
        now=lambda: cpu.NOW,
        cpu_quote_verifier=cpu._verifier(pki),
        trusted_manifest_identities={manifest_identity(structural_manifest)},
    )
    _, enclave_pub = generate_transport_keypair()

    def release(rewrite):
        challenge = kbs.issue_challenge()
        quote = cpu._container(
            pki, cpu._report_body_cb(challenge.nonce, bytes.fromhex(enclave_pub))
        )
        evidence = cpu._evidence(
            challenge.nonce, quote_b64=rewrite(quote), current=current, rim=rim,
            transport_public_key=enclave_pub,
        )
        return kbs.verify_and_release(structural_manifest, evidence)

    assert release(lambda quote: quote).released
    denied = release(lambda quote: _alias(quote, "\n", "trailing"))
    assert not denied.released
    check = next(c for c in denied.checks if c.name == "cpu_quote_verified")
    assert not check.passed
    assert "unparseable quote container" in (check.detail or "")


# -- NvidiaGpuVerifier -----------------------------------------------------------


def _gpu_verify(evidence_b64: str, nonce: str):
    return build_gpu_verifier(gpu._real_root_pem()).verify(
        evidence_b64, expected_nonce=nonce, now=gpu.NOW
    )


def test_clean_gpu_evidence_still_verifies():
    b = gpu._real_bundle()
    result = _gpu_verify(gpu._evidence_b64(b["report_b64"], b["cert_chain_pem"]), b["nonce"])
    assert result.verified, result.reason


@junk_param
@place_param
def test_gpu_verifier_refuses_junk_in_the_outer_evidence(junk, place):
    b = gpu._real_bundle()
    evidence = _alias(gpu._evidence_b64(b["report_b64"], b["cert_chain_pem"]), junk, place)
    result = _gpu_verify(evidence, b["nonce"])
    assert not result.verified
    assert "unparseable GPU evidence" in (result.reason or "")


@junk_param
@place_param
def test_gpu_verifier_refuses_junk_in_report_b64(junk, place):
    b = gpu._real_bundle()
    evidence = gpu._evidence_b64(_alias(b["report_b64"], junk, place), b["cert_chain_pem"])
    result = _gpu_verify(evidence, b["nonce"])
    assert not result.verified
    assert "unparseable GPU evidence" in (result.reason or "")


def test_kbs_denies_gpu_evidence_with_a_padded_wire_encoding(example_manifest):
    pki = gpu._Pki()
    current, rim = gpu._measurements(example_manifest)
    kbs = KeyBrokerService(
        {example_manifest.weights_hash: b"KEY"},
        now=lambda: gpu.NOW,
        gpu_report_verifier=build_gpu_verifier(gpu._pem(pki.root)),
        require_gpu_report_verification=True,
        trusted_manifest_identities={manifest_identity(example_manifest)},
    )
    challenge = kbs.issue_challenge()
    quote = _alias(gpu._synth_evidence(pki, challenge.nonce), "\n", "trailing")
    evidence = gpu._evidence(challenge.nonce, gpu_quote_b64=quote, current=current, rim=rim)
    decision = kbs.verify_and_release(example_manifest, evidence)
    assert not decision.released
    check = next(c for c in decision.checks if c.name == "gpu_report_verified")
    assert not check.passed
    assert "unparseable GPU evidence" in (check.detail or "")
