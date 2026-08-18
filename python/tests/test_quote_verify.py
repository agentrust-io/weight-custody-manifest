"""Quote verification against a synthetic PKI.

Builds a real root -> intermediate -> leaf chain, signs a report body whose
REPORT_DATA binds a nonce, and drives the verifier through the happy path and
every failure mode. This validates the verification *machinery* with real
cryptography; it does not use (or need) real AMD/NVIDIA quotes.
"""
from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from wcm import (
    CompositeEvidence,
    CpuQuote,
    GpuReport,
    JsonQuoteParser,
    KeyBrokerService,
    QuoteVerifier,
    SealError,
    TrustStore,
    WeightCustodyManifest,
    generate_transport_keypair,
    open_sealed,
    verify_cert_chain,
)

NOW = datetime(2026, 7, 20, 12, 0, 0, tzinfo=timezone.utc)
NONCE = "ab" * 32  # 32-byte nonce as hex


def _key():
    return ec.generate_private_key(ec.SECP256R1())


def _cert(subject, issuer_name, subject_key, issuer_key, *, ca=False, nb=None, na=None):
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_name)]))
        .public_key(subject_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(nb or (NOW - timedelta(days=1)))
        .not_valid_after(na or (NOW + timedelta(days=365)))
    )
    if ca:
        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True
        )
    return builder.sign(issuer_key, hashes.SHA256())


def _pem(cert) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode()


class Pki:
    def __init__(self):
        self.root_key = _key()
        self.root = _cert("wcm-test-root", "wcm-test-root", self.root_key, self.root_key, ca=True)
        self.inter_key = _key()
        self.inter = _cert("wcm-test-inter", "wcm-test-root", self.inter_key, self.root_key, ca=True)
        self.leaf_key = _key()
        self.leaf = _cert("attestation-key", "wcm-test-inter", self.leaf_key, self.inter_key)


def _report_body(nonce_hex: str, offset: int = 0) -> bytes:
    digest = hashlib.sha256(bytes.fromhex(nonce_hex)).digest()
    return bytes(offset) + digest + bytes(32) + b"measurement-and-tcb-fields"


def _container(pki: Pki, report_body: bytes, *, offset: int = 0, sign_key=None) -> str:
    signer = sign_key or pki.leaf_key
    signature = signer.sign(report_body, ec.ECDSA(hashes.SHA256()))
    doc = {
        "report_b64": base64.b64encode(report_body).decode(),
        "signature_b64": base64.b64encode(signature).decode(),
        "leaf_pem": _pem(pki.leaf),
        "intermediates_pem": [_pem(pki.inter)],
        "report_data_offset": offset,
    }
    return base64.b64encode(json.dumps(doc).encode()).decode()


def _trust(pki: Pki) -> TrustStore:
    ts = TrustStore()
    ts.add_root(pki.root)
    return ts


def _verifier(pki: Pki) -> QuoteVerifier:
    return QuoteVerifier(JsonQuoteParser(), _trust(pki))


# -- verifier unit tests -------------------------------------------------------


def test_valid_quote_verifies():
    pki = Pki()
    q = _container(pki, _report_body(NONCE))
    result = _verifier(pki).verify(q, expected_nonce=NONCE, now=NOW)
    assert result.verified
    assert "attestation-key" in (result.leaf_subject or "")


def test_untrusted_root_fails():
    pki = Pki()
    q = _container(pki, _report_body(NONCE))
    other = QuoteVerifier(JsonQuoteParser(), _trust(Pki()))  # different root
    result = other.verify(q, expected_nonce=NONCE, now=NOW)
    assert not result.verified
    assert "trusted root" in (result.reason or "")


def test_tampered_report_fails_signature():
    pki = Pki()
    body = bytearray(_report_body(NONCE))
    q = _container(pki, bytes(body))
    # Tamper the container's report after signing.
    doc = json.loads(base64.b64decode(q))
    tampered = bytearray(base64.b64decode(doc["report_b64"]))
    tampered[-1] ^= 0xFF
    doc["report_b64"] = base64.b64encode(bytes(tampered)).decode()
    q2 = base64.b64encode(json.dumps(doc).encode()).decode()
    result = _verifier(pki).verify(q2, expected_nonce=NONCE, now=NOW)
    assert not result.verified
    assert "signature" in (result.reason or "")


def test_nonce_mismatch_fails_binding():
    pki = Pki()
    q = _container(pki, _report_body(NONCE))
    result = _verifier(pki).verify(q, expected_nonce="cd" * 32, now=NOW)
    assert not result.verified
    assert "REPORT_DATA" in (result.reason or "")


def test_broken_chain_fails():
    pki = Pki()
    # Sign the leaf with a stranger key so it is not signed by the intermediate.
    stranger = _key()
    pki.leaf = _cert("attestation-key", "wcm-test-inter", pki.leaf_key, stranger)
    q = _container(pki, _report_body(NONCE))
    result = _verifier(pki).verify(q, expected_nonce=NONCE, now=NOW)
    assert not result.verified
    assert "chain" in (result.reason or "").lower()


def test_expired_leaf_fails():
    pki = Pki()
    pki.leaf = _cert(
        "attestation-key",
        "wcm-test-inter",
        pki.leaf_key,
        pki.inter_key,
        nb=NOW - timedelta(days=10),
        na=NOW - timedelta(days=1),  # already expired at NOW
    )
    q = _container(pki, _report_body(NONCE))
    result = _verifier(pki).verify(q, expected_nonce=NONCE, now=NOW)
    assert not result.verified
    assert "validity" in (result.reason or "")


def test_malformed_quote_fails():
    pki = Pki()
    result = _verifier(pki).verify("not-a-valid-container", expected_nonce=NONCE, now=NOW)
    assert not result.verified


def test_offset_report_data():
    pki = Pki()
    q = _container(pki, _report_body(NONCE, offset=16), offset=16)
    result = _verifier(pki).verify(q, expected_nonce=NONCE, now=NOW)
    assert result.verified


def test_rsa_pss_chain_verifies():
    """Regression: real vendor chains (AMD VCEK/ASK/ARK) are RSASSA-PSS signed,
    validated against a live SEV-SNP host. A PKCS#1-v1.5-only verifier rejects
    them, so verify_cert_chain must honor each cert's own signature parameters.
    """
    from cryptography.hazmat.primitives.asymmetric import padding, rsa

    pss = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)

    def rkey():
        return rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def cert_pss(subject, issuer_name, subj_key, issuer_key, ca=False):
        b = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)]))
            .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_name)]))
            .public_key(subj_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(NOW - timedelta(days=1))
            .not_valid_after(NOW + timedelta(days=365))
        )
        if ca:
            b = b.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        return b.sign(issuer_key, hashes.SHA256(), rsa_padding=pss)

    rk, ik, lk = rkey(), rkey(), rkey()
    root = cert_pss("pss-root", "pss-root", rk, rk, ca=True)
    inter = cert_pss("pss-inter", "pss-root", ik, rk, ca=True)
    leaf = cert_pss("pss-leaf", "pss-inter", lk, ik)
    ts = TrustStore()
    ts.add_root(root)
    assert verify_cert_chain(leaf, [inter], ts, NOW) is None
    # A different root must still fail.
    other = TrustStore()
    other.add_root(cert_pss("other-root", "other-root", rkey(), rkey(), ca=True))
    assert verify_cert_chain(leaf, [inter], other, NOW) is not None


# -- KBS integration -----------------------------------------------------------


def _evidence(nonce: str, *, quote_b64, current, rim):
    return CompositeEvidence(
        cpu=CpuQuote(
            platform="amd-sev-snp",
            assurance_tier="hardware-attested",
            serving_image_measurement=current,
            nonce_echo=nonce,
            attestation_key_id="vcek:test",
            quote_b64=quote_b64,
        ),
        gpu=GpuReport(platform="nvidia-cc-gpu", measurement=rim, nonce_echo=nonce),
    )


def _measurements(m):
    ams = m.release_policy.required_serving_image.accepted_measurements
    current = next(x.measurement for x in ams if x.status.value == "current")
    rim = m.release_policy.required_gpu_measurement.rim_pin
    return current, rim


def test_kbs_releases_with_verified_quote(example_manifest):
    pki = Pki()
    current, rim = _measurements(example_manifest)
    kbs = KeyBrokerService(
        {example_manifest.weights_hash: b"KEY"},
        now=lambda: NOW,
        cpu_quote_verifier=_verifier(pki),
    )
    challenge = kbs.issue_challenge()
    q = _container(pki, _report_body(challenge.nonce))
    ev = _evidence(challenge.nonce, quote_b64=q, current=current, rim=rim)

    decision = kbs.verify_and_release(example_manifest, ev)
    assert decision.released
    assert any(c.name == "cpu_quote_verified" and c.passed for c in decision.checks)


def test_kbs_denies_bad_quote(example_manifest):
    pki = Pki()
    current, rim = _measurements(example_manifest)
    kbs = KeyBrokerService(
        {example_manifest.weights_hash: b"KEY"},
        now=lambda: NOW,
        cpu_quote_verifier=_verifier(Pki()),  # trusts a different root
    )
    challenge = kbs.issue_challenge()
    q = _container(pki, _report_body(challenge.nonce))  # signed by an untrusted chain
    ev = _evidence(challenge.nonce, quote_b64=q, current=current, rim=rim)

    decision = kbs.verify_and_release(example_manifest, ev)
    assert not decision.released
    assert any(c.name == "cpu_quote_verified" and not c.passed for c in decision.checks)


def test_kbs_denies_when_verifier_set_but_no_quote(example_manifest):
    pki = Pki()
    current, rim = _measurements(example_manifest)
    kbs = KeyBrokerService(
        {example_manifest.weights_hash: b"KEY"},
        now=lambda: NOW,
        cpu_quote_verifier=_verifier(pki),
    )
    challenge = kbs.issue_challenge()
    ev = _evidence(challenge.nonce, quote_b64=None, current=current, rim=rim)

    decision = kbs.verify_and_release(example_manifest, ev)
    assert not decision.released
    assert any(c.name == "cpu_quote_verified" and not c.passed for c in decision.checks)


def test_kbs_without_verifier_notes_structural_only(example_manifest):
    current, rim = _measurements(example_manifest)
    kbs = KeyBrokerService({example_manifest.weights_hash: b"KEY"}, now=lambda: NOW)
    challenge = kbs.issue_challenge()
    ev = _evidence(challenge.nonce, quote_b64=None, current=current, rim=rim)

    decision = kbs.verify_and_release(example_manifest, ev)
    assert decision.released
    chk = [c for c in decision.checks if c.name == "cpu_quote_verified"][0]
    assert chk.passed and "structural trust only" in (chk.detail or "")


# -- channel binding (SPEC 3.2, CVE-2026-33697 relay defense) ------------------


def _report_body_cb(nonce_hex: str, channel_binding: bytes, offset: int = 0) -> bytes:
    digest = hashlib.sha256(bytes.fromhex(nonce_hex) + channel_binding).digest()
    return bytes(offset) + digest + bytes(32) + b"measurement-and-tcb-fields"


def test_verifier_binds_transport_key_into_report_data():
    pki = Pki()
    _, enclave_pub = generate_transport_keypair()
    cb = bytes.fromhex(enclave_pub)
    q = _container(pki, _report_body_cb(NONCE, cb))
    v = _verifier(pki)
    # The transport key the quote was built over verifies.
    assert v.verify(q, expected_nonce=NONCE, channel_binding=cb, now=NOW).verified
    # A relay swapping in a different transport key no longer matches REPORT_DATA.
    _, attacker_pub = generate_transport_keypair()
    r = v.verify(q, expected_nonce=NONCE, channel_binding=bytes.fromhex(attacker_pub), now=NOW)
    assert not r.verified and "relay" in (r.reason or "")


KEY32 = b"the-weight-decryption-key-32byte"


def test_relayed_release_is_denied_and_yields_only_ciphertext(example_manifest):
    """Core CVE-2026-33697 fix.

    A valid quote binds the enclave's transport key into REPORT_DATA under the
    nonce. On the legitimate path the KBS seals the key to that transport key, so
    even the released material is useless to a relay. And a relay that swaps in
    its own transport key to divert the seal breaks the REPORT_DATA binding, so
    verification fails and nothing is released.
    """
    pki = Pki()
    current, rim = _measurements(example_manifest)
    kbs = KeyBrokerService(
        {example_manifest.weights_hash: KEY32},
        now=lambda: NOW,
        cpu_quote_verifier=_verifier(pki),
        require_channel_binding=True,
    )

    # Legitimate enclave: transport key bound into REPORT_DATA under the nonce.
    enclave_priv, enclave_pub = generate_transport_keypair()
    attacker_priv, attacker_pub = generate_transport_keypair()
    cb = bytes.fromhex(enclave_pub)

    challenge = kbs.issue_challenge()
    q = _container(pki, _report_body_cb(challenge.nonce, cb))
    ev = _evidence(challenge.nonce, quote_b64=q, current=current, rim=rim)
    ev.cpu.transport_public_key = enclave_pub

    decision = kbs.verify_and_release(example_manifest, ev)
    assert decision.released
    # No raw key ever crosses the channel; only the enclave transport key opens it.
    assert decision.key is None and decision.sealed_key is not None
    assert open_sealed(decision.sealed_key, enclave_priv) == KEY32
    # A relay observing the sealed release cannot open it with its own key.
    with pytest.raises(SealError):
        open_sealed(decision.sealed_key, attacker_priv)

    # Relay/diversion: present the enclave's quote (bound to enclave_pub) but claim
    # the attacker's transport key so the seal would land on the attacker channel.
    # The bound REPORT_DATA no longer matches, so the quote fails verification.
    challenge2 = kbs.issue_challenge()
    q2 = _container(pki, _report_body_cb(challenge2.nonce, cb))  # still the enclave binding
    relayed = _evidence(challenge2.nonce, quote_b64=q2, current=current, rim=rim)
    relayed.cpu.transport_public_key = attacker_pub  # diverted target
    d2 = kbs.verify_and_release(example_manifest, relayed)
    assert not d2.released
    assert any(c.name == "cpu_quote_verified" and not c.passed for c in d2.checks)


# -- memory-fingerprint binding (SPEC 3.6, issue #79) -------------------------


def _hostile(example_manifest):
    """The example manifest in the posture that requires the sweep."""
    data = example_manifest.model_dump(mode="json", exclude_none=True)
    data["release_policy"]["memory_fingerprint_challenge"] = (
        "required-for-hostile-owner-posture"
    )
    data["release_policy"]["physical_hardening"] = (
        "tamper-evident-enclosure+access-control+chain-of-custody"
    )
    return WeightCustodyManifest.model_validate(data)


def _swept_evidence(kbs, manifest, nonce, *, quote_b64):
    """Evidence carrying a real sweep over a real 1 MiB region."""
    from wcm.attestation import DeclaredMemoryRange, MemoryFingerprint
    from wcm.memory_sweep import ProtectedRange, fingerprint_commitment, run_sweep

    current, rim = _measurements(manifest)
    declared = ProtectedRange(base_address=0x4000_0000, size_bytes=1 << 20, probe_count=64)
    result = run_sweep(nonce, declared)
    ev = _evidence(nonce, quote_b64=quote_b64, current=current, rim=rim)
    ev.memory_fingerprint = MemoryFingerprint(
        challenge_nonce=nonce,
        aliasing_detected=result.aliasing_detected,
        readback_hash=result.readback_hash,
        declared_range=DeclaredMemoryRange(**declared.as_dict()),
        commitment=fingerprint_commitment(
            nonce, declared, result.readback_hash, result.aliasing_detected
        ).hex(),
    )
    return ev, fingerprint_commitment(
        nonce, declared, result.readback_hash, result.aliasing_detected
    )


def test_sweep_result_must_be_carried_by_the_quote(example_manifest):
    """The whole weight of the challenge rests here.

    The readback is derived from the nonce and the declared range by a public
    rule, so a host that never touched protected memory computes the same value.
    What separates the two is that the enclave folds the sweep's commitment into
    REPORT_DATA, under a key the host does not have. A quote that covers the
    commitment releases; the identical evidence on a quote that binds the nonce
    alone, which is what a host-authored result rides on, does not.
    """
    pki = Pki()
    manifest = _hostile(example_manifest)
    kbs = KeyBrokerService(
        {manifest.weights_hash: KEY32},
        now=lambda: NOW,
        cpu_quote_verifier=_verifier(pki),
        require_memory_fingerprint_binding=True,
    )

    challenge = kbs.issue_challenge()
    ev, commitment = _swept_evidence(kbs, manifest, challenge.nonce, quote_b64=None)
    ev.cpu.quote_b64 = _container(pki, _report_body_cb(challenge.nonce, commitment))
    decision = kbs.verify_and_release(manifest, ev)
    assert decision.released, [c for c in decision.checks if not c.passed]

    # Same sweep, same fields, on a quote that vouches for the nonce only.
    challenge2 = kbs.issue_challenge()
    ev2, _ = _swept_evidence(kbs, manifest, challenge2.nonce, quote_b64=None)
    ev2.cpu.quote_b64 = _container(pki, _report_body(challenge2.nonce))
    decision2 = kbs.verify_and_release(manifest, ev2)
    assert not decision2.released
    quote_check = [c for c in decision2.checks if c.name == "cpu_quote_verified"][0]
    assert not quote_check.passed
    assert "memory-fingerprint commitment" in (quote_check.detail or "")


def test_a_commitment_from_another_attempt_does_not_transfer(example_manifest):
    """A commitment is per-attempt: it binds the nonce, so one lifted from an
    earlier release does not verify against this quote or this challenge."""
    pki = Pki()
    manifest = _hostile(example_manifest)
    kbs = KeyBrokerService(
        {manifest.weights_hash: KEY32},
        now=lambda: NOW,
        cpu_quote_verifier=_verifier(pki),
        require_memory_fingerprint_binding=True,
    )

    first = kbs.issue_challenge()
    _, stale_commitment = _swept_evidence(kbs, manifest, first.nonce, quote_b64=None)

    second = kbs.issue_challenge()
    ev, _ = _swept_evidence(kbs, manifest, second.nonce, quote_b64=None)
    ev.memory_fingerprint.commitment = stale_commitment.hex()
    ev.cpu.quote_b64 = _container(pki, _report_body_cb(second.nonce, stale_commitment))

    decision = kbs.verify_and_release(manifest, ev)
    assert not decision.released
    mf = [c for c in decision.checks if c.name == "memory_fingerprint"][0]
    assert not mf.passed and "commitment does not match" in (mf.detail or "")
