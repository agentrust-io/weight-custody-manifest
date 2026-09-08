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
from wcm.renewal import manifest_identity
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
        trusted_manifest_identities={manifest_identity(example_manifest)},
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
        trusted_manifest_identities={manifest_identity(example_manifest)},
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
        trusted_manifest_identities={manifest_identity(example_manifest)},
    )
    challenge = kbs.issue_challenge()
    ev = _evidence(challenge.nonce, quote_b64=None, current=current, rim=rim)

    decision = kbs.verify_and_release(example_manifest, ev)
    assert not decision.released
    assert any(c.name == "cpu_quote_verified" and not c.passed for c in decision.checks)


def test_kbs_without_verifier_notes_structural_only(example_manifest):
    current, rim = _measurements(example_manifest)
    kbs = KeyBrokerService(
        {example_manifest.weights_hash: b"KEY"},
        now=lambda: NOW,
        trusted_manifest_identities={manifest_identity(example_manifest)},
    )
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
        trusted_manifest_identities={manifest_identity(example_manifest)},
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


@pytest.mark.parametrize("profile", ["ecdsa-sha256", "ecdsa-p384-sha384",
                                     "rsa-pss-sha256", "rsa-pkcs1-sha256", "ed25519"])
def test_report_profiles_are_parser_configuration(profile):
    from cryptography.hazmat.primitives.asymmetric import rsa, padding, ed25519
    pki = Pki()
    if profile.startswith("rsa"):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    elif profile == "ed25519":
        key = ed25519.Ed25519PrivateKey.generate()
    else:
        key = ec.generate_private_key(ec.SECP384R1() if "p384" in profile else ec.SECP256R1())
    pki.leaf = _cert("report-key", "wcm-test-inter", key, pki.inter_key)
    body = _report_body(NONCE)
    if profile == "rsa-pss-sha256":
        signature = key.sign(body, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32), hashes.SHA256())
    elif profile == "rsa-pkcs1-sha256":
        signature = key.sign(body, padding.PKCS1v15(), hashes.SHA256())
    elif profile == "ed25519":
        signature = key.sign(body)
    else:
        signature = key.sign(body, ec.ECDSA(hashes.SHA384() if "p384" in profile else hashes.SHA256()))
    doc = {"report_b64": base64.b64encode(body).decode(),
           "signature_b64": base64.b64encode(signature).decode(),
           "leaf_pem": _pem(pki.leaf), "intermediates_pem": [_pem(pki.inter)],
           "report_signature_algorithm": "attacker-selected-profile"}
    parser = JsonQuoteParser(report_signature_algorithm=profile)
    verifier = QuoteVerifier(parser, _trust(pki))
    encode = lambda: base64.b64encode(json.dumps(doc).encode()).decode()
    assert verifier.verify(encode(), expected_nonce=NONCE, now=NOW).verified
    doc["signature_b64"] = base64.b64encode(bytes(len(signature))).decode()
    result = verifier.verify(encode(), expected_nonce=NONCE, now=NOW)
    assert not result.verified and "signature" in result.reason


def test_unsupported_report_profile_returns_denial():
    pki = Pki()
    verifier = QuoteVerifier(JsonQuoteParser(report_signature_algorithm="unsupported"), _trust(pki))
    result = verifier.verify(_container(pki, _report_body(NONCE)), expected_nonce=NONCE, now=NOW)
    assert not result.verified and "signature" in result.reason


def test_snp_profile_rejects_non_p384_key():
    pki = Pki()
    verifier = QuoteVerifier(JsonQuoteParser(report_signature_algorithm="ecdsa-p384-sha384"), _trust(pki))
    result = verifier.verify(_container(pki, _report_body(NONCE)), expected_nonce=NONCE, now=NOW)
    assert not result.verified and "signature" in result.reason
