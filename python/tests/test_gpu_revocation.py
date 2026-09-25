"""Live, nonce-bound OCSP for the GPU attestation chain.

The answers replayed here are genuine. They were obtained from NVIDIA's public
responder for the device chain committed in ``gpu_h100_attestation.json``, using
``tools/capture_gpu_ocsp.py``, and they are replayed against a pinned ``now``
because each one carries a ``nextUpdate`` a day after it was minted.

No GPU is involved in any of this. The responder is a public endpoint and the
chain is a fixture.
"""
from __future__ import annotations

import itertools
import json
import pathlib
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.x509 import ocsp
from cryptography.x509.oid import ExtendedKeyUsageOID

from wcm.gpu_revocation import (
    DEFAULT_MAX_AGE_SECONDS,
    GpuRevocationUnavailable,
    NvidiaOcspClient,
    RESPONDER,
    chain_from_evidence,
    check_chain,
    responder_for,
    verify_answer,
)

FIXTURES = pathlib.Path(__file__).parent / "fixtures"
OCSP_DIR = FIXTURES / "nvidia" / "ocsp"
MANIFEST = json.loads((OCSP_DIR / "manifest.json").read_text(encoding="utf-8"))

#: Inside every captured answer's validity. Read from the capture rather than
#: hard-coded, so refreshing the fixtures does not silently invalidate the tests.
WHEN = datetime.fromisoformat(MANIFEST["captured_at"]) + timedelta(minutes=1)

#: Which captured file answers which link, in chain order after the leaf.
ASKED = ("brom", "provisioner_ica", "identity_ca")


def chain() -> list[x509.Certificate]:
    document = json.loads((FIXTURES / "gpu_h100_attestation.json").read_text(encoding="utf-8"))
    return list(x509.load_pem_x509_certificates(document["cert_chain_pem"].encode()))


def answer_bytes(label: str, *, nonce: bool = True) -> bytes:
    return (OCSP_DIR / f"{label}_{'nonce' if nonce else 'nononce'}.der").read_bytes()


def nonce_of(label: str) -> bytes:
    """The nonce NVIDIA echoed, taken from the answer it was echoed in."""
    response = ocsp.load_der_ocsp_response(answer_bytes(label))
    from cryptography.x509.oid import OCSPExtensionOID

    return response.extensions.get_extension_for_oid(OCSPExtensionOID.NONCE).value.nonce


def replay(*, nonce: bool = True, order: tuple[str, ...] = ASKED):
    """A transport that hands back the captured answers in chain order."""
    answers = iter([answer_bytes(label, nonce=nonce) for label in order])

    def post(url: str, body: bytes) -> bytes:
        return next(answers)

    return post


def held_key(links, index: int):
    """The cache key for one link: its CertID under its own issuer.

    Tests used to index the cache by serial number. The client no longer does,
    because a serial is unique per issuer and not globally, so tests must ask
    for the same triple the client stores under.
    """
    from wcm.gpu_revocation import _held_key

    return _held_key(links[index], links[index + 1])


def client_for(order: tuple[str, ...] = ASKED, **kwargs) -> NvidiaOcspClient:
    """A client whose nonces are the ones the captured answers echo.

    Cycled rather than exhausted: a nonce is minted before the request is sent,
    so a later pass that fails at the transport still asks for one.
    """
    nonces = itertools.cycle([nonce_of(label) for label in order])
    return NvidiaOcspClient(post=replay(order=order), nonce=lambda: next(nonces), **kwargs)


# ---- what NVIDIA actually answers ----------------------------------------

def test_the_captured_answers_are_what_the_issue_reported():
    """Leaf UNAUTHORIZED, every other link GOOD. The premise of the change."""
    by_label = {}
    for entry in MANIFEST["answers"]:
        if entry["nonce_sent"]:
            by_label[entry["label"]] = entry
    assert by_label["fmc_leaf"]["response_status"] == "UNAUTHORIZED"
    for label in ASKED:
        assert by_label[label]["certificate_status"] == "GOOD", label
        assert by_label[label]["next_update"] is not None


def test_every_good_answer_came_from_a_delegated_responder():
    for entry in MANIFEST["answers"]:
        if entry.get("certificate_status") == "GOOD":
            assert "OCSP Responder" in (entry["responder_common_name"] or "")


def test_a_healthy_chain_passes_and_reports_what_it_rested_on():
    result = check_chain(chain(), client_for(), WHEN)
    assert result.passed is True, result.detail
    assert result.detail.count("GOOD") == 3
    assert result.not_after is not None and result.not_after > WHEN


def test_the_verdict_never_claims_the_signing_leaf_was_checked():
    """The limit, preserved in the words the caller actually sees.

    NVIDIA is not authoritative for the leaf. A GOOD for BROM establishes that
    the chip is not revoked, which is a different statement from having checked
    the certificate that signs the report.
    """
    detail = check_chain(chain(), client_for(), WHEN).detail
    assert "leaf not established" in detail
    assert "says nothing about the signing certificate itself" in detail
    assert "covered by" not in detail


# ---- the rules ------------------------------------------------------------

def test_an_answer_with_no_nonce_is_refused():
    """NVIDIA answers a request that carries no nonce, so tolerating a missing
    echo would accept a replay. The captured no-nonce answers are genuine and
    signed, and they are still refused."""
    nonces = iter([nonce_of(label) for label in ASKED])
    client = NvidiaOcspClient(post=replay(nonce=False), nonce=lambda: next(nonces))
    result = check_chain(chain(), client, WHEN)
    assert result.passed is False
    assert "did not echo the nonce" in result.detail


def test_an_answer_echoing_someone_elses_nonce_is_refused():
    client = NvidiaOcspClient(post=replay(), nonce=lambda: bytes(32))
    result = check_chain(chain(), client, WHEN)
    assert result.passed is False
    assert "echoed a different nonce" in result.detail


def test_a_genuine_answer_about_a_different_certificate_is_refused():
    """The CertID rule, with two real answers about two different links.

    Both of these are signed by NVIDIA and both say GOOD. Swapping one for the
    other has to be caught by comparing the CertID, because the signature and
    the status are both perfectly valid.
    """
    links = chain()
    response = ocsp.load_der_ocsp_response(answer_bytes("identity_ca"))
    with pytest.raises(GpuRevocationUnavailable, match="different certificate"):
        # An answer about the Identity CA, offered as though it were about BROM.
        verify_answer(response, links[1], links[2], nonce_of("identity_ca"))


def test_the_certid_rule_holds_when_the_nonce_is_the_victims_own():
    """The nonce ties an answer to a request, not to a certificate.

    This is the case the nonce cannot catch on its own: the answer echoes the
    nonce that was sent, and is still about the wrong certificate.
    """
    links = chain()
    response = ocsp.load_der_ocsp_response(answer_bytes("provisioner_ica"))
    echoed = nonce_of("provisioner_ica")
    # Same nonce the request carried, so rule 2 is satisfied and rule 3 is not.
    with pytest.raises(GpuRevocationUnavailable, match="different certificate"):
        verify_answer(response, links[1], links[2], echoed)


def test_an_unauthorized_answer_for_an_asked_link_is_a_refusal():
    """Otherwise a responder that stopped answering would read as a pass."""
    def post(url: str, body: bytes) -> bytes:
        return answer_bytes("fmc_leaf")

    client = NvidiaOcspClient(post=post, nonce=lambda: bytes(32))
    result = check_chain(chain(), client, WHEN)
    assert result.passed is False
    assert "would not answer for a link it must vouch for" in result.detail


def test_an_unreachable_responder_with_nothing_held_is_a_refusal():
    """Even where reuse is allowed, there has to be something to reuse."""
    def post(url: str, body: bytes) -> bytes:
        raise OSError("no route to host")

    client = NvidiaOcspClient(post=post, nonce=lambda: bytes(32))
    result = check_chain(chain(), client, WHEN, allow_reuse=True)
    assert result.passed is False
    assert "could not be reached" in result.detail
    assert "no earlier answer" in result.detail


def test_an_answer_already_past_its_next_update_is_a_refusal():
    client = client_for()
    later = WHEN + timedelta(days=2)
    result = check_chain(chain(), client, later)
    assert result.passed is False
    assert "past its own nextUpdate" in result.detail


def test_a_short_outage_is_ridden_out_on_what_was_verified_before():
    """A renewal inside a window already granted. A first release cannot."""
    client = client_for()
    assert check_chain(chain(), client, WHEN, allow_reuse=True).passed is True

    def offline(url: str, body: bytes) -> bytes:
        raise OSError("responder down")

    client._post = offline  # noqa: SLF001
    result = check_chain(chain(), client, WHEN + timedelta(seconds=30), allow_reuse=True)
    assert result.passed is True, result.detail
    assert "reused 30s after it was obtained" in result.detail


def test_a_long_outage_is_not():
    client = client_for()
    assert check_chain(chain(), client, WHEN, allow_reuse=True).passed is True

    def offline(url: str, body: bytes) -> bytes:
        raise OSError("responder down")

    client._post = offline  # noqa: SLF001
    late = WHEN + timedelta(seconds=DEFAULT_MAX_AGE_SECONDS + 60)
    result = check_chain(chain(), client, late, allow_reuse=True)
    assert result.passed is False
    assert "short window" in result.detail


def test_reuse_does_not_move_the_bound_the_original_answer_carried():
    """Reuse must not restart the clock, so the deadline cannot move outwards.

    It may move inwards. A reused answer is bounded by the short window as well
    as by nextUpdate, so the second result is normally the tighter of the two.
    What must never happen is the second buying time the first did not have.
    """
    client = client_for()
    first = check_chain(chain(), client, WHEN, allow_reuse=True)

    def offline(url: str, body: bytes) -> bytes:
        raise OSError("responder down")

    client._post = offline  # noqa: SLF001
    later = check_chain(chain(), client, WHEN + timedelta(seconds=60), allow_reuse=True)
    assert later.passed is True
    assert later.not_after is not None and first.not_after is not None
    assert later.not_after <= first.not_after


def test_a_verified_revocation_replaces_a_held_good_at_once():
    """Rule 7, and the reason the held answer is not simply a cache.

    A GOOD is verified and held. NVIDIA then reports the same certificate
    REVOKED. From that moment the held answer is the revocation, so an outage
    afterwards cannot serve the earlier GOOD.
    """
    client = client_for()
    links = chain()
    key = held_key(links, 1)
    assert check_chain(links, client, WHEN, allow_reuse=True).passed is True
    assert client._held[key][0] == "GOOD"  # noqa: SLF001

    # Stand in for NVIDIA answering REVOKED, which is what status() would store.
    client._held[key] = ("REVOKED", WHEN, WHEN + timedelta(hours=24))  # noqa: SLF001

    def offline(url: str, body: bytes) -> bytes:
        raise OSError("responder down")

    client._post = offline  # noqa: SLF001
    answer = client._reuse(  # noqa: SLF001
        links[1], links[2], WHEN + timedelta(seconds=30), OSError("down")
    )
    assert answer.status == "REVOKED"
    result = check_chain(links, client, WHEN + timedelta(seconds=30), allow_reuse=True)
    assert result.passed is False
    assert "REVOKED" in result.detail


def test_a_chain_too_short_to_check_is_a_refusal():
    result = check_chain(chain()[:2], client_for(), WHEN)
    assert result.passed is False
    assert "too short" in result.detail


# ---- responder selection ---------------------------------------------------

def test_a_certificate_with_no_ocsp_url_falls_back_to_nvidias_responder():
    """BROM names no OCSP pointer and the responder answers for it anyway."""
    assert responder_for(chain()[1]) == RESPONDER


def test_the_intermediates_name_their_own_responder():
    assert responder_for(chain()[2]).startswith("http")


def test_https_is_preferred_where_a_certificate_offers_both():
    from cryptography.x509.oid import AuthorityInformationAccessOID as AIA

    class FakeAccess:
        def __init__(self, value):
            self.access_method = AIA.OCSP
            self.access_location = type("L", (), {"value": value})()

    class FakeExtensions:
        def get_extension_for_oid(self, oid):
            return type("E", (), {"value": [FakeAccess("http://a.example"),
                                            FakeAccess("https://b.example")]})()

    fake = type("C", (), {"extensions": FakeExtensions()})()
    assert responder_for(fake) == "https://b.example"


def test_the_chain_can_be_read_back_out_of_gpu_evidence():
    import base64

    document = json.loads((FIXTURES / "gpu_h100_attestation.json").read_text(encoding="utf-8"))
    evidence_b64 = base64.b64encode(json.dumps(document).encode()).decode()
    assert len(chain_from_evidence(evidence_b64)) == len(chain())


# ---- the two rules the captured answers cannot exercise --------------------
#
# NVIDIA's own responder is correctly configured, so a badly delegated signer
# and an answer served past its own nextUpdate have to be constructed.

def _synthetic_responder(*, ocsp_signing: bool):
    """A tiny PKI: an issuer, a subject it signed, and a responder it delegated."""
    from cryptography.hazmat.primitives import hashes as _h
    from cryptography.hazmat.primitives.asymmetric import ec as _ec

    def key():
        return _ec.generate_private_key(_ec.SECP384R1())

    def cert(subject_name, signer_key, issuer_name, public_key, extensions=()):
        builder = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, subject_name)]))
            .issuer_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, issuer_name)]))
            .public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime(2026, 1, 1, tzinfo=timezone.utc))
            .not_valid_after(datetime(2030, 1, 1, tzinfo=timezone.utc))
        )
        for extension, critical in extensions:
            builder = builder.add_extension(extension, critical)
        return builder.sign(signer_key, _h.SHA384())

    issuer_key, subject_key, responder_key = key(), key(), key()
    issuer = cert("Synthetic Issuer", issuer_key, "Synthetic Issuer", issuer_key.public_key())
    subject = cert("Synthetic Device", issuer_key, "Synthetic Issuer", subject_key.public_key())
    usages = [x509.ExtendedKeyUsage([ExtendedKeyUsageOID.OCSP_SIGNING])] if ocsp_signing else [
        x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH])
    ]
    responder = cert("Synthetic Responder", issuer_key, "Synthetic Issuer",
                     responder_key.public_key(), [(usages[0], False)])
    return issuer, subject, responder, responder_key


def _synthetic_answer(issuer, subject, responder, responder_key, nonce, *,
                      this_update, next_update):
    from cryptography.hazmat.primitives import hashes as _h

    builder = (
        ocsp.OCSPResponseBuilder()
        .add_response(
            cert=subject, issuer=issuer, algorithm=_h.SHA384(),
            cert_status=ocsp.OCSPCertStatus.GOOD,
            this_update=this_update, next_update=next_update,
            revocation_time=None, revocation_reason=None,
        )
        .responder_id(ocsp.OCSPResponderEncoding.NAME, responder)
        .certificates([responder])
        .add_extension(x509.OCSPNonce(nonce), critical=False)
    )
    return builder.sign(responder_key, _h.SHA384())


def test_a_responder_without_the_ocsp_signing_usage_is_refused():
    """Rule 4. A certificate the issuer signed is not automatically allowed to
    answer on its behalf; the delegation has to be explicit."""
    issuer, subject, responder, responder_key = _synthetic_responder(ocsp_signing=False)
    nonce = bytes(range(32))
    answer = _synthetic_answer(issuer, subject, responder, responder_key, nonce,
                               this_update=WHEN.replace(tzinfo=None),
                               next_update=(WHEN + timedelta(hours=24)).replace(tzinfo=None))
    with pytest.raises(GpuRevocationUnavailable, match="not authorised to sign OCSP"):
        verify_answer(answer, subject, issuer, nonce)


def test_a_properly_delegated_responder_is_accepted():
    """The same construction with the usage present, so the refusal above is
    about the delegation and not about the synthetic PKI."""
    issuer, subject, responder, responder_key = _synthetic_responder(ocsp_signing=True)
    nonce = bytes(range(32))
    answer = _synthetic_answer(issuer, subject, responder, responder_key, nonce,
                               this_update=WHEN.replace(tzinfo=None),
                               next_update=(WHEN + timedelta(hours=24)).replace(tzinfo=None))
    verify_answer(answer, subject, issuer, nonce)


def test_a_held_answer_past_its_next_update_is_refused_inside_the_short_window():
    """Both bounds on reuse apply, not whichever is looser.

    The held answer is two minutes old, well inside the ten minute window, and
    already past the nextUpdate it carried. That is still a refusal.
    """
    links = chain()
    client = client_for()
    client._held[held_key(links, 1)] = (  # noqa: SLF001
        "GOOD", WHEN, WHEN + timedelta(seconds=60),
    )

    def offline(url: str, body: bytes) -> bytes:
        raise OSError("responder down")

    client._post = offline  # noqa: SLF001
    with pytest.raises(GpuRevocationUnavailable, match="past its own nextUpdate"):
        client._reuse(  # noqa: SLF001
            links[1], links[2], WHEN + timedelta(seconds=120), OSError("down")
        )


def test_an_answer_whose_signature_does_not_verify_is_refused():
    """A genuine NVIDIA answer with one byte of its signature flipped.

    Everything else about it is untouched: the CertID still names the right
    certificate, the nonce still echoes, and the delegated responder is still
    the one NVIDIA issued. Only the signature is wrong.
    """
    links = chain()
    raw = bytearray(answer_bytes("brom"))
    signature = ocsp.load_der_ocsp_response(bytes(raw)).signature
    at = bytes(raw).find(signature)
    assert at > 0, "could not locate the signature inside the answer"
    raw[at] ^= 0x01
    tampered = ocsp.load_der_ocsp_response(bytes(raw))
    assert tampered.signature != signature
    with pytest.raises(GpuRevocationUnavailable, match="signature does not verify"):
        verify_answer(tampered, links[1], links[2], nonce_of("brom"))


# ---- a first release may not lean on an earlier answer --------------------

def test_a_first_release_has_nothing_to_fall_back_to():
    """Reuse exists to ride out an outage inside a window already granted.

    Starting a new one is a different act. Even with a verified answer held
    from an earlier release, a first release with the responder down is
    refused, because there is no window here to protect.
    """
    client = client_for()
    assert check_chain(chain(), client, WHEN, allow_reuse=True).passed is True

    def offline(url: str, body: bytes) -> bytes:
        raise OSError("responder down")

    client._post = offline  # noqa: SLF001
    soon = WHEN + timedelta(seconds=30)
    assert check_chain(chain(), client, soon, allow_reuse=True).passed is True
    refused = check_chain(chain(), client, soon)
    assert refused.passed is False
    assert "a first release may not rest on an earlier answer" in refused.detail


def test_reuse_is_off_unless_the_caller_asks_for_it():
    """The default is the strict one, so a caller that forgets is not looser."""
    links = chain()
    client = client_for()
    client._held[held_key(links, 1)] = (  # noqa: SLF001
        "GOOD", WHEN, WHEN + timedelta(hours=24),
    )

    def offline(url: str, body: bytes) -> bytes:
        raise OSError("responder down")

    client._post = offline  # noqa: SLF001
    with pytest.raises(GpuRevocationUnavailable, match="first release"):
        client.status(links[1], links[2], WHEN + timedelta(seconds=30))
    answer = client.status(links[1], links[2], WHEN + timedelta(seconds=30), allow_reuse=True)
    assert answer.status == "GOOD" and answer.source.startswith("reused")


# ---- the cache key ---------------------------------------------------------

def _same_serial_under_two_issuers():
    """Two certificates sharing a serial number, signed by different issuers.

    Serial numbers are unique per issuer, not globally, so this is a legitimate
    pair rather than a forgery. Two independent CAs can each issue serial 1.
    """
    from cryptography.hazmat.primitives import hashes as _h
    from cryptography.hazmat.primitives.asymmetric import ec as _ec

    shared_serial = 0x5EC0DE

    def key():
        return _ec.generate_private_key(_ec.SECP384R1())

    def cert(name, signer_key, issuer_name, public_key, serial):
        return (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, name)]))
            .issuer_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, issuer_name)]))
            .public_key(public_key)
            .serial_number(serial)
            .not_valid_before(datetime(2026, 1, 1, tzinfo=timezone.utc))
            .not_valid_after(datetime(2030, 1, 1, tzinfo=timezone.utc))
            .sign(signer_key, _h.SHA384())
        )

    pairs = []
    for label in ("One", "Two"):
        issuer_key, subject_key = key(), key()
        issuer_name = f"Synthetic Issuer {label}"
        issuer = cert(issuer_name, issuer_key, issuer_name, issuer_key.public_key(),
                      x509.random_serial_number())
        subject = cert(f"Device under {label}", issuer_key, issuer_name,
                       subject_key.public_key(), shared_serial)
        pairs.append((subject, issuer))
    return pairs


def test_a_held_answer_is_not_served_for_a_different_issuers_certificate():
    """The cache is keyed on the CertID, not on the serial number alone.

    Keyed on the serial only, an outage served one issuer's held GOOD for a
    different issuer's certificate carrying the same serial. That is the same
    triple RFC 6960 makes a response's CertID match, so the key and the check
    agree on what identifies a certificate.
    """
    from wcm.gpu_revocation import _held_key

    (first, first_issuer), (second, second_issuer) = _same_serial_under_two_issuers()
    assert first.serial_number == second.serial_number, "the premise of this test"

    client = client_for()
    client._held[_held_key(first, first_issuer)] = (  # noqa: SLF001
        "GOOD", WHEN, WHEN + timedelta(hours=24),
    )

    def offline(url: str, body: bytes) -> bytes:
        raise OSError("responder down")

    client._post = offline  # noqa: SLF001

    # The first certificate has an answer and may ride out the outage.
    assert client.status(
        first, first_issuer, WHEN + timedelta(seconds=30), allow_reuse=True
    ).status == "GOOD"

    # The second shares its serial and nothing else. It must not inherit it.
    with pytest.raises(GpuRevocationUnavailable) as raised:
        client.status(
            second, second_issuer, WHEN + timedelta(seconds=30), allow_reuse=True
        )
    assert "no earlier answer about this certificate is held" in str(raised.value)


def test_a_reused_answer_is_bounded_by_the_short_window_not_only_next_update():
    """Both limits apply, and the short window is normally the tighter one.

    NVIDIA's nextUpdate is a day out. Returning only that let a renewal taken
    near the end of a short window carry custody to the next day, because the
    caller clamps on what this returns.
    """
    from wcm.gpu_revocation import _held_key

    links = chain()
    client = client_for(max_age_seconds=900)
    obtained = WHEN
    client._held[_held_key(links[1], links[2])] = (  # noqa: SLF001
        "GOOD", obtained, obtained + timedelta(hours=24),
    )

    def offline(url: str, body: bytes) -> bytes:
        raise OSError("responder down")

    client._post = offline  # noqa: SLF001
    answer = client.status(
        links[1], links[2], obtained + timedelta(minutes=14), allow_reuse=True
    )

    assert answer.status == "GOOD"
    assert answer.not_after == obtained + timedelta(seconds=900), (
        f"bounded at {answer.not_after}, expected the short window"
    )
