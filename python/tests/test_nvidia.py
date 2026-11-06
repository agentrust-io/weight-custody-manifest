"""NVIDIA CC GPU-report verification.

Primary validation: a REAL H100 NVL confidential-compute attestation captured on
live silicon (`fixtures/gpu_h100_attestation.json`, cross-checked with NVIDIA's
own local verifier) is verified OFFLINE against the pinned NVIDIA Device Identity
CA root (`fixtures/nvidia_device_identity_ca.pem`): cert chain + ECDSA-P384/SHA384
report signature + raw-nonce-at-offset-4 binding.

The KBS-integration and nonce-binding tests use a synthetic NVIDIA-format report
(same layout: 4-byte header, raw nonce at offset 4, ECDSA-P384 raw r||s over
report[:-96]) so they can bind an arbitrary KBS challenge nonce; the real report
is fixed to its captured nonce.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import pathlib
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.x509.oid import NameOID
from tests.conftest import waive
from wcm.renewal import manifest_identity

from wcm import (
    CompositeEvidence,
    CpuQuote,
    GpuReport,
    KeyBrokerService,
    NvidiaGpuVerifier,
    build_gpu_verifier,
    generate_transport_keypair,
    parse_gpu_report,
)
from wcm.nvidia import GpuReportFormatError, gpu_measurement_from_report, parse_gpu_opaque_fields

FIXTURES = pathlib.Path(__file__).parent / "fixtures"
NOW = datetime(2026, 7, 28, 12, 0, 0, tzinfo=timezone.utc)


def _real_bundle() -> dict:
    return json.loads((FIXTURES / "gpu_h100_attestation.json").read_text())


def _real_root_pem() -> str:
    return (FIXTURES / "nvidia_device_identity_ca.pem").read_text()


def _evidence_b64(report_b64: str, cert_chain_pem: str) -> str:
    doc = {"report_b64": report_b64, "cert_chain_pem": cert_chain_pem}
    return base64.b64encode(json.dumps(doc).encode()).decode()


# -- REAL captured H100 attestation (the point) --------------------------------


def test_real_h100_attestation_verifies_offline():
    b = _real_bundle()
    v = build_gpu_verifier(_real_root_pem())
    result = v.verify(
        _evidence_b64(b["report_b64"], b["cert_chain_pem"]),
        expected_nonce=b["nonce"],
        now=NOW,
    )
    assert result.verified, result.reason
    assert "GSP FMC LF" in (result.leaf_subject or "")


def test_real_h100_raw_nonce_at_offset_4():
    b = _real_bundle()
    report = base64.b64decode(b["report_b64"])
    parsed = parse_gpu_report(report)
    assert parsed.raw_nonce == bytes.fromhex(b["nonce"])
    assert len(parsed.signature) == 96


def test_real_h100_wrong_nonce_fails():
    b = _real_bundle()
    v = build_gpu_verifier(_real_root_pem())
    result = v.verify(
        _evidence_b64(b["report_b64"], b["cert_chain_pem"]),
        expected_nonce="cd" * 32,
        now=NOW,
    )
    assert not result.verified
    assert "nonce" in (result.reason or "").lower()


def test_real_h100_tampered_report_fails_signature():
    b = _real_bundle()
    report = bytearray(base64.b64decode(b["report_b64"]))
    report[100] ^= 0xFF  # flip a byte inside the signed body
    v = build_gpu_verifier(_real_root_pem())
    result = v.verify(
        _evidence_b64(base64.b64encode(bytes(report)).decode(), b["cert_chain_pem"]),
        expected_nonce=b["nonce"],
        now=NOW,
    )
    assert not result.verified
    assert "signature" in (result.reason or "")


def test_real_h100_untrusted_root_fails():
    b = _real_bundle()
    v = build_gpu_verifier(_pem(_Pki().root))  # a stranger root
    result = v.verify(
        _evidence_b64(b["report_b64"], b["cert_chain_pem"]),
        expected_nonce=b["nonce"],
        now=NOW,
    )
    assert not result.verified
    assert "trusted root" in (result.reason or "")


# -- synthetic NVIDIA-format helpers (controllable nonce) ----------------------


def _p384():
    return ec.generate_private_key(ec.SECP384R1())


def _cert(subject, issuer_name, subj_key, issuer_key, *, ca=False, nb=None, na=None):
    b = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_name)]))
        .public_key(subj_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(nb or (NOW - timedelta(days=1)))
        .not_valid_after(na or (NOW + timedelta(days=365)))
    )
    if ca:
        b = b.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    return b.sign(issuer_key, hashes.SHA384())


def _pem(cert) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode()


class _Pki:
    """Synthetic NVIDIA-like device chain (all P-384): root -> inter -> leaf."""

    def __init__(self):
        self.root_key = _p384()
        self.root = _cert("nv-test-root", "nv-test-root", self.root_key, self.root_key, ca=True)
        self.inter_key = _p384()
        self.inter = _cert("nv-test-inter", "nv-test-root", self.inter_key, self.root_key, ca=True)
        self.leaf_key = _p384()
        # The chip prefix matters: the KBS reads the architecture from it.
        self.leaf = _cert("GH100 A01 GSP FMC LF", "nv-test-inter", self.leaf_key, self.inter_key)

    def chain_pem(self) -> str:
        return _pem(self.leaf) + _pem(self.inter) + _pem(self.root)


def _nv_report(nonce_hex: str, leaf_key, measurements: bytes = b"synthetic-gpu-measurements") -> bytes:
    """Build a report in the real NVIDIA layout signed by leaf_key."""
    signed_body = b"\x11\xe0\x01\xff" + bytes.fromhex(nonce_hex) + measurements
    der = leaf_key.sign(signed_body, ec.ECDSA(hashes.SHA384()))
    r, s = decode_dss_signature(der)
    raw = r.to_bytes(48, "big") + s.to_bytes(48, "big")
    return signed_body + raw


SYNTH_DRIVER = "595.71.05"
SYNTH_VBIOS = bytes.fromhex("0088009611000000")  # formats as 96.00.88.00.11
SYNTH_MEASUREMENT = "nvidia-rim:arch=HOPPER;driver=595.71.05;vbios=96.00.88.00.11"


def _opaque(fields) -> bytes:
    return b"".join(
        fid.to_bytes(2, "little") + len(val).to_bytes(2, "little") + val for fid, val in fields
    )


def _spdm_body(driver: str = SYNTH_DRIVER, vbios: bytes = SYNTH_VBIOS, *, fields=None,
               opaque_len_delta: int = 0) -> bytes:
    """SPDM MEASUREMENTS response after the request: header, record, nonce, opaque."""
    if fields is None:
        fields = [(3, driver.encode() + b"\x00"), (6, vbios)]
    opaque = _opaque(fields)
    record = b"\x01\x01\x33\x00" + b"\x01" + b"\x30\x00" + b"\x5a" * 48
    return (
        b"\x11\x60\x00\x00" + b"\x01" + len(record).to_bytes(3, "little") + record
        + b"\xee" * 32  # responder nonce, changes per call on real devices
        + (len(opaque) + opaque_len_delta).to_bytes(2, "little") + opaque
    )


def _spdm_report(nonce_hex: str, leaf_key, **kwargs) -> bytes:
    """Build an SPDM GET_MEASUREMENTS transcript in NVIDIA's layout."""
    return _nv_report(nonce_hex, leaf_key, measurements=b"\x00" + _spdm_body(**kwargs))


def _synth_evidence(pki: _Pki, nonce_hex: str, **kwargs) -> str:
    report = _spdm_report(nonce_hex, pki.leaf_key, **kwargs)
    return _evidence_b64(base64.b64encode(report).decode(), pki.chain_pem())


def _legacy_evidence(pki: _Pki, nonce_hex: str) -> str:
    """A correctly signed report with no SPDM response, so no readable identity."""
    report = _nv_report(nonce_hex, pki.leaf_key)
    return _evidence_b64(base64.b64encode(report).decode(), pki.chain_pem())


def test_synthetic_report_verifies():
    pki = _Pki()
    v = build_gpu_verifier(_pem(pki.root))
    r = v.verify(_synth_evidence(pki, "ab" * 32), expected_nonce="ab" * 32, now=NOW)
    assert r.verified, r.reason


def test_build_gpu_verifier_shape():
    assert isinstance(build_gpu_verifier(_pem(_Pki().root)), NvidiaGpuVerifier)


# -- KBS integration -----------------------------------------------------------


def _evidence(nonce, *, gpu_quote_b64, current, rim):
    return CompositeEvidence(
        cpu=CpuQuote(
            platform="amd-sev-snp",
            assurance_tier="hardware-attested",
            serving_image_measurement=current,
            nonce_echo=nonce,
            attestation_key_id="vcek:test",
            # These cases are about the GPU report; the CPU side carries the
            # transport key the KBS seals to by default.
            transport_public_key=generate_transport_keypair()[1],
        ),
        gpu=GpuReport(
            platform="nvidia-cc-gpu", measurement=rim, cc_mode=True, nonce_echo=nonce,
            quote_b64=gpu_quote_b64,
        ),
    )


def _pin_gpu(m, rim_pin):
    policy = m.release_policy
    gpu = policy.required_gpu_measurement.model_copy(update={"rim_pin": rim_pin})
    return m.model_copy(update={
        "release_policy": policy.model_copy(update={"required_gpu_measurement": gpu})
    })


def _measurements(m):
    ams = m.release_policy.required_serving_image.accepted_measurements
    current = next(x.measurement for x in ams if x.status.value == "current")
    rim = m.release_policy.required_gpu_measurement.rim_pin
    return current, rim


def test_kbs_releases_with_verified_gpu(example_manifest):
    """A verified GPU report meets require_cc_mode on its own (SPEC 3.2 assumption).

    Only CPU verification is waived: the manifest still requires the mode, and
    nothing states it except the report having verified.
    """
    example_manifest = _pin_gpu(waive(example_manifest, cc_mode=False), SYNTH_MEASUREMENT)
    pki = _Pki()
    current, rim = _measurements(example_manifest)
    kbs = KeyBrokerService(
        {example_manifest.weights_hash: b"KEY"},
        now=lambda: NOW,
        gpu_report_verifier=build_gpu_verifier(_pem(pki.root)),
        require_gpu_report_verification=True,
        trusted_manifest_identities={manifest_identity(example_manifest)},
    )
    challenge = kbs.issue_challenge()
    ev = _evidence(challenge.nonce, gpu_quote_b64=_synth_evidence(pki, challenge.nonce), current=current, rim=rim)
    decision = kbs.verify_and_release(example_manifest, ev)
    assert decision.released
    assert any(c.name == "gpu_report_verified" and c.passed for c in decision.checks)
    gpu = [c for c in decision.checks if c.name == "gpu"][0]
    assert "inferred from a verified GPU report" in (gpu.detail or "")


def test_kbs_denies_untrusted_gpu(example_manifest):
    pki = _Pki()
    current, rim = _measurements(example_manifest)
    kbs = KeyBrokerService(
        {example_manifest.weights_hash: b"KEY"},
        now=lambda: NOW,
        gpu_report_verifier=build_gpu_verifier(_pem(_Pki().root)),  # different root
        trusted_manifest_identities={manifest_identity(example_manifest)},
    )
    challenge = kbs.issue_challenge()
    ev = _evidence(challenge.nonce, gpu_quote_b64=_synth_evidence(pki, challenge.nonce), current=current, rim=rim)
    decision = kbs.verify_and_release(example_manifest, ev)
    assert not decision.released
    assert any(c.name == "gpu_report_verified" and not c.passed for c in decision.checks)


def test_kbs_denies_gpu_verifier_set_but_no_quote(example_manifest):
    current, rim = _measurements(example_manifest)
    kbs = KeyBrokerService(
        {example_manifest.weights_hash: b"KEY"},
        now=lambda: NOW,
        gpu_report_verifier=build_gpu_verifier(_pem(_Pki().root)),
        trusted_manifest_identities={manifest_identity(example_manifest)},
    )
    challenge = kbs.issue_challenge()
    ev = _evidence(challenge.nonce, gpu_quote_b64=None, current=current, rim=rim)
    decision = kbs.verify_and_release(example_manifest, ev)
    assert not decision.released
    assert any(c.name == "gpu_report_verified" and not c.passed for c in decision.checks)


def test_kbs_without_gpu_verifier_notes_structural_only(structural_manifest):
    current, rim = _measurements(structural_manifest)
    kbs = KeyBrokerService(
        {structural_manifest.weights_hash: b"KEY"},
        now=lambda: NOW,
        trusted_manifest_identities={manifest_identity(structural_manifest)},
    )
    challenge = kbs.issue_challenge()
    ev = _evidence(challenge.nonce, gpu_quote_b64=None, current=current, rim=rim)
    decision = kbs.verify_and_release(structural_manifest, ev)
    assert decision.released
    chk = [c for c in decision.checks if c.name == "gpu_report_verified"][0]
    assert chk.passed and "structural trust only" in (chk.detail or "")


def test_kbs_gpu_must_bind_this_nonce(example_manifest):
    """A crypto-valid GPU report bound to a different nonce than this challenge
    fails: the raw nonce echoed in the report must equal the KBS challenge."""
    pki = _Pki()
    current, rim = _measurements(example_manifest)
    kbs = KeyBrokerService(
        {example_manifest.weights_hash: b"KEY"},
        now=lambda: NOW,
        gpu_report_verifier=build_gpu_verifier(_pem(pki.root)),
        trusted_manifest_identities={manifest_identity(example_manifest)},
    )
    challenge = kbs.issue_challenge()
    # report bound to a stale nonce, though the structured nonce_echo is set to this challenge
    stale = _synth_evidence(pki, "cd" * 32)
    ev = _evidence(challenge.nonce, gpu_quote_b64=stale, current=current, rim=rim)
    decision = kbs.verify_and_release(example_manifest, ev)
    assert not decision.released
    assert any(c.name == "gpu_report_verified" and not c.passed for c in decision.checks)


def test_non_string_cert_chain_is_a_denial_not_an_exception():
    # cert_chain_pem as a JSON number raised AttributeError out of verify().
    b = _real_bundle()
    evidence = base64.b64encode(
        json.dumps({"report_b64": b["report_b64"], "cert_chain_pem": 1}).encode()
    ).decode()
    result = build_gpu_verifier(_real_root_pem()).verify(
        evidence, expected_nonce=b["nonce"], now=NOW
    )
    assert not result.verified
    assert "unparseable GPU evidence" in (result.reason or "")


# -- GHSA-5mg4-8gw3-3xmm: rim_pin is matched against the signed report ---------

REAL_H100_MEASUREMENT = "nvidia-rim:arch=HOPPER;driver=595.71.05;vbios=96.00.88.00.11"


def test_real_h100_report_states_its_identity():
    """Driver and VBIOS come from the signed SPDM opaque data of the real capture."""
    b = _real_bundle()
    result = build_gpu_verifier(_real_root_pem()).verify(
        _evidence_b64(b["report_b64"], b["cert_chain_pem"]), expected_nonce=b["nonce"], now=NOW
    )
    assert result.verified, result.reason
    assert result.gpu_measurement == REAL_H100_MEASUREMENT


def test_real_h100_opaque_fields_end_at_the_signature():
    report = base64.b64decode(_real_bundle()["report_b64"])
    fields = parse_gpu_opaque_fields(report)
    assert fields[3] == b"595.71.05\x00"
    assert len(fields[6]) == 8


def _gpu_kbs(manifest, pki):
    return KeyBrokerService(
        {manifest.weights_hash: b"KEY"},
        now=lambda: NOW,
        gpu_report_verifier=build_gpu_verifier(_pem(pki.root)),
        require_gpu_report_verification=True,
        trusted_manifest_identities={manifest_identity(manifest)},
    )


def _gpu_check(decision):
    return next(c for c in decision.checks if c.name == "gpu")


def test_caller_measurement_cannot_satisfy_pin_the_report_does_not_state(example_manifest):
    """The advisory's world B: the signed report states another driver, and the
    requester writes the approved pin into gpu.measurement. That used to release."""
    manifest = _pin_gpu(waive(example_manifest, cc_mode=False), SYNTH_MEASUREMENT)
    pki = _Pki()
    current, rim = _measurements(manifest)
    kbs = _gpu_kbs(manifest, pki)
    challenge = kbs.issue_challenge()
    other = _synth_evidence(pki, challenge.nonce, driver="550.00.01")
    decision = kbs.verify_and_release(
        manifest, _evidence(challenge.nonce, gpu_quote_b64=other, current=current, rim=rim)
    )
    assert not decision.released
    assert any(c.name == "gpu_report_verified" and c.passed for c in decision.checks)
    gpu = _gpu_check(decision)
    assert not gpu.passed
    assert gpu.detail == "verified GPU report measurement does not match rim_pin"


def test_caller_measurement_does_not_decide_when_report_matches(example_manifest):
    """The structured claim is not read on the verified path, either way."""
    manifest = _pin_gpu(waive(example_manifest, cc_mode=False), SYNTH_MEASUREMENT)
    pki = _Pki()
    current, _ = _measurements(manifest)
    kbs = _gpu_kbs(manifest, pki)
    challenge = kbs.issue_challenge()
    ev = _evidence(
        challenge.nonce, gpu_quote_b64=_synth_evidence(pki, challenge.nonce),
        current=current, rim="nvidia-rim:whatever-the-caller-wrote",
    )
    decision = kbs.verify_and_release(manifest, ev)
    assert decision.released, decision.failures()


def test_verified_report_without_identity_cannot_match_a_pin(example_manifest):
    manifest = _pin_gpu(waive(example_manifest, cc_mode=False), SYNTH_MEASUREMENT)
    pki = _Pki()
    current, rim = _measurements(manifest)
    kbs = _gpu_kbs(manifest, pki)
    challenge = kbs.issue_challenge()
    ev = _evidence(
        challenge.nonce, gpu_quote_b64=_legacy_evidence(pki, challenge.nonce),
        current=current, rim=rim,
    )
    decision = kbs.verify_and_release(manifest, ev)
    assert not decision.released
    assert any(c.name == "gpu_report_verified" and c.passed for c in decision.checks)
    assert "states no measurement" in (_gpu_check(decision).detail or "")


def test_unknown_chip_states_no_identity():
    pki = _Pki()
    pki.leaf = _cert("GZ999 A01 GSP FMC LF", "nv-test-inter", pki.leaf_key, pki.inter_key)
    result = build_gpu_verifier(_pem(pki.root)).verify(
        _synth_evidence(pki, "ab" * 32), expected_nonce="ab" * 32, now=NOW
    )
    assert result.verified and result.gpu_measurement is None


@pytest.mark.parametrize(
    "kwargs",
    [
        {"opaque_len_delta": -1},  # opaque data stops short of the signature
        {"opaque_len_delta": 1},  # opaque data overruns into the signature
        {"fields": [(3, b"595.71.05\x00"), (6, SYNTH_VBIOS), (3, b"999.99.99\x00")]},
        {"fields": [(3, b"595.71.05\x00")]},  # no VBIOS field
        {"fields": [(3, b"595.71.05;vbios=0\x00"), (6, SYNTH_VBIOS)]},
        {"vbios": b"\x00" * 7},
    ],
)
def test_malformed_identity_is_refused(kwargs):
    report = _spdm_report("ab" * 32, _p384(), **kwargs)
    with pytest.raises(GpuReportFormatError):
        gpu_measurement_from_report(report, _Pki().leaf)


def _nvdaod_report(nonce, key, *, entries=None, header=b"NVDAOD\x00\x00\x02\x00\x00\x00",
                   opaque=None):
    if entries is None:
        entries = [(3, 0x86, b"595.71.05\x00"), (6, 0x86, SYNTH_VBIOS)]
    if opaque is None:
        opaque = header + b"".join(
            fid.to_bytes(2, "little") + value_type.to_bytes(2, "little")
            + len(value).to_bytes(2, "little") + value
            for fid, value_type, value in entries
        )
    # Keep the real SPDM framing and sign all new opaque bytes.
    response = _spdm_body(fields=[])[:-2] + len(opaque).to_bytes(2, "little") + opaque
    return _nv_report(nonce, key, measurements=b"\x00" + response)


@pytest.mark.skipif(not os.environ.get("WCM_NVDAOD_VENDOR_TRANSCRIPT"),
                    reason="optional public NVIDIA structural transcript not supplied")
def test_vendor_nvdaod_vector_is_structural_only():
    """NVIDIA supplies no certificate chain for this sample; do not authenticate it."""
    source = pathlib.Path(os.environ["WCM_NVDAOD_VENDOR_TRANSCRIPT"]).read_bytes()
    assert hashlib.sha256(source).hexdigest() == (
        "346fff240b98f3be7ee50bf5d3ddfd1f7013df77dc5460c7dae3fd1c9634c13b"
    )
    report = bytes.fromhex(source.decode("ascii"))
    fields = parse_gpu_opaque_fields(report)
    assert len(fields) == 17
    assert fields[3] == b"620.12\x00"  # Variable-length vendor sample, not char[16].
    assert fields[6] == bytes.fromhex("00d900960f000000")


@pytest.mark.parametrize("minor,patch", [(0, 0), (1, 0), (0, 1), (255, 255)])
def test_nvdaod_supported_major_keeps_minor_patch_compatibility(minor, patch):
    pki = _Pki()
    header = b"NVDAOD\x00\x00" + bytes([2, minor, patch, 0])
    report = _nvdaod_report("ab" * 32, pki.leaf_key, header=header)
    result = build_gpu_verifier(_pem(pki.root)).verify(
        _evidence_b64(base64.b64encode(report).decode(), pki.chain_pem()),
        expected_nonce="ab" * 32, now=NOW,
    )
    assert result.verified and result.gpu_measurement == SYNTH_MEASUREMENT


def test_nvdaod_retains_unknown_value_type_without_using_it_as_identity():
    from wcm.nvidia import _parse_gpu_opaque_entries

    pki = _Pki()
    report = _nvdaod_report("ab" * 32, pki.leaf_key, entries=[
        (3, 0x86, b"595.71.05\x00"), (6, 0x86, SYNTH_VBIOS), (0x1234, 0xbeef, b"new"),
        (0x22, 0x86, b"\xff\xff"),  # Header major, not this legacy field, is authoritative.
    ])
    assert _parse_gpu_opaque_entries(report)[0x1234].value_type == 0xbeef
    assert parse_gpu_opaque_fields(report)[0x1234] == b"new"
    assert gpu_measurement_from_report(report, pki.leaf) == SYNTH_MEASUREMENT


@pytest.mark.parametrize("opaque", [
    b"NVDAOD", b"NVDAOD\x00\x00\x02\x00\x00",
    b"NVDAOD\x01\x00\x02\x00\x00\x00",
    b"NVDAOD\x00\x00\x03\x00\x00\x00",
    b"NVDAOD\x00\x00\x02\x00\x00\x00\x03\x00\x86\x00\x01",
    b"NVDAOD\x00\x00\x02\x00\x00\x00\x03\x00\x86\x00\xff\xff",
    b"NVDAOD\x00\x00\x02\x00\x00\x00" + b"\x03\x00\x86\x00\x00\x00" * 2,
])
def test_nvdaod_refuses_truncation_profile_future_major_overrun_and_duplicate(opaque):
    pki = _Pki()
    valid = _nvdaod_report("ab" * 32, pki.leaf_key)
    assert gpu_measurement_from_report(valid, pki.leaf) == SYNTH_MEASUREMENT
    with pytest.raises(GpuReportFormatError):
        parse_gpu_opaque_fields(_nvdaod_report("ab" * 32, pki.leaf_key, opaque=opaque))


@pytest.mark.parametrize("entries", [
    [(3, 0x86, b"595.71.05\x00")],
    [(6, 0x86, SYNTH_VBIOS)],
    [(3, 0x06, b"595.71.05\x00"), (6, 0x86, SYNTH_VBIOS)],
    [(3, 0x86, b"595.71.05\x00"), (6, 0x06, SYNTH_VBIOS)],
    [(3, 0x86, b"595.71.05\x00"), (6, 0x86, b"\x00" * 7)],
])
def test_nvdaod_unreadable_identity_still_cannot_satisfy_kbs_pin(example_manifest, entries):
    manifest = _pin_gpu(waive(example_manifest, cc_mode=False), SYNTH_MEASUREMENT)
    pki = _Pki()
    current, rim = _measurements(manifest)
    kbs = _gpu_kbs(manifest, pki)
    challenge = kbs.issue_challenge()
    report = _nvdaod_report(challenge.nonce, pki.leaf_key, entries=entries)
    decision = kbs.verify_and_release(manifest, _evidence(
        challenge.nonce, current=current, rim=rim,
        gpu_quote_b64=_evidence_b64(base64.b64encode(report).decode(), pki.chain_pem()),
    ))
    assert any(c.name == "gpu_report_verified" and c.passed for c in decision.checks)
    assert not decision.released and not _gpu_check(decision).passed


@pytest.mark.parametrize("driver,release", [(b"595.71.05\x00", True), (b"620.12\x00", False)])
def test_nvdaod_kbs_compares_signed_identity_instead_of_caller_claim(example_manifest, driver, release):
    manifest = _pin_gpu(waive(example_manifest, cc_mode=False), SYNTH_MEASUREMENT)
    pki = _Pki()
    current, rim = _measurements(manifest)
    kbs = _gpu_kbs(manifest, pki)
    challenge = kbs.issue_challenge()
    report = _nvdaod_report(challenge.nonce, pki.leaf_key, entries=[
        (3, 0x86, driver), (6, 0x86, SYNTH_VBIOS),
    ])
    decision = kbs.verify_and_release(manifest, _evidence(
        challenge.nonce, current=current, rim=rim,
        gpu_quote_b64=_evidence_b64(base64.b64encode(report).decode(), pki.chain_pem()),
    ))
    assert any(c.name == "gpu_report_verified" and c.passed for c in decision.checks)
    assert decision.released is release


def test_nvdaod_signature_and_nonce_still_precede_identity():
    pki = _Pki()
    verifier = build_gpu_verifier(_pem(pki.root))
    report = _nvdaod_report("ab" * 32, pki.leaf_key)
    evidence = _evidence_b64(base64.b64encode(report).decode(), pki.chain_pem())
    assert verifier.verify(evidence, expected_nonce="ab" * 32, now=NOW).gpu_measurement
    assert not verifier.verify(evidence, expected_nonce="cd" * 32, now=NOW).verified
    changed = report[:-1] + bytes([report[-1] ^ 1])
    assert not verifier.verify(
        _evidence_b64(base64.b64encode(changed).decode(), pki.chain_pem()),
        expected_nonce="ab" * 32, now=NOW,
    ).verified


@pytest.mark.parametrize("version", [b"\x03\x00", b"\x01", b"\x01\x00\x00"])
def test_legacy_explicit_unsupported_version_is_refused(version):
    report = _spdm_report("ab" * 32, _p384(), fields=[
        (3, b"595.71.05\x00"), (6, SYNTH_VBIOS), (0x22, version),
    ])
    with pytest.raises(GpuReportFormatError, match="legacy opaque major"):
        parse_gpu_opaque_fields(report)


def test_nvdaod_does_not_infer_unknown_architecture():
    pki = _Pki()
    pki.leaf = _cert("GZ999 A01 GSP FMC LF", "nv-test-inter", pki.leaf_key, pki.inter_key)
    report = _nvdaod_report("ab" * 32, pki.leaf_key)
    result = build_gpu_verifier(_pem(pki.root)).verify(
        _evidence_b64(base64.b64encode(report).decode(), pki.chain_pem()),
        expected_nonce="ab" * 32, now=NOW,
    )
    assert result.verified and result.gpu_measurement is None
