"""A certificate that loads but does not parse further is a denial, never an exception.

cryptography parses certificate names, extensions and keys lazily, so a
certificate that loads can still raise later. verify_cert_chain read a CA's
extensions in _may_issue, which caught only ExtensionNotFound, and
verify_tdx_quote read the PCK leaf's public key before the chain check, and
NvidiaGpuVerifier read the device leaf's public key at the signature check. The
chain comes from the evidence, and verify_cert_chain is shared by
verify_tdx_quote, AzureSnpVtpmVerifier, QuoteVerifier and NvidiaGpuVerifier,
so through a verifier configured in KeyBrokerService the exception also left
verify_and_release.
"""
from __future__ import annotations

import base64
import datetime
import json
import pathlib
import re
from datetime import timedelta

import pytest
from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtensionOID, NameOID, ObjectIdentifier

import tests.test_azure_vtpm_verify as snp_vtpm
import tests.test_nvidia as nv
import tests.test_quote_verify as qv
from wcm import (
    JsonQuoteParser,
    KeyBrokerService,
    QuoteVerifier,
    TrustStore,
    build_gpu_verifier,
    generate_transport_keypair,
    parse_tdx_quote,
    verify_cert_chain,
    verify_gpu_report_signature,
    verify_tdx_quote,
)
from wcm.nvidia import NvidiaGpuVerifier
from wcm.renewal import manifest_identity

NOW = datetime.datetime(2026, 7, 21, 12, 0, 0, tzinfo=datetime.timezone.utc)
AZURE_TDX = pathlib.Path(__file__).resolve().parent / "fixtures" / "tdx_quote_azure.json"
NONCE = "ab" * 32
# basicConstraints SEQUENCE { BOOLEAN TRUE [, INTEGER pathLen] }. Rewriting the
# BOOLEAN tag to INTEGER keeps the length, so the certificate still loads and only
# reading its extensions fails.
_BC_CA = re.compile(rb"\x30[\x03\x06]\x01\x01\xff")
_OID_BASIC_CONSTRAINTS = bytes.fromhex("0603551d13")
_OID_KEY_USAGE = bytes.fromhex("0603551d0f")
_OID_P256 = bytes.fromhex("06082a8648ce3d030107")
_OID_P384 = bytes.fromhex("06052b81040022")


def _break_basic_constraints(der: bytes) -> bytes:
    (match,) = _BC_CA.finditer(der)
    tag = match.start() + 2
    return der[:tag] + b"\x02" + der[tag + 1 :]


def _pem(der: bytes) -> str:
    b64 = base64.b64encode(der).decode()
    body = "\n".join(b64[i : i + 64] for i in range(0, len(b64), 64))
    return f"-----BEGIN CERTIFICATE-----\n{body}\n-----END CERTIFICATE-----\n"


def _der(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.DER)


def _cert_pem(cert: x509.Certificate) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def _b64_json(doc) -> str:
    return base64.b64encode(json.dumps(doc).encode()).decode()


def _cert(subject, issuer, key, issuer_key, *, ca, extra=None):
    b = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer)]))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - timedelta(days=1))
        .not_valid_after(NOW + timedelta(days=365))
    )
    if ca:
        b = b.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    if extra is not None:
        b = b.add_extension(extra, critical=False)
    return b.sign(issuer_key, hashes.SHA384())


class _Chain:
    """root -> inter -> leaf under a test root; the leaf is genuinely signed by inter."""

    def __init__(self):
        self.root_key, self.inter_key, self.leaf_key = (
            ec.generate_private_key(ec.SECP384R1()) for _ in range(3)
        )
        self.root = _cert("root", "root", self.root_key, self.root_key, ca=True)
        self.inter = _cert("inter", "root", self.inter_key, self.root_key, ca=True)
        self.leaf = _cert("leaf", "inter", self.leaf_key, self.inter_key, ca=False)
        self.trust = TrustStore()
        self.trust.add_root(self.root)


def _broken_ca_chains():
    """For each way a CA's extensions fail to parse: an intact chain and the inter that breaks it.

    Each broken inter keeps the intact inter's key, so the leaf's signature link
    still verifies and the chain check reaches the inter's extensions.
    """
    plain = _Chain()
    yield pytest.param(plain, _pem(_break_basic_constraints(_der(plain.inter))), "ValueError", id="basicConstraints")
    # A second extension whose OID is rewritten to basicConstraints' own.
    dup = _Chain()
    der = _der(_cert("inter", "root", dup.inter_key, dup.root_key, ca=True,
                     extra=x509.UnrecognizedExtension(ObjectIdentifier("2.5.29.20"), b"\x30\x03\x01\x01\xff")))
    assert der.count(bytes.fromhex("0603551d14")) == 1
    yield pytest.param(
        dup, _pem(der.replace(bytes.fromhex("0603551d14"), _OID_BASIC_CONSTRAINTS)),
        "DuplicateExtension", id="DuplicateExtension"
    )
    # A subjectAltName carrying an x400Address, which cryptography does not support.
    san = _Chain()
    inter = _cert("inter", "root", san.inter_key, san.root_key, ca=True,
                  extra=x509.UnrecognizedExtension(ExtensionOID.SUBJECT_ALTERNATIVE_NAME, b"\x30\x02\xa3\x00"))
    yield pytest.param(san, _cert_pem(inter), "UnsupportedGeneralNameType", id="UnsupportedGeneralNameType")


BROKEN_CA = pytest.mark.parametrize("chain, inter_pem, error", list(_broken_ca_chains()))


# -- verify_cert_chain and its callers ----------------------------------------------


@BROKEN_CA
def test_verify_cert_chain_denies_a_ca_whose_extensions_do_not_parse(chain, inter_pem, error):
    assert verify_cert_chain(chain.leaf, [chain.inter], chain.trust, NOW) is None
    reason = verify_cert_chain(chain.leaf, [x509.load_pem_x509_certificate(inter_pem.encode())], chain.trust, NOW)
    assert reason == f"malformed certificate while checking the chain: {error}"


@BROKEN_CA
def test_quote_verifier_denies_a_chain_whose_ca_does_not_parse(chain, inter_pem, error):
    doc = {
        "leaf_pem": _cert_pem(chain.leaf),
        "intermediates_pem": [inter_pem],
        "report_b64": base64.b64encode(bytes(64)).decode(),
        "signature_b64": base64.b64encode(b"sig").decode(),
    }
    result = QuoteVerifier(JsonQuoteParser(), chain.trust).verify(_b64_json(doc), expected_nonce=NONCE, now=NOW)
    assert not result.verified
    assert result.reason == f"malformed certificate while checking the chain: {error}"


@BROKEN_CA
def test_nvidia_gpu_verifier_denies_a_chain_whose_ca_does_not_parse(chain, inter_pem, error):
    doc = {"report_b64": base64.b64encode(bytes(64)).decode(), "cert_chain_pem": _cert_pem(chain.leaf) + inter_pem}
    result = NvidiaGpuVerifier(chain.trust).verify(_b64_json(doc), expected_nonce=NONCE, now=NOW)
    assert not result.verified
    assert result.reason == f"malformed certificate while checking the chain: {error}"


def test_azure_snp_vtpm_denies_an_intermediate_whose_extensions_do_not_parse():
    bundle, trust = snp_vtpm._bundle()
    assert snp_vtpm._verify(bundle, trust).verified
    doc = json.loads(base64.b64decode(bundle))
    inter = x509.load_pem_x509_certificate(doc["intermediates_pem"][0].encode())
    doc["intermediates_pem"] = [_pem(_break_basic_constraints(_der(inter)))]
    result = snp_vtpm._verify(_b64_json(doc), trust)
    assert not result.verified
    assert result.reason == "malformed certificate while checking the chain: ValueError"


def test_key_broker_denies_a_chain_whose_ca_does_not_parse(structural_manifest):
    """Through verify_and_release, with the CPU verifier the reference server builds.

    server.py builds QuoteVerifier(JsonQuoteParser(launch_measurement_offset=...),
    trust, require_launch_measurement=True); 0x90 is the SEV-SNP offset.

    The control sends the same request with the intact intermediate; its report
    is not genuinely signed, so it is an ordinary denial at the signature check.
    """
    chain = _Chain()
    broken = _pem(_break_basic_constraints(_der(chain.inter)))
    current, rim = qv._measurements(structural_manifest)
    reasons = []
    for inter_pem in (_cert_pem(chain.inter), broken):
        kbs = KeyBrokerService(
            {structural_manifest.weights_hash: b"KEY"},
            now=lambda: qv.NOW,
            cpu_quote_verifier=QuoteVerifier(
                JsonQuoteParser(launch_measurement_offset=0x90), chain.trust,
                require_launch_measurement=True,
            ),
            trusted_manifest_identities={manifest_identity(structural_manifest)},
        )
        challenge = kbs.issue_challenge()
        _, enclave_pub = generate_transport_keypair()
        doc = {
            "leaf_pem": _cert_pem(chain.leaf),
            "intermediates_pem": [inter_pem],
            "report_b64": base64.b64encode(bytes(1184)).decode(),
            "signature_b64": base64.b64encode(b"sig").decode(),
        }
        ev = qv._evidence(
            challenge.nonce, quote_b64=_b64_json(doc), current=current, rim=rim,
            transport_public_key=enclave_pub,
        )
        decision = kbs.verify_and_release(structural_manifest, ev)
        assert not decision.released and decision.key is None and decision.sealed_key is None
        failed = [c for c in decision.checks if not c.passed]
        assert [c.name for c in failed] == ["cpu_quote_verified"]
        reasons.append(failed[0].detail)
    assert reasons[0] == "report signature does not verify under the leaf key"
    assert reasons[1] == "malformed certificate while checking the chain: ValueError"


# -- NvidiaGpuVerifier on a re-signed device leaf ------------------------------------


def _der_length(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    encoded = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(encoded)]) + encoded


def _der_bounds(der: bytes, start: int) -> tuple[int, int]:
    """Return (end of header, end of element) for the DER element at *start*."""
    n = der[start + 1]
    if n < 0x80:
        return start + 2, start + 2 + n
    size = n & 0x7F
    header_end = start + 2 + size
    return header_end, header_end + int.from_bytes(der[start + 2 : header_end], "big")


def _resign_leaf(cert, issuer_key, old: bytes, new: bytes):
    """Rewrite the leaf's key and re-sign it so the chain check still passes."""
    tbs = cert.tbs_certificate_bytes
    assert tbs.count(old) == 1 and len(old) == len(new)
    tbs = tbs.replace(old, new)
    signature = issuer_key.sign(tbs, ec.ECDSA(hashes.SHA384()))
    der = _der(cert)
    header_end, _ = _der_bounds(der, 0)
    _, tbs_end = _der_bounds(der, header_end)
    _, algorithm_end = _der_bounds(der, tbs_end)
    bits = b"\x03" + _der_length(len(signature) + 1) + b"\x00" + signature
    body = tbs + der[tbs_end:algorithm_end] + bits
    return x509.load_der_x509_certificate(b"\x30" + _der_length(len(body)) + body)


@pytest.mark.parametrize("unsupported_curve, error", [
    pytest.param(True, UnsupportedAlgorithm, id="unsupported-curve"),
    pytest.param(False, ValueError, id="off-curve"),
])
def test_nvidia_gpu_verifier_denies_a_device_leaf_whose_key_does_not_parse(unsupported_curve, error):
    pki = nv._Pki()
    verifier = build_gpu_verifier(nv._pem(pki.root))
    report = nv._nv_report(NONCE, pki.leaf_key)
    report_b64 = base64.b64encode(report).decode()
    intact = nv._evidence_b64(report_b64, pki.chain_pem())
    assert verifier.verify(intact, expected_nonce=NONCE, now=nv.NOW).verified

    if unsupported_curve:
        old, new = _OID_P384, _OID_P384[:-1] + b"\x7f"  # 1.3.132.0.127
    else:
        old = pki.leaf.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
        )
        new = old[:-1] + bytes([old[-1] ^ 1])
    leaf = _resign_leaf(pki.leaf, pki.inter_key, old, new)
    trust = TrustStore()
    trust.add_root(pki.root)
    assert verify_cert_chain(leaf, [pki.inter, pki.root], trust, nv.NOW) is None
    with pytest.raises(error):
        leaf.public_key()
    with pytest.raises(error):
        verify_gpu_report_signature(report, leaf)
    evidence = nv._evidence_b64(report_b64, nv._pem(leaf) + nv._pem(pki.inter) + nv._pem(pki.root))
    result = verifier.verify(evidence, expected_nonce=NONCE, now=nv.NOW)
    assert not result.verified
    assert result.reason == f"GPU report signature verification failed: {error.__name__}"


# -- verify_tdx_quote on the captured Azure quote ------------------------------------
#
# The PEM PCK chain (leaf, platform CA, root) sits in the QE certification data,
# outside the attestation-key-signed header and TD report and outside the
# PCK-signed QE report, so a certificate can be rewritten in place at the same
# length without touching either. The rewritten certificate's own issuer
# signature no longer verifies; each test reaches its target parse first.


def _azure_quote():
    if not AZURE_TDX.exists():
        pytest.skip("no captured Azure TDX quote committed")
    quote = base64.b64decode(json.loads(AZURE_TDX.read_text(encoding="utf-8"))["quote_b64"])
    q = parse_tdx_quote(quote)
    root = next(c for c in [q.pck_leaf, *q.pck_intermediates] if c.subject == c.issuer)
    trust = TrustStore()
    trust.add_root(root)
    assert verify_tdx_quote(quote, trust, expected_nonce=None, now=NOW).verified
    return quote, trust


def _rewrite_pck_cert(quote: bytes, index: int, rewrite) -> bytes:
    """Rewrite the *index*-th PEM certificate in the quote, keeping its length and line breaks."""
    blocks = list(re.finditer(rb"-----BEGIN CERTIFICATE-----\n(.*?)-----END CERTIFICATE-----", quote, re.S))
    start, end = blocks[index].span(1)
    lines = quote[start:end].split(b"\n")
    der = base64.b64decode(b"".join(lines))
    new = rewrite(der)
    assert len(new) == len(der) and new != der
    b64 = base64.b64encode(new)
    out, pos = [], 0
    for line in lines:
        out.append(b64[pos : pos + len(line)])
        pos += len(line)
    return quote[:start] + b"\n".join(out) + quote[end:]


def _duplicate_key_usage(der: bytes) -> bytes:
    # basicConstraints is the platform CA's last extension; giving it keyUsage's
    # OID makes two keyUsage extensions.
    assert der.count(_OID_BASIC_CONSTRAINTS) == 1 and der.count(_OID_KEY_USAGE) == 1
    return der.replace(_OID_BASIC_CONSTRAINTS, _OID_KEY_USAGE)


@pytest.mark.parametrize("rewrite, error", [
    (_break_basic_constraints, "ValueError"), (_duplicate_key_usage, "DuplicateExtension"),
])
def test_tdx_pck_ca_whose_extensions_do_not_parse_is_denied(rewrite, error):
    quote, trust = _azure_quote()
    bad = _rewrite_pck_cert(quote, 1, rewrite)  # the platform CA
    result = verify_tdx_quote(bad, trust, expected_nonce=None, now=NOW)
    assert not result.verified
    assert result.reason == f"malformed certificate while checking the chain: {error}"


def _leaf_point(quote: bytes) -> bytes:
    leaf = parse_tdx_quote(quote).pck_leaf
    return leaf.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )


def test_tdx_pck_leaf_key_off_the_curve_is_denied():
    quote, trust = _azure_quote()
    point = _leaf_point(quote)

    def off_curve(der: bytes) -> bytes:
        assert der.count(point) == 1
        return der.replace(point, point[:-1] + bytes([point[-1] ^ 1]))

    result = verify_tdx_quote(_rewrite_pck_cert(quote, 0, off_curve), trust, expected_nonce=None, now=NOW)
    assert not result.verified
    assert result.reason == "PCK leaf public key does not parse: ValueError"


def test_tdx_pck_leaf_key_on_an_unsupported_curve_is_denied():
    quote, trust = _azure_quote()

    def unknown_curve(der: bytes) -> bytes:
        assert der.count(_OID_P256) == 1
        return der.replace(_OID_P256, _OID_P256[:-1] + b"\x7f")  # 1.2.840.10045.3.1.127

    result = verify_tdx_quote(_rewrite_pck_cert(quote, 0, unknown_curve), trust, expected_nonce=None, now=NOW)
    assert not result.verified
    assert result.reason == "PCK leaf public key does not parse: UnsupportedAlgorithm"
