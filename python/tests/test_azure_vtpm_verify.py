from __future__ import annotations

import base64
import hashlib
import json
import struct
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.x509.oid import NameOID

from wcm import AzureSnpVtpmVerifier, TrustStore

NOW = datetime(2026, 8, 12, tzinfo=timezone.utc)
NONCE = "ab" * 32
BINDING = b"\xcd" * 32


def _cert(subject, issuer, key, issuer_key, *, ca=False):
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
    return b.sign(issuer_key, hashes.SHA384())


def _tpm2b(value: bytes) -> bytes:
    return len(value).to_bytes(2, "big") + value


def _bundle(*, wrong_binding=False, wrong_ak=False, no_pcr23=False):
    root_key, inter_key, vcek_key = (ec.generate_private_key(ec.SECP384R1()) for _ in range(3))
    root = _cert("root", "root", root_key, root_key, ca=True)
    inter = _cert("inter", "root", inter_key, root_key, ca=True)
    vcek = _cert("vcek", "inter", vcek_key, inter_key)
    ak_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    runtime_key = rsa.generate_private_key(public_exponent=65537, key_size=2048) if wrong_ak else ak_key
    n = runtime_key.public_key().public_numbers().n.to_bytes(256, "big")
    runtime_json = json.dumps(
        {"keys": [{"kid": "HCLAkPub", "n": base64.urlsafe_b64encode(n).rstrip(b"=").decode()}]},
        separators=(",", ":"),
    ).encode()
    report = bytearray(1184)
    struct.pack_into("<I", report, 0, 3)
    report[0x50:0x70] = hashlib.sha256(runtime_json).digest()
    der = vcek_key.sign(bytes(report[:0x2A0]), ec.ECDSA(hashes.SHA384()))
    r, s = decode_dss_signature(der)
    report[0x2A0:0x2D0] = r.to_bytes(48, "little")
    report[0x2E8:0x318] = s.to_bytes(48, "little")
    runtime = bytes(16) + len(runtime_json).to_bytes(4, "little") + runtime_json
    hcl = b"HCLA" + bytes(28) + bytes(report) + runtime

    extra = hashlib.sha256(bytes.fromhex("ef" * 32) + BINDING).digest() if wrong_binding else hashlib.sha256(bytes.fromhex(NONCE) + BINDING).digest()
    selection = b"\x00\x0b\x03" + (b"\x00\x00\x80" if not no_pcr23 else b"\x01\x00\x00")
    quote = b"\xffTCG\x80\x18" + _tpm2b(b"signer") + _tpm2b(extra) + bytes(25) + (1).to_bytes(4, "big") + selection + _tpm2b(bytes(32))
    sig = ak_key.sign(quote, padding.PKCS1v15(), hashes.SHA256())
    signature_blob = b"\x00\x14\x00\x0b" + _tpm2b(sig)
    pem = lambda c: c.public_bytes(serialization.Encoding.PEM).decode()
    doc = {
        "hcl_b64": base64.b64encode(hcl).decode(),
        "ak_pem": ak_key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode(),
        "tpm_quote_b64": base64.b64encode(quote).decode(),
        "tpm_signature_b64": base64.b64encode(signature_blob).decode(),
        "vcek_pem": pem(vcek),
        "intermediates_pem": [pem(inter)],
    }
    trust = TrustStore()
    trust.add_root(root)
    return base64.b64encode(json.dumps(doc).encode()).decode(), trust


def test_azure_snp_vtpm_full_chain_verifies():
    bundle, trust = _bundle()
    result = AzureSnpVtpmVerifier(trust).verify(bundle, expected_nonce=NONCE, channel_binding=BINDING, now=NOW)
    assert result.verified


def test_azure_snp_vtpm_rejects_wrong_nonce_binding():
    bundle, trust = _bundle(wrong_binding=True)
    result = AzureSnpVtpmVerifier(trust).verify(bundle, expected_nonce=NONCE, channel_binding=BINDING, now=NOW)
    assert not result.verified and "qualifying data" in (result.reason or "")


def test_azure_snp_vtpm_rejects_unlinked_ak():
    bundle, trust = _bundle(wrong_ak=True)
    result = AzureSnpVtpmVerifier(trust).verify(bundle, expected_nonce=NONCE, channel_binding=BINDING, now=NOW)
    assert not result.verified and "does not match" in (result.reason or "")


def test_azure_snp_vtpm_requires_pcr23():
    bundle, trust = _bundle(no_pcr23=True)
    result = AzureSnpVtpmVerifier(trust).verify(bundle, expected_nonce=NONCE, channel_binding=BINDING, now=NOW)
    assert not result.verified and "PCR 23" in (result.reason or "")
