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
from wcm.azure_vtpm import expected_pcr23_digest

NOW = datetime(2026, 8, 12, tzinfo=timezone.utc)
NONCE = "ab" * 32
BINDING = b"\xcd" * 32
MEASUREMENT = "sha256:" + "42" * 32


def test_expected_pcr23_quote_digest_has_both_tpm_hash_stages() -> None:
    event = bytes.fromhex(MEASUREMENT.removeprefix("sha256:"))
    pcr_value = hashlib.sha256(bytes(32) + event).digest()
    assert expected_pcr23_digest(MEASUREMENT) == hashlib.sha256(pcr_value).digest()
    assert expected_pcr23_digest(MEASUREMENT) != pcr_value


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


def _b64url(value: int, size: int) -> str:
    return base64.urlsafe_b64encode(value.to_bytes(size, "big")).rstrip(b"=").decode()


def _bundle(*, wrong_binding=False, wrong_ak=False, no_pcr23=False, pcr_digest=None, jwk=None):
    root_key, inter_key, vcek_key = (ec.generate_private_key(ec.SECP384R1()) for _ in range(3))
    root = _cert("root", "root", root_key, root_key, ca=True)
    inter = _cert("inter", "root", inter_key, root_key, ca=True)
    vcek = _cert("vcek", "inter", vcek_key, inter_key)
    ak_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    runtime_key = rsa.generate_private_key(public_exponent=65537, key_size=2048) if wrong_ak else ak_key
    # Same shape as a real Azure HCL runtime JWK: kid, key_ops, kty, e, n.
    hcl_jwk = {
        "kid": "HCLAkPub",
        "key_ops": ["sign"],
        "kty": "RSA",
        "e": "AQAB",
        "n": _b64url(runtime_key.public_key().public_numbers().n, 256),
    }
    if jwk is not None:
        hcl_jwk = {k: v for k, v in {**hcl_jwk, **jwk}.items() if v is not None}
    runtime_json = json.dumps({"keys": [hcl_jwk]}, separators=(",", ":")).encode()
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
    digest = expected_pcr23_digest(MEASUREMENT) if pcr_digest is None else pcr_digest
    quote = b"\xffTCG\x80\x18" + _tpm2b(b"signer") + _tpm2b(extra) + bytes(25) + (1).to_bytes(4, "big") + selection + _tpm2b(digest)
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
    result = AzureSnpVtpmVerifier(trust).verify(bundle, expected_nonce=NONCE, channel_binding=BINDING, expected_workload_measurement=MEASUREMENT, now=NOW)
    assert result.verified


def test_azure_snp_vtpm_rejects_wrong_nonce_binding():
    bundle, trust = _bundle(wrong_binding=True)
    result = AzureSnpVtpmVerifier(trust).verify(bundle, expected_nonce=NONCE, channel_binding=BINDING, expected_workload_measurement=MEASUREMENT, now=NOW)
    assert not result.verified and "qualifying data" in (result.reason or "")


def test_azure_snp_vtpm_rejects_unlinked_ak():
    bundle, trust = _bundle(wrong_ak=True)
    result = AzureSnpVtpmVerifier(trust).verify(bundle, expected_nonce=NONCE, channel_binding=BINDING, expected_workload_measurement=MEASUREMENT, now=NOW)
    assert not result.verified and "does not match" in (result.reason or "")


def test_azure_snp_vtpm_requires_pcr23():
    bundle, trust = _bundle(no_pcr23=True)
    result = AzureSnpVtpmVerifier(trust).verify(bundle, expected_nonce=NONCE, channel_binding=BINDING, expected_workload_measurement=MEASUREMENT, now=NOW)
    assert not result.verified and "PCR 23" in (result.reason or "")


def test_azure_snp_vtpm_rejects_changed_pcr_state():
    bundle, trust = _bundle(pcr_digest=b"\xff" * 32)
    result = AzureSnpVtpmVerifier(trust).verify(bundle, expected_nonce=NONCE, channel_binding=BINDING, expected_workload_measurement=MEASUREMENT, now=NOW)
    assert not result.verified and "approved workload" in (result.reason or "")


def test_azure_snp_vtpm_rejects_wrong_policy_measurement():
    bundle, trust = _bundle()
    result = AzureSnpVtpmVerifier(trust).verify(bundle, expected_nonce=NONCE, channel_binding=BINDING, expected_workload_measurement="sha256:" + "43" * 32, now=NOW)
    assert not result.verified and "approved workload" in (result.reason or "")


def test_azure_snp_vtpm_rejects_malformed_pcr_digest():
    bundle, trust = _bundle(pcr_digest=b"short")
    result = AzureSnpVtpmVerifier(trust).verify(bundle, expected_nonce=NONCE, channel_binding=BINDING, expected_workload_measurement=MEASUREMENT, now=NOW)
    assert not result.verified and "32-byte SHA-256" in (result.reason or "")


def test_azure_snp_vtpm_requires_policy_measurement():
    bundle, trust = _bundle()
    result = AzureSnpVtpmVerifier(trust).verify(bundle, expected_nonce=NONCE, channel_binding=BINDING, now=NOW)
    assert not result.verified and "release policy" in (result.reason or "")


def _mutated(**changes):
    bundle, trust = _bundle()
    doc = json.loads(base64.b64decode(bundle))
    doc.update(changes)
    return base64.b64encode(json.dumps(doc).encode()).decode(), trust, doc


def _verify(bundle, trust):
    return AzureSnpVtpmVerifier(trust).verify(
        bundle, expected_nonce=NONCE, channel_binding=BINDING,
        expected_workload_measurement=MEASUREMENT, now=NOW,
    )


def test_azure_snp_vtpm_malformed_bundles_deny_instead_of_raising():
    # Each of these used to raise out of verify() (AttributeError,
    # QuoteFormatError, IndexError) instead of returning a denial.
    _, _, doc = _mutated()
    hcl = base64.b64decode(doc["hcl_b64"])
    quote = base64.b64decode(doc["tpm_quote_b64"])
    # Cut the quote inside its first TPMS_PCR_SELECTION.
    cut = 6 + 2 + len(b"signer") + 2 + 32 + 25 + 4 + 1
    cases = {
        "ak_pem not a string": {"ak_pem": 1},
        "not an HCL blob": {"hcl_b64": base64.b64encode(b"XXXX" + hcl[4:]).decode()},
        "HCL shorter than an SNP report": {"hcl_b64": base64.b64encode(hcl[:100]).decode()},
        "quote truncated in PCR selection": {
            "tpm_quote_b64": base64.b64encode(quote[:cut]).decode()
        },
        "intermediate not a string": {"intermediates_pem": [7]},
    }
    for label, change in cases.items():
        bundle, trust, _ = _mutated(**change)
        result = _verify(bundle, trust)
        assert not result.verified, label
        assert result.reason, label


# The AK is the HCL-authenticated key, modulus AND exponent. Matching only the
# modulus let an attacker-supplied ak_pem choose the exponent.

_SHA256_DIGEST_INFO = bytes.fromhex("3031300d060960864801650304020105000420")


def _der_len(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    raw = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def _tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _der_len(len(value)) + value


def _der_int(value: int) -> bytes:
    return _tlv(0x02, value.to_bytes(value.bit_length() // 8 + 1, "big"))


def _rsa_spki_pem(n: int, e: int) -> str:
    """SubjectPublicKeyInfo for (n, e), built by hand so e=1 is expressible."""
    rsa_key = _tlv(0x30, _der_int(n) + _der_int(e))
    algorithm = bytes.fromhex("300d06092a864886f70d0101010500")
    spki = _tlv(0x30, algorithm + _tlv(0x03, b"\x00" + rsa_key))
    body = base64.encodebytes(spki).decode()
    return "-----BEGIN PUBLIC KEY-----\n" + body + "-----END PUBLIC KEY-----\n"


def _supplied_ak_n(doc) -> int:
    return serialization.load_pem_public_key(doc["ak_pem"].encode()).public_numbers().n


def test_azure_snp_vtpm_rejects_exponent_one_forgery():
    # Under e=1 a PKCS#1 v1.5 signature is just the padded digest, so anyone who
    # knows the HCL modulus can "sign" any quote: any nonce, any transport key,
    # any PCR 23 measurement. The modulus-only check verified this.
    bundle, trust = _bundle()
    doc = json.loads(base64.b64decode(bundle))
    nonce, binding, measurement = "11" * 32, b"\x22" * 32, "sha256:" + "ee" * 32
    quote = (
        b"\xffTCG\x80\x18" + _tpm2b(b"signer")
        + _tpm2b(hashlib.sha256(bytes.fromhex(nonce) + binding).digest())
        + bytes(25) + (1).to_bytes(4, "big") + b"\x00\x0b\x03\x00\x00\x80"
        + _tpm2b(expected_pcr23_digest(measurement))
    )
    t = _SHA256_DIGEST_INFO + hashlib.sha256(quote).digest()
    forged = b"\x00\x01" + b"\xff" * (256 - len(t) - 3) + b"\x00" + t
    doc.update(
        ak_pem=_rsa_spki_pem(_supplied_ak_n(doc), 1),
        tpm_quote_b64=base64.b64encode(quote).decode(),
        tpm_signature_b64=base64.b64encode(b"\x00\x14\x00\x0b" + _tpm2b(forged)).decode(),
    )
    evil = base64.b64encode(json.dumps(doc).encode()).decode()
    result = AzureSnpVtpmVerifier(trust).verify(
        evil, expected_nonce=nonce, channel_binding=binding,
        expected_workload_measurement=measurement, now=NOW,
    )
    assert not result.verified
    # cryptography 50 refuses to load e=1 at all; older releases load it and
    # the HCL key comparison is what denies. Either way it must not verify.
    reason = result.reason or ""
    assert "does not match" in reason or "e must be" in reason, reason


def test_azure_snp_vtpm_rejects_ak_pem_with_matching_modulus_other_exponent():
    bundle, trust = _bundle()
    doc = json.loads(base64.b64decode(bundle))
    doc["ak_pem"] = _rsa_spki_pem(_supplied_ak_n(doc), 3)
    result = _verify(base64.b64encode(json.dumps(doc).encode()).decode(), trust)
    assert not result.verified
    assert "does not match" in (result.reason or "")


def test_azure_snp_vtpm_rejects_hcl_ak_with_non_default_exponent():
    bundle, trust = _bundle(jwk={"e": "Aw"})
    result = _verify(bundle, trust)
    assert not result.verified
    assert "exponent 3 is not 65537" in (result.reason or "")


def test_azure_snp_vtpm_rejects_short_hcl_ak_modulus():
    short = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    bundle, trust = _bundle(jwk={"n": _b64url(short.public_key().public_numbers().n, 128)})
    result = _verify(bundle, trust)
    assert not result.verified
    assert "shorter than 2048 bits" in (result.reason or "")


def test_azure_snp_vtpm_rejects_malformed_hcl_ak_jwk():
    cases = {
        "missing e": {"e": None},
        "missing kty": {"kty": None},
        "not RSA": {"kty": "EC"},
        "padded n": {"n": "AQAB=="},
        "standard alphabet": {"e": "AQ+B"},
        "e not a string": {"e": 65537},
    }
    for label, change in cases.items():
        bundle, trust = _bundle(jwk=change)
        result = _verify(bundle, trust)
        assert not result.verified, label
        assert "invalid HCLAkPub" in (result.reason or ""), label
