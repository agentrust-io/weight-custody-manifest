"""Fail-closed verification of Azure SEV-SNP plus fresh vTPM evidence."""
from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Optional

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from ._quote_verify import QuoteVerification, TrustStore, verify_cert_chain
from .snp import extract_snp_report_from_hcl, parse_snp_report, verify_snp_report_signature


def _b64(value: str) -> bytes:
    return base64.b64decode(value, validate=True)


def _take_u16(blob: bytes, offset: int) -> tuple[bytes, int]:
    if offset + 2 > len(blob):
        raise ValueError("truncated TPM2B")
    size = int.from_bytes(blob[offset : offset + 2], "big")
    start = offset + 2
    end = start + size
    if end > len(blob):
        raise ValueError("truncated TPM2B payload")
    return blob[start:end], end


class AzureSnpVtpmVerifier:
    """Verify SNP authenticity, the HCL AK link, and a fresh AK-signed TPM quote.

    ``quote_b64`` is base64 JSON containing ``hcl_b64``, ``ak_pem``,
    ``tpm_quote_b64``, ``tpm_signature_b64``, ``vcek_pem``,
    ``intermediates_pem`` and ``root_pem``. The TPM quote must use
    SHA-256(nonce || channel_binding) as qualifying data and select PCR 23.
    """

    def __init__(self, trust_store: TrustStore) -> None:
        self._trust = trust_store

    def verify(
        self,
        quote_b64: str,
        *,
        expected_nonce: str,
        channel_binding: bytes = b"",
        now: Optional[datetime] = None,
    ) -> QuoteVerification:
        try:
            doc: dict[str, Any] = json.loads(_b64(quote_b64))
            hcl = _b64(doc["hcl_b64"])
            quote = _b64(doc["tpm_quote_b64"])
            signature_blob = _b64(doc["tpm_signature_b64"])
            ak = serialization.load_pem_public_key(doc["ak_pem"].encode())
            vcek = x509.load_pem_x509_certificate(doc["vcek_pem"].encode())
            intermediates = [
                x509.load_pem_x509_certificate(p.encode())
                for p in doc["intermediates_pem"]
            ]
        except (KeyError, ValueError, TypeError, json.JSONDecodeError) as exc:
            return QuoteVerification(False, f"invalid Azure vTPM evidence: {exc}")
        if not isinstance(ak, rsa.RSAPublicKey):
            return QuoteVerification(False, "HCL AK is not RSA")

        report = extract_snp_report_from_hcl(hcl)
        parsed = parse_snp_report(report)
        current = now or datetime.now(timezone.utc)
        chain_error = verify_cert_chain(vcek, intermediates, self._trust, current)
        if chain_error:
            return QuoteVerification(False, chain_error)
        if not verify_snp_report_signature(report, vcek):
            return QuoteVerification(False, "SNP report signature does not verify")

        runtime = hcl[32 + 1184 :]
        if len(runtime) < 20:
            return QuoteVerification(False, "HCL runtime data is truncated")
        json_len = int.from_bytes(runtime[16:20], "little")
        runtime_json = runtime[20 : 20 + json_len]
        if len(runtime_json) != json_len:
            return QuoteVerification(False, "HCL runtime JSON is truncated")
        if parsed.report_data[:32] != hashlib.sha256(runtime_json).digest():
            return QuoteVerification(False, "SNP REPORT_DATA does not bind HCL runtime JSON")
        if parsed.report_data[32:] != bytes(32):
            return QuoteVerification(False, "unexpected nonzero SNP REPORT_DATA tail")
        try:
            runtime_doc = json.loads(runtime_json)
            jwk = next(k for k in runtime_doc["keys"] if k["kid"] == "HCLAkPub")
            modulus = int.from_bytes(base64.urlsafe_b64decode(jwk["n"] + "=" * (-len(jwk["n"]) % 4)), "big")
        except (KeyError, StopIteration, ValueError, TypeError) as exc:
            return QuoteVerification(False, f"invalid HCLAkPub: {exc}")
        if modulus != ak.public_numbers().n:
            return QuoteVerification(False, "TPM quote key does not match HCL-authenticated AK")

        try:
            if quote[:4] != b"\xffTCG" or quote[4:6] != b"\x80\x18":
                raise ValueError("not a TPM generated quote")
            _, offset = _take_u16(quote, 6)  # qualified signer
            extra_data, offset = _take_u16(quote, offset)
            offset += 25  # TPMS_CLOCK_INFO (17) + firmwareVersion (8)
            count = int.from_bytes(quote[offset : offset + 4], "big")
            offset += 4
            selected_pcr23 = False
            for _ in range(count):
                algorithm = int.from_bytes(quote[offset : offset + 2], "big")
                size = quote[offset + 2]
                selection = quote[offset + 3 : offset + 3 + size]
                offset += 3 + size
                selected_pcr23 |= algorithm == 0x000B and size >= 3 and bool(selection[2] & 0x80)
            if not selected_pcr23:
                return QuoteVerification(False, "TPM quote does not select SHA-256 PCR 23")
            if extra_data != hashlib.sha256(bytes.fromhex(expected_nonce) + channel_binding).digest():
                return QuoteVerification(False, "TPM qualifying data does not bind nonce and transport key")
            if signature_blob[:4] != b"\x00\x14\x00\x0b":
                raise ValueError("TPM signature is not RSASSA/SHA-256")
            signature, end = _take_u16(signature_blob, 4)
            if end != len(signature_blob):
                raise ValueError("trailing TPM signature bytes")
            ak.verify(signature, quote, padding.PKCS1v15(), hashes.SHA256())
        except (ValueError, InvalidSignature) as exc:
            return QuoteVerification(False, f"TPM quote verification failed: {exc}")
        return QuoteVerification(True, leaf_subject=vcek.subject.rfc4514_string())
