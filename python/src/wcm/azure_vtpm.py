"""Fail-closed verification of Azure SEV-SNP plus fresh vTPM evidence."""
from __future__ import annotations

import base64
import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Any, Iterable, Optional, Union

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from ._quote_verify import (
    QuoteFormatError,
    QuoteVerification,
    TrustStore,
    _nonce_bytes,
    _unique_object,
    verify_cert_chain,
)
from ._certificates import load_pem_certificate
from .snp import extract_snp_report_from_hcl, parse_snp_report, verify_snp_report_signature

_B64URL_RE = re.compile(r"^[A-Za-z0-9_-]+\Z")
_JWK_PRIVATE_PARAMS = frozenset({"d", "p", "q", "dp", "dq", "qi", "oth", "k"})


def expected_pcr23_digest(measurement: str) -> bytes:
    """Return a quote's pcrDigest for measured-launch SHA-256 PCR 23.

    The launch agent resets the application-owned PCR 23 to zero and extends
    the manifest's 32-byte event digest once. TPM extend semantics produce the
    PCR value as ``SHA256(old_pcr || event_digest)``. ``TPMS_QUOTE_INFO`` then
    carries the SHA-256 digest of the concatenated selected PCR values. Because
    WCM selects only PCR 23, the signed value is ``SHA256(pcr23_value)``.
    """
    algorithm, separator, digest = measurement.partition(":")
    if separator != ":" or algorithm != "sha256" or len(digest) != 64:
        raise ValueError("workload measurement must be sha256:<64 lowercase hex digits>")
    if digest.lower() != digest:
        raise ValueError("workload measurement hex must be lowercase")
    try:
        event_digest = bytes.fromhex(digest)
    except ValueError as exc:
        raise ValueError("workload measurement contains non-hex characters") from exc
    pcr23_value = hashlib.sha256(bytes(32) + event_digest).digest()
    return hashlib.sha256(pcr23_value).digest()


def _b64(value: str) -> bytes:
    return base64.b64decode(value, validate=True)


# Azure vTPM AKs are RSA-2048 with the TPM default exponent; HCLAkPub carries
# e = "AQAB" on every capture WCM has seen.
_AK_EXPONENT = 65537
_AK_MIN_BITS = 2048


def _b64url_uint(value: str) -> int:
    """Decode a JWK Base64urlUInt (RFC 7518 section 2), rejecting non-minimal encodings."""
    if not isinstance(value, str) or not _B64URL_RE.match(value) or len(value) % 4 == 1:
        raise ValueError("JWK integer must be an unpadded base64url string")
    std = value.replace("-", "+").replace("_", "/")
    raw = base64.b64decode(std + "=" * (-len(std) % 4), validate=True)
    if base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") != value:
        raise ValueError("JWK integer is not canonical base64url")
    if not raw or raw[0] == 0:
        raise ValueError("JWK Base64urlUInt must not be empty or carry leading zero bytes")
    return int.from_bytes(raw, "big")


_MEASUREMENT_LEN = 48
_POLICY_DEBUG = 1 << 19


def _paravisor_measurement(value: Union[str, bytes]) -> bytes:
    """Normalise one allowed SNP launch measurement to its 48 raw bytes."""
    if isinstance(value, bytes):
        raw = value
    elif isinstance(value, str):
        if value != value.lower():
            raise ValueError("paravisor measurement hex must be lowercase")
        try:
            raw = bytes.fromhex(value)
        except ValueError as exc:
            raise ValueError("paravisor measurement contains non-hex characters") from exc
    else:
        raise TypeError("paravisor measurement must be hex str or bytes")
    if len(raw) != _MEASUREMENT_LEN:
        raise ValueError(f"paravisor measurement must be {_MEASUREMENT_LEN} bytes (SHA-384)")
    return raw


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

    ``paravisor_measurements`` is the operator's allowlist of SNP launch
    measurements for the Azure paravisor builds it trusts. The REPORT_DATA
    binding below proves only that whoever requested the SNP report chose the
    HCL runtime data; any SNP guest that controls REPORT_DATA can do that. The
    launch measurement is what ties the report to Azure's paravisor rather than
    to an arbitrary guest, so it is required and there is no default. Azure
    updates the paravisor, so this is an allowlist the operator maintains, not
    a constant.
    """

    def __init__(
        self,
        trust_store: TrustStore,
        *,
        paravisor_measurements: Iterable[Union[str, bytes]],
    ) -> None:
        if isinstance(paravisor_measurements, (str, bytes)):
            raise TypeError("paravisor_measurements must be a collection, not one value")
        allowed = frozenset(_paravisor_measurement(m) for m in paravisor_measurements)
        if not allowed:
            raise ValueError("at least one Azure paravisor launch measurement is required")
        self._trust = trust_store
        self._paravisor_measurements = allowed

    def verify(
        self,
        quote_b64: str,
        *,
        expected_nonce: str,
        channel_binding: bytes = b"",
        expected_workload_measurement: Optional[str] = None,
        now: Optional[datetime] = None,
    ) -> QuoteVerification:
        try:
            doc: dict[str, Any] = json.loads(_b64(quote_b64), object_pairs_hook=_unique_object)
            if not isinstance(doc, dict):
                raise ValueError("quote bundle must be a JSON object")
            hcl = _b64(doc["hcl_b64"])
            quote = _b64(doc["tpm_quote_b64"])
            signature_blob = _b64(doc["tpm_signature_b64"])
            ak = serialization.load_pem_public_key(doc["ak_pem"].encode())
            # Azure's THIM currently serves an otherwise verifiable AMD VCEK with
            # a non-positive serial. Keep the compatibility exception local to
            # this authenticated provider leaf; every other provider certificate
            # continues to use WCM's positive-serial policy.
            vcek = load_pem_certificate(
                doc["vcek_pem"].encode(), allow_non_positive_serial=True
            )
            intermediates = [
                load_pem_certificate(p.encode())
                for p in doc["intermediates_pem"]
            ]
            report = extract_snp_report_from_hcl(hcl)
            parsed = parse_snp_report(report)
        except (
            KeyError, ValueError, TypeError, AttributeError,
            UnsupportedAlgorithm, QuoteFormatError,
        ) as exc:
            # The bundle is attacker-supplied: every malformed shape is a
            # denial with a reason, never an exception out of the release path.
            return QuoteVerification(False, f"invalid Azure vTPM evidence: {exc}")
        if not isinstance(ak, rsa.RSAPublicKey):
            return QuoteVerification(False, "HCL AK is not RSA")
        current = now or datetime.now(timezone.utc)
        chain_error = verify_cert_chain(vcek, intermediates, self._trust, current)
        if chain_error:
            return QuoteVerification(False, chain_error)
        if not verify_snp_report_signature(report, vcek):
            return QuoteVerification(False, "SNP report signature does not verify")
        if parsed.measurement not in self._paravisor_measurements:
            return QuoteVerification(
                False, "SNP launch measurement is not an allowed Azure paravisor measurement"
            )
        if parsed.policy & _POLICY_DEBUG:
            return QuoteVerification(False, "SNP guest policy allows debugging")
        # The paravisor runs at VMPL 0 and requests this report itself; a report
        # requested at VMPL 1 to 3 came from less privileged guest software.
        if parsed.vmpl != 0:
            return QuoteVerification(False, f"SNP report is from VMPL {parsed.vmpl}, not VMPL 0")

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
            runtime_doc = json.loads(runtime_json, object_pairs_hook=_unique_object)
            if not isinstance(runtime_doc, dict):
                raise ValueError("HCL runtime JSON must be a JSON object")
            jwk = next(
                k for k in runtime_doc["keys"]
                if isinstance(k, dict) and k.get("kid") == "HCLAkPub"
            )
            private_members = sorted(_JWK_PRIVATE_PARAMS.intersection(jwk))
            if private_members:
                raise ValueError(
                    f"HCLAkPub must not contain private key material ({', '.join(private_members)})"
                )
            if jwk["kty"] != "RSA":
                raise ValueError(f"kty {jwk['kty']!r} is not RSA")
            modulus = _b64url_uint(jwk["n"])
            exponent = _b64url_uint(jwk["e"])
        except (KeyError, StopIteration, ValueError, TypeError, AttributeError) as exc:
            return QuoteVerification(False, f"invalid HCLAkPub: {exc}")
        if exponent != _AK_EXPONENT:
            return QuoteVerification(False, f"HCLAkPub exponent {exponent} is not {_AK_EXPONENT}")
        if modulus.bit_length() < _AK_MIN_BITS:
            return QuoteVerification(False, f"HCLAkPub modulus is shorter than {_AK_MIN_BITS} bits")
        # The quote is verified under the key the SNP report authenticates,
        # never under ``ak_pem``: that field is attacker-supplied, and matching
        # only its modulus let an (n, e=1) key verify a forged signature.
        # ``ak_pem`` must still name exactly the same key.
        supplied = ak.public_numbers()
        if (supplied.n, supplied.e) != (modulus, exponent):
            return QuoteVerification(False, "TPM quote key does not match HCL-authenticated AK")
        ak = rsa.RSAPublicNumbers(exponent, modulus).public_key()

        try:
            if quote[:4] != b"\xffTCG" or quote[4:6] != b"\x80\x18":
                raise ValueError("not a TPM generated quote")
            _, offset = _take_u16(quote, 6)  # qualified signer
            extra_data, offset = _take_u16(quote, offset)
            offset += 25  # TPMS_CLOCK_INFO (17) + firmwareVersion (8)
            if offset + 4 > len(quote):
                raise ValueError("truncated TPM PCR selection")
            count = int.from_bytes(quote[offset : offset + 4], "big")
            offset += 4
            selected_pcr23 = False
            for _ in range(count):
                if offset + 3 > len(quote):
                    raise ValueError("truncated TPM PCR selection")
                algorithm = int.from_bytes(quote[offset : offset + 2], "big")
                size = quote[offset + 2]
                selection = quote[offset + 3 : offset + 3 + size]
                if len(selection) != size:
                    raise ValueError("truncated TPM PCR selection")
                offset += 3 + size
                selected_pcr23 |= algorithm == 0x000B and size >= 3 and bool(selection[2] & 0x80)
            if not selected_pcr23:
                return QuoteVerification(False, "TPM quote does not select SHA-256 PCR 23")
            pcr_digest, offset = _take_u16(quote, offset)
            if offset != len(quote):
                raise ValueError("trailing TPM quote bytes")
            if len(pcr_digest) != hashlib.sha256().digest_size:
                raise ValueError("TPM PCR digest is not 32-byte SHA-256")
            if expected_workload_measurement is None:
                return QuoteVerification(
                    False, "expected workload measurement is required by release policy"
                )
            if pcr_digest != expected_pcr23_digest(expected_workload_measurement):
                return QuoteVerification(
                    False, "TPM PCR digest does not match the approved workload measurement"
                )
            if extra_data != hashlib.sha256(_nonce_bytes(expected_nonce) + channel_binding).digest():
                return QuoteVerification(False, "TPM qualifying data does not bind nonce and transport key")
            if signature_blob[:4] != b"\x00\x14\x00\x0b":
                raise ValueError("TPM signature is not RSASSA/SHA-256")
            signature, end = _take_u16(signature_blob, 4)
            if end != len(signature_blob):
                raise ValueError("trailing TPM signature bytes")
            ak.verify(signature, quote, padding.PKCS1v15(), hashes.SHA256())
        except (ValueError, InvalidSignature) as exc:
            return QuoteVerification(False, f"TPM quote verification failed: {exc}")
        return QuoteVerification(
            True, leaf_subject=vcek.subject.rfc4514_string(), snp_report=report
        )
