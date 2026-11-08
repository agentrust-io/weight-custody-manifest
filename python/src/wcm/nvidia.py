"""NVIDIA Confidential Computing (Hopper H100) GPU attestation verification.

The GPU is a SECOND attestation chain alongside the CPU CVM quote (see
``attestation`` and ``kbs``): an H100 in CC mode produces an attestation report
signed by an on-die attestation key, carried with a device certificate chain
that roots in NVIDIA's device-identity CA.

This verifier is validated against a REAL H100 NVL confidential-compute
attestation captured on live silicon (``tests/fixtures/gpu_h100_attestation.json``,
cross-checked with NVIDIA's own local verifier). The confirmed on-wire format:

  - the report echoes the RAW 32-byte challenge nonce at offset 4 (NOT
    ``sha256(nonce)``, which is the CPU SEV-SNP / TDX convention);
  - the report signature is the last 96 bytes, ECDSA P-384 raw ``r || s``
    (r = 48 bytes, s = 48 bytes), over ``report[:-96]``, using SHA-384;
  - the signer is the leaf of the device cert chain (``GH100 ... GSP FMC LF``),
    a secp384r1 key, and the chain roots in the self-signed
    ``NVIDIA Device Identity CA``.

The GPU report is bound to the CPU quote by the shared KBS nonce (the composite
check in ``kbs._check_gpu``), so a valid GPU paired with a mismatched CPU is
rejected. Plug ``build_gpu_verifier`` into ``KeyBrokerService(gpu_report_verifier=)``
to cryptographically verify the GPU chain instead of trusting the structured
fields alone.

Do not fingerprint a whole report to pin a measurement. On an H200 (driver
595.71.05) three ranges of a 4,129-byte report move between calls: the nonce at
[4, 36), the signature at [4033, 4129), and 32 bytes at [3565, 3597) that change
on every call even under an identical nonce. Varying the nonce hides the middle
one, so a pin built by diffing two reports with different nonces looks stable and
is not. 3,969 bytes were stable there. This verifier checks chain, signature and
nonce rather than a report digest, so it is unaffected; an implementer pinning a
measurement is not.

What the KBS pins instead (GHSA-5mg4-8gw3-3xmm). The report is an SPDM
GET_MEASUREMENTS request and response, and the response's opaque data carries
the driver version (field 3) and the VBIOS version (field 6) inside the signed
bytes. ``gpu_measurement_from_report`` reads both, adds the architecture from the
verified device certificate (``GH...`` is Hopper, ``GB...`` is Blackwell), and
returns ``nvidia-rim:arch=<A>;driver=<D>;vbios=<V>``, the same identity
``tools/nvat_adapter.py`` emits after NVIDIA's own appraisal. The KBS compares
``required_gpu_measurement.rim_pin`` against that value. The structured
``GpuReport.measurement`` is the requester's claim and no longer decides release
when a verifier is configured. This binds the pin to the identity the signed
report states; it is not a RIM golden-value comparison, which stays with
NVIDIA's appraisal.

Honesty, matching ``_quote_verify``: WCM ships only NVIDIA's public device root
(the caller supplies it to ``build_gpu_verifier``; the pinned fixture is the root
only, not any per-GPU cert). And as everywhere in WCM, a physically-extracted
attestation key still produces a genuinely-valid signature (the key-extraction
half of open question 8.8); this raises the bar to a real hardware signature, it
does not defeat a hardware owner.
"""
from __future__ import annotations

import base64
import binascii
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional, Union

from cryptography import x509
from ._certificates import load_pem_certificates
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

from ._quote_verify import QuoteVerification, TrustStore, verify_cert_chain

# The report's 4-byte header is followed by the raw 32-byte challenge nonce.
NVIDIA_NONCE_OFFSET = 4
_NONCE_LEN = 32
# ECDSA P-384 raw signature: r (48) || s (48), appended as the last 96 bytes.
_SIG_LEN = 96


class GpuReportFormatError(Exception):
    """The GPU attestation report is too short to be a valid report."""


@dataclass(frozen=True)
class GpuAttestationReport:
    """An NVIDIA GPU attestation report decomposed into what verification needs."""

    raw_nonce: bytes  # the 32-byte challenge nonce echoed at NVIDIA_NONCE_OFFSET
    signed_body: bytes  # the bytes the signature covers: report[:-96]
    signature: bytes  # ECDSA P-384 raw r||s, the last 96 bytes
    raw: bytes  # the full report


def parse_gpu_report(report: bytes) -> GpuAttestationReport:
    """Decompose an NVIDIA GPU attestation report (raw bytes)."""
    if len(report) <= NVIDIA_NONCE_OFFSET + _NONCE_LEN + _SIG_LEN:
        raise GpuReportFormatError(
            f"report is {len(report)} bytes, too short to hold header + nonce + signature"
        )
    return GpuAttestationReport(
        raw_nonce=report[NVIDIA_NONCE_OFFSET : NVIDIA_NONCE_OFFSET + _NONCE_LEN],
        signed_body=report[:-_SIG_LEN],
        signature=report[-_SIG_LEN:],
        raw=report,
    )


def verify_gpu_report_signature(report: bytes, leaf_cert: x509.Certificate) -> None:
    """Verify the report signature with the leaf attestation key.

    ECDSA P-384 over SHA-384 of ``report[:-96]``; the trailing 96 bytes are the
    raw ``r || s`` (each 48 bytes). Raises ``InvalidSignature`` on failure.
    """
    parsed = parse_gpu_report(report)
    r = int.from_bytes(parsed.signature[:48], "big")
    s = int.from_bytes(parsed.signature[48:], "big")
    der = utils.encode_dss_signature(r, s)
    pub = leaf_cert.public_key()
    if not isinstance(pub, ec.EllipticCurvePublicKey):
        raise InvalidSignature("leaf attestation key is not an elliptic-curve key")
    pub.verify(der, parsed.signed_body, ec.ECDSA(hashes.SHA384()))


# SPDM 1.1 GET_MEASUREMENTS transcript, as NVIDIA's report carries it: a 37-byte
# request (4-byte header, 32-byte nonce, slot id), then the response header,
# measurement record, responder nonce, opaque data and the signature.
_SPDM_REQUEST_LEN = 4 + _NONCE_LEN + 1
_SPDM_GET_MEASUREMENTS = 0xE0
_SPDM_MEASUREMENTS = 0x60
_OPAQUE_DRIVER_VERSION = 3
_OPAQUE_VBIOS_VERSION = 6
# Device-certificate chip prefix -> the architecture name nvattest reports.
_ARCH_BY_CHIP_PREFIX = {"GH": "HOPPER", "GB": "BLACKWELL"}


def parse_gpu_opaque_fields(report: bytes) -> dict[int, bytes]:
    """Return the SPDM opaque-data fields of an NVIDIA report, by field id.

    Strict: the response must follow the request immediately, every length must
    land inside the report, and the opaque data must end exactly where the
    signature starts, so no byte between them is unaccounted for. Raises
    ``GpuReportFormatError`` otherwise. A repeated field id is refused rather
    than resolved, since either choice would let the sender pick.
    """
    end = len(report) - _SIG_LEN
    if end < _SPDM_REQUEST_LEN + 8 or report[1] != _SPDM_GET_MEASUREMENTS:
        raise GpuReportFormatError("report is not an SPDM GET_MEASUREMENTS transcript")
    pos = _SPDM_REQUEST_LEN
    if report[pos + 1] != _SPDM_MEASUREMENTS:
        raise GpuReportFormatError("report carries no SPDM MEASUREMENTS response")
    record_len = int.from_bytes(report[pos + 5 : pos + 8], "little")
    pos += 8 + record_len + _NONCE_LEN
    if pos + 2 > end:
        raise GpuReportFormatError("SPDM measurement record overruns the report")
    opaque_len = int.from_bytes(report[pos : pos + 2], "little")
    pos += 2
    if pos + opaque_len != end:
        raise GpuReportFormatError("SPDM opaque data does not end at the signature")
    fields: dict[int, bytes] = {}
    while pos < end:
        if pos + 4 > end:
            raise GpuReportFormatError("truncated SPDM opaque field header")
        field_id = int.from_bytes(report[pos : pos + 2], "little")
        size = int.from_bytes(report[pos + 2 : pos + 4], "little")
        pos += 4
        if pos + size > end:
            raise GpuReportFormatError("SPDM opaque field overruns the opaque data")
        if field_id in fields:
            raise GpuReportFormatError(f"SPDM opaque field {field_id} is repeated")
        fields[field_id] = report[pos : pos + size]
        pos += size
    return fields


def _format_vbios(value: bytes) -> str:
    # NVIDIA's own formatting: the low four bytes big-endian, then the fifth.
    if len(value) != 8:
        raise GpuReportFormatError("VBIOS version field is not 8 bytes")
    return ".".join(f"{b:02X}" for b in (value[3], value[2], value[1], value[0], value[4]))


def _format_driver(value: bytes) -> str:
    text = value.split(b"\x00", 1)[0]
    try:
        driver = text.decode("ascii")
    except UnicodeDecodeError as exc:
        raise GpuReportFormatError("driver version field is not ASCII") from exc
    if not driver or not driver.isprintable() or ";" in driver or "=" in driver:
        raise GpuReportFormatError("driver version field is empty or malformed")
    return driver


def _arch_from_leaf(leaf_cert: x509.Certificate) -> str:
    names = leaf_cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    chip = str(names[0].value).split(" ", 1)[0] if names else ""
    arch = _ARCH_BY_CHIP_PREFIX.get(chip[:2])
    if arch is None:
        raise GpuReportFormatError(
            f"device certificate names chip {chip!r}, whose architecture is not known"
        )
    return arch


def gpu_measurement_from_report(report: bytes, leaf_cert: x509.Certificate) -> str:
    """The GPU identity the signed report states, in ``rim_pin`` form.

    Call only on a report whose signature has verified under ``leaf_cert``.
    """
    fields = parse_gpu_opaque_fields(report)
    try:
        driver = _format_driver(fields[_OPAQUE_DRIVER_VERSION])
        vbios = _format_vbios(fields[_OPAQUE_VBIOS_VERSION])
    except KeyError as exc:
        raise GpuReportFormatError(
            f"signed report has no SPDM opaque field {exc.args[0]}"
        ) from exc
    return f"nvidia-rim:arch={_arch_from_leaf(leaf_cert)};driver={driver};vbios={vbios}"


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class NvidiaGpuVerifier:
    """Verifies an NVIDIA CC GPU attestation: cert chain, signature, nonce.

    Verification steps, all against the real on-wire format:
      1. the device cert chain (leaf -> intermediates) chains to a trusted
         NVIDIA device root in ``trust_store``;
      2. the report signature verifies under the leaf key;
      3. the raw 32-byte nonce echoed in the report equals the expected nonce.
    """

    def __init__(self, trust_store: TrustStore) -> None:
        self._trust = trust_store

    def verify(
        self,
        evidence_b64: str,
        *,
        expected_nonce: str,
        now: Optional[datetime] = None,
    ) -> QuoteVerification:
        """Verify GPU evidence.

        ``evidence_b64`` is base64(JSON) with ``report_b64`` (the raw report) and
        ``cert_chain_pem`` (the PEM device cert chain, leaf first). ``expected_nonce``
        is the KBS challenge nonce (hex); it must appear raw at offset 4 in the
        report, which is what binds this report to the CPU quote's shared nonce.
        """
        current = now if now is not None else _utcnow()
        try:
            doc = json.loads(base64.b64decode(evidence_b64))
            report = base64.b64decode(doc["report_b64"])
            certs = load_pem_certificates(doc["cert_chain_pem"].encode())
        except RecursionError as exc:
            # RecursionError is json.loads on deeply nested input.
            return QuoteVerification(False, f"unparseable GPU evidence: {type(exc).__name__}")
        except (KeyError, ValueError, TypeError, AttributeError, binascii.Error) as exc:
            return QuoteVerification(False, f"unparseable GPU evidence: {exc}")
        if not certs:
            return QuoteVerification(False, "GPU evidence carries no certificate chain")

        leaf = certs[0]
        chain_error = verify_cert_chain(leaf, certs[1:], self._trust, current)
        if chain_error is not None:
            return QuoteVerification(False, chain_error)

        try:
            verify_gpu_report_signature(report, leaf)
        except GpuReportFormatError as exc:
            return QuoteVerification(False, str(exc))
        except InvalidSignature:
            return QuoteVerification(
                False, "GPU report signature does not verify under the leaf key"
            )
        except (ValueError, UnsupportedAlgorithm) as exc:
            return QuoteVerification(
                False, f"GPU report signature verification failed: {type(exc).__name__}"
            )

        try:
            expected = bytes.fromhex(expected_nonce)
        except ValueError:
            return QuoteVerification(False, "expected_nonce is not valid hex")
        actual = report[NVIDIA_NONCE_OFFSET : NVIDIA_NONCE_OFFSET + _NONCE_LEN]
        if actual != expected:
            return QuoteVerification(
                False, "GPU report does not bind the challenge nonce (raw nonce mismatch)"
            )

        # Read only after the signature verified, so every byte is NVIDIA's. A
        # report whose identity cannot be read still verifies; the KBS refuses
        # to match a measurement pin against it (see kbs._check_gpu).
        try:
            measurement: Optional[str] = gpu_measurement_from_report(report, leaf)
        except GpuReportFormatError:
            measurement = None
        return QuoteVerification(
            True, leaf_subject=leaf.subject.rfc4514_string(), gpu_measurement=measurement
        )


def build_gpu_verifier(device_root_pem: Union[str, bytes]) -> NvidiaGpuVerifier:
    """Build a verifier trusting ``device_root_pem`` (NVIDIA's device-identity root).

    WCM ships only the public root (see ``tests/fixtures/nvidia_device_identity_ca.pem``),
    mirroring the AMD/Intel root-only stance in ``_quote_verify``. Pass the result
    as ``KeyBrokerService(gpu_report_verifier=...)``.
    """
    store = TrustStore()
    store.add_root_pem(device_root_pem.decode() if isinstance(device_root_pem, bytes) else device_root_pem)
    return NvidiaGpuVerifier(store)
