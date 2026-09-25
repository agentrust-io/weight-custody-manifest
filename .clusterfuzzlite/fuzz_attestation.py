#!/usr/bin/python3
"""Fuzz the attestation parsers and verifiers.

A key broker hands each of these attacker-supplied bytes before it has decided
to trust anything about them: a TDX quote with nested declared lengths, an SNP
report and its Azure HCL wrapper, an NVIDIA GPU report, and the base64 JSON
bundles the CPU and GPU verifiers take.

The property is that each one fails closed. A parser returns or raises the
error type its module declares; a verifier returns a ``QuoteVerification``
that is not verified (the trust store holds a root nothing chains to). Any
other exception reaching the caller means a length field or a JSON shape was
believed, and the release path does not catch it.
"""
import base64
import sys

import atheris

with atheris.instrument_imports():
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    import datetime

    from wcm import AzureSnpVtpmVerifier, JsonQuoteParser, QuoteVerifier, TrustStore
    from wcm._quote_verify import QuoteFormatError
    from wcm.nvidia import GpuReportFormatError, NvidiaGpuVerifier, parse_gpu_report
    from wcm.snp import extract_snp_report_from_hcl, parse_snp_report
    from wcm.tdx import parse_tdx_quote, verify_tdx_quote


def _unrelated_root() -> x509.Certificate:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "wcm-fuzz-root")])
    now = datetime.datetime.now(datetime.timezone.utc)
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )


_TRUST = TrustStore()
_TRUST.add_root(_unrelated_root())
_NONCE = "ab" * 32
_MEASUREMENT = "sha256:" + "42" * 32

# (parser, the exception it is allowed to raise)
_PARSERS = [
    (parse_tdx_quote, QuoteFormatError),
    (parse_snp_report, QuoteFormatError),
    (extract_snp_report_from_hcl, QuoteFormatError),
    (parse_gpu_report, GpuReportFormatError),
]


def _verifiers(blob: bytes) -> None:
    text = base64.b64encode(blob).decode()
    results = [
        verify_tdx_quote(blob, _TRUST, expected_nonce=_NONCE),
        AzureSnpVtpmVerifier(_TRUST).verify(
            text, expected_nonce=_NONCE, expected_workload_measurement=_MEASUREMENT
        ),
        QuoteVerifier(JsonQuoteParser(), _TRUST).verify(text, expected_nonce=_NONCE),
        NvidiaGpuVerifier(_TRUST).verify(text, expected_nonce=_NONCE),
    ]
    for result in results:
        if result.verified:
            raise AssertionError("evidence verified against a root nothing chains to")


def TestOneInput(data: bytes) -> None:
    if not data:
        return
    fdp = atheris.FuzzedDataProvider(data)
    choice = fdp.ConsumeIntInRange(0, len(_PARSERS))
    blob = fdp.ConsumeBytes(fdp.remaining_bytes())
    if choice == len(_PARSERS):
        _verifiers(blob)
        return
    parser, declared = _PARSERS[choice]
    try:
        parser(blob)
    except declared:
        pass


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
