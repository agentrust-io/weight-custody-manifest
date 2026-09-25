"""Capture NVIDIA OCSP answers for a committed GPU attestation chain.

Reproduction tool for the fixtures under ``tests/fixtures/nvidia/ocsp``. It asks
NVIDIA's public responder about every certificate in a chain, once with a nonce
and once without, and writes the DER answers plus a manifest of what was asked.

No GPU is required. The responder is a public endpoint and the chain is already
committed; this only needs outbound network access.

    python tools/capture_gpu_ocsp.py tests/fixtures/gpu_h100_attestation.json \
        --out tests/fixtures/nvidia/ocsp

Answers carry a ``nextUpdate`` a day out, so the tests that use them pin a fixed
``now`` rather than reading the clock. Re-running this tool refreshes the bytes
but does not change what the tests assert.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import time
import urllib.request
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import ocsp
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtensionOID

RESPONDER = "http://ocsp.ndis.nvidia.com"
LABELS = ("fmc_leaf", "brom", "provisioner_ica", "identity_ca")


def responder_for(certificate: x509.Certificate) -> str:
    """The certificate's own OCSP URL, or NVIDIA's responder when it names none."""
    try:
        aia = certificate.extensions.get_extension_for_oid(
            ExtensionOID.AUTHORITY_INFORMATION_ACCESS
        ).value
        for access in aia:
            if access.access_method == AuthorityInformationAccessOID.OCSP:
                return access.access_location.value
    except x509.ExtensionNotFound:
        pass
    return RESPONDER


def ask(certificate: x509.Certificate, issuer: x509.Certificate,
        nonce: bytes | None, timeout: int) -> bytes:
    builder = ocsp.OCSPRequestBuilder().add_certificate(certificate, issuer, hashes.SHA384())
    if nonce is not None:
        builder = builder.add_extension(x509.OCSPNonce(nonce), critical=False)
    body = builder.build().public_bytes(serialization.Encoding.DER)
    url = responder_for(certificate)
    # The responder intermittently resets a connection. Retry here, in the
    # capture tool, and nowhere else: for the verifier a reset is an answer it
    # did not get, which is a refusal, and retrying inside it would quietly turn
    # fail-closed into fail-eventually.
    last = None
    for attempt in range(4):
        try:
            request = urllib.request.Request(
                url, data=body, headers={"Content-Type": "application/ocsp-request"},
            )
            with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
                return response.read()
        except Exception as exc:  # noqa: BLE001 - captured and reported below
            last = exc
            time.sleep(0.5 * (attempt + 1))
    raise RuntimeError(f"the responder did not answer after four attempts: {last}")


def common_name(certificate: x509.Certificate) -> str:
    """The CN alone.

    Deliberately not the full RFC4514 subject: for a device certificate that
    carries the serialNumber attribute (OID 2.5.4.5), which identifies one
    physical GPU and has no business in a committed manifest.
    """
    names = certificate.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    return str(names[0].value) if names else "(no common name)"


def describe(raw: bytes) -> dict:
    answer = ocsp.load_der_ocsp_response(raw)
    if answer.response_status != ocsp.OCSPResponseStatus.SUCCESSFUL:
        return {"response_status": answer.response_status.name, "bytes": len(raw)}
    return {
        "response_status": answer.response_status.name,
        "certificate_status": answer.certificate_status.name,
        "this_update": answer.this_update_utc.isoformat(),
        "next_update": answer.next_update_utc.isoformat() if answer.next_update_utc else None,
        "responder_common_name": (common_name(answer.certificates[0])
                                  if answer.certificates else None),
        "bytes": len(raw),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("attestation", type=pathlib.Path,
                        help="a JSON attestation carrying cert_chain_pem")
    parser.add_argument("--out", type=pathlib.Path, required=True)
    parser.add_argument("--timeout", type=int, default=20)
    args = parser.parse_args()

    document = json.loads(args.attestation.read_text(encoding="utf-8"))
    chain = x509.load_pem_x509_certificates(document["cert_chain_pem"].encode())
    args.out.mkdir(parents=True, exist_ok=True)

    manifest = {
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "responder": RESPONDER,
        "source_attestation": args.attestation.name,
        "certid_hash": "SHA384",
        "answers": [],
    }
    # The root is asked about by nobody: it is the trust anchor, and a chain
    # never carries a question about its own anchor.
    for index in range(len(chain) - 1):
        certificate, issuer = chain[index], chain[index + 1]
        label = LABELS[index] if index < len(LABELS) else f"link{index}"
        nonce = os.urandom(32)
        for suffix, value in (("nonce", nonce), ("nononce", None)):
            raw = ask(certificate, issuer, value, args.timeout)
            name = f"{label}_{suffix}.der"
            (args.out / name).write_bytes(raw)
            # No serial numbers and no full subjects: a device certificate's
            # serialNumber attribute names one physical GPU. The digest pins the
            # bytes, which is what a fixture actually needs.
            entry = {
                "file": name,
                "label": label,
                "asked_common_name": common_name(certificate),
                "nonce_sent": value is not None,
                "sha256": hashlib.sha256(raw).hexdigest(),
            }
            entry.update(describe(raw))
            manifest["answers"].append(entry)
            print(f"{name:28s} {entry.get('certificate_status', entry['response_status']):14s} "
                  f"{entry['bytes']:5d} bytes")
    (args.out / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("\nwrote", args.out / "manifest.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
