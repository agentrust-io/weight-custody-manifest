"""Regenerate the committed synthetic SEV-SNP quote bundle used by the replay demo.

The bundle is a self-consistent (synthetic ARK -> VCEK) SNP report that passes
the FULL WCM verify path offline, so `snp_replay.py` and its test have something
to chew on with no hardware. It is clearly labelled `"source": "synthetic"`; a
real Azure capture (tools/capture_snp_quote.py) produces the same shape with
`"source": "azure-sev-snp-vtpm"` and a genuine VCEK -> ASK -> ARK chain.

Run:  python tools/gen_synthetic_snp_bundle.py
Then: python examples/snp_replay.py            # replays the synthetic bundle
"""
from __future__ import annotations

import base64
import datetime
import hashlib
import json
import pathlib
import struct

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.x509.oid import NameOID

# A fixed demo nonce (what a KBS challenge would be) and launch measurement, so
# the committed bundle is stable across regenerations.
NONCE = "ab" * 32
MEASUREMENT = bytes.fromhex("11" * 48)
CHIP_ID = bytes.fromhex("22" * 64)

OUT = pathlib.Path(__file__).resolve().parent.parent / "tests" / "fixtures" / "snp_quote_synthetic.json"


def _cert(subject: str, issuer: str, subj_key, issuer_key, *, ca: bool) -> x509.Certificate:
    # Wide validity so the demo's real-clock `now` is always in range.
    b = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer)]))
        .public_key(subj_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc))
        .not_valid_after(datetime.datetime(2099, 1, 1, tzinfo=datetime.timezone.utc))
    )
    if ca:
        b = b.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    return b.sign(issuer_key, hashes.SHA384())


def _synth_report(vcek_key) -> bytes:
    body = bytearray(0x2A0)
    struct.pack_into("<I", body, 0x00, 3)  # SNP report version 3
    body[0x50 : 0x50 + 32] = hashlib.sha256(bytes.fromhex(NONCE)).digest()  # REPORT_DATA
    body[0x90 : 0x90 + 48] = MEASUREMENT
    body[0x1A0 : 0x1A0 + 64] = CHIP_ID
    der = vcek_key.sign(bytes(body), ec.ECDSA(hashes.SHA384()))
    r, s = decode_dss_signature(der)
    sig = bytearray(512)  # AMD little-endian r || s
    sig[0:48] = r.to_bytes(48, "little")
    sig[72 : 72 + 48] = s.to_bytes(48, "little")
    return bytes(body) + bytes(sig)


def _pem(cert: x509.Certificate) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def main() -> None:
    root_k = ec.generate_private_key(ec.SECP384R1())
    root = _cert("synthetic-snp-root (stand-in for AMD ARK)", "synthetic-snp-root (stand-in for AMD ARK)", root_k, root_k, ca=True)
    vcek_k = ec.generate_private_key(ec.SECP384R1())
    vcek = _cert("SEV-VCEK (synthetic)", "synthetic-snp-root (stand-in for AMD ARK)", vcek_k, root_k, ca=False)
    report = _synth_report(vcek_k)

    bundle = {
        "kind": "wcm-snp-quote-bundle/v1",
        "source": "synthetic",
        "note": "Self-consistent synthetic ARK->VCEK chain and report. NOT real hardware. "
        "Replace with tools/capture_snp_quote.py output for a genuine Azure SEV-SNP quote.",
        "report_b64": base64.b64encode(report).decode(),
        "vcek_pem": _pem(vcek),
        "intermediates_pem": [],
        "root_pem": _pem(root),
        "expected_nonce": NONCE,
        "expected_measurement": MEASUREMENT.hex(),
    }
    OUT.write_text(json.dumps(bundle, indent=2) + "\n", encoding="utf-8")
    print("wrote", OUT)


if __name__ == "__main__":
    main()
