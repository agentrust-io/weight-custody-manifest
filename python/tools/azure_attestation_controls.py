"""Live Azure SNP/vTPM diagnostic; not native-SNP broker image acceptance.

Use an isolated disposable VM: the provider resets and extends application PCR
23. Roots and both nonces must come from the owner. Raw evidence contains device
identifiers and must stay private; only summary.json is intended for review.
"""
from __future__ import annotations

import argparse
import base64
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import platform

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from wcm import AzureSnpVtpmProvider, AzureSnpVtpmVerifier, Challenge, TrustStore
from wcm import generate_transport_keypair
from wcm.providers import AttestationUnavailableError
from wcm._hw_providers import SevSnpProvider
from wcm.snp import extract_snp_report_from_hcl, parse_snp_report


def nonce(value: str) -> str:
    if len(value) != 64 or bytes.fromhex(value).hex() != value:
        raise ValueError("owner nonce must be canonical 32-byte hex")
    return value


def controls(verifier, encoded, expected_nonce, key, measurement):
    def verify(quote=encoded, challenge=expected_nonce, binding=key, digest=measurement):
        return verifier.verify(quote, expected_nonce=challenge, channel_binding=binding,
                               expected_workload_measurement=digest)

    results = []

    def record(name, result, expected):
        results.append({"case": name, "verified": result.verified,
                        "expected": expected, "reason": result.reason})
        if result.verified != expected:
            raise AssertionError(f"unexpected outcome: {name}: {result.reason}")

    record("positive", verify(), True)
    other_nonce = (bytes([bytes.fromhex(expected_nonce)[0] ^ 1]) + bytes.fromhex(expected_nonce)[1:]).hex()
    record("wrong-nonce", verify(challenge=other_nonce), False)
    record("wrong-transport-key", verify(binding=bytes([key[0] ^ 1]) + key[1:]), False)
    other_digest = "sha256:" + ("0" if measurement[7] != "0" else "1") + measurement[8:]
    record("wrong-workload-digest", verify(digest=other_digest), False)
    for field, offset in (("tpm_signature_b64", -1), ("hcl_b64", 32 + 0x90)):
        doc = json.loads(base64.b64decode(encoded))
        raw = bytearray(base64.b64decode(doc[field]))
        raw[offset] ^= 1
        doc[field] = base64.b64encode(raw).decode()
        altered = base64.b64encode(json.dumps(doc).encode()).decode()
        record("tampered-" + field, verify(quote=altered), False)
    record("untrusted-root", AzureSnpVtpmVerifier(TrustStore()).verify(
        encoded, expected_nonce=expected_nonce, channel_binding=key,
        expected_workload_measurement=measurement), False)
    return results


def run(root: Path, first: str, second: str, output: Path):
    first, second = nonce(first), nonce(second)
    if first == second:
        raise ValueError("distinct owner nonces required")
    output.mkdir(parents=True, exist_ok=False)
    roots = x509.load_pem_x509_certificates(root.read_bytes())
    if len(roots) != 1 or roots[0].issuer != roots[0].subject:
        raise ValueError("exactly one independently pinned AMD root required")
    trust = TrustStore()
    trust.add_root(roots[0])
    verifier = AzureSnpVtpmVerifier(trust)
    if not AzureSnpVtpmProvider.is_available():
        raise RuntimeError("Azure SNP/vTPM unavailable; no software fallback")
    provider = AzureSnpVtpmProvider()
    sample = output / "nonsecret-application-probe.py"
    sample.write_bytes(b"print('approved diagnostic file')\n")
    digest = "sha256:" + hashlib.sha256(sample.read_bytes()).hexdigest()
    _, public = generate_transport_keypair()
    key = bytes.fromhex(public)

    def capture(value):
        now = datetime.now(timezone.utc)
        return provider.cpu_quote(Challenge(value, now, now + timedelta(minutes=5)),
            serving_image_measurement=digest, transport_public_key=public).quote_b64

    quote = capture(first)
    if not quote:
        raise RuntimeError("empty hardware evidence")
    (output / "private-evidence.json").write_text(json.dumps({
        "quote_b64": quote, "nonce": first, "transport_public_key": public,
        "workload_digest": digest}, indent=2) + "\n")
    results = controls(verifier, quote, first, key, digest)
    # Executable counterexample to calling PCR23 an enforced app measurement:
    # this API accepts a caller-provided digest; it does not hash the file.
    sample.write_bytes(b"print('changed diagnostic file')\n")
    changed_digest = "sha256:" + hashlib.sha256(sample.read_bytes()).hexdigest()
    changed_quote = capture(second)
    counterexample = verifier.verify(changed_quote, expected_nonce=second,
        channel_binding=key, expected_workload_measurement=digest)
    if digest == changed_digest or not counterexample.verified:
        raise AssertionError("stale caller-digest counterexample not reproduced")
    (output / "private-counterexample.json").write_text(json.dumps({
        "quote_b64": changed_quote, "nonce": second, "transport_public_key": public,
        "workload_digest": digest, "actual_file_digest": changed_digest}, indent=2) + "\n")
    native_available = True
    try:
        SevSnpProvider().provisioning_report(bytes(64))
    except AttestationUnavailableError:
        native_available = False
    report = parse_snp_report(extract_snp_report_from_hcl(
        base64.b64decode(json.loads(base64.b64decode(quote))["hcl_b64"])))
    summary = {
        "kind": "wcm/azure-live-attestation-controls/v1",
        "captured_at": datetime.now(timezone.utc).isoformat(), "kernel": platform.release(),
        "root_der_sha256": hashlib.sha256(roots[0].public_bytes(serialization.Encoding.DER)).hexdigest(),
        "quote_sha256": hashlib.sha256(base64.b64decode(quote)).hexdigest(),
        "launch_measurement_sha256": hashlib.sha256(report.measurement).hexdigest(),
        "devices": {name: Path(name).exists() for name in
                    ("/dev/sev", "/dev/sev-guest", "/dev/kvm", "/dev/tpmrm0")},
        "native_provisioning_interface_available": native_available,
        "controls": results,
        "changed_file_with_stale_caller_digest": {
            "verified": counterexample.verified, "approved_digest": digest,
            "actual_file_digest": changed_digest, "classification": "measurement-enforcement-counterexample"},
        "custom_firmware_loaded": False, "application_identity_established": False,
        "limits": ["Provider firmware, not the restricted OVMF candidate.",
                   "PCR23 authenticates the digest supplied to the provider, not file immutability.",
                   "No native-SNP provisioning acceptance or protected model execution is established.",
                   "This diagnostic does not check certificate revocation."],
    }
    (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, separators=(",", ":")))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--nonce", required=True)
    parser.add_argument("--second-nonce", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    run(args.root, args.nonce, args.second_nonce, args.output)
