"""Capture a REAL AMD SEV-SNP quote bundle on an Azure confidential VM.

Run this ON a running Azure SEV-SNP CVM (e.g. Standard_DC2as_v5, a few cents an
hour, no special quota). It reads the SNP report the paravisor exposes through
the vTPM, fetches the VCEK certificate chain, and writes a bundle JSON that
`examples/snp_replay.py` verifies OFFLINE afterward, anywhere.

    sudo apt-get install -y tpm2-tools
    python3 tools/capture_snp_quote.py --out snp_quote_azure.json
    # copy snp_quote_azure.json off the VM, tear the VM down, then:
    python examples/snp_replay.py snp_quote_azure.json

Azure freshness topology (important, and reflected in the bundle):
  Azure CVMs do NOT expose /dev/sev-guest, so the guest cannot write our KBS
  nonce into the SNP report's REPORT_DATA. The paravisor binds REPORT_DATA to the
  vTPM attestation key instead; freshness for a live exchange comes from a
  separate vTPM quote over that AK. So this bundle sets `expected_nonce: null`
  and the replay verifies the chain and report signature (genuine on Azure), not
  a guest nonce. A bare-metal /dev/sev-guest capture would set a real nonce.

This tool has host-specific side effects (reads the vTPM, calls the local Azure
metadata/THIM endpoint) and only runs on the CVM, so it is not imported by the
package or exercised in CI. The offline replay it feeds is what CI covers.
"""
from __future__ import annotations

import argparse
import base64
import json
import subprocess  # nosec B404 - deliberate local tpm2-tools invocation on the CVM
import urllib.request

# vTPM NV index where the Azure paravisor stores the HCL report (SNP report at
# offset 32 inside an "HCLA"-tagged wrapper). Established during hw validation.
HCL_NV_INDEX = "0x01400001"
# THIM (Tenant Hardware Identity Management) endpoint on the Azure host: serves
# the VCEK + AMD chain for this specific CPU. Local link-local address.
THIM_URL = "http://169.254.169.254/metadata/THIM/amd/certification"


def read_hcl_via_tpm() -> bytes:
    """Read the raw HCL blob from the vTPM NV index using tpm2-tools."""
    # 0x01400001 is ownerread on the Azure vTPM, so read via the owner hierarchy
    # (-C o); a plain read fails with a TPM auth error (0x9a2). Validated live.
    subprocess.run(  # nosec B603 B607
        ["tpm2_nvread", "-C", "o", "-o", "/tmp/hcl.bin", HCL_NV_INDEX], check=True  # nosec B108
    )
    with open("/tmp/hcl.bin", "rb") as fh:  # nosec B108
        return fh.read()


def fetch_thim_chain() -> dict:
    """Fetch the VCEK + ASK/ARK certs for this CPU from the Azure THIM endpoint."""
    req = urllib.request.Request(THIM_URL, headers={"Metadata": "true"})
    with urllib.request.urlopen(req, timeout=10) as resp:  # nosec B310 - fixed link-local host
        return json.loads(resp.read().decode())


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", default="snp_quote_azure.json")
    ap.add_argument(
        "--hcl-file",
        help="read the HCL blob from a file instead of the vTPM (for a two-step capture)",
    )
    args = ap.parse_args()

    # Import here so the offline replay path never needs the SDK's parser present
    # on the capture host in an odd state; on the CVM the package is installed.
    from wcm import extract_snp_report_from_hcl

    if args.hcl_file:
        hcl = open(args.hcl_file, "rb").read()
    else:
        hcl = read_hcl_via_tpm()
    report = extract_snp_report_from_hcl(hcl)

    thim = fetch_thim_chain()
    # THIM returns PEM strings; field names vary by API version, so accept a few.
    vcek_pem = thim.get("vcekCert") or thim.get("vcek") or thim["vcekCertificate"]
    chain_pem = thim.get("certificateChain") or thim.get("chain") or ""

    bundle = {
        "kind": "wcm-snp-quote-bundle/v1",
        "source": "azure-sev-snp-vtpm",
        "note": "Genuine Azure SEV-SNP report via the vTPM (NV 0x01400001). REPORT_DATA "
        "is paravisor-bound to the vTPM AK, not a guest nonce, so expected_nonce is null.",
        "report_b64": base64.b64encode(report).decode(),
        "vcek_pem": vcek_pem,
        # Split a bundled chain into individual PEMs; ARK (self-signed) becomes root.
        "intermediates_pem": _split_pems(chain_pem)[:-1],
        "root_pem": _split_pems(chain_pem)[-1] if chain_pem else "",
        "expected_nonce": None,
        "expected_measurement": None,
    }
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(bundle, fh, indent=2)
    print(f"wrote {args.out} ({len(report)} report bytes). Verify offline with:")
    print(f"  python examples/snp_replay.py {args.out}")
    return 0


def _split_pems(blob: str) -> list[str]:
    marker = "-----END CERTIFICATE-----"
    parts = [p + marker + "\n" for p in blob.split(marker) if "BEGIN CERTIFICATE" in p]
    return parts


if __name__ == "__main__":
    raise SystemExit(main())
