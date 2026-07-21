"""Replay a captured AMD SEV-SNP quote through the full WCM verification path.

    python examples/snp_replay.py                         # the committed synthetic bundle
    python examples/snp_replay.py path/to/snp_quote.json  # a real captured bundle

This is the CPU half of Layer 2's composite verification (SPEC 3.2), run OFFLINE
against a recorded quote. It exercises exactly the code a KBS runs before
releasing a key: parse the SNP report, verify the VCEK -> ASK -> ARK certificate
chain to a trusted AMD root, verify the report's own signature under the VCEK,
and confirm REPORT_DATA binds the challenge nonce (anti-replay).

A "bundle" is the evidence a KBS would receive, captured to a JSON file so the
verification is reproducible with no hardware:

    { "kind": "wcm-snp-quote-bundle/v1", "source": "...",
      "report_b64": "...",            # raw SNP report bytes, base64
      "vcek_pem": "...",              # leaf cert that signed the report
      "intermediates_pem": ["..."],   # ASK (empty for the synthetic root)
      "root_pem": "...",              # trusted root (real AMD ARK, or synthetic)
      "expected_nonce": "hex|null",   # guest-controlled REPORT_DATA nonce, or null
      "expected_measurement": "hex" } # optional launch measurement to assert

Two freshness topologies, and the demo handles both honestly:

  * Guest-controlled REPORT_DATA (bare-metal /dev/sev-guest, and the synthetic
    bundle): the guest writes sha256(nonce) into REPORT_DATA, so the KBS's nonce
    gate applies directly. `expected_nonce` is set.
  * Azure CVM vTPM path: REPORT_DATA is paravisor-bound to the vTPM attestation
    key, NOT to our KBS nonce, so freshness comes from a separate vTPM quote over
    the AK (one layer up). `expected_nonce` is null; the demo verifies the chain
    and report signature (which ARE genuine on Azure) and reports the AK binding
    rather than pretending the SNP report itself binds our nonce.

The committed default bundle is `source: synthetic` (a self-consistent stand-in
chain, NOT real silicon) so the demo runs anywhere. Capture a genuine one on an
Azure SEV-SNP CVM with tools/capture_snp_quote.py.
"""
from __future__ import annotations

import base64
import datetime
import json
import pathlib
import sys

from cryptography import x509

from wcm import (
    QuoteVerifier,
    SnpQuoteParser,
    TrustStore,
    parse_snp_report,
    verify_cert_chain,
    verify_snp_report_signature,
)

DEFAULT_BUNDLE = pathlib.Path(__file__).resolve().parent.parent / "tests" / "fixtures" / "snp_quote_synthetic.json"


def rule(title: str) -> None:
    print(f"\n{'=' * 70}\n{title}\n{'=' * 70}")


def load_bundle(path: pathlib.Path) -> dict:
    bundle = json.loads(path.read_text(encoding="utf-8"))
    if bundle.get("kind") != "wcm-snp-quote-bundle/v1":
        raise SystemExit(f"{path}: not a wcm-snp-quote-bundle/v1")
    return bundle


def main() -> int:
    path = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_BUNDLE
    bundle = load_bundle(path)

    rule(f"SEV-SNP quote replay  (source: {bundle['source']})")
    print("bundle    :", path)
    if bundle["source"] == "synthetic":
        print("WARNING   : synthetic bundle, NOT real hardware. This proves the")
        print("            verification path, not a genuine attestation. Capture a real")
        print("            one with tools/capture_snp_quote.py on an Azure SEV-SNP CVM.")
    else:
        print("this is a genuine hardware quote captured from real SEV-SNP silicon.")

    vcek = x509.load_pem_x509_certificate(bundle["vcek_pem"].encode())
    intermediates = [x509.load_pem_x509_certificate(p.encode()) for p in bundle["intermediates_pem"]]
    root = x509.load_pem_x509_certificate(bundle["root_pem"].encode())
    report_b64 = bundle["report_b64"]
    nonce = bundle["expected_nonce"]

    trust = TrustStore()
    trust.add_root(root)
    report = base64.b64decode(report_b64)

    if nonce:
        # Guest-controlled REPORT_DATA: the KBS's full gate applies, nonce and all.
        rule("Step 1 - The gate the KBS runs (parse + chain + signature + nonce)")
        result = QuoteVerifier(SnpQuoteParser(vcek, intermediates), trust).verify(
            report_b64, expected_nonce=nonce
        )
        print("verified            :", result.verified)
        if not result.verified:
            print("reason              :", result.reason)
            print("\nThe KBS would REFUSE to release the key.")
            return 1
        print("leaf (VCEK) subject :", result.leaf_subject)
        print("checks passed       : VCEK chains to the trusted root; report signature")
        print("                      verifies under the VCEK; REPORT_DATA binds the nonce")
        print(f"                      {nonce[:16]}... (a captured quote for a different")
        print("                      nonce would be rejected as a replay).")
    else:
        # Azure vTPM path: REPORT_DATA binds the vTPM AK, not our nonce. Verify the
        # parts that are genuine on this platform (chain + report signature) and be
        # explicit that freshness lives one layer up, in the vTPM quote over the AK.
        rule("Step 1 - Chain + report signature (Azure vTPM freshness topology)")
        chain_error = verify_cert_chain(vcek, intermediates, trust, datetime.datetime.now(datetime.timezone.utc))
        print("VCEK chains to root :", chain_error is None, "" if chain_error is None else f"({chain_error})")
        sig_ok = verify_snp_report_signature(report, vcek)
        print("report signature ok :", sig_ok)
        if chain_error is not None or not sig_ok:
            print("\nThe KBS would REFUSE to release the key.")
            return 1
        rd = parse_snp_report(report).report_data
        print("REPORT_DATA         :", rd.hex()[:32], "...")
        print("note                : on Azure CVMs REPORT_DATA is paravisor-bound to the")
        print("                      vTPM AK, not our KBS nonce. Freshness comes from a")
        print("                      separate vTPM quote over that AK (SPEC 3.2). This")
        print("                      demo replays the SNP report; the vTPM-quote layer is")
        print("                      not part of the recorded bundle.")

    # Surface the measured fields the manifest's policy would pin.
    rule("Step 2 - Measured fields the manifest pins")
    parsed = parse_snp_report(report)
    print("SNP report version  :", parsed.version)
    print("launch measurement  :", parsed.measurement.hex())
    print("chip id (VCEK)      :", parsed.chip_id.hex()[:32], "...")
    expected_m = bundle.get("expected_measurement")
    if expected_m:
        ok = parsed.measurement.hex() == expected_m
        print("measurement matches manifest expectation:", ok)
        if not ok:
            print("  -> a KBS pinning required launch measurement would refuse here")
            return 1

    rule("What this did and did not prove")
    print("proved   : the SEV-SNP CPU quote is genuine, unmodified, bound to our")
    print("           nonce, and rooted in the trusted AMD chain (Layer 2 CPU half).")
    print("not here  : the separate GPU (NVIDIA CC) report and the CPU-GPU nonce")
    print("           binding (SPEC 3.2 composite verification); GPU needs H100 quota.")
    if bundle["source"] == "synthetic":
        print("not here  : real silicon. Swap in a captured bundle for that.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
