"""NVIDIA Confidential Computing (Hopper H100) GPU attestation verification.

The GPU is a SECOND attestation chain alongside the CPU CVM quote (see
``attestation`` and ``kbs``): an H100 in CC mode produces an SPDM-based
attestation report signed by an on-die attestation key, carried with a device
certificate chain that roots in NVIDIA's device-identity CA. NVIDIA's local
verifier (nvtrust) or the remote NRAS service checks the chain, the report
signature, a freshness nonce, and the measurements against a golden RIM.

WCM verifies the GPU report with the SAME machinery as the CPU quote
(``_quote_verify.QuoteVerifier``): cert chain -> a trusted root, report
signature by the leaf key, and nonce binding (REPORT_DATA == sha256(nonce)). The
GPU report is bound to the CPU quote by the shared KBS nonce (the composite
check in ``kbs._check_gpu``), so a valid GPU paired with a mismatched CPU is
rejected. Plug the verifier below into ``KeyBrokerService(gpu_report_verifier=)``
to cryptographically verify the GPU chain instead of trusting the structured
fields alone.

Honesty, matching ``_quote_verify``: this module ships NO NVIDIA root
certificate, and the binary SPDM report offsets are PROVISIONAL until validated
against a real H100 capture (Azure ``NCC40ads_H100_v5``). The reference parser
consumes the same tested JSON container as ``JsonQuoteParser``; a real binary
parser with confirmed offsets is a tracked follow-up once we have captured
evidence. The caller supplies NVIDIA's device root (``build_gpu_verifier``). And
as everywhere in WCM, a physically-extracted attestation key still produces a
genuinely-valid signature (the key-extraction half of open question 8.8); this
raises the bar to a real hardware signature, it does not defeat a hardware owner.
"""
from __future__ import annotations

from typing import Optional

from ._quote_verify import JsonQuoteParser, QuoteParser, QuoteVerifier, TrustStore

# Where the 32-byte REPORT_DATA (carrying sha256(nonce)) sits in the GPU report
# body. PROVISIONAL: confirming this against a real H100 SPDM report is part of
# the hardware-validation follow-up; the reference container carries the offset
# explicitly so tests do not depend on this default.
NVIDIA_REPORT_DATA_OFFSET = 0


class NvidiaCcReportParser(JsonQuoteParser):
    """Parses an NVIDIA CC GPU report into a ``ParsedQuote``.

    Reference container (the same tested shape as ``JsonQuoteParser``):
    base64(JSON) with ``report_b64`` / ``signature_b64`` / ``leaf_pem`` /
    ``intermediates_pem`` / ``report_data_offset``. The real SPDM binary parser
    (fixed NVIDIA offsets, device cert chain extraction) is a follow-up pending a
    captured H100 report; the verification machinery it feeds is already tested.
    """


def build_gpu_verifier(
    device_root_pem: str, parser: Optional[QuoteParser] = None
) -> QuoteVerifier:
    """Build a verifier for NVIDIA CC GPU reports.

    ``device_root_pem`` is NVIDIA's device-identity root CA, supplied by the
    caller (WCM ships none, mirroring the AMD/Intel stance in ``_quote_verify``).
    The returned ``QuoteVerifier`` checks the GPU report's cert chain to that
    root, the report signature, and the nonce binding; pass it as
    ``KeyBrokerService(gpu_report_verifier=...)``.
    """
    store = TrustStore()
    store.add_root_pem(device_root_pem)
    return QuoteVerifier(parser or NvidiaCcReportParser(), store)
