"""AzureSnpVtpmProvider: what's testable without an Azure CVM.

The vTPM fetch only runs on-guest; CI covers availability detection, fail-closed
behavior off-guest, and the HCL-extraction + report-parsing path via a mocked
fetch (a synthetic HCL wrapping a synthetic SNP report).
"""
from __future__ import annotations

import base64
import json
import struct

import pytest

from wcm import AzureSnpVtpmProvider, AttestationUnavailableError, ChallengeStore


def _challenge():
    return ChallengeStore().issue()


def _synth_hcl(chip: bytes = b"\x5a" * 8) -> bytes:
    report = bytearray(0x4A0)  # 1184-byte SNP report
    struct.pack_into("<I", report, 0, 3)  # version 3
    report[0x1A0 : 0x1A0 + 8] = chip  # CHIP_ID head
    return b"HCLA" + b"\x00" * 28 + bytes(report) + b"runtime-data-trailer"


def test_unavailable_off_guest():
    # No /dev/tpmrm0 on CI/Windows, so the Azure provider is not available.
    assert AzureSnpVtpmProvider.is_available() is False


def test_cpu_quote_raises_off_guest():
    p = AzureSnpVtpmProvider()  # real _fetch_hcl -> no tpm2_nvread
    with pytest.raises(AttestationUnavailableError):
        p.cpu_quote(_challenge(), serving_image_measurement="sha256:" + "0" * 64)


def test_parse_path_with_mocked_fetch():
    p = AzureSnpVtpmProvider()
    hcl = _synth_hcl()
    p._fetch_hcl = lambda: hcl  # type: ignore[method-assign]
    p._fetch_freshness_bundle = lambda got, binding: {  # type: ignore[method-assign]
        "kind": "wcm-azure-snp-vtpm/v1",
        "hcl_b64": base64.b64encode(got).decode(),
        "binding": binding.hex(),
    }
    ch = _challenge()
    quote = p.cpu_quote(ch, serving_image_measurement="sha256:" + "5e2d" * 16)
    assert quote.platform == "amd-sev-snp"
    assert quote.nonce_echo == ch.nonce
    assert quote.attestation_key_id == "vcek:" + (b"\x5a" * 8).hex()
    bundle = json.loads(base64.b64decode(quote.quote_b64))
    assert base64.b64decode(bundle["hcl_b64"]) == hcl
    assert len(bytes.fromhex(bundle["binding"])) == 32
