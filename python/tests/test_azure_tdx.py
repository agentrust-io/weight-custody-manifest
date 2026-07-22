"""AzureTdxVtpmProvider: what's testable without an Azure TDX CVM.

The vTPM read and the IMDS /acc/tdquote call only run on-guest; CI covers
availability detection, fail-closed behavior off-guest, and the
HCL -> TD report -> quote plumbing via mocked fetches.
"""
from __future__ import annotations

import base64

import pytest

from wcm import AttestationUnavailableError, AzureTdxVtpmProvider, ChallengeStore


def _challenge():
    return ChallengeStore().issue()


def _synth_hcl_tdx() -> bytes:
    # HCLA header, then a TD report at offset 32 whose REPORTMACSTRUCT TYPE byte
    # is 0x81 (TDX) - the marker AzureTdxVtpmProvider keys on.
    body = bytearray(2600)
    body[:4] = b"HCLA"
    body[32] = 0x81
    body[33:64] = bytes(range(31))  # arbitrary TD report bytes
    return bytes(body)


def test_unavailable_off_guest():
    # No /dev/tpmrm0 on CI/Windows, so the Azure TDX provider is not available.
    assert AzureTdxVtpmProvider.is_available() is False


def test_cpu_quote_raises_off_guest():
    p = AzureTdxVtpmProvider()  # real _fetch_hcl -> no tpm2_nvread
    with pytest.raises(AttestationUnavailableError):
        p.cpu_quote(_challenge(), serving_image_measurement="sha256:" + "0" * 64)


def test_plumbing_with_mocked_fetches():
    p = AzureTdxVtpmProvider()
    hcl = _synth_hcl_tdx()
    captured = {}

    def fake_quote(tdreport: bytes) -> bytes:
        captured["tdreport"] = tdreport
        return b"FAKE-DCAP-TD-QUOTE-BYTES"

    p._fetch_hcl = lambda: hcl  # type: ignore[method-assign]
    p._fetch_quote = fake_quote  # type: ignore[method-assign]

    ch = _challenge()
    quote = p.cpu_quote(ch, serving_image_measurement="sha256:" + "ab" * 32)
    assert quote.platform == "intel-tdx"
    assert quote.nonce_echo == ch.nonce
    assert quote.attestation_key_id == "tdx-quote:azure-vtpm"
    # The TD report handed to the quote service is the 1024 bytes at HCL offset 32.
    assert len(captured["tdreport"]) == 1024
    assert captured["tdreport"][0] == 0x81
    assert base64.b64decode(quote.quote_b64) == b"FAKE-DCAP-TD-QUOTE-BYTES"
