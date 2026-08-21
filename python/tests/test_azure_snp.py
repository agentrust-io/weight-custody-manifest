"""AzureSnpVtpmProvider: what's testable without an Azure CVM.

The vTPM fetch only runs on-guest; CI covers availability detection, fail-closed
behavior off-guest, and the HCL-extraction + report-parsing path via a mocked
fetch (a synthetic HCL wrapping a synthetic SNP report).
"""
from __future__ import annotations

import base64
import json
import struct
import subprocess

import pytest

from wcm import AzureSnpVtpmProvider, AttestationUnavailableError, ChallengeStore


def _challenge():
    return ChallengeStore().issue()


def _synth_hcl(chip: bytes = b"\x5a" * 8) -> bytes:
    report = bytearray(0x4A0)  # 1184-byte SNP report
    struct.pack_into("<I", report, 0, 3)  # version 3
    report[0x1A0 : 0x1A0 + 8] = chip  # CHIP_ID head
    return b"HCLA" + b"\x00" * 28 + bytes(report) + b"runtime-data-trailer"


def test_unavailable_off_guest(monkeypatch):
    monkeypatch.setattr(AzureSnpVtpmProvider, "_TPM_DEV", "/wcm-test/no-tpmrm0")
    assert AzureSnpVtpmProvider.is_available() is False


def test_cpu_quote_raises_off_guest(monkeypatch):
    monkeypatch.setattr("wcm._hw_providers.shutil.which", lambda _name: None)
    p = AzureSnpVtpmProvider()  # real _fetch_hcl -> no tpm2_nvread
    with pytest.raises(AttestationUnavailableError):
        p.cpu_quote(_challenge(), serving_image_measurement="sha256:" + "0" * 64)


def test_parse_path_with_mocked_fetch():
    p = AzureSnpVtpmProvider()
    hcl = _synth_hcl()
    p._fetch_hcl = lambda: hcl  # type: ignore[method-assign]
    p._measure_workload = lambda measurement: None  # type: ignore[method-assign]
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


def test_measured_launch_resets_then_extends_pcr23(monkeypatch):
    commands = []
    monkeypatch.setattr("wcm._hw_providers.shutil.which", lambda name: f"/usr/bin/{name}")

    def run(command, **kwargs):
        commands.append((command, kwargs))
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr("wcm._hw_providers.subprocess.run", run)
    digest = "5e2d" * 16
    AzureSnpVtpmProvider()._measure_workload(f"sha256:{digest}")
    assert [command for command, _ in commands] == [
        ["tpm2_pcrreset", "23"],
        ["tpm2_pcrextend", f"23:sha256={digest}"],
    ]
    assert all(kwargs == {"capture_output": True, "timeout": 30, "check": True} for _, kwargs in commands)


@pytest.mark.parametrize(
    "measurement",
    [
        "sha384:" + "0" * 64,
        "sha256:" + "A" * 64,
        "sha256:" + "g" * 64,
        "sha256:short",
    ],
)
def test_measured_launch_rejects_noncanonical_measurement(measurement):
    with pytest.raises(AttestationUnavailableError, match="measured launch|measured-launch"):
        AzureSnpVtpmProvider()._measure_workload(measurement)


def test_measured_launch_fails_closed_when_tool_is_missing(monkeypatch):
    monkeypatch.setattr(
        "wcm._hw_providers.shutil.which",
        lambda name: None if name == "tpm2_pcrextend" else f"/usr/bin/{name}",
    )
    with pytest.raises(AttestationUnavailableError, match="tpm2_pcrextend"):
        AzureSnpVtpmProvider()._measure_workload("sha256:" + "0" * 64)


def test_measured_launch_fails_closed_when_reset_fails(monkeypatch):
    monkeypatch.setattr("wcm._hw_providers.shutil.which", lambda name: f"/usr/bin/{name}")

    def fail(*args, **kwargs):
        raise subprocess.CalledProcessError(1, args[0])

    monkeypatch.setattr("wcm._hw_providers.subprocess.run", fail)
    with pytest.raises(AttestationUnavailableError, match="reset/extend failed"):
        AzureSnpVtpmProvider()._measure_workload("sha256:" + "0" * 64)
