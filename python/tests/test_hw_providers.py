"""Hardware providers: what CAN be verified without real silicon.

CI has no /dev/sev-guest, /dev/tdx-guest, or NVIDIA tool, so these cover:
availability detection, the software fallback, report *parsing* against
synthetic fixtures (validating the offsets against our own bytes, not real
hardware), and the full producer -> KBS gate path with faked device I/O.
"""
from __future__ import annotations

import base64
import json

import pytest

from wcm import (
    AttestationUnavailableError,
    ChallengeStore,
    HardwareCompositeProvider,
    KeyBrokerService,
    NvidiaCcProvider,
    SevSnpProvider,
    SoftwareProvider,
    TdxProvider,
    select_cpu_provider,
    select_provider,
)

KEY = b"hw-released-decryption-key-32byte"


@pytest.fixture(autouse=True)
def _no_nvidia_env(monkeypatch):
    monkeypatch.delenv("WCM_NVIDIA_ATTESTATION_CMD", raising=False)


def _challenge():
    return ChallengeStore().issue()


# -- availability / selection (real on CI) -------------------------------------


def test_no_hardware_available_on_ci():
    assert SevSnpProvider.is_available() is False
    assert TdxProvider.is_available() is False
    assert NvidiaCcProvider.is_available() is False
    assert select_cpu_provider() is None


def test_select_provider_falls_back_to_software():
    provider = select_provider(require_hardware=False)
    assert isinstance(provider, SoftwareProvider)


def test_select_provider_require_hardware_raises():
    with pytest.raises(AttestationUnavailableError):
        select_provider(require_hardware=True)


def test_nvidia_available_only_with_env(monkeypatch):
    monkeypatch.setenv("WCM_NVIDIA_ATTESTATION_CMD", "python")  # a binary that exists
    assert NvidiaCcProvider.is_available() is True
    monkeypatch.setenv("WCM_NVIDIA_ATTESTATION_CMD", "definitely-not-a-real-binary-xyz")
    assert NvidiaCcProvider.is_available() is False


# -- SEV-SNP parsing against a synthetic report --------------------------------


def _synthetic_snp(chip_id: bytes = b"\xab" * 8) -> bytes:
    buf = bytearray(4096)
    buf[0x1A0 : 0x1A0 + 8] = chip_id
    return bytes(buf)


def test_sev_snp_parses_synthetic_report():
    p = SevSnpProvider()
    raw = _synthetic_snp()
    p._fetch_report = lambda report_data: raw  # type: ignore[method-assign]
    ch = _challenge()
    quote = p.cpu_quote(ch, serving_image_measurement="sha256:" + "5e2d" * 16)
    assert quote.platform == "amd-sev-snp"
    assert quote.nonce_echo == ch.nonce
    assert quote.attestation_key_id == "vcek:" + (b"\xab" * 8).hex()
    assert base64.b64decode(quote.quote_b64) == raw


def test_sev_snp_unavailable_raises_real():
    # No monkeypatch: the real _fetch_report hits a missing /dev/sev-guest.
    p = SevSnpProvider()
    with pytest.raises(AttestationUnavailableError):
        p.cpu_quote(_challenge(), serving_image_measurement="sha256:" + "0" * 64)


def test_tdx_parses_synthetic_report():
    p = TdxProvider()
    raw = bytes(bytearray(1088))
    p._fetch_report = lambda report_data: raw  # type: ignore[method-assign]
    ch = _challenge()
    quote = p.cpu_quote(ch, serving_image_measurement="sha256:" + "5e2d" * 16)
    assert quote.platform == "intel-tdx"
    assert quote.nonce_echo == ch.nonce
    assert quote.attestation_key_id.startswith("tdx-quote:")


# -- NVIDIA GPU report via a faked tool ----------------------------------------


def test_nvidia_report_parses_tool_output(monkeypatch):
    monkeypatch.setenv("WCM_NVIDIA_ATTESTATION_CMD", "python")
    p = NvidiaCcProvider()
    p._run_tool = lambda nonce_hex: {  # type: ignore[method-assign]
        "measurement": "nvidia-rim:driver+vbios golden measurement id",
        "cc_mode": True,
        "report_b64": "AAAA",
    }
    ch = _challenge()
    report = p.gpu_report(ch)
    assert report.platform == "nvidia-cc-gpu"
    assert report.nonce_echo == ch.nonce
    assert report.cc_mode is True


def test_nvidia_missing_command_raises():
    p = NvidiaCcProvider()  # env not set (autouse fixture cleared it)
    with pytest.raises(AttestationUnavailableError):
        p.gpu_report(_challenge())


def test_tdx_unavailable_raises_real():
    p = TdxProvider()
    with pytest.raises(AttestationUnavailableError):
        p.cpu_quote(_challenge(), serving_image_measurement="sha256:" + "0" * 64)


def test_nvidia_run_tool_success(monkeypatch):
    monkeypatch.setenv("WCM_NVIDIA_ATTESTATION_CMD", "python")

    class _Result:
        stdout = json.dumps({"measurement": "nvidia-rim:xyz", "cc_mode": True})

    monkeypatch.setattr("wcm._hw_providers.subprocess.run", lambda *a, **k: _Result())
    report = NvidiaCcProvider().gpu_report(_challenge())  # real _run_tool path
    assert report.measurement == "nvidia-rim:xyz"


def test_nvidia_missing_measurement_raises(monkeypatch):
    monkeypatch.setenv("WCM_NVIDIA_ATTESTATION_CMD", "python")

    class _Result:
        stdout = json.dumps({"cc_mode": True})  # no measurement

    monkeypatch.setattr("wcm._hw_providers.subprocess.run", lambda *a, **k: _Result())
    with pytest.raises(AttestationUnavailableError):
        NvidiaCcProvider().gpu_report(_challenge())


def test_nvidia_bad_json_raises(monkeypatch):
    monkeypatch.setenv("WCM_NVIDIA_ATTESTATION_CMD", "python")

    class _Result:
        stdout = "not json"

    monkeypatch.setattr(
        "wcm._hw_providers.subprocess.run", lambda *a, **k: _Result()
    )
    p = NvidiaCcProvider()
    with pytest.raises(AttestationUnavailableError):
        p.gpu_report(_challenge())


# -- full producer -> KBS gate path with faked device I/O ----------------------


def test_hardware_composite_releases_through_gate(example_manifest, monkeypatch):
    ams = example_manifest.release_policy.required_serving_image.accepted_measurements
    current = next(m.measurement for m in ams if m.status.value == "current")
    rim = example_manifest.release_policy.required_gpu_measurement.rim_pin

    kbs = KeyBrokerService({example_manifest.weights_hash: KEY})
    challenge = kbs.issue_challenge()

    cpu = SevSnpProvider()
    cpu._fetch_report = lambda report_data: _synthetic_snp()  # type: ignore[method-assign]
    gpu = NvidiaCcProvider()
    gpu._run_tool = lambda nonce_hex: {"measurement": rim, "cc_mode": True}  # type: ignore[method-assign]

    provider = HardwareCompositeProvider(cpu, gpu)
    evidence = provider.produce(challenge, serving_image_measurement=current)

    decision = kbs.verify_and_release(example_manifest, evidence)
    assert decision.released
    assert decision.key == KEY
