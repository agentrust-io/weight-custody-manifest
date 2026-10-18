"""The ``allowed_platform_instances`` release gate (GHSA-jr5r-w684-fg5m).

Genuine evidence proves a genuine chip, not the operator's chip. The gate pins
release to SEV-SNP CHIP_IDs the operator listed, read only from the report the
CPU quote verifier authenticated. Cases run against the real Azure and GCP
captures in ``fixtures/``, so the CHIP_ID offsets are checked on live silicon.
"""
from __future__ import annotations

import base64
import json
import pathlib

import pytest

from wcm import KeyBrokerService, SoftwareProvider, manifest_identity
from wcm._quote_verify import QuoteVerification
from wcm.snp import parse_snp_report

FIXTURES = pathlib.Path(__file__).parent / "fixtures"
KEY = b"decryption-key-for-these-weights"


def _report(name: str) -> bytes:
    doc = json.loads((FIXTURES / name).read_text())
    return base64.b64decode(doc["report_b64"])


AZURE = _report("snp_quote_azure.json")
GCP = _report("snp_platform_info_gcp_milan.json")
AZURE_CHIP = parse_snp_report(AZURE).chip_id.hex()
GCP_CHIP = parse_snp_report(GCP).chip_id.hex()


class _AuthenticatedReport:
    """Stub verifier: reports *report* as the bytes it authenticated."""

    def __init__(self, report, verified=True):
        self._report = report
        self._verified = verified

    def verify(self, quote_b64, **kwargs):
        if not self._verified:
            return QuoteVerification(False, "stub: not verified", snp_report=self._report)
        return QuoteVerification(True, snp_report=self._report)


def _kbs(manifest, report=None, allowed=None, verified=True):
    return KeyBrokerService(
        {manifest.weights_hash: KEY},
        trusted_manifest_identities={manifest_identity(manifest)},
        cpu_quote_verifier=None if report is None else _AuthenticatedReport(report, verified),
        allowed_platform_instances=allowed,
    )


def _evidence(kbs, manifest, report: bytes, platform: str = "amd-sev-snp"):
    ams = manifest.release_policy.required_serving_image.accepted_measurements
    current = next(m.measurement for m in ams if m.status.value == "current")
    rim = manifest.release_policy.required_gpu_measurement.rim_pin
    evidence = SoftwareProvider().produce(
        kbs.issue_challenge(), serving_image_measurement=current, gpu_measurement=rim,
        platform=platform,
    )
    return evidence.model_copy(
        update={"cpu": evidence.cpu.model_copy(
            update={"quote_b64": base64.b64encode(report).decode()}
        )}
    )


def _check(decision):
    return next(c for c in decision.checks if c.name == "platform_instance_allowed")


def test_live_captures_carry_distinct_unmasked_chip_ids():
    assert len(AZURE_CHIP) == len(GCP_CHIP) == 128
    assert AZURE_CHIP != GCP_CHIP
    assert any(parse_snp_report(AZURE).chip_id)


def test_unset_list_is_not_required(example_manifest):
    kbs = _kbs(example_manifest, AZURE)
    decision = kbs.verify_and_release(example_manifest, _evidence(kbs, example_manifest, AZURE))
    assert _check(decision).passed
    assert _check(decision).detail == "not required"


def test_listed_chip_passes(example_manifest):
    kbs = _kbs(example_manifest, AZURE, allowed=[AZURE_CHIP.upper()])
    decision = kbs.verify_and_release(example_manifest, _evidence(kbs, example_manifest, AZURE))
    assert _check(decision).passed


def test_genuine_report_from_another_chip_is_denied(example_manifest):
    """The diversion case: real evidence, wrong machine."""
    kbs = _kbs(example_manifest, GCP, allowed=[AZURE_CHIP])
    decision = kbs.verify_and_release(example_manifest, _evidence(kbs, example_manifest, GCP))
    check = _check(decision)
    assert not check.passed
    assert "not in allowed_platform_instances" in check.detail
    assert not decision.released
    assert decision.key is None and decision.sealed_key is None


def test_sender_bytes_are_not_read_when_the_verifier_authenticated_another_report(
    example_manifest,
):
    """The sender puts a listed chip's report on the wire; the verifier saw another."""
    kbs = _kbs(example_manifest, GCP, allowed=[AZURE_CHIP])
    decision = kbs.verify_and_release(example_manifest, _evidence(kbs, example_manifest, AZURE))
    assert not _check(decision).passed


def test_no_verifier_fails_closed(example_manifest):
    kbs = _kbs(example_manifest, None, allowed=[AZURE_CHIP])
    decision = kbs.verify_and_release(example_manifest, _evidence(kbs, example_manifest, AZURE))
    check = _check(decision)
    assert not check.passed
    assert "no cryptographically verified SNP report" in check.detail


def test_failed_verification_bytes_are_not_trusted(example_manifest):
    kbs = _kbs(example_manifest, AZURE, allowed=[AZURE_CHIP], verified=False)
    decision = kbs.verify_and_release(example_manifest, _evidence(kbs, example_manifest, AZURE))
    assert not _check(decision).passed
    assert not decision.released


def test_masked_chip_id_fails_closed(example_manifest):
    masked = bytearray(AZURE)
    masked[0x1A0 : 0x1A0 + 64] = bytes(64)
    kbs = _kbs(example_manifest, bytes(masked), allowed=[AZURE_CHIP])
    decision = kbs.verify_and_release(
        example_manifest, _evidence(kbs, example_manifest, bytes(masked))
    )
    check = _check(decision)
    assert not check.passed
    assert "masked" in check.detail


def test_non_snp_platform_fails_closed(example_manifest):
    kbs = _kbs(example_manifest, AZURE, allowed=[AZURE_CHIP])
    decision = kbs.verify_and_release(
        example_manifest, _evidence(kbs, example_manifest, AZURE, platform="intel-tdx")
    )
    check = _check(decision)
    assert not check.passed
    assert "SEV-SNP-only" in check.detail


@pytest.mark.parametrize(
    "bad",
    [[], ["ab" * 63], ["zz" * 64], ["00" * 64], [123]],
    ids=["empty", "short", "not-hex", "masked", "not-a-string"],
)
def test_invalid_lists_are_refused_at_construction(example_manifest, bad):
    with pytest.raises(ValueError):
        _kbs(example_manifest, AZURE, allowed=bad)


def test_server_env_wires_the_list(monkeypatch, tmp_path):
    from wcm.server import build_kbs_from_env

    path = tmp_path / "instances.json"
    path.write_text(json.dumps([AZURE_CHIP]))
    monkeypatch.setenv("WCM_ALLOWED_PLATFORM_INSTANCES_FILE", str(path))
    assert build_kbs_from_env()._allowed_platform_instances == frozenset({AZURE_CHIP})

    path.write_text(json.dumps({"chip": AZURE_CHIP}))
    with pytest.raises(ValueError):
        build_kbs_from_env()


def test_server_env_unset_leaves_the_check_off(monkeypatch):
    from wcm.server import build_kbs_from_env

    monkeypatch.delenv("WCM_ALLOWED_PLATFORM_INSTANCES_FILE", raising=False)
    assert build_kbs_from_env()._allowed_platform_instances is None
