"""PLATFORM_INFO parsing and the ``platform_integrity`` release-policy gate.

The parse cases run against the real SEV-SNP report captured from a live Azure
confidential VM (``fixtures/snp_quote_azure.json``), not a synthetic one, because
the point of the field is what production platforms actually report.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import pathlib

import pytest

from wcm import KeyBrokerService, SoftwareProvider, WeightCustodyManifest, manifest_identity
from wcm._signing import signing_pre_image
from wcm.models import PlatformIntegrity, PlatformIntegrityRequirement
from wcm.snp import parse_snp_report

FIXTURES = pathlib.Path(__file__).parent / "fixtures"
KEY = b"decryption-key-for-these-weights"


def _azure_report_bytes() -> bytes:
    doc = json.loads((FIXTURES / "snp_quote_azure.json").read_text())
    return base64.b64decode(doc["report_b64"])


def _gcp_milan_report_bytes() -> bytes:
    doc = json.loads((FIXTURES / "snp_platform_info_gcp_milan.json").read_text())
    return base64.b64decode(doc["report_b64"])


def _with_version(report: bytes, version: int) -> bytes:
    """Return *report* with its VERSION field rewritten.

    This invalidates the report signature, which is fine here: the
    platform_integrity gate is a field check and the signature is verified by a
    different check entirely. It exists to exercise version gating, for which no
    real pre-v3 capture is on hand.
    """
    out = bytearray(report)
    out[0:4] = version.to_bytes(4, "little")
    return bytes(out)


# --------------------------------------------------------------------------
# Parsing, against live silicon
# --------------------------------------------------------------------------


def test_live_azure_report_platform_info_decodes():
    report = parse_snp_report(_azure_report_bytes())
    pi = report.platform_info

    assert report.version == 3
    assert pi.raw == 0x25
    assert pi.smt_en is True
    assert pi.ecc_en is True
    assert pi.tsme_en is False
    assert pi.rapl_dis is False


def test_live_azure_platform_has_alias_check_but_not_ciphertext_hiding():
    """The measured state of a real Azure SEV-SNP CVM.

    Recorded as a test so a future platform change is visible rather than
    silent. ``alias_check_complete`` is set, so the BadRAM mitigation firmware
    floor is deployed. ``ciphertext_hiding_en`` is clear, which means this
    platform does not meet the precondition SPEC.md section 3.6 attaches to the
    semi-trusted-operator custody claim.
    """
    pi = parse_snp_report(_azure_report_bytes()).platform_info

    assert pi.alias_check_complete is True
    assert pi.ciphertext_hiding_en is False


def test_live_gcp_milan_matches_azure_on_platform_info():
    """A second cloud, a second report version, the same answer.

    GCP N2D (AMD EPYC 7B13, report version 5) and the Azure CVM (version 3)
    both report PLATFORM_INFO = 0x25. Neither enables ciphertext hiding, and on
    GCP that is structural rather than a configuration choice: Google documents
    SEV-SNP as N2D/Milan only, and ciphertext hiding requires EPYC 9005 (Turin),
    so no GCP SEV-SNP platform can currently set bit 4. Recorded so a future
    platform that does set it shows up as a test failure.
    """
    gcp = parse_snp_report(_gcp_milan_report_bytes())
    azure = parse_snp_report(_azure_report_bytes())

    assert gcp.platform_info.raw == azure.platform_info.raw == 0x25
    assert gcp.platform_info.ciphertext_hiding_en is False
    assert gcp.platform_info.alias_check_complete is True


def test_sev_tio_is_defined_on_v5_and_undefined_on_v3():
    """Version gating, exercised by two real captures rather than a synthetic one."""
    gcp = parse_snp_report(_gcp_milan_report_bytes())  # version 5
    azure = parse_snp_report(_azure_report_bytes())  # version 3

    assert gcp.version == 5
    assert azure.version == 3
    assert gcp.platform_info.sev_tio_en is False
    assert azure.platform_info.sev_tio_en is None


def test_bits_below_their_report_version_are_unknown_not_false():
    """A reserved zero must not be reported as a negative finding."""
    v2 = parse_snp_report(_with_version(_azure_report_bytes(), 2)).platform_info
    v3 = parse_snp_report(_azure_report_bytes()).platform_info

    # ALIAS_CHECK_COMPLETE arrives in report version 3, SEV-TIO in version 5.
    assert v2.alias_check_complete is None
    assert v3.alias_check_complete is True
    assert v3.sev_tio_en is None

    # Bits defined since version 2 are unaffected by the gating.
    assert v2.ciphertext_hiding_en is False
    assert v2.smt_en is True


# --------------------------------------------------------------------------
# The gate
# --------------------------------------------------------------------------


def _evidence_with_report(kbs, example_manifest, report: bytes):
    ams = example_manifest.release_policy.required_serving_image.accepted_measurements
    current = next(m.measurement for m in ams if m.status.value == "current")
    rim = example_manifest.release_policy.required_gpu_measurement.rim_pin
    challenge = kbs.issue_challenge()
    evidence = SoftwareProvider().produce(
        challenge, serving_image_measurement=current, gpu_measurement=rim
    )
    return evidence.model_copy(
        update={
            "cpu": evidence.cpu.model_copy(
                update={"quote_b64": base64.b64encode(report).decode()}
            )
        }
    )


def _manifest_requiring(example_dict: dict, **kwargs) -> WeightCustodyManifest:
    doc = copy.deepcopy(example_dict)
    doc["release_policy"]["platform_integrity"] = {
        k: v.value for k, v in kwargs.items()
    }
    return WeightCustodyManifest.model_validate(doc)


def _kbs_for(manifest):
    return KeyBrokerService(
        {manifest.weights_hash: KEY},
        trusted_manifest_identities={manifest_identity(manifest)},
    )


def _check(decision, name: str):
    return next(c for c in decision.checks if c.name == name)


def test_gate_passes_when_platform_integrity_absent(example_manifest):
    kbs = _kbs_for(example_manifest)
    evidence = _evidence_with_report(kbs, example_manifest, _azure_report_bytes())

    decision = kbs.verify_and_release(example_manifest, evidence)

    assert _check(decision, "platform_integrity").passed
    assert _check(decision, "platform_integrity").detail == "not required"


def test_gate_passes_when_alias_check_required_and_set(example_dict):
    manifest = _manifest_requiring(
        example_dict, alias_check_complete=PlatformIntegrityRequirement.required
    )
    kbs = _kbs_for(manifest)
    evidence = _evidence_with_report(kbs, manifest, _azure_report_bytes())

    decision = kbs.verify_and_release(manifest, evidence)

    assert _check(decision, "platform_integrity").passed


def test_gate_denies_ciphertext_hiding_on_the_real_azure_platform(example_dict):
    """The measured consequence: this platform cannot satisfy the requirement."""
    manifest = _manifest_requiring(
        example_dict, ciphertext_hiding=PlatformIntegrityRequirement.required
    )
    kbs = _kbs_for(manifest)
    evidence = _evidence_with_report(kbs, manifest, _azure_report_bytes())

    decision = kbs.verify_and_release(manifest, evidence)

    check = _check(decision, "platform_integrity")
    assert not check.passed
    assert "bit 4" in check.detail
    assert not decision.released


def test_gate_denies_alias_check_when_report_version_cannot_carry_it(example_dict):
    manifest = _manifest_requiring(
        example_dict, alias_check_complete=PlatformIntegrityRequirement.required
    )
    kbs = _kbs_for(manifest)
    evidence = _evidence_with_report(
        kbs, manifest, _with_version(_azure_report_bytes(), 2)
    )

    decision = kbs.verify_and_release(manifest, evidence)

    check = _check(decision, "platform_integrity")
    assert not check.passed
    assert "version 2" in check.detail
    assert "version >= 3" in check.detail


def test_gate_denies_when_evidence_carries_no_report(example_dict):
    manifest = _manifest_requiring(
        example_dict, alias_check_complete=PlatformIntegrityRequirement.required
    )
    kbs = _kbs_for(manifest)
    ams = manifest.release_policy.required_serving_image.accepted_measurements
    current = next(m.measurement for m in ams if m.status.value == "current")
    rim = manifest.release_policy.required_gpu_measurement.rim_pin
    challenge = kbs.issue_challenge()
    evidence = SoftwareProvider().produce(
        challenge, serving_image_measurement=current, gpu_measurement=rim
    )

    decision = kbs.verify_and_release(manifest, evidence)

    check = _check(decision, "platform_integrity")
    assert not check.passed
    assert "no SNP report" in check.detail


def test_gate_denies_on_a_non_snp_platform(example_dict):
    manifest = _manifest_requiring(
        example_dict, alias_check_complete=PlatformIntegrityRequirement.required
    )
    kbs = _kbs_for(manifest)
    ams = manifest.release_policy.required_serving_image.accepted_measurements
    current = next(m.measurement for m in ams if m.status.value == "current")
    rim = manifest.release_policy.required_gpu_measurement.rim_pin
    challenge = kbs.issue_challenge()
    evidence = SoftwareProvider().produce(
        challenge,
        serving_image_measurement=current,
        gpu_measurement=rim,
        platform="intel-tdx",
    )
    evidence = evidence.model_copy(
        update={
            "cpu": evidence.cpu.model_copy(
                update={"quote_b64": base64.b64encode(_azure_report_bytes()).decode()}
            )
        }
    )

    decision = kbs.verify_and_release(manifest, evidence)

    check = _check(decision, "platform_integrity")
    assert not check.passed
    assert "SEV-SNP-only" in check.detail


# --------------------------------------------------------------------------
# Backwards compatibility
# --------------------------------------------------------------------------


def test_adding_platform_integrity_does_not_perturb_the_signing_pre_image(example_dict):
    """A manifest that does not set the field must sign exactly as before.

    ``signing_pre_image`` runs over ``model_dump(exclude_none=True)``, so a new
    field with a non-None default would enter the canonical bytes and invalidate
    every signature written before it existed. The field is optional and absent
    by default precisely to avoid that, and this pins it.
    """
    dumped = WeightCustodyManifest.model_validate(example_dict).model_dump(
        mode="json", exclude_none=True
    )
    assert "platform_integrity" not in dumped["release_policy"]
    assert (
        hashlib.sha256(signing_pre_image(dumped)).hexdigest()
        == hashlib.sha256(signing_pre_image(example_dict)).hexdigest()
    )


def test_setting_platform_integrity_does_enter_the_pre_image(example_dict):
    """It is a signed control, so a manifest that sets it must sign differently."""
    plain = WeightCustodyManifest.model_validate(example_dict)
    required = _manifest_requiring(
        example_dict, alias_check_complete=PlatformIntegrityRequirement.required
    )

    def digest(m):
        return hashlib.sha256(
            signing_pre_image(m.model_dump(mode="json", exclude_none=True))
        ).hexdigest()

    assert digest(plain) != digest(required)


def test_platform_integrity_defaults_within_the_object_are_permissive(example_dict):
    """An empty object requires nothing, so it cannot silently deny."""
    doc = copy.deepcopy(example_dict)
    doc["release_policy"]["platform_integrity"] = {}
    manifest = WeightCustodyManifest.model_validate(doc)
    pi = manifest.release_policy.platform_integrity

    assert pi == PlatformIntegrity(
        alias_check_complete=PlatformIntegrityRequirement.not_required,
        ciphertext_hiding=PlatformIntegrityRequirement.not_required,
    )

    kbs = _kbs_for(manifest)
    evidence = _evidence_with_report(kbs, manifest, _azure_report_bytes())
    assert _check(kbs.verify_and_release(manifest, evidence), "platform_integrity").passed
