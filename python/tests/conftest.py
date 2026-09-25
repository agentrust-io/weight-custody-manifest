from __future__ import annotations

import json
from pathlib import Path

import pytest

from wcm import WeightCustodyManifest

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


@pytest.fixture
def example_dict() -> dict:
    with open(EXAMPLES / "manifest.example.json", "r", encoding="utf-8") as fh:
        return json.load(fh)


@pytest.fixture
def example_manifest(example_dict: dict) -> WeightCustodyManifest:
    return WeightCustodyManifest.model_validate(example_dict)


def waive(
    manifest: WeightCustodyManifest,
    *,
    evidence_verification: bool = True,
    cc_mode: bool = True,
) -> WeightCustodyManifest:
    """Return *manifest* with the verification requirements explicitly waived.

    A manifest that is silent on either requires it, so a test releasing on
    mock evidence with no verifier configured has to say so in the manifest,
    the same way a deployment would. Only the named requirements are waived.
    """
    policy = manifest.release_policy
    update: dict = {}
    if evidence_verification:
        update["require_evidence_verification"] = False
    if cc_mode and policy.required_gpu_measurement is not None:
        update["required_gpu_measurement"] = policy.required_gpu_measurement.model_copy(
            update={"require_cc_mode": False}
        )
    return manifest.model_copy(
        update={"release_policy": policy.model_copy(update=update)}
    )


@pytest.fixture
def structural_manifest(example_manifest: WeightCustodyManifest) -> WeightCustodyManifest:
    """The example manifest for tests that release on mock evidence.

    Waives cryptographic evidence verification and the GPU confidential-compute
    requirement, because neither can be met without a verifier. For tests of
    custody, channel binding, replay and the like, not of verification itself.
    """
    return waive(example_manifest)
