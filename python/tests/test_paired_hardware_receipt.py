from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

PACK = (
    Path(__file__).parent
    / "fixtures/live-validation/weight-custody-manifest/paired-2026-08-20"
)

RECEIPT = PACK / "paired-release.json"

# paired-release.json is deliberately excluded from the sdist: it carries an
# Azure SNP/vTPM device serial and the H100 model, driver, VBIOS and PCI address,
# and the sdist reaches a public index whatever this repository's visibility says
# (RCA-0008). It cannot be redacted in place because the SHA-256 below is what
# shows the receipt is the one the hardware produced, so the fixture stays whole
# in the repository and does not ship. This test therefore runs in CI, where the
# checkout has it, and skips for anyone running the suite out of an sdist.
requires_receipt = pytest.mark.skipif(
    not RECEIPT.exists(),
    reason="paired-release.json is excluded from the sdist by design; see "
    "python/pyproject.toml [tool.hatch.build.targets.sdist] exclude",
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


@requires_receipt
def test_paired_hardware_receipt_is_pinned_and_fail_closed():
    receipt = RECEIPT
    assert (
        _sha256(receipt)
        == "16b9b39d381a1342491234b8024a3390894bdbe13a0fccee282f6f9a69b3d654"
    )
    value = json.loads(receipt.read_text())

    assert value["passed"] is True
    assert value["release_candidate"] == "78839c751934c45f6f34988c878442ec2e8d827d"
    assert value["happy_release"]["released"] is True
    assert value["happy_release"]["plaintext_key_returned"] is False
    assert value["happy_release"]["correct_transport_recovered"] is True
    assert value["happy_release"]["wrong_transport_refused"] is True
    assert all(check["passed"] for check in value["happy_release"]["checks"])
    assert value["negative_cross_run_cpu_substitution"]["released"] is False
    assert value["negative_cross_run_gpu_substitution"]["released"] is False


def test_paired_hardware_preflight_is_pinned():
    preflight = PACK / "preflight.json"
    assert (
        _sha256(preflight)
        == "fd67a9034e32f03d45e976ab8a6dc406240e930446a60ceae4c8d7a3e0845866"
    )
    value = json.loads(preflight.read_text())

    assert value["devices"]["/dev/nvidia0"] is True
    assert value["devices"]["/dev/tpmrm0"] is True
    assert value["tools"]["nvidia_cc"]["stdout"] == "CC status: ON"
