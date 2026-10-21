"""Synthetic post-verification controls, not signed or live hardware evidence.

Exercise both platform gates together through sealed release. All unrelated
checks pass, so a negative cannot pass merely because the GPU policy denied it.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from wcm import KeyBrokerService, manifest_identity, open_sealed
from wcm._quote_verify import QuoteVerification
from wcm.models import PlatformIntegrity

from tests.conftest import waive
from tests.test_platform_instance import AZURE, AZURE_CHIP, KEY, TRANSPORT_PRIV, _evidence


def _synthetic_report(*, bits=0x30, chip=None, version=3):
    # Mutations invalidate the capture's signature. The stub below deliberately
    # models the output boundary of a verifier, never cryptographic acceptance.
    report = bytearray(AZURE)
    report[0:4] = version.to_bytes(4, "little")
    report[0x40:0x48] = bits.to_bytes(8, "little")
    if chip is not None:
        report[0x1A0:0x1E0] = chip
    return bytes(report)


class _Verifier:
    def __init__(self, result):
        self.result = result

    def verify(self, quote_b64, **kwargs):
        return self.result


@pytest.mark.parametrize(
    "case,failed",
    [
        ("alias-clear", {"platform_integrity"}),
        ("ciphertext-clear", {"platform_integrity"}),
        ("old-version", {"platform_integrity"}),
        ("wrong-chip", {"platform_instance_allowed"}),
        ("masked-chip", {"platform_instance_allowed"}),
        ("missing-report", {"platform_integrity", "platform_instance_allowed"}),
        ("legacy-result", {"platform_integrity", "platform_instance_allowed"}),
        ("truncated-report", {"platform_integrity", "platform_instance_allowed"}),
        ("failed-verifier", {
            "cpu_quote_verified", "platform_integrity", "platform_instance_allowed",
        }),
        ("tdx", {"platform_integrity", "platform_instance_allowed"}),
    ],
)
def test_combined_gates_recheck_each_release(example_manifest, case, failed):
    manifest = waive(example_manifest)
    policy = manifest.release_policy.model_copy(update={
        "required_hw_platform": ["amd-sev-snp", "intel-tdx"],
        "platform_integrity": PlatformIntegrity(
            alias_check_complete="required", ciphertext_hiding="required",
        ),
    })
    manifest = manifest.model_copy(update={"release_policy": policy})
    good = _synthetic_report()
    verifier = _Verifier(QuoteVerification(True, snp_report=good))
    kbs = KeyBrokerService(
        {manifest.weights_hash: KEY},
        trusted_manifest_identities={manifest_identity(manifest)},
        cpu_quote_verifier=verifier,
        allowed_platform_instances=[AZURE_CHIP],
    )

    # Positive control on the same broker before and after the negative: this
    # also detects stale verifier-result reuse and permanently poisoned state.
    for phase in ("positive-before", "negative", "positive-after"):
        result = QuoteVerification(True, snp_report=good)
        platform = "amd-sev-snp"
        if phase == "negative":
            if case == "alias-clear":
                result = QuoteVerification(True, snp_report=_synthetic_report(bits=0x10))
            elif case == "ciphertext-clear":
                result = QuoteVerification(True, snp_report=_synthetic_report(bits=0x20))
            elif case == "old-version":
                result = QuoteVerification(True, snp_report=_synthetic_report(version=2))
            elif case in ("wrong-chip", "masked-chip"):
                chip = b"\xff" * 64 if case == "wrong-chip" else bytes(64)
                result = QuoteVerification(True, snp_report=_synthetic_report(chip=chip))
            elif case == "missing-report":
                result = QuoteVerification(True)
            elif case == "legacy-result":
                result = SimpleNamespace(verified=True, reason=None)
            elif case == "truncated-report":
                result = QuoteVerification(True, snp_report=good[:64])
            elif case == "failed-verifier":
                result = QuoteVerification(False, "synthetic refusal", snp_report=good)
            elif case == "tdx":
                platform = "intel-tdx"
        verifier.result = result
        decision = kbs.verify_and_release(manifest, _evidence(kbs, manifest, good, platform))
        actual_failures = {c.name for c in decision.checks if not c.passed}
        if phase == "negative":
            assert actual_failures == failed
            assert not decision.released
            assert decision.key is None and decision.sealed_key is None
        else:
            assert actual_failures == set()
            assert decision.released
            assert open_sealed(decision.sealed_key, TRANSPORT_PRIV) == KEY
