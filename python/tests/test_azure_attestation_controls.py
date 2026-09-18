"""The live diagnostic must fail if the verifier loses a negative gate."""
import importlib.util
from pathlib import Path
from types import SimpleNamespace

import pytest

from wcm import AzureSnpVtpmVerifier
from wcm._quote_verify import QuoteVerification
from tests.test_azure_vtpm_verify import _bundle, NONCE, BINDING, MEASUREMENT, NOW

spec = importlib.util.spec_from_file_location("azure_controls",
    Path(__file__).parents[1] / "tools/azure_attestation_controls.py")
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


def fixture_verifier(trust):
    verifier = AzureSnpVtpmVerifier(trust)
    return SimpleNamespace(verify=lambda quote, **kwargs: verifier.verify(quote, now=NOW, **kwargs))


def test_live_oracle_accepts_all_expected_signed_fixture_outcomes():
    encoded, trust = _bundle()
    results = probe.controls(fixture_verifier(trust), encoded, NONCE, BINDING, MEASUREMENT)
    assert len(results) == 7
    assert all(item["verified"] == item["expected"] for item in results)


def test_live_oracle_detects_a_weakened_nonce_gate():
    encoded, trust = _bundle()
    actual = fixture_verifier(trust)

    class Weakened:
        def verify(self, quote, **kwargs):
            if kwargs["expected_nonce"] != NONCE:
                return QuoteVerification(True)
            return actual.verify(quote, **kwargs)

    with pytest.raises(AssertionError, match="wrong-nonce"):
        probe.controls(Weakened(), encoded, NONCE, BINDING, MEASUREMENT)
