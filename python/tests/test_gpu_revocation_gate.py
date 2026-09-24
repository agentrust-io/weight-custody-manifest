"""The gate, once a live revocation client is configured.

``attestation_revocation`` stops being a set-membership test and becomes a
question put to NVIDIA per release. These exercise the whole gate rather than
the client on its own, including the one thing limiting cache age cannot do:
stop reuse from granting another full permission window.
"""
from __future__ import annotations

import base64
import json
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509

from wcm.attestation import CompositeEvidence, CpuQuote, GpuReport
from wcm.gpu_revocation import NvidiaOcspClient
from wcm.kbs import KeyBrokerService
from wcm.renewal import manifest_identity

from tests.test_gpu_revocation import (  # noqa: F401
    ASKED, FIXTURES, WHEN, answer_bytes, chain, client_for, nonce_of,
)


def gpu_evidence_b64() -> str:
    """The committed H100 evidence, as the runtime would present it."""
    document = json.loads((FIXTURES / "gpu_h100_attestation.json").read_text(encoding="utf-8"))
    return base64.b64encode(json.dumps(document).encode()).decode()


def evidence(nonce: str, manifest) -> CompositeEvidence:
    accepted = manifest.release_policy.required_serving_image.accepted_measurements
    current = next(x.measurement for x in accepted if x.status.value == "current")
    return CompositeEvidence(
        cpu=CpuQuote(
            platform="amd-sev-snp",
            assurance_tier="hardware-attested",
            serving_image_measurement=current,
            nonce_echo=nonce,
            attestation_key_id="vcek:test",
        ),
        gpu=GpuReport(
            platform="nvidia-cc-gpu",
            measurement=manifest.release_policy.required_gpu_measurement.rim_pin,
            nonce_echo=nonce,
            quote_b64=gpu_evidence_b64(),
        ),
    )


def kbs_for(manifest, client, *, ttl: int = 3600) -> KeyBrokerService:
    return KeyBrokerService(
        {manifest.weights_hash: b"KEY"},
        now=lambda: WHEN,
        gpu_revocation_client=client,
        renewal_decision_ttl_seconds=ttl,
        trusted_manifest_identities={manifest_identity(manifest)},
    )


def requires_revocation(manifest):
    assert manifest.release_policy.attestation_revocation_check is not None, (
        "this fixture must ask for a revocation check or the gate is not exercised"
    )
    return manifest


# ---- the gate itself -------------------------------------------------------

def test_the_gate_passes_on_live_answers(example_manifest):
    manifest = requires_revocation(example_manifest)
    kbs = kbs_for(manifest, client_for())
    decision = kbs.verify_and_release(manifest, evidence(kbs.issue_challenge().nonce, manifest))
    check = next(c for c in decision.checks if c.name == "attestation_revocation")
    assert check.passed is True, check.detail
    assert "NVIDIA OCSP, nonce-bound" in check.detail
    assert decision.evidence_not_after is not None


def test_the_gate_fails_closed_when_nvidia_cannot_be_reached(example_manifest):
    manifest = requires_revocation(example_manifest)

    def offline(url: str, body: bytes) -> bytes:
        raise OSError("no route to host")

    kbs = kbs_for(manifest, NvidiaOcspClient(post=offline, nonce=lambda: bytes(32)))
    decision = kbs.verify_and_release(manifest, evidence(kbs.issue_challenge().nonce, manifest))
    check = next(c for c in decision.checks if c.name == "attestation_revocation")
    assert check.passed is False
    assert "could not be reached" in check.detail
    assert decision.released is False
    assert decision.key is None and decision.sealed_key is None


def test_the_gate_fails_closed_when_the_evidence_carries_no_chain(example_manifest):
    manifest = requires_revocation(example_manifest)
    kbs = kbs_for(manifest, client_for())
    nonce = kbs.issue_challenge().nonce
    without = evidence(nonce, manifest).model_copy(
        update={"gpu": GpuReport(
            platform="nvidia-cc-gpu",
            measurement=manifest.release_policy.required_gpu_measurement.rim_pin,
            nonce_echo=nonce, quote_b64=None,
        )}
    )
    decision = kbs.verify_and_release(manifest, without)
    check = next(c for c in decision.checks if c.name == "attestation_revocation")
    assert check.passed is False
    assert "no GPU certificate chain" in check.detail


def test_without_a_client_the_pass_says_what_it_rested_on(example_manifest):
    """A tick with no explanation would overstate a check that cannot fail."""
    manifest = requires_revocation(example_manifest)
    kbs = KeyBrokerService(
        {manifest.weights_hash: b"KEY"},
        now=lambda: WHEN,
        trusted_manifest_identities={manifest_identity(manifest)},
    )
    decision = kbs.verify_and_release(manifest, evidence(kbs.issue_challenge().nonce, manifest))
    check = next(c for c in decision.checks if c.name == "attestation_revocation")
    assert check.passed is True
    assert "no vendor revocation service was asked" in check.detail
    assert decision.evidence_not_after is None


# ---- the permission window -------------------------------------------------

def test_a_renewal_window_may_not_outlive_the_evidence(example_manifest):
    """Limiting cache age alone is not enough if reuse grants another window.

    The captured answers stand for 24 hours. A 48 hour renewal TTL would hand
    out a window that runs a day past the evidence, so it is cut back.
    """
    manifest = requires_revocation(example_manifest)
    kbs = kbs_for(manifest, client_for(), ttl=48 * 3600)
    decision = kbs.verify_for_renewal(manifest, evidence(kbs.issue_challenge().nonce, manifest))
    assert decision.renewed is True
    expires = datetime.fromisoformat(decision.expires_at.replace("Z", "+00:00"))
    assert expires < WHEN + timedelta(hours=48), "the TTL was not clamped"
    assert expires <= WHEN + timedelta(hours=24, minutes=1)


def test_a_window_shorter_than_the_evidence_is_left_alone(example_manifest):
    """Clamping only ever shortens. The ordinary case is untouched."""
    manifest = requires_revocation(example_manifest)
    kbs = kbs_for(manifest, client_for(), ttl=60)
    decision = kbs.verify_for_renewal(manifest, evidence(kbs.issue_challenge().nonce, manifest))
    expires = datetime.fromisoformat(decision.expires_at.replace("Z", "+00:00"))
    assert expires == WHEN + timedelta(seconds=60)


def test_reuse_during_an_outage_does_not_restart_the_clock(example_manifest):
    """The example Imran gave, at the scale of the fixtures.

    A first renewal is granted on a fresh answer. The responder then goes away
    and a second renewal rides on the held answer. Both windows end at the same
    instant, because that is when the evidence ends, so the second renewal buys
    no time the first did not already have.
    """
    manifest = requires_revocation(example_manifest)
    client = client_for()
    kbs = kbs_for(manifest, client, ttl=48 * 3600)
    first = kbs.verify_for_renewal(manifest, evidence(kbs.issue_challenge().nonce, manifest))

    def offline(url: str, body: bytes) -> bytes:
        raise OSError("responder down")

    client._post = offline  # noqa: SLF001
    later = WHEN + timedelta(seconds=120)
    kbs._now = lambda: later  # noqa: SLF001
    second = kbs.verify_for_renewal(manifest, evidence(kbs.issue_challenge().nonce, manifest))

    assert second.renewed is True, second.checks
    assert first.expires_at == second.expires_at, (
        "reuse granted a fresh window instead of inheriting the evidence's bound"
    )


def test_a_first_release_is_refused_during_an_outage(example_manifest):
    """'A first release needs a fresh check.'

    The held answer is keyed by certificate and shared across workloads, so
    without this a workload starting for the first time could ride on an
    answer some other release obtained.
    """
    manifest = requires_revocation(example_manifest)
    client = client_for()
    warm = kbs_for(manifest, client)
    assert warm.verify_and_release(
        manifest, evidence(warm.issue_challenge().nonce, manifest)
    ).released is True

    def offline(url: str, body: bytes) -> bytes:
        raise OSError("responder down")

    client._post = offline  # noqa: SLF001
    kbs = kbs_for(manifest, client)
    decision = kbs.verify_and_release(manifest, evidence(kbs.issue_challenge().nonce, manifest))
    check = next(c for c in decision.checks if c.name == "attestation_revocation")
    assert check.passed is False
    assert "first release may not rest on an earlier answer" in check.detail
    assert decision.released is False


def test_a_renewal_may_ride_out_the_same_outage(example_manifest):
    """The other half, so the refusal above is the rule and not a breakage."""
    manifest = requires_revocation(example_manifest)
    client = client_for()
    kbs = kbs_for(manifest, client, ttl=900)
    assert kbs.verify_for_renewal(
        manifest, evidence(kbs.issue_challenge().nonce, manifest)
    ).renewed is True

    def offline(url: str, body: bytes) -> bytes:
        raise OSError("responder down")

    client._post = offline  # noqa: SLF001
    kbs._now = lambda: WHEN + timedelta(seconds=60)  # noqa: SLF001
    later = kbs.verify_for_renewal(manifest, evidence(kbs.issue_challenge().nonce, manifest))
    assert later.renewed is True, later.checks
    detail = next(c for c in later.checks if c["name"] == "attestation_revocation")["detail"]
    assert "reused" in detail


# ---- the window that actually holds the key -------------------------------

def test_the_custody_window_is_bounded_by_the_evidence(example_manifest):
    """'Its permission window must end before the cached evidence's lifetime.'

    The permission window is the custody session's deadline, not the renewal
    decision's own validity. Applying a decision used to set that deadline to
    a full cadence from now regardless of what the decision rested on, so a
    short-lived answer still bought a long window at the layer holding the key.
    """
    from wcm.custody import EnclaveSession

    manifest = requires_revocation(example_manifest)
    client = client_for()
    kbs = kbs_for(manifest, client, ttl=900)
    release = kbs.verify_and_release(
        manifest, evidence(kbs.issue_challenge().nonce, manifest)
    )
    assert release.released is True
    session = EnclaveSession.from_release(
        manifest, release, max_operations=10, now=lambda: WHEN,
    )
    cadence = session._cadence  # noqa: SLF001

    decision = kbs.verify_for_renewal(
        manifest, evidence(kbs.issue_challenge().nonce, manifest)
    )
    assert decision.evidence_expires_at is not None, "the bound must be carried and signed"
    bound = datetime.fromisoformat(decision.evidence_expires_at.replace("Z", "+00:00"))

    session.apply_renewal(manifest, decision)
    deadline = session._deadline  # noqa: SLF001

    # The cadence is far longer than what NVIDIA's answer stands for, so the
    # answer is what ends the window.
    assert cadence > (bound - WHEN).total_seconds(), (
        "this fixture must have a cadence longer than the evidence to be a test"
    )
    assert deadline <= bound, (
        f"custody ran to {deadline}, past the evidence at {bound}"
    )


def test_a_decision_with_no_evidence_bound_keeps_the_cadence(example_manifest):
    """Backward compatible: without a live revocation client nothing changes."""
    from wcm.custody import EnclaveSession
    from wcm.kbs import KeyBrokerService

    manifest = requires_revocation(example_manifest)
    plain = KeyBrokerService(
        {manifest.weights_hash: b"KEY"}, now=lambda: WHEN,
        renewal_decision_ttl_seconds=900,
        trusted_manifest_identities={manifest_identity(manifest)},
    )
    release = plain.verify_and_release(
        manifest, evidence(plain.issue_challenge().nonce, manifest)
    )
    session = EnclaveSession.from_release(
        manifest, release, max_operations=10, now=lambda: WHEN,
    )
    decision = plain.verify_for_renewal(
        manifest, evidence(plain.issue_challenge().nonce, manifest)
    )
    assert decision.evidence_expires_at is None
    session.apply_renewal(manifest, decision)
    assert session._deadline == WHEN + timedelta(seconds=session._cadence)  # noqa: SLF001
