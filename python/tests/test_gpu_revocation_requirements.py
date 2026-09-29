"""One test per sentence of the requirement agreed on issue #123.

Each test is named after the rule it holds and fails if that rule is removed.
Read together they are the audit: the requirement, clause by clause, against the
code rather than against a description of it.
"""
from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from wcm.custody import EnclaveSession, RenewalDenied
from wcm.gpu_revocation import NvidiaOcspClient, check_chain
from wcm.kbs import KeyBrokerService
from wcm.renewal import manifest_identity

from tests.test_gpu_revocation import WHEN, chain, client_for, held_key, nonce_of
from tests.test_gpu_revocation_gate import evidence, kbs_for, requires_revocation


def offline(url: str, body: bytes) -> bytes:
    raise OSError("responder unreachable")


def session_for(kbs, manifest, at):
    release = kbs.verify_and_release(manifest, evidence(kbs.issue_challenge().nonce, manifest))
    assert release.released is True, [c for c in release.checks if not c.passed]
    return EnclaveSession.from_release(manifest, release, max_operations=100, now=lambda: at)


# 1 -------------------------------------------------------------------------
def test_retries_during_an_outage_within_the_existing_lease_are_allowed(example_manifest):
    """'section 3.2 already allows retries during an outage within the existing lease.'

    The rule being kept, not changed. A deployment already running must be able
    to ride out a responder outage, or failing closed becomes an availability
    weapon rather than a safety property.
    """
    manifest = requires_revocation(example_manifest)
    client = client_for()
    kbs = kbs_for(manifest, client, ttl=900)
    assert kbs.verify_for_renewal(
        manifest, evidence(kbs.issue_challenge().nonce, manifest)
    ).renewed is True

    client._post = offline  # noqa: SLF001
    kbs._now = lambda: WHEN + timedelta(seconds=60)  # noqa: SLF001
    during = kbs.verify_for_renewal(manifest, evidence(kbs.issue_challenge().nonce, manifest))
    assert during.renewed is True, during.checks
    detail = next(c for c in during.checks if c["name"] == "attestation_revocation")["detail"]
    assert "reused" in detail


# 2 -------------------------------------------------------------------------
def test_an_unsuccessful_renewal_cannot_extend_that_lease(example_manifest):
    """'An unsuccessful renewal cannot extend that lease.'

    Already held before this change; asserted so it stays true. A refusal is
    raised before the deadline is touched, so the window does not move.
    """
    manifest = requires_revocation(example_manifest)
    client = client_for()
    kbs = kbs_for(manifest, client, ttl=900)
    session = session_for(kbs, manifest, WHEN)
    before = session._deadline  # noqa: SLF001

    client._post = offline  # noqa: SLF001
    client._held.clear()  # noqa: SLF001 - nothing to fall back to, so the gate refuses
    later = WHEN + timedelta(seconds=30)
    kbs._now = lambda: later  # noqa: SLF001
    refused = kbs.verify_for_renewal(manifest, evidence(kbs.issue_challenge().nonce, manifest))
    assert refused.renewed is False

    with pytest.raises(RenewalDenied):
        session.apply_renewal(manifest, refused, now=later)
    assert session._deadline == before, "a refused renewal moved the window"  # noqa: SLF001


# 3 -------------------------------------------------------------------------
def test_a_first_release_needs_a_fresh_check(example_manifest):
    """'A first release needs a fresh check.'

    Held answers are keyed by certificate and shared across workloads, so
    without this a deployment starting for the first time could ride on an
    answer that some other release obtained.
    """
    manifest = requires_revocation(example_manifest)
    client = client_for()
    warm = kbs_for(manifest, client)
    assert warm.verify_and_release(
        manifest, evidence(warm.issue_challenge().nonce, manifest)
    ).released is True

    client._post = offline  # noqa: SLF001
    kbs = kbs_for(manifest, client)
    decision = kbs.verify_and_release(manifest, evidence(kbs.issue_challenge().nonce, manifest))
    check = next(c for c in decision.checks if c.name == "attestation_revocation")
    assert check.passed is False
    assert "first release may not rest on an earlier answer" in check.detail
    assert decision.released is False


# 4 and 5 -------------------------------------------------------------------
def test_the_permission_window_must_end_before_the_evidence_does(example_manifest):
    """'its permission window must end before the cached evidence's allowed
    lifetime ends. Limiting cache age alone is insufficient if reuse grants
    another full window.'

    The permission window is the custody deadline, which is what holds the key,
    not the renewal decision's own validity.
    """
    manifest = requires_revocation(example_manifest)
    client = client_for()
    kbs = kbs_for(manifest, client, ttl=900)
    session = session_for(kbs, manifest, WHEN)

    decision = kbs.verify_for_renewal(manifest, evidence(kbs.issue_challenge().nonce, manifest))
    assert decision.evidence_expires_at is not None
    bound = datetime.fromisoformat(decision.evidence_expires_at.replace("Z", "+00:00"))
    assert session._cadence > (bound - WHEN).total_seconds(), (  # noqa: SLF001
        "the cadence must exceed the evidence or this proves nothing"
    )

    session.apply_renewal(manifest, decision)
    assert session._deadline <= bound  # noqa: SLF001


# 6 -------------------------------------------------------------------------
def test_a_fourteen_minute_old_answer_does_not_grant_another_fifteen(example_manifest):
    """'a 14-minute-old answer must not grant another 15 minutes when the
    promised limit is 15 minutes. Reuse must not restart the clock.'

    His example, at his numbers. The answer was obtained at T and stands until
    T plus fifteen minutes. The renewal happens at T plus fourteen. Custody may
    run to T plus fifteen and not one second further, so the reuse is worth one
    minute rather than another fifteen.
    """
    manifest = requires_revocation(example_manifest)
    promised = timedelta(minutes=15)
    # The promised limit is the short window, so set it to his fifteen minutes
    # rather than the ten minute default, which would refuse a 14 minute old
    # answer for a different reason and prove nothing about the clock.
    client = client_for(max_age_seconds=int(promised.total_seconds()))
    kbs = kbs_for(manifest, client, ttl=900)
    session = session_for(kbs, manifest, WHEN)

    # NVIDIA's nextUpdate is a day out, which is what it actually is. The
    # short window is the tighter limit and the one the bound has to respect.
    # Setting them equal, as this test once did, hides exactly the defect it
    # is meant to catch.
    links = chain()
    obtained_at = WHEN
    good_until = obtained_at + timedelta(hours=24)
    short_window_ends = obtained_at + promised
    for index in range(1, len(links) - 1):
        client._held[held_key(links, index)] = (  # noqa: SLF001
            "GOOD", obtained_at, good_until,
        )
    client._post = offline  # noqa: SLF001

    fourteen = WHEN + timedelta(minutes=14)
    kbs._now = lambda: fourteen  # noqa: SLF001
    session._now = lambda: fourteen  # noqa: SLF001
    decision = kbs.verify_for_renewal(manifest, evidence(kbs.issue_challenge().nonce, manifest))
    assert decision.renewed is True, decision.checks

    session.apply_renewal(manifest, decision, now=fourteen)
    granted = session._deadline - fourteen  # noqa: SLF001
    assert session._deadline <= short_window_ends, (  # noqa: SLF001
        f"custody ran to {session._deadline}, past the short window ending "  # noqa: SLF001
        f"{short_window_ends}"
    )
    assert granted <= timedelta(minutes=1), f"a 14 minute old answer bought {granted}"


# 7 -------------------------------------------------------------------------
def test_a_verified_revocation_overrides_a_cached_good_immediately(example_manifest):
    """'A verified revocation must also override any cached GOOD answer
    immediately.'
    """
    manifest = requires_revocation(example_manifest)
    client = client_for()
    kbs = kbs_for(manifest, client, ttl=900)
    assert kbs.verify_for_renewal(
        manifest, evidence(kbs.issue_challenge().nonce, manifest)
    ).renewed is True

    links = chain()
    key = held_key(links, 1)
    assert client._held[key][0] == "GOOD"  # noqa: SLF001
    client._held[key] = ("REVOKED", WHEN, WHEN + timedelta(hours=24))  # noqa: SLF001
    client._post = offline  # noqa: SLF001

    kbs._now = lambda: WHEN + timedelta(seconds=1)  # noqa: SLF001
    after = kbs.verify_for_renewal(manifest, evidence(kbs.issue_challenge().nonce, manifest))
    assert after.renewed is False
    detail = next(c for c in after.checks if c["name"] == "attestation_revocation")["detail"]
    assert "REVOKED" in detail


# 8 -------------------------------------------------------------------------
def test_the_leaf_limit_is_preserved_in_what_the_caller_sees(example_manifest):
    """'the service checks device and intermediate certificates, but does not
    establish the signing leaf's own revocation status. Please preserve that
    limit.'
    """
    result = check_chain(chain(), client_for(), WHEN)
    assert result.passed is True
    assert "leaf not established" in result.detail
    assert "says nothing about the signing certificate itself" in result.detail
    assert "covered by" not in result.detail

    manifest = requires_revocation(example_manifest)
    kbs = kbs_for(manifest, client_for())
    decision = kbs.verify_and_release(manifest, evidence(kbs.issue_challenge().nonce, manifest))
    check = next(c for c in decision.checks if c.name == "attestation_revocation")
    assert "leaf not established" in check.detail


# 9 -------------------------------------------------------------------------
def test_the_captured_responses_and_reproduction_steps_ship_with_the_change():
    """'include the captured responses and reproduction steps with the proposed
    change.'
    """
    import json
    import pathlib

    here = pathlib.Path(__file__).parent
    ocsp_dir = here / "fixtures" / "nvidia" / "ocsp"
    manifest = json.loads((ocsp_dir / "manifest.json").read_text(encoding="utf-8"))

    # The answers themselves.
    for entry in manifest["answers"]:
        assert (ocsp_dir / entry["file"]).exists(), entry["file"]
    assert {e["label"] for e in manifest["answers"]} == {
        "fmc_leaf", "brom", "provisioner_ica", "identity_ca"
    }

    # What was asked, and no device identifiers while doing it.
    assert manifest["responder"] and manifest["certid_hash"] == "SHA384"
    text = json.dumps(manifest)
    assert "serial" not in text.lower(), "a device serial reached the committed manifest"

    # The tool that produced them, and that reproduces them.
    tool = here.parent / "tools" / "capture_gpu_ocsp.py"
    assert tool.exists()
    assert "capture_gpu_ocsp.py" in tool.read_text(encoding="utf-8")
