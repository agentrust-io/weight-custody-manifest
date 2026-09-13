"""The vendor-evidence vector format, exercised against a real silicon capture.

No vendor vectors are committed yet, by design: the format lands first and the
captures follow. So these tests build vectors from the Azure SEV-SNP capture
already in ``tests/fixtures`` rather than from anything synthetic. That matters
more than it sounds. Every rule in this format exists because a synthetic chain
satisfies it already, and a test suite that checked the rules against minted
certificates would repeat exactly the mistake the format is for.

Two mutations had to be told where to land, and both were found by running them
against that capture. An SEV-SNP report carries reserved bytes after its
signature field, so a tamper at "the last byte" left the signed material and the
signature both intact; and the middle of a quote is not reliably inside the
signed body. A case whose mutation changes nothing reports a refusal it never
performed, which is worse than no case at all.
"""

from __future__ import annotations

import base64
import hashlib
import json
import warnings
from datetime import datetime, timezone
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.utils import CryptographyDeprecationWarning
from cryptography.hazmat.primitives.serialization import Encoding

from wcm._vendor_vectors import (
    BINDING_KINDS,
    REFUSAL_CASES,
    VendorVectorError,
    evaluate_vendor,
    live_check,
    load_root_store,
)
from wcm.conformance import evaluate

FIXTURES = Path(__file__).parent / "fixtures"
SNP = FIXTURES / "snp_quote_azure.json"
MATRIX = list(REFUSAL_CASES)

#: Substrings every vendor's refusal reason shares, so one declaration covers
#: an AMD, an Intel and an NVIDIA capture. Substrings rather than exact
#: messages, or the corpus becomes a change detector for wording.
REASONS = {
    "wrong-binding": "does not bind",
    "tampered-report": "does not verify",
    "tampered-signature": "does not verify",
    "stripped-chain": "trusted root",
    "out-of-chain-root": "trusted root",
    "expired-at-now": "validity window",
}


def _load(pem: str) -> x509.Certificate:
    """A VCEK carries a non-positive serial, so the policy loader is not used
    here. These tests only need the certificate's dates and digest.

    The transition warning is suppressed the way the SDK suppresses it: WCM has
    already chosen a rejection policy, and the noise would otherwise arrive once
    per certificate per test.
    """
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", CryptographyDeprecationWarning)
        return x509.load_pem_x509_certificate(pem.encode())


def _digest(pem: str) -> str:
    return "sha256:" + hashlib.sha256(_load(pem).public_bytes(Encoding.DER)).hexdigest()


def _amd_root() -> str:
    """AMD's ARK-Milan, the self-signed certificate in the committed chain."""
    blob = (FIXTURES / "amd_milan_cert_chain.pem").read_bytes()
    out, buf = [], b""
    for line in blob.splitlines(True):
        buf += line
        if b"END CERTIFICATE" in line:
            out.append(buf.decode())
            buf = b""
    return next(pem for pem in out if _load(pem).subject == _load(pem).issuer)


@pytest.fixture
def stage(tmp_path: Path) -> Path:
    """A directory standing in for roots an operator has staged."""
    return tmp_path


def _snp_vector(stage: Path) -> dict:
    """An Azure SEV-SNP capture, in the shape this format defines.

    Its ``REPORT_DATA`` is paravisor-bound to the vTPM attestation key rather
    than to a guest nonce, which is why the fixture's own ``expected_nonce`` is
    null and why this vector declares the ``attestation-key`` binding.
    """
    doc = json.loads(SNP.read_text(encoding="utf-8"))
    # The root is staged from amd_milan_cert_chain.pem rather than from the
    # fixture's own root_pem. That field is what the fixture migration removes,
    # and a format PR should not hold a dependency on a field the next PR
    # deletes.
    root_pem = _amd_root()
    (stage / "amd-ark.pem").write_text(root_pem)
    pems = [doc["vcek_pem"], *doc["intermediates_pem"], root_pem]
    return {
        "id": "accept-snp-azure-attestation-key",
        "level": "L2",
        "kind": "vendor",
        "description": "An Azure SEV-SNP report whose REPORT_DATA binds the vTPM AK.",
        "expect": "accept",
        "capture": {
            "vendor": "amd",
            "technology": "sev-snp",
            "part": "EPYC Milan",
            "captured_at": "2026-01-01",
            "source": "committed SDK fixture",
        },
        "evidence": {"format": "sev-snp-report", "report_b64": doc["report_b64"]},
        "chain": {
            "leaf_pem": doc["vcek_pem"],
            "intermediates_pem": doc["intermediates_pem"],
            "root": {"id": "amd-ark-milan", "der_sha256": _digest(root_pem)},
            "root_source": "AMD KDS, staged by the runner",
        },
        "binding": {
            "kind": "attestation-key",
            "note": "the paravisor binds REPORT_DATA to the vTPM AK, not a guest nonce",
        },
        "validity": {
            "now": "2026-01-01T00:00:00+00:00",
            "not_after": min(_load(pem).not_valid_after_utc for pem in pems).isoformat(),
        },
        "refusals": {case: {"reason_contains": REASONS[case]} for case in MATRIX},
    }


@pytest.fixture
def snp_store(stage: Path):
    return _snp_vector(stage), load_root_store(extra_dirs=[stage])


# ---- vector shape: named root, leaf and intermediates inline ----------


def test_a_capture_verifies_against_a_staged_root(snp_store) -> None:
    vector, store = snp_store
    outcome = evaluate_vendor(vector, store=store)
    assert outcome.verified, outcome.reason


def test_a_root_nobody_staged_fails_rather_than_being_fetched(stage: Path) -> None:
    """The failure names the root, and nothing reaches the network.

    A suite that fetched here would fail differently on an aeroplane than in CI,
    and staging a vendor root is a step every real implementer performs anyway.
    """
    vector = _snp_vector(stage)
    (stage / "amd-ark.pem").unlink()
    with pytest.raises(VendorVectorError) as exc:
        evaluate_vendor(vector, store=load_root_store(extra_dirs=[stage]))
    assert "root not staged" in str(exc.value)
    assert "sha256:" in str(exc.value)


def test_a_vector_carries_its_chain_but_not_its_anchor(snp_store) -> None:
    """A chain carrying its own anchor proves internal consistency, which the
    synthetic PKI already proves."""
    vector, _ = snp_store
    assert "leaf_pem" in vector["chain"]
    assert "intermediates_pem" in vector["chain"]
    assert set(vector["chain"]["root"]) == {"id", "der_sha256"}


def test_a_chain_without_a_leaf_is_refused(snp_store) -> None:
    vector, store = snp_store
    del vector["chain"]["leaf_pem"]
    with pytest.raises(VendorVectorError) as exc:
        evaluate_vendor(vector, store=store)
    assert "leaf_pem" in str(exc.value)


# ---- binding kinds ---------------------------------------------------


def test_an_unrecognised_binding_kind_is_a_hard_failure(snp_store) -> None:
    """The silent skip is the failure mode that matters: a runner that skips
    what it does not understand reports a pass it never performed.

    The schema rejects this before the runner's own check reaches it, which is
    the right order and means the assertion is about the offending value rather
    than about which of the two gates spoke first.
    """
    vector, store = snp_store
    vector["binding"] = {"kind": "nonce-over-carrier-pigeon", "nonce_hex": "ab"}
    with pytest.raises(VendorVectorError) as exc:
        evaluate_vendor(vector, store=store)
    assert "nonce-over-carrier-pigeon" in str(exc.value) or "binding" in str(exc.value)


def test_an_unrecognised_evidence_format_is_a_hard_failure(snp_store) -> None:
    vector, store = snp_store
    vector["evidence"]["format"] = "some-future-vendor"
    with pytest.raises(VendorVectorError) as exc:
        evaluate_vendor(vector, store=store)
    assert "some-future-vendor" in str(exc.value) or "format" in str(exc.value)


def test_the_vocabulary_is_closed_and_covers_the_real_mechanisms() -> None:
    """``none`` earns its place: some real captures prove only that a chip
    signed something, and a format that cannot say so will have a nonce
    invented for it. ``nonce-echo`` earns its place for the opposite reason:
    NVIDIA does bind a caller nonce, verbatim rather than as a digest, and
    labelling that ``nonce-digest`` names a mechanism not in those bytes."""
    assert BINDING_KINDS == {
        "nonce-digest",
        "nonce-and-transport",
        "nonce-echo",
        "attestation-key",
        "none",
    }


def test_a_capture_may_assert_no_caller_freshness(snp_store) -> None:
    """The Azure path binds REPORT_DATA to the vTPM attestation key.

    Passing an empty nonce would not express this: that computes sha256(b"") and
    compares, so the capture fails a check it never claimed to make. The reason
    returned says what was and was not established, so a pass cannot be read as
    freshness.
    """
    vector, store = snp_store
    outcome = evaluate_vendor(vector, store=store)
    assert outcome.verified
    assert "no caller freshness asserted" in outcome.reason


# ---- expiry ----------------------------------------------------------


def test_the_scored_tier_reads_the_vector_clock(snp_store) -> None:
    """A conformance score that changes as certificates age is not a score."""
    vector, store = snp_store
    assert evaluate_vendor(vector, store=store).verified
    assert datetime.fromisoformat(vector["validity"]["now"]) < datetime.now(timezone.utc)


def test_the_live_tier_reads_the_wall_clock(snp_store) -> None:
    vector, store = snp_store
    assert live_check(vector, store=store, now=datetime.now(timezone.utc))[0]


def test_the_live_tier_shows_a_capture_outside_its_window(snp_store) -> None:
    """Where a capture ageing out becomes visible, without degrading a score."""
    vector, store = snp_store
    ok, reason = live_check(
        vector, store=store, now=datetime(2019, 1, 1, tzinfo=timezone.utc)
    )
    assert not ok
    assert "validity window" in reason


def test_not_after_is_required_not_optional(snp_store) -> None:
    vector, store = snp_store
    del vector["validity"]["not_after"]
    with pytest.raises(VendorVectorError) as exc:
        evaluate_vendor(vector, store=store)
    assert "not_after" in str(exc.value)


# ---- refusals --------------------------------------------------------


def test_every_mutation_is_refused_on_a_real_capture(snp_store) -> None:
    vector, store = snp_store
    outcome = evaluate_vendor(vector, store=store)
    unrefused = sorted(case for case, (ok, _) in outcome.refusals.items() if not ok)
    assert not unrefused, {c: outcome.refusals[c][1] for c in unrefused}


def test_a_capture_cannot_arrive_with_only_a_happy_path(snp_store) -> None:
    vector, store = snp_store
    del vector["refusals"]["tampered-signature"]
    with pytest.raises(VendorVectorError) as exc:
        evaluate_vendor(vector, store=store)
    assert "tampered-signature" in str(exc.value)


def test_the_tamper_cases_land_where_verification_looks(snp_store) -> None:
    """An SEV-SNP report has reserved bytes after its signature field.

    Flipping the last byte leaves the signed material and the signature both
    intact, so the case passed having changed nothing an implementation checks.
    Both tamper mutations now ask the format where to land.
    """
    vector, store = snp_store
    outcome = evaluate_vendor(vector, store=store)
    for case in ("tampered-report", "tampered-signature"):
        refused, reason = outcome.refusals[case]
        assert refused, reason
        assert "signature does not verify" in reason


def test_the_untrusted_root_is_the_one_the_suite_ships(snp_store) -> None:
    """Every runner should fail that case for the same reason, which only
    happens if they are all given the same root.

    The two obvious ways to invent it both look like passes: an anchor that
    legitimately verifies, and a VCEK rejected on serial policy before chain
    logic runs.
    """
    _, store = snp_store
    anchor = store.out_of_chain()
    assert "wcm-conformance-out-of-chain-root" in anchor.subject.rfc4514_string()
    assert anchor.serial_number > 0, "a non-positive serial fails before chain logic"


def test_a_reason_is_matched_on_a_substring_not_an_exact_message(snp_store) -> None:
    """Or the vectors become a change detector for wording."""
    vector, store = snp_store
    vector["refusals"]["out-of-chain-root"] = {"reason_contains": "trusted root"}
    refused, reason = evaluate_vendor(vector, store=store).refusals["out-of-chain-root"]
    assert refused
    assert reason != "trusted root"


def test_a_declared_reason_that_does_not_match_fails_the_vector(snp_store) -> None:
    vector, store = snp_store
    vector["refusals"]["out-of-chain-root"] = {"reason_contains": "something else"}
    refused, _ = evaluate_vendor(vector, store=store).refusals["out-of-chain-root"]
    assert not refused


# ---- what the runner reports -----------------------------------------


def test_the_runner_accepts_a_capture_that_passes_its_whole_matrix(
    snp_store, monkeypatch: pytest.MonkeyPatch
) -> None:
    import wcm._vendor_vectors as vv

    vector, store = snp_store
    monkeypatch.setattr(vv, "load_root_store", lambda *a, **k: store)
    assert evaluate(vector).verdict == "accept"


def test_the_runner_fails_a_capture_whose_mutation_still_verified(
    snp_store, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The case that matters: a parser passes this, a verifier does not."""
    import wcm._vendor_vectors as vv

    vector, store = snp_store
    monkeypatch.setattr(vv, "load_root_store", lambda *a, **k: store)
    monkeypatch.setattr(vv, "_mutate", lambda vector, case: vector)
    result = evaluate(vector)
    assert result.verdict == "reject"
    assert "not refused" in result.detail


def test_a_vector_the_runner_cannot_use_fails_rather_than_being_skipped(
    stage: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Silence about a vector is not evidence of passing it."""
    import wcm._vendor_vectors as vv

    vector = _snp_vector(stage)
    (stage / "amd-ark.pem").unlink()
    monkeypatch.setattr(
        vv, "load_root_store", lambda *a, **k: load_root_store(extra_dirs=[stage])
    )
    result = evaluate(vector)
    assert result.verdict == "reject"
    assert "root not staged" in result.detail


# ---- the rule holds for a vendor whose evidence carries its own chain ----


def _tdx_vector(stage: Path) -> dict:
    """A GCP C3 TDX capture, carrying leaf and intermediates inline.

    A TDX quote carries a copy of its PCK chain inside the signed bytes, so the
    chain is recoverable and the vector carries it like every other vendor. No
    flag, no exception: the runner checks the carried chain against the named
    root before the quote's own verifier runs, which is what keeps these fields
    load-bearing rather than decorative on this one vendor.
    """
    from wcm.tdx import parse_tdx_quote

    doc = json.loads((FIXTURES / "tdx_quote_gcp.json").read_text(encoding="utf-8"))
    quote = parse_tdx_quote(base64.b64decode(doc["quote_b64"]))
    chain = [quote.pck_leaf, *quote.pck_intermediates]
    root = next(c for c in chain if c.subject == c.issuer)
    below = [c for c in chain if c is not root]
    (stage / "intel-sgx-root.pem").write_bytes(root.public_bytes(Encoding.PEM))

    def pem(cert: x509.Certificate) -> str:
        return cert.public_bytes(Encoding.PEM).decode()

    return {
        "id": "accept-tdx-gcp-nonce-digest",
        "level": "L2",
        "kind": "vendor",
        "description": "A GCP C3 TDX quote, verified to a staged Intel SGX root.",
        "expect": "accept",
        "capture": {
            "vendor": "intel",
            "technology": "tdx",
            "part": "GCP C3",
            "captured_at": "2026-01-01",
            "source": "committed SDK fixture",
        },
        "evidence": {"format": "tdx-quote", "report_b64": doc["quote_b64"]},
        "chain": {
            "leaf_pem": pem(below[0]),
            "intermediates_pem": [pem(c) for c in below[1:]],
            "root": {
                "id": "intel-sgx-root-ca",
                "der_sha256": "sha256:"
                + hashlib.sha256(root.public_bytes(Encoding.DER)).hexdigest(),
            },
            "root_source": "Intel SGX root CA, staged by the runner",
        },
        "binding": {"kind": "nonce-digest", "nonce_hex": doc["expected_nonce"]},
        "validity": {
            "now": max(c.not_valid_before_utc for c in chain).isoformat(),
            "not_after": min(c.not_valid_after_utc for c in chain).isoformat(),
        },
        "refusals": {case: {"reason_contains": REASONS[case]} for case in MATRIX},
    }


def test_a_tdx_capture_carries_its_chain_inline_like_everything_else(
    stage: Path,
) -> None:
    vector = _tdx_vector(stage)
    outcome = evaluate_vendor(vector, store=load_root_store(extra_dirs=[stage]))
    assert outcome.verified, outcome.reason
    unrefused = sorted(case for case, (ok, _) in outcome.refusals.items() if not ok)
    assert not unrefused, {c: outcome.refusals[c][1] for c in unrefused}


def test_stripping_a_tdx_chain_fails_even_though_the_quote_still_has_one(
    stage: Path,
) -> None:
    """The case the exception would have hidden.

    verify_tdx_quote reads the chain out of the quote, so without the carried
    chain being checked this mutation changes nothing and the case reports a
    refusal nobody performed.
    """
    vector = _tdx_vector(stage)
    refused, reason = evaluate_vendor(
        vector, store=load_root_store(extra_dirs=[stage])
    ).refusals["stripped-chain"]
    assert refused
    assert "trusted root" in reason


# ---- the hard case, handled by the rule rather than by an exception ----


def _gpu_vector(stage: Path) -> dict:
    """The H100 capture, in the shape this format defines.

    Its chain terminates in a self-signed CN=NVIDIA Device Identity CA carried
    inside the file, so today it anchors itself. Under this format it carries
    leaf and intermediates inline and names that certificate as a root the
    runner stages. The same bytes either way, and only one of the two
    arrangements tests anything about the vendor.

    ``chain.root_limit`` records what is and is not known about where that root
    comes from, because this repository holds the certificate with no recorded
    source.
    """
    doc = json.loads((FIXTURES / "gpu_h100_attestation.json").read_text(encoding="utf-8"))
    blob, certs, buf = doc["cert_chain_pem"], [], ""
    for line in blob.splitlines(True):
        buf += line
        if "END CERTIFICATE" in line:
            certs.append(buf)
            buf = ""
    leaf, intermediates, root = certs[0], certs[1:-1], certs[-1]
    (stage / "nvidia-root.pem").write_text(root)
    return {
        "id": "accept-nvidia-h100",
        "level": "L2",
        "kind": "vendor",
        "description": "An H100 device report, verified to a staged NVIDIA root.",
        "expect": "accept",
        "capture": {
            "vendor": "nvidia",
            "technology": "nvidia-cc",
            "part": "H100",
            "captured_at": "2026-01-01",
            "source": "committed SDK fixture",
        },
        "evidence": {
            "format": "nvidia-attestation-report",
            "report_b64": doc["report_b64"],
        },
        "chain": {
            "leaf_pem": leaf,
            "intermediates_pem": intermediates,
            "root": {"id": "nvidia-device-identity-ca", "der_sha256": _digest(root)},
            "root_source": "NVIDIA Device Identity CA, staged by the runner",
            "root_limit": (
                "this repository holds the certificate with no recorded "
                "publication source, so a runner stages it from the device "
                "chain rather than from a published distribution"
            ),
        },
        # The report echoes the nonce verbatim at offset 4, so it declares the
        # kind that says so rather than one that claims a digest.
        "binding": {
            "kind": "nonce-echo",
            "nonce_hex": doc["nonce"],
            "nonce_offset": 4,
        },
        "validity": {
            "now": max(_load(pem).not_valid_before_utc for pem in certs).isoformat(),
            "not_after": min(_load(pem).not_valid_after_utc for pem in certs).isoformat(),
        },
        "refusals": {case: {"reason_contains": REASONS[case]} for case in MATRIX},
    }


def test_the_gpu_capture_passes_the_whole_matrix(stage: Path) -> None:
    """The hard case, and the test of the rule.

    A format whose hardest case is handled by exception is not a format, so this
    capture takes the same shape as every other: chain inline, root named and
    staged, all six refusals derived and refused.
    """
    vector = _gpu_vector(stage)
    outcome = evaluate_vendor(vector, store=load_root_store(extra_dirs=[stage]))
    assert outcome.verified, outcome.reason
    unrefused = sorted(case for case, (ok, _) in outcome.refusals.items() if not ok)
    assert not unrefused, {c: outcome.refusals[c][1] for c in unrefused}


def test_the_expiry_case_fires_on_a_chain_that_never_expires(stage: Path) -> None:
    """Every NVIDIA certificate here is valid until 9999-12-31T23:59:59.

    A one-second step past that overflows, which looked at first like a capture
    the matrix could not cover. Validity is an inclusive comparison, so the
    smallest representable step past not_after is outside the window and the
    case applies to this capture like any other.
    """
    vector = _gpu_vector(stage)
    assert vector["validity"]["not_after"].startswith("9999-12-31")
    refused, reason = evaluate_vendor(
        vector, store=load_root_store(extra_dirs=[stage])
    ).refusals["expired-at-now"]
    assert refused
    assert "validity window" in reason


def test_a_root_that_cannot_be_staged_from_a_published_source_says_so(
    stage: Path,
) -> None:
    """Said in the vector as a stated limit, rather than left implicit."""
    vector = _gpu_vector(stage)
    assert vector["chain"]["root_limit"]
    assert evaluate_vendor(vector, store=load_root_store(extra_dirs=[stage])).verified


# ---- the live tier is reported, not merely available ------------------


def test_the_live_tier_is_part_of_the_report(stage: Path, monkeypatch) -> None:
    """A tier nobody reports is not a separately reported tier.

    live_check existed and nothing called it, so a capture ageing out would have
    been invisible, which is the one thing this tier is for.
    """
    from wcm.conformance import live_tier

    vector = _snp_vector(stage)
    import wcm._vendor_vectors as vv

    monkeypatch.setattr(
        vv, "load_root_store", lambda *a, **k: load_root_store(extra_dirs=[stage])
    )
    results = live_tier([vector, {"kind": "manifest", "id": "not-a-capture"}])
    assert [r[0] for r in results] == ["accept-snp-azure-attestation-key"]
    assert results[0][1] is True


def test_the_live_tier_never_changes_the_score(stage: Path, monkeypatch) -> None:
    """Certificates expire. A score that moved when they did would say nothing
    about the implementation it was scoring."""
    from wcm.conformance import SuiteReport

    report = SuiteReport(levels=[], live=[("aged-capture", False, "outside window")])
    rendered = report.render()
    assert "reported, not scored" in rendered
    assert "aged-capture" in rendered
    assert report.ok is False  # no levels at all, not because of the live tier


# ---- the schema is enforced, not merely shipped -----------------------


def test_a_vector_cannot_carry_a_digest_of_the_report(snp_store) -> None:
    """The pinning rule, enforced where it is stated.

    "The schema has nowhere to record a digest" is only true of a schema
    something validates against. Three ranges of an H200 report move between
    calls and 32 bytes at [3565, 3597) change even under an identical nonce, so
    a pin built by diffing two reports under different nonces looks stable and
    is not.
    """
    vector, store = snp_store
    vector["evidence"]["report_sha256"] = "sha256:" + "00" * 32
    with pytest.raises(VendorVectorError) as exc:
        evaluate_vendor(vector, store=store)
    assert "report_sha256" in str(exc.value)


def test_a_vector_cannot_pin_the_full_report_bytes_under_another_name(
    snp_store,
) -> None:
    vector, store = snp_store
    vector["expected_report_b64"] = vector["evidence"]["report_b64"]
    with pytest.raises(VendorVectorError) as exc:
        evaluate_vendor(vector, store=store)
    assert "expected_report_b64" in str(exc.value)


def test_a_capture_without_provenance_is_refused(snp_store) -> None:
    """Vendor, part, capture date and source.

    Without them a vector that starts failing is unattributable, and nobody can
    tell whether the implementation regressed or the platform moved. The rule
    lives only in the schema, so it only exists if the schema is checked.
    """
    vector, store = snp_store
    del vector["capture"]["part"]
    with pytest.raises(VendorVectorError) as exc:
        evaluate_vendor(vector, store=store)
    assert "part" in str(exc.value)


def test_intermediates_must_be_carried_inline(snp_store) -> None:
    """"Carry leaf and intermediates inline" is a schema rule.

    The runner alone would accept a vector with no intermediates field at all,
    because it reads that field with a default.
    """
    vector, store = snp_store
    del vector["chain"]["intermediates_pem"]
    with pytest.raises(VendorVectorError) as exc:
        evaluate_vendor(vector, store=store)
    assert "intermediates_pem" in str(exc.value)


def test_an_empty_reason_substring_is_refused(snp_store) -> None:
    """An empty substring is contained in every string, so a case declaring one
    would report a refusal for any reason at all, including the wrong one."""
    vector, store = snp_store
    vector["refusals"]["stripped-chain"] = {"reason_contains": ""}
    with pytest.raises(VendorVectorError) as exc:
        evaluate_vendor(vector, store=store)
    assert "non-empty" in str(exc.value)


def test_the_shipped_schema_is_loadable_from_the_package() -> None:
    from wcm.schema import VENDOR_VECTOR_SCHEMA_ID, vendor_vector_schema

    assert vendor_vector_schema()["$id"] == VENDOR_VECTOR_SCHEMA_ID


# ---- the published schema and the reference validator agree ----------
#
# jsonschema is a development dependency here, and pyproject says why: wcm.schema
# hands back the schema document and leaves validation to the caller. So the
# runner validates natively and the schema is the published form, exactly as the
# manifest does it. This is the test that stops the two drifting, which is the
# only thing that makes the published document worth anything to an
# implementation in another language.


def _mutations(vector: dict) -> list[tuple[str, dict]]:
    """Vectors that must be rejected, and why, one lie each."""
    import copy

    cases: list[tuple[str, dict]] = []

    def case(label, fn):
        bad = copy.deepcopy(vector)
        fn(bad)
        cases.append((label, bad))

    case("a digest of the report", lambda v: v["evidence"].update(report_sha256="sha256:00"))
    case("the full report bytes under another name",
       lambda v: v.update(expected_report_b64=v["evidence"]["report_b64"]))
    case("no provenance", lambda v: v["capture"].pop("part"))
    case("no intermediates carried", lambda v: v["chain"].pop("intermediates_pem"))
    case("no recorded horizon", lambda v: v["validity"].pop("not_after"))
    case("an unrecognised binding kind", lambda v: v["binding"].update(kind="nonce-by-post"))
    case("an empty reason substring",
       lambda v: v["refusals"].update({"stripped-chain": {"reason_contains": ""}}))
    case("a missing refusal case", lambda v: v["refusals"].pop("tampered-report"))
    return cases


def test_the_schema_and_the_runner_accept_the_same_vector(snp_store) -> None:
    jsonschema = pytest.importorskip("jsonschema")
    from wcm.schema import vendor_vector_schema

    vector, store = snp_store
    jsonschema.validate(vector, vendor_vector_schema())
    assert evaluate_vendor(vector, store=store).verified


def test_the_schema_and_the_runner_reject_the_same_vectors(snp_store) -> None:
    """Parity, case by case, so a rule added to one is not missing from the other."""
    jsonschema = pytest.importorskip("jsonschema")
    from wcm.schema import vendor_vector_schema

    vector, store = snp_store
    schema = vendor_vector_schema()
    for label, bad in _mutations(vector):
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(bad, schema)
        with pytest.raises(VendorVectorError):
            evaluate_vendor(bad, store=store)
        assert label  # named so a failure says which rule drifted


def test_a_vendor_vector_cannot_be_a_reject_vector(snp_store) -> None:
    """The negatives are derived, not contributed.

    It was also unsound while it existed. The suite's second scoring rule is
    that a reject must carry the declared code, and this evaluator has no WCM
    code vocabulary, so it returned the vector's own declared code and the check
    compared a value to itself.
    """
    vector, store = snp_store
    vector["expect"] = "reject"
    with pytest.raises(VendorVectorError) as exc:
        evaluate_vendor(vector, store=store)
    assert "expect must be 'accept'" in str(exc.value)


def test_the_schema_also_refuses_a_reject_vector(snp_store) -> None:
    jsonschema = pytest.importorskip("jsonschema")
    from wcm.schema import vendor_vector_schema

    vector, _ = snp_store
    vector["expect"] = "reject"
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(vector, vendor_vector_schema())


# ---- the fifth kind: the nonce appears verbatim (#128) ---------------


def test_the_gpu_capture_declares_the_mechanism_in_its_bytes(stage: Path) -> None:
    """nonce-digest says REPORT_DATA equals sha256(nonce). NVIDIA reports have
    no REPORT_DATA and echo the nonce verbatim, so that label named something
    that is not there. It verified either way, which is exactly why a closed
    vocabulary is the only thing that catches it."""
    vector = _gpu_vector(stage)
    assert vector["binding"]["kind"] == "nonce-echo"
    assert vector["binding"]["nonce_offset"] == 4
    assert evaluate_vendor(vector, store=load_root_store(extra_dirs=[stage])).verified


def test_the_offset_is_checked_against_the_report_format(stage: Path) -> None:
    """A capture declaring an offset its report does not use is describing a
    mechanism it does not have, which is the whole reason this kind exists."""
    vector = _gpu_vector(stage)
    vector["binding"]["nonce_offset"] = 8
    outcome = evaluate_vendor(vector, store=load_root_store(extra_dirs=[stage]))
    assert not outcome.verified
    assert "offset 8" in outcome.reason and "echoes it at 4" in outcome.reason


def test_an_offset_is_refused_on_a_kind_that_binds_a_digest(snp_store) -> None:
    """A digest has no offset to declare, so the field describes nothing."""
    vector, store = snp_store
    vector["binding"] = {
        "kind": "nonce-digest",
        "nonce_hex": "ab" * 32,
        "nonce_offset": 4,
    }
    with pytest.raises(VendorVectorError) as exc:
        evaluate_vendor(vector, store=store)
    assert "nonce_offset belongs to 'nonce-echo'" in str(exc.value)


def test_the_new_kind_is_named_for_the_bytes_not_the_vendor() -> None:
    """Any platform echoing a nonce verbatim belongs in it, so the name says
    what happens rather than who does it."""
    assert "nonce-echo" in BINDING_KINDS
    assert not any(
        v in kind for kind in BINDING_KINDS for v in ("nvidia", "amd", "intel", "gpu")
    )


def test_a_nonce_echo_capture_must_carry_a_nonce(snp_store) -> None:
    vector, store = snp_store
    vector["binding"] = {"kind": "nonce-echo", "nonce_offset": 4}
    with pytest.raises(VendorVectorError) as exc:
        evaluate_vendor(vector, store=store)
    assert "requires nonce_hex" in str(exc.value)
