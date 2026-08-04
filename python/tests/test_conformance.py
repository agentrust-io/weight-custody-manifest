"""Tests for the conformance suite itself.

A conformance suite that is not itself tested is worse than none: it hands out
verdicts nobody has checked. Four things need to hold.

1. **The reference passes its own suite**, verdicts *and* codes. This is the
   weakest of the four as evidence about the protocol (one codebase wrote both
   sides) but the strongest as a regression net: it catches a vector whose
   expectation has drifted from the implementation.
2. **Every declared code is reachable and every reachable code is declared.** An
   unreachable code is a documented behaviour nothing produces; an undeclared one
   is a report an implementer cannot look up.
3. **The scorer cannot be fooled.** Rejecting everything, omitting vectors, or
   rejecting for the wrong reason must all fail. This is what the pass means.
4. **Uncovered levels stay visibly uncovered.** L2 and L3 have no vectors, and a
   report must not let that read as a pass.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest

from wcm.conformance import (
    CODES,
    DECLARED_ONLY_LEVELS,
    LEVELS,
    VECTORED_LEVELS,
    Verdict,
    evaluate,
    level_of_code,
    load_vectors,
    run_reference,
    score_results,
    vectors_dir,
)

VECTORS = load_vectors()
IDS = [v["id"] for v in VECTORS]
REJECTS = [v for v in VECTORS if v["expect"] == "reject"]


def _codes_md() -> Path:
    for parent in Path(__file__).resolve().parents:
        candidate = parent / "conformance" / "codes.md"
        if candidate.is_file():
            return candidate
    raise AssertionError("could not find conformance/codes.md")


# --------------------------------------------------------------------------
# 1. The reference passes its own suite
# --------------------------------------------------------------------------


def test_reference_passes_every_vectored_level() -> None:
    report = run_reference()
    assert report.ok, report.render()
    assert {r.level for r in report.levels} == set(VECTORED_LEVELS)


@pytest.mark.parametrize("vector", VECTORS, ids=IDS)
def test_reference_reaches_the_declared_code(vector: dict[str, Any]) -> None:
    """Codes are only useful if the reference actually produces them.

    This is also what makes the message-text matching in ``_structural_code``
    safe: rewording a validator message breaks this test loudly instead of
    silently reclassifying the error.
    """
    got = evaluate(vector)
    assert got.verdict == vector["expect"], f"{vector['id']}: {got.detail}"
    if vector["expect"] == "reject":
        assert got.code == vector["code"], (
            f"{vector['id']}: reference reported {got.code} for "
            f"{vector['code']}. Detail: {got.detail}"
        )


def test_every_level_with_vectors_has_some_of_each_outcome() -> None:
    for level_id in VECTORED_LEVELS:
        outcomes = {v["expect"] for v in load_vectors(level=level_id)}
        assert outcomes == {"accept", "reject"}, level_id


# --------------------------------------------------------------------------
# 2. The code registry is honest in both directions
# --------------------------------------------------------------------------


def test_vector_codes_are_all_declared() -> None:
    undeclared = sorted({v["code"] for v in REJECTS} - set(CODES))
    assert not undeclared, f"vectors use codes absent from CODES: {undeclared}"


def test_vector_code_level_matches_vector_level() -> None:
    for vector in REJECTS:
        assert level_of_code(vector["code"]) == vector["level"], vector["id"]


def test_codes_md_matches_the_registry() -> None:
    """The published table and the code must not drift apart."""
    text = _codes_md().read_text(encoding="utf-8")
    documented = dict(re.findall(r"^\| `(WCM-[^`]+)` \| (.+?) \|$", text, re.MULTILINE))
    assert documented == CODES, (
        "conformance/codes.md and wcm.conformance.CODES disagree. "
        f"only in docs: {sorted(set(documented) - set(CODES))}; "
        f"only in code: {sorted(set(CODES) - set(documented))}"
    )


def test_every_vectored_level_code_is_exercised() -> None:
    """A code on a vectored level with no vector is an unenforced claim.

    Codes on L2/L3 are deliberately unexercised: those levels have no vectors
    yet, which is the documented gap, not an oversight.
    """
    used = {v["code"] for v in REJECTS}
    unexercised = sorted(
        code
        for code in CODES
        if level_of_code(code) in VECTORED_LEVELS and code not in used
    )
    assert not unexercised, f"declared but never exercised by a vector: {unexercised}"


def test_declared_only_levels_have_codes_but_no_vectors() -> None:
    for level_id in DECLARED_ONLY_LEVELS:
        assert not load_vectors(level=level_id), f"{level_id} unexpectedly has vectors"
        assert any(level_of_code(c) == level_id for c in CODES), (
            f"{level_id} has no codes allocated, so an implementation has nothing "
            "to report against"
        )


# --------------------------------------------------------------------------
# 3. The scorer cannot be fooled
# --------------------------------------------------------------------------


def _results(entries: list[dict[str, Any]]) -> dict[str, Any]:
    return {"implementation": "test-double", "results": entries}


def test_a_perfect_results_file_passes() -> None:
    entries = [
        {"id": v["id"], "verdict": v["expect"], **({"code": v["code"]} if v["expect"] == "reject" else {})}
        for v in VECTORS
    ]
    report = score_results(_results(entries))
    assert report.ok, report.render()


def test_rejecting_everything_fails() -> None:
    """The obvious cheat: deny every input and claim perfect rejection coverage."""
    entries = [{"id": v["id"], "verdict": "reject", "code": "WCM-L1-0001"} for v in VECTORS]
    report = score_results(_results(entries))
    assert not report.ok
    failed = {o.vector_id for r in report.levels for o in r.failures}
    assert {v["id"] for v in VECTORS if v["expect"] == "accept"} <= failed


def test_accepting_everything_fails() -> None:
    entries = [{"id": v["id"], "verdict": "accept"} for v in VECTORS]
    report = score_results(_results(entries))
    assert not report.ok
    failed = {o.vector_id for r in report.levels for o in r.failures}
    assert {v["id"] for v in REJECTS} <= failed


def test_right_verdict_wrong_code_fails() -> None:
    """Rejecting for the wrong reason is not conformance."""
    wrong = "WCM-L1-0005"
    target = next(v for v in REJECTS if v["code"] != wrong)
    entries = [
        {"id": v["id"], "verdict": v["expect"], **({"code": v["code"]} if v["expect"] == "reject" else {})}
        for v in VECTORS
    ]
    for entry in entries:
        if entry["id"] == target["id"]:
            entry["code"] = wrong
    report = score_results(_results(entries))
    assert not report.ok
    failure = next(
        o for r in report.levels for o in r.failures if o.vector_id == target["id"]
    )
    assert wrong in failure.reason and target["code"] in failure.reason


def test_omitting_a_vector_fails() -> None:
    """Silence about a vector is not evidence of passing it."""
    omitted = VECTORS[0]["id"]
    entries = [
        {"id": v["id"], "verdict": v["expect"], **({"code": v["code"]} if v["expect"] == "reject" else {})}
        for v in VECTORS
        if v["id"] != omitted
    ]
    report = score_results(_results(entries))
    assert not report.ok
    failed = {o.vector_id for r in report.levels for o in r.failures}
    assert omitted in failed


def test_empty_results_file_fails() -> None:
    report = score_results(_results([]))
    assert not report.ok


def test_unknown_verdict_string_fails() -> None:
    entries = [{"id": v["id"], "verdict": "maybe"} for v in VECTORS]
    report = score_results(_results(entries))
    assert not report.ok


def test_results_for_an_unknown_vector_are_surfaced() -> None:
    entries = [
        {"id": v["id"], "verdict": v["expect"], **({"code": v["code"]} if v["expect"] == "reject" else {})}
        for v in VECTORS
    ]
    entries.append({"id": "accept-vector-from-the-future", "verdict": "accept"})
    report = score_results(_results(entries))
    rendered = report.render()
    assert "accept-vector-from-the-future" in rendered


# --------------------------------------------------------------------------
# 4. Uncovered levels stay visibly uncovered
# --------------------------------------------------------------------------


def test_declared_only_level_cannot_pass() -> None:
    for level_id in DECLARED_ONLY_LEVELS:
        report = run_reference(level=level_id)
        assert not report.ok, f"{level_id} has no vectors and must not report a pass"
        assert level_id in report.unscoreable


def test_full_report_names_the_uncovered_levels() -> None:
    rendered = run_reference().render()
    for level_id in DECLARED_ONLY_LEVELS:
        assert level_id in rendered
        assert LEVELS[level_id].title in rendered
    assert "no vectors yet" in rendered


# --------------------------------------------------------------------------
# Plumbing
# --------------------------------------------------------------------------


def test_vectors_dir_resolves_and_holds_every_kind() -> None:
    root = vectors_dir()
    assert root.is_dir()
    kinds = {p.name for p in root.iterdir() if p.is_dir()}
    expected = {kind for level in LEVELS.values() for kind in level.kinds}
    assert expected <= kinds


def test_vector_ids_are_unique_and_match_filenames() -> None:
    assert len(IDS) == len(set(IDS))
    for kind_dir in sorted(p for p in vectors_dir().iterdir() if p.is_dir()):
        for path in sorted(kind_dir.glob("*.json")):
            vector = json.loads(path.read_text(encoding="utf-8"))
            assert vector["id"] == path.stem, path.name
            assert vector["kind"] == kind_dir.name, path.name


def test_load_vectors_filters() -> None:
    assert load_vectors(level="L4") == load_vectors(kind="lineage")
    assert len(load_vectors(level="L1")) == len(VECTORS) - len(load_vectors(level="L4"))
    with pytest.raises(ValueError, match="unknown level"):
        load_vectors(level="L9")


def test_level_of_code_rejects_nonsense() -> None:
    assert level_of_code("WCM-L2-0007") == "L2"
    for bad in ("WCM-L9-0001", "TR-L1-0001", "WCM-L1", "nonsense"):
        with pytest.raises(ValueError):
            level_of_code(bad)


def test_evaluate_rejects_an_unknown_kind() -> None:
    with pytest.raises(ValueError, match="no evaluator"):
        evaluate({"id": "x", "level": "L1", "kind": "telepathy", "expect": "accept"})


def test_signature_vector_with_an_unsupported_trusted_key_algorithm() -> None:
    vector = dict(load_vectors(kind="signature")[0])
    vector["trusted_keys"] = [{"algorithm": "ML-DSA-65", "public_key": "AAAA"}]
    with pytest.raises(ValueError, match="does not load yet"):
        evaluate(vector)


def test_verdict_is_hashable_and_frozen() -> None:
    verdict = Verdict("reject", "WCM-L1-0001", "detail")
    assert hash(verdict)
    with pytest.raises(Exception):
        verdict.code = "WCM-L1-0002"  # type: ignore[misc]
