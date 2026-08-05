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
    COVERAGE_NOTES,
    DECLARED_ONLY_LEVELS,
    DIAGNOSTIC_ONLY_CODES,
    LEVELS,
    NOT_YET_VECTORED_CODES,
    LevelReport,
    SuiteReport,
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
    documented = dict(
        re.findall(r"^\| `(WCM-[^`]+)` \| (.+?) \|.*\|$", text, re.MULTILINE)
    )
    assert documented == CODES, (
        "conformance/codes.md and wcm.conformance.CODES disagree. "
        f"only in docs: {sorted(set(documented) - set(CODES))}; "
        f"only in code: {sorted(set(CODES) - set(documented))}"
    )


def test_codes_md_marks_the_exempt_codes() -> None:
    """The two exemptions must be visible in the published table, not just in code."""
    text = _codes_md().read_text(encoding="utf-8")
    for code in DIAGNOSTIC_ONLY_CODES:
        row = next(line for line in text.splitlines() if f"`{code}`" in line)
        assert "diagnostic only" in row, code
    for code in NOT_YET_VECTORED_CODES:
        row = next(line for line in text.splitlines() if f"`{code}`" in line)
        assert "not yet vectored" in row, code


def test_every_code_is_exercised_or_explicitly_exempt() -> None:
    """A code with no vector and no exemption is an unenforced claim."""
    used = {v["code"] for v in REJECTS}
    exempt = DIAGNOSTIC_ONLY_CODES | NOT_YET_VECTORED_CODES
    unexercised = sorted(
        code
        for code in CODES
        if level_of_code(code) in VECTORED_LEVELS
        and code not in used
        and code not in exempt
    )
    assert not unexercised, f"declared but never exercised by a vector: {unexercised}"


def test_the_exemption_lists_do_not_quietly_grow() -> None:
    """Exemptions are deliberate; adding one is a decision.

    Without this, "add it to the exempt set" becomes the way to make a failing
    code disappear, which is the same failure mode as suppressing a CVE.
    """
    assert DIAGNOSTIC_ONLY_CODES == {"WCM-L3-0003", "WCM-L3-0004"}
    assert NOT_YET_VECTORED_CODES == frozenset(), (
        "every reportable code is vectored; a new entry here needs a reason in "
        "conformance/README.md, not just a line of code"
    )
    assert not (DIAGNOSTIC_ONLY_CODES & NOT_YET_VECTORED_CODES)
    # An exempt code must still be a real registered code.
    for code in DIAGNOSTIC_ONLY_CODES | NOT_YET_VECTORED_CODES:
        assert code in CODES, code


def test_not_yet_vectored_codes_really_have_no_vector() -> None:
    used = {v["code"] for v in REJECTS}
    assert not (NOT_YET_VECTORED_CODES & used), (
        "a code listed as not-yet-vectored now has a vector; remove it from "
        "NOT_YET_VECTORED_CODES"
    )


def test_coverage_notes_exist_and_say_what_is_missing() -> None:
    """The prose limits are load-bearing, so they must actually be there.

    Every reportable code is vectored now, which is exactly when it gets easy to
    read a green run as total coverage. These notes are what stop that.
    """
    assert COVERAGE_NOTES, "coverage limits must be stated somewhere the runner prints"
    for note in COVERAGE_NOTES:
        assert len(note) > 80, f"too terse to be useful: {note!r}"
    joined = " ".join(COVERAGE_NOTES)
    assert "GPU" in joined
    assert "synthetic PKI" in joined


def test_every_level_is_vectored() -> None:
    """All four levels have corpora now; DECLARED_ONLY_LEVELS should be empty.

    The declared-only machinery stays, because it is what keeps a future level
    from silently reporting a pass before it has vectors (see
    test_a_level_without_vectors_cannot_pass).
    """
    assert DECLARED_ONLY_LEVELS == ()
    assert set(VECTORED_LEVELS) == set(LEVELS)


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


def test_a_level_without_vectors_cannot_pass() -> None:
    """The guard for whatever level gets added next.

    Every level is vectored today, so this exercises the machinery directly rather
    than relying on L2 or L3 still being empty. A LevelReport with no vectors must
    report ok=False: unscoreable is not the same as passed.
    """
    empty = LevelReport(level="L2", vectored=False, outcomes=[])
    assert not empty.ok
    assert not SuiteReport(levels=[empty], unscoreable=["L2"]).ok
    # And with vectors declared but none present, still not a pass.
    assert not LevelReport(level="L2", vectored=True, outcomes=[]).ok


def test_full_report_names_every_level() -> None:
    rendered = run_reference().render()
    for level_id, level in LEVELS.items():
        assert level_id in rendered
        assert level.title in rendered
    assert "FAIL" not in rendered


# --------------------------------------------------------------------------
# Plumbing
# --------------------------------------------------------------------------


def test_vectors_dir_resolves_and_holds_every_kind() -> None:
    root = vectors_dir()
    assert root.is_dir()
    kinds = {p.name for p in root.iterdir() if p.is_dir()}
    expected = {kind for level in LEVELS.values() for kind in level.kinds}
    assert expected <= kinds


def test_vector_ids_are_globally_unique_and_match_filenames() -> None:
    """Unique across every kind, not just within one.

    The results-file contract keys on `id` alone, so two vectors sharing a name in
    different directories would silently collapse into one scored entry.
    """
    duplicates = sorted({i for i in IDS if IDS.count(i) > 1})
    assert not duplicates, f"vector ids are not globally unique: {duplicates}"
    for kind_dir in sorted(p for p in vectors_dir().iterdir() if p.is_dir()):
        for path in sorted(kind_dir.glob("*.json")):
            vector = json.loads(path.read_text(encoding="utf-8"))
            assert vector["id"] == path.stem, path.name
            assert vector["kind"] == kind_dir.name, path.name


def test_load_vectors_filters() -> None:
    assert load_vectors(level="L4") == load_vectors(kind="lineage")
    assert load_vectors(level="L2") == load_vectors(kind="gate")
    assert load_vectors(level="L3") == load_vectors(kind="custody")
    # L1 is the only level with two kinds.
    assert len(load_vectors(level="L1")) == len(
        load_vectors(kind="manifest")
    ) + len(load_vectors(kind="signature"))
    assert sum(len(load_vectors(level=lid)) for lid in LEVELS) == len(VECTORS)
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
