"""CLI surface for the conformance suite.

The exit status is the contract: a CI job somewhere will gate on it, so it has to
be 0 only when every scored level actually passed, and non-zero when a level was
asked for but cannot be scored at all.
"""
from __future__ import annotations

import json
from pathlib import Path

from wcm.cli import main
from wcm.conformance import DECLARED_ONLY_LEVELS, VECTORED_LEVELS, load_vectors


def _perfect_results() -> dict:
    return {
        "implementation": "test-double 1.0",
        "results": [
            {
                "id": v["id"],
                "verdict": v["expect"],
                **({"code": v["code"]} if v["expect"] == "reject" else {}),
            }
            for v in load_vectors()
        ],
    }


def test_self_test_passes_and_names_covered_levels(capsys):
    assert main(["conformance"]) == 0
    out = capsys.readouterr().out
    for level_id in VECTORED_LEVELS:
        assert f"{level_id}  PASS" in out
    assert "levels ok : " + ", ".join(VECTORED_LEVELS) in out


def test_self_test_warns_about_uncovered_levels(capsys):
    """The whole point of the honesty framing: a green run must not read as full
    conformance while L2 and L3 have no vectors."""
    assert main(["conformance"]) == 0
    out = capsys.readouterr().out
    assert "NOT COVERED:" in out
    for level_id in DECLARED_ONLY_LEVELS:
        assert level_id in out


def test_single_vectored_level(capsys):
    assert main(["conformance", "--level", "L4"]) == 0
    out = capsys.readouterr().out
    assert "L4  PASS" in out
    assert "L1" not in out.split("subject")[-1].split("levels ok")[0]


def test_declared_only_level_exits_nonzero(capsys):
    """You cannot pass a level that has no vectors."""
    assert main(["conformance", "--level", "L2"]) == 1
    out = capsys.readouterr().out
    assert "no vectors yet" in out
    assert "levels ok : none" in out


def test_score_a_perfect_results_file(tmp_path: Path, capsys):
    path = tmp_path / "results.json"
    path.write_text(json.dumps(_perfect_results()), encoding="utf-8")
    assert main(["conformance", "--results", str(path)]) == 0
    out = capsys.readouterr().out
    assert "test-double 1.0" in out
    # An external run is not labelled as a self-test.
    assert "reference self-test" not in out


def test_score_a_failing_results_file(tmp_path: Path, capsys):
    results = _perfect_results()
    results["results"] = [
        {"id": entry["id"], "verdict": "accept"} for entry in results["results"]
    ]
    path = tmp_path / "bad.json"
    path.write_text(json.dumps(results), encoding="utf-8")
    assert main(["conformance", "--results", str(path)]) == 1
    out = capsys.readouterr().out
    assert "FAIL" in out
    assert "expected reject" in out


def test_score_a_truncated_results_file(tmp_path: Path, capsys):
    """A partial file must not be able to claim a level."""
    results = _perfect_results()
    results["results"] = results["results"][:3]
    path = tmp_path / "partial.json"
    path.write_text(json.dumps(results), encoding="utf-8")
    assert main(["conformance", "--results", str(path)]) == 1
    assert "no result reported" in capsys.readouterr().out


def test_list_vectors(capsys):
    assert main(["conformance", "--list-vectors"]) == 0
    out = capsys.readouterr().out
    assert len(out.strip().splitlines()) == len(load_vectors())
    assert "reject-self-derivation" in out


def test_list_codes(capsys):
    assert main(["conformance", "--list-codes"]) == 0
    out = capsys.readouterr().out
    # Every level's codes are listed, including the levels without vectors.
    for prefix in ("WCM-L1-", "WCM-L2-", "WCM-L3-", "WCM-L4-"):
        assert prefix in out
