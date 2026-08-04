"""The manifest JSON Schema is a real, normative artifact, so test it as one.

Three properties matter, and each has a failure mode worth catching:

1. The committed schema matches what ``tools/gen_schema.py`` produces. Otherwise
   a model change silently leaves the published schema behind.
2. The schema and the reference model accept and reject the same manifests. A
   structurally-generated schema is easy to keep in sync; the hand-maintained
   cross-field ``if``/``then`` blocks are not, and this is what catches a
   validator added without a matching schema rule.
3. The one constraint JSON Schema cannot express stays *explicitly* marked. If
   someone later removes the model validator for self-derivation, the parity
   check alone would go green (schema and model would agree by both accepting),
   so that case is asserted directly.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator
from pydantic import ValidationError

from wcm.models import WeightCustodyManifest
from wcm.schema import SCHEMA_ID, manifest_schema, schema_path

import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import gen_schema  # noqa: E402

def _vector_dir() -> Path:
    """Locate the vector corpus by searching upward.

    A git checkout puts it at ``<repo>/conformance``; an unpacked sdist puts it at
    the sdist root next to ``tests/``. Searching upward covers both without
    hard-coding a parent depth that is wrong in one of them.
    """
    relative = Path("conformance") / "vectors" / "manifest"
    for parent in Path(__file__).resolve().parents:
        candidate = parent / relative
        if candidate.is_dir():
            return candidate
    raise AssertionError(f"could not find {relative} above {__file__}")


VECTOR_DIR = _vector_dir()


def _vectors() -> list[dict[str, Any]]:
    files = sorted(VECTOR_DIR.glob("*.json"))
    assert files, f"no manifest vectors found in {VECTOR_DIR}"
    return [json.loads(p.read_text(encoding="utf-8")) for p in files]


VECTORS = _vectors()
IDS = [v["id"] for v in VECTORS]


def _model_accepts(manifest: dict[str, Any]) -> bool:
    try:
        WeightCustodyManifest.model_validate(manifest)
    except ValidationError:
        return False
    return True


def _schema_accepts(manifest: dict[str, Any]) -> bool:
    return not list(Draft202012Validator(manifest_schema()).iter_errors(manifest))


# --------------------------------------------------------------------------
# 1. The schema is a valid schema, and the committed file is not stale
# --------------------------------------------------------------------------


def test_schema_is_valid_2020_12() -> None:
    Draft202012Validator.check_schema(manifest_schema())


def test_committed_schema_is_not_stale() -> None:
    """Fails if the model changed without regenerating: run tools/gen_schema.py."""
    assert schema_path().read_text(encoding="utf-8") == gen_schema.render()


def test_schema_identity() -> None:
    schema = manifest_schema()
    assert schema["$id"] == SCHEMA_ID
    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    # v1 is frozen and additive-only; a v2 would be a new file, not an edit.
    assert SCHEMA_ID.endswith("/v1.json")


def test_manifest_schema_returns_a_copy() -> None:
    first = manifest_schema()
    first["properties"].clear()
    assert manifest_schema()["properties"], "callers must not be able to corrupt the cache"


def test_schema_forbids_unknown_fields_at_every_level() -> None:
    """extra='forbid' on every model must survive into the schema."""
    schema = manifest_schema()
    assert schema["additionalProperties"] is False
    object_defs = {
        name: d
        for name, d in schema["$defs"].items()
        if d.get("type") == "object"
    }
    assert object_defs, "expected object definitions in $defs"
    permissive = [n for n, d in object_defs.items() if d.get("additionalProperties") is not False]
    assert not permissive, f"these objects accept unknown fields: {permissive}"


# --------------------------------------------------------------------------
# 2. Schema and model agree on the whole vector corpus
# --------------------------------------------------------------------------


@pytest.mark.parametrize("vector", VECTORS, ids=IDS)
def test_reference_model_matches_vector_expectation(vector: dict[str, Any]) -> None:
    expected = vector["expect"] == "accept"
    assert _model_accepts(vector["manifest"]) is expected, (
        f"{vector['id']}: reference model disagrees with the vector "
        f"(expected {vector['expect']})"
    )


@pytest.mark.parametrize("vector", VECTORS, ids=IDS)
def test_schema_matches_vector_expectation(vector: dict[str, Any]) -> None:
    """The schema must agree, except where the vector says it cannot.

    ``schema_expressible: false`` is the escape hatch, and it is deliberately
    narrow: see ``test_only_self_derivation_is_inexpressible``.
    """
    if vector["expect"] == "accept":
        expected = True
    else:
        expected = not vector.get("schema_expressible", True)
    assert _schema_accepts(vector["manifest"]) is expected, (
        f"{vector['id']}: schema disagrees with the vector "
        f"(expected the schema to {'accept' if expected else 'reject'})"
    )


def test_vector_corpus_covers_both_outcomes() -> None:
    outcomes = {v["expect"] for v in VECTORS}
    assert outcomes == {"accept", "reject"}
    assert sum(1 for v in VECTORS if v["expect"] == "accept") >= 5
    assert sum(1 for v in VECTORS if v["expect"] == "reject") >= 10


def test_vector_ids_are_unique_and_match_filenames() -> None:
    for path in sorted(VECTOR_DIR.glob("*.json")):
        vector = json.loads(path.read_text(encoding="utf-8"))
        assert vector["id"] == path.stem, f"{path.name} does not match its id"
    assert len(IDS) == len(set(IDS))


def test_reject_vectors_state_a_reason() -> None:
    for vector in VECTORS:
        if vector["expect"] == "reject":
            assert vector.get("reject_reason"), f"{vector['id']} has no reject_reason"


# --------------------------------------------------------------------------
# 3. The documented inexpressible constraint stays documented and enforced
# --------------------------------------------------------------------------


def test_only_self_derivation_is_inexpressible() -> None:
    """Guards the escape hatch itself.

    If a future change marks another rule inexpressible, that is a real decision
    that belongs in schema/README.md, not something to slip past the parity test.
    """
    inexpressible = [v["id"] for v in VECTORS if v.get("schema_expressible") is False]
    assert inexpressible == ["reject-self-derivation"]


def test_self_derivation_rejected_by_model_and_accepted_by_schema() -> None:
    """Asserts the divergence directly, in both directions.

    Parity alone would go green if the model validator were removed (both would
    accept), which is exactly the regression this catches.
    """
    vector = next(v for v in VECTORS if v["id"] == "reject-self-derivation")
    manifest = vector["manifest"]
    assert manifest["derived_from"] == manifest["weights_hash"]
    assert not _model_accepts(manifest), "the model must still reject self-derivation"
    assert _schema_accepts(manifest), (
        "if JSON Schema gained a way to express this, update schema/README.md "
        "and flip schema_expressible on the vector"
    )
