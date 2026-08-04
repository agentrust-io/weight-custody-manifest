#!/usr/bin/env python3
"""Regenerate the normative WCM manifest JSON Schema (schema/wcm-manifest-v1.schema.json).

The schema is *generated* from the Pydantic reference model and then *augmented*
with the cross-field constraints the model enforces in ``model_validator`` hooks,
which Pydantic does not export to JSON Schema. Generation keeps the structural
half in lockstep with the reference implementation; the augmentation block below
is hand-maintained and must be updated whenever a validator is added or changed.
``tests/test_schema.py`` fails if the committed file does not match this script's
output, and separately checks that the schema and the model accept and reject the
same vector corpus, so a missed augmentation surfaces as a test failure rather
than as a silently weaker schema.

Usage (from the ``python/`` directory):

    python tools/gen_schema.py            # rewrite the committed schema
    python tools/gen_schema.py --check    # exit 1 if the committed file is stale
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = REPO_ROOT / "schema" / "wcm-manifest-v1.schema.json"

SCHEMA_ID = "https://wcm.agentrust-io.com/schema/manifest/v1.json"
SCHEMA_DIALECT = "https://json-schema.org/draft/2020-12/schema"

TITLE = "Weight Custody Manifest"

DESCRIPTION = (
    "The Layer 1 Weight Custody Manifest: the jointly signed artifact a builder "
    "issues to state which weights are released, under what terms, and against "
    "which release policy (SPEC.md section 3.1).\n\n"
    "Frozen at v1: fields are added, never removed or repurposed, and no "
    "existing field's meaning or value set narrows. See schema/README.md for the "
    "versioning policy and for the one model constraint this schema cannot "
    "express (derived_from must not equal weights_hash, which requires comparing "
    "two instance locations and has no standard JSON Schema form)."
)


def _accepted_measurement_rule() -> dict[str, Any]:
    """``retire_after`` is required by, and exclusive to, a retiring measurement.

    Mirrors ``RequiredServingImage._retire_after_only_when_retiring``. The check
    lives on the item rather than on the array so the error points at the
    offending measurement.
    """
    return {
        "if": {"properties": {"status": {"const": "retiring"}}, "required": ["status"]},
        "then": {
            "required": ["retire_after"],
            "properties": {"retire_after": {"type": "string"}},
        },
        "else": {"properties": {"retire_after": {"type": "null"}}},
    }


def _sovereign_profile_rule() -> dict[str, Any]:
    """An enabled sovereign profile forces quorum revocation and names a signer.

    Mirrors ``SovereignProfile._enabled_requires_quorum``. ``enabled`` is listed
    as required inside the ``if`` so that a manifest omitting it (defaulting to
    false) does not vacuously match and pull in the ``then`` branch.
    """
    return {
        "if": {"properties": {"enabled": {"const": True}}, "required": ["enabled"]},
        "then": {
            "required": ["sovereign_signer"],
            "properties": {
                "revocation_authority": {"const": "quorum"},
                "sovereign_signer": {"type": "string", "minLength": 1},
            },
        },
    }


def _manifest_rules() -> list[dict[str, Any]]:
    """Top-level cross-field rules, each mirroring a manifest ``model_validator``.

    Not included: ``_derived_from_not_self``. Standard JSON Schema cannot compare
    the values at two instance locations, so that check is verifier-only and is
    documented as such in schema/README.md.
    """
    return [
        {
            # _byom_symmetric_is_self_custody: symmetric BYOM means one org brings
            # its own model into infrastructure it also custodies, so a hosted
            # custodian is contradictory.
            "$comment": (
                "deployment_model 'byom-symmetric' requires "
                "custody.custodian_type 'customer-self-custody'"
            ),
            "if": {
                "properties": {"deployment_model": {"const": "byom-symmetric"}},
                "required": ["deployment_model"],
            },
            "then": {
                "properties": {
                    "custody": {
                        "properties": {
                            "custodian_type": {"const": "customer-self-custody"}
                        },
                        "required": ["custodian_type"],
                    }
                },
                "required": ["custody"],
            },
        },
        {
            # _sovereign_consistency: with the sovereign profile on, top-level
            # revocation is quorum-based and the unilateral path is gone.
            "$comment": (
                "with release_policy.sovereign_profile.enabled, "
                "release_policy.revocation_authority must be 'quorum'"
            ),
            "if": {
                "properties": {
                    "release_policy": {
                        "properties": {
                            "sovereign_profile": {
                                "properties": {"enabled": {"const": True}},
                                "required": ["enabled"],
                            }
                        },
                        "required": ["sovereign_profile"],
                    }
                },
                "required": ["release_policy"],
            },
            "then": {
                "properties": {
                    "release_policy": {
                        "properties": {"revocation_authority": {"const": "quorum"}},
                        "required": ["revocation_authority"],
                    }
                }
            },
        },
    ]


def build_schema() -> dict[str, Any]:
    # Imported here so ``--check`` failures point at the model, not at import time.
    from wcm.models import WeightCustodyManifest

    generated = WeightCustodyManifest.model_json_schema(mode="validation")
    defs = generated.pop("$defs", {})
    generated.pop("title", None)
    generated.pop("description", None)

    if "AcceptedMeasurement" not in defs or "SovereignProfile" not in defs:
        raise SystemExit(
            "expected AcceptedMeasurement and SovereignProfile in $defs; "
            "the model layout changed, so the augmentation rules need review"
        )
    defs["AcceptedMeasurement"].update(_accepted_measurement_rule())
    defs["SovereignProfile"].update(_sovereign_profile_rule())

    # Explicit top-level ordering: the dialect and identity first, the (large)
    # $defs block last, so the file reads as a schema rather than as an export.
    schema: dict[str, Any] = {
        "$schema": SCHEMA_DIALECT,
        "$id": SCHEMA_ID,
        "title": TITLE,
        "description": DESCRIPTION,
    }
    schema.update(generated)
    schema["allOf"] = _manifest_rules()
    schema["$defs"] = defs
    return schema


def render() -> str:
    return json.dumps(build_schema(), indent=2, ensure_ascii=False) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="do not write; exit 1 if the committed schema is stale",
    )
    args = parser.parse_args()

    rendered = render()
    if args.check:
        current = SCHEMA_PATH.read_text(encoding="utf-8") if SCHEMA_PATH.exists() else ""
        if current != rendered:
            print(
                f"{SCHEMA_PATH} is stale; run 'python tools/gen_schema.py'",
                file=sys.stderr,
            )
            return 1
        print(f"{SCHEMA_PATH} is up to date")
        return 0

    SCHEMA_PATH.parent.mkdir(parents=True, exist_ok=True)
    SCHEMA_PATH.write_text(rendered, encoding="utf-8")
    print(f"wrote {SCHEMA_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
