"""Access to the normative WCM manifest JSON Schema (``schema/`` at the repo root).

The schema is the machine-readable form of SPEC.md section 3.1, frozen at v1 and
additive-only. It is generated from :mod:`wcm.models` and then augmented with the
cross-field constraints the model enforces in validators (see
``tools/gen_schema.py``), so schema-valid and model-valid agree except for one
documented case:

    ``derived_from`` must not equal ``weights_hash``.

Comparing two instance locations has no standard JSON Schema form, so that check
is verifier-only. A schema-only implementation must enforce it separately; it is
listed in ``schema/README.md`` and covered by the conformance vectors.

The schema ships inside the wheel, so this works from an installed package:

    >>> from wcm.schema import manifest_schema
    >>> manifest_schema()["$id"]
    'https://wcm.agentrust-io.com/schema/manifest/v1.json'

This module deliberately has no validator dependency. It hands back the schema
document; validating with it is the caller's choice of tooling. The reference
validator is :class:`wcm.models.WeightCustodyManifest` itself.
"""
from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

#: Identifier of the frozen v1 manifest schema. This is an identity, not a
#: promise that the URL is fetchable: it resolves once the docs site is served.
SCHEMA_ID = "https://wcm.agentrust-io.com/schema/manifest/v1.json"

_FILENAME = "wcm-manifest-v1.schema.json"


def _candidates() -> list[Path]:
    """Where the schema can be, in preference order.

    First the installed layout, where the build copies it next to this module.
    Then a search upward for the canonical repo-root ``schema/`` directory, which
    covers both a git checkout (``python/src/wcm`` -> repo root) and an unpacked
    sdist (whose root holds ``schema/`` and ``src/`` as siblings).
    """
    found = [Path(__file__).parent / "_schema" / _FILENAME]
    here = Path(__file__).resolve()
    found.extend(parent / "schema" / _FILENAME for parent in here.parents)
    return found


def schema_path() -> Path:
    """Filesystem path to the manifest schema.

    Raises:
        FileNotFoundError: if the schema is missing from both the installed
            package and any enclosing checkout, which means a broken build
            rather than a recoverable condition.
    """
    for candidate in _candidates():
        if candidate.is_file():
            return candidate
    raise FileNotFoundError(
        f"{_FILENAME} not found in the installed package or any enclosing "
        f"checkout (looked next to {Path(__file__).parent} and in every parent's "
        "schema/ directory)"
    )


@lru_cache(maxsize=1)
def _load() -> dict[str, Any]:
    data: dict[str, Any] = json.loads(schema_path().read_text(encoding="utf-8"))
    return data


def manifest_schema() -> dict[str, Any]:
    """The manifest JSON Schema as a dict.

    Returns a deep copy, so a caller that mutates the result (to add a ``$ref``
    base, say) does not corrupt it for the next caller.
    """
    import copy

    return copy.deepcopy(_load())
