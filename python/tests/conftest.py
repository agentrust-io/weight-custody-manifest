from __future__ import annotations

import json
from pathlib import Path

import pytest

from wcm import WeightCustodyManifest

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


@pytest.fixture
def example_dict() -> dict:
    with open(EXAMPLES / "manifest.example.json", "r", encoding="utf-8") as fh:
        return json.load(fh)


@pytest.fixture
def example_manifest(example_dict: dict) -> WeightCustodyManifest:
    return WeightCustodyManifest.model_validate(example_dict)
