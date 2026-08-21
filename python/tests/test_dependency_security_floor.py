"""Keep the runtime cryptography requirement above known vulnerable releases."""

from __future__ import annotations

import tomllib
from pathlib import Path


def test_cryptography_floor_excludes_vulnerable_49_x_releases() -> None:
    project = tomllib.loads(
        (Path(__file__).parents[1] / "pyproject.toml").read_text(encoding="utf-8")
    )["project"]
    assert "cryptography>=50,<51" in project["dependencies"]
