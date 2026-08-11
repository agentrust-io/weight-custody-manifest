"""Release workflows must execute immutable third-party action revisions."""

from __future__ import annotations

import re
from pathlib import Path


_ACTION_USE = re.compile(r"uses:\s*([^\s#]+)@([^\s#]+)")
_SHA = re.compile(r"^[0-9a-f]{40}$")


def test_all_workflow_actions_are_pinned_to_commits() -> None:
    root = Path(__file__).parents[2]
    workflow_files = sorted((root / ".github" / "workflows").glob("*.yml"))
    assert workflow_files

    unpinned: list[str] = []
    for workflow in workflow_files:
        for line_number, line in enumerate(
            workflow.read_text(encoding="utf-8").splitlines(), start=1
        ):
            match = _ACTION_USE.search(line)
            if match and not _SHA.fullmatch(match.group(2)):
                unpinned.append(f"{workflow}:{line_number}: {match.group(1)}")

    assert not unpinned, "workflow actions must use immutable commit SHAs: " + ", ".join(
        unpinned
    )
