"""The docs home cites conformance counts; keep them tied to the actual vectors.

wcm.agentrust-io.com is now the single WCM home (agentrust-io.com/wcm/ redirects
to it), so its landing numbers are the published ones. They used to be gated by a
proof.json in the website repo, which could not see this repo's vectors and went
stale at 0.27.0. This gate derives the numbers instead.
"""

from __future__ import annotations

import collections
import json
import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parents[2]
VECTORS = REPO_ROOT / "conformance" / "vectors"
DOCS_HOME = REPO_ROOT / "docs" / "index.md"


def _counts_by_level() -> collections.Counter:
    counts: collections.Counter = collections.Counter()
    for path in sorted(VECTORS.rglob("*.json")):
        with open(path, "r", encoding="utf-8") as fh:
            vector = json.load(fh)
        level = vector.get("level") or vector.get("conformance_level")
        if level:
            counts[level] += 1
    return counts


@pytest.mark.skipif(
    not DOCS_HOME.exists() or not VECTORS.exists(),
    reason="docs/ and conformance/ are not both present (sdist layout)",
)
def test_docs_home_vector_counts_match_the_vectors() -> None:
    counts = _counts_by_level()
    total = sum(counts.values())
    assert total, "no conformance vectors found; the gate would pass vacuously"

    home = DOCS_HOME.read_text(encoding="utf-8")

    assert f"**{total} portable conformance vectors**" in home, (
        f"docs/index.md must cite {total} portable conformance vectors"
    )

    for level, count in sorted(counts.items()):
        assert re.search(rf"\b{count} at {level}\b", home), (
            f"docs/index.md must cite {count} at {level}"
        )


@pytest.mark.skipif(
    not DOCS_HOME.exists(), reason="docs/ is not present (sdist layout)"
)
def test_docs_home_keeps_the_honest_scope() -> None:
    # Collapse wrapping and emphasis so a reflow or an added *emphasis* does not
    # fail the gate for a caveat that is still on the page.
    home = DOCS_HOME.read_text(encoding="utf-8").replace("*", "")
    home = " ".join(home.split())
    # These caveats carried over from the launch page. Losing them silently is
    # how a self-test starts reading as certification.
    for phrase in (
        "not independent certification",
        "synthetic attestation",
        "not cryptographic custody",
        "does not establish production readiness",
    ):
        assert phrase in home, f"docs/index.md must keep the caveat: {phrase!r}"
