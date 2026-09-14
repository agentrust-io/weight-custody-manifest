"""Build hook that locates the repo-root spec artifacts for the wheel.

The manifest JSON Schema and the conformance vectors are canonically at the REPO
root, next to SPEC.md, because they are specification artifacts rather than Python
ones. The wheel still has to carry them so ``wcm.schema`` and ``wcm conformance``
work from an installed package.

A static ``force-include`` cannot do that, because the path to them depends on how
the wheel is being built:

- **from the source tree**, ``pyproject.toml`` lives in ``python/``, so the
  artifacts are at ``../schema`` and ``../conformance``;
- **from an unpacked sdist**, ``pyproject.toml`` is at the sdist ROOT (PEP 517
  requires it there) and the sdist's own force-include has already placed the
  artifacts at ``schema`` and ``conformance`` beside it, so ``../`` would point
  outside the sdist entirely.

``python -m build`` does the second: it builds the sdist, unpacks it, and builds
the wheel from that. So a static ``"../schema" = ...`` works when you invoke
hatchling directly and fails on the real release path, which is exactly how this
got missed once. Resolving the location at build time fixes both.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from hatchling.builders.hooks.plugin.interface import BuildHookInterface

#: (source path relative to whichever base holds it) -> (destination in the wheel)
_ARTIFACTS = {
    "schema/wcm-manifest-v1.schema.json": "wcm/_schema/wcm-manifest-v1.schema.json",
    "schema/wcm-vendor-vector-v1.schema.json": "wcm/_schema/wcm-vendor-vector-v1.schema.json",
    "conformance/vectors": "wcm/_conformance/vectors",
    # The root store travels with the vectors. A vendor vector names its root
    # and the runner resolves it, so an installed package without the suite's
    # own out-of-chain root cannot run the untrusted-root case at all.
    "conformance/roots": "wcm/_conformance/roots",
}


class CustomBuildHook(BuildHookInterface):  # type: ignore[type-arg]
    def initialize(self, version: str, build_data: dict[str, Any]) -> None:
        # Only the wheel carries the packaged copies. The sdist ships the
        # artifacts at its root via its own force-include, which is what this hook
        # then finds when the wheel is built from that sdist.
        if self.target_name != "wheel":
            return

        root = Path(self.root)
        # Source tree first (python/.. -> repo root), then the sdist layout where
        # they sit beside pyproject.toml.
        bases = (root.parent, root)

        for relative, destination in _ARTIFACTS.items():
            for base in bases:
                candidate = base / relative
                if candidate.exists():
                    build_data["force_include"][str(candidate)] = destination
                    break
            else:
                looked = ", ".join(str(base / relative) for base in bases)
                raise FileNotFoundError(
                    f"cannot build the wheel: {relative} was not found. Looked in "
                    f"{looked}. In a source tree it should be at the repo root; in "
                    "an sdist the sdist force-include should have placed it beside "
                    "pyproject.toml."
                )
