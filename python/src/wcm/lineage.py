"""Layer 4: derivative lineage and its policy enforcement (SPEC.md section 3.4).

A fine-tune produces a new ``weights_hash`` whose manifest carries ``derived_from``
pointing at the parent's ``weights_hash``, forming a chain of custody back to the
root manifest. This module resolves that chain and enforces what is structurally
enforceable:

  - the chain resolves (every ``derived_from`` names a manifest in the set),
  - it terminates at a root (a manifest with no ``derived_from``),
  - it contains no cycle, and
  - no link crosses a parent whose ``release_terms.derivatives`` is ``none``.

The freeform ``permitted_derivatives`` string carries the legal terms and is NOT
machine-parsed; a parent whose structured ``derivatives`` policy is unspecified
produces a note, not a verdict. This module makes no cryptographic claim on its
own: it assumes each manifest's signatures were already verified (``verify_manifest``).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping, Optional

from .models import DerivativePolicy, WeightCustodyManifest


@dataclass(frozen=True)
class LineageResult:
    ok: bool
    chain: list[str] = field(default_factory=list)  # weights_hash, leaf -> root
    violations: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def root(self) -> Optional[str]:
        return self.chain[-1] if self.chain else None

    @property
    def depth(self) -> int:
        """Number of derivation steps from leaf to root (0 for a root manifest)."""
        return max(0, len(self.chain) - 1)


def is_root(manifest: WeightCustodyManifest) -> bool:
    return manifest.derived_from is None


def verify_lineage(
    manifests: Mapping[str, WeightCustodyManifest], leaf_hash: str
) -> LineageResult:
    """Resolve and check the lineage of *leaf_hash* within *manifests*.

    Args:
        manifests: manifests keyed by their ``weights_hash``.
        leaf_hash: the ``weights_hash`` whose lineage to verify.
    """
    if leaf_hash not in manifests:
        return LineageResult(
            ok=False, violations=[f"leaf '{leaf_hash}' is not in the manifest set"]
        )

    chain: list[str] = []
    violations: list[str] = []
    notes: list[str] = []
    seen: set[str] = set()
    current = leaf_hash

    while True:
        if current in seen:
            violations.append(f"cycle detected at '{current}'")
            break
        seen.add(current)
        chain.append(current)

        manifest = manifests[current]
        parent = manifest.derived_from
        if parent is None:
            break  # reached a root

        parent_hash = str(parent)
        parent_manifest = manifests.get(parent_hash)
        if parent_manifest is None:
            violations.append(
                f"parent '{parent_hash}' of '{current}' is not in the manifest set"
            )
            break

        policy = parent_manifest.release_terms.derivatives
        if policy is DerivativePolicy.none:
            violations.append(
                f"parent '{parent_hash}' forbids derivatives (derivatives=none), "
                f"but '{current}' derives from it"
            )
        elif policy is None:
            notes.append(
                f"parent '{parent_hash}' derivative policy is unspecified; "
                "not machine-enforced (see permitted_derivatives for the legal terms)"
            )

        current = parent_hash

    return LineageResult(ok=not violations, chain=chain, violations=violations, notes=notes)
