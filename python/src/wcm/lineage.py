"""Layer 4: derivative lineage and its policy enforcement (SPEC.md 3.4, 3.8).

A fine-tune produces a new ``weights_hash`` whose manifest carries ``derived_from``
pointing at the parent's ``weights_hash``, forming a chain of custody back to the
root manifest. This module resolves that chain and enforces what is structurally
enforceable:

  - the chain resolves (every ``derived_from`` names a manifest in the set),
  - it terminates at a root (a manifest with no ``derived_from``),
  - it contains no cycle,
  - no link crosses a parent whose ``release_terms.derivatives`` is ``none``, and
  - rights are monotone down the chain: a derivative may narrow but never widen
    what it inherited (SPEC.md 3.8). The machine-checkable parts are the
    structured ``derivatives`` policy (none < fine-tune-only < unrestricted) and
    ``permitted_environments`` (a child set must be a subset of its parent's).

For the multi-stage BYOM / sequential re-custody protocol (SPEC.md 3.8), two
optional gates model the transparency-log binding and revocation cascade:

  - ``logged``: the caller confirms each manifest's transparency-log inclusion
    (via ``verify_inclusion``) and passes the set of in-force ``weights_hash``es;
    any manifest in the chain not in that set is a violation (an unattested
    intermediate cannot slip in).
  - ``revoked``: ``weights_hash``es with a verified revocation entry; a revocation
    anywhere in the chain cascades to invalidate the leaf.

The freeform ``permitted_derivatives``, ``license``, and ``jurisdiction_restriction``
strings carry legal terms and are NOT machine-compared for narrowing; a parent
whose structured ``derivatives`` policy is unspecified produces a note, not a
verdict. This module makes no cryptographic claim on its own: it assumes each
manifest's signatures were already verified (``verify_manifest``) and each
inclusion proof already checked (``verify_inclusion``).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, Mapping, Optional

from .models import DerivativePolicy, ReleaseTerms, WeightCustodyManifest

# Permissiveness order for the structured derivative policy.
_DERIV_RANK = {
    DerivativePolicy.none: 0,
    DerivativePolicy.fine_tune_only: 1,
    DerivativePolicy.unrestricted: 2,
}


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


def _check_monotone_rights(
    child_hash: str,
    child: ReleaseTerms,
    parent_hash: str,
    parent: ReleaseTerms,
    violations: list[str],
) -> None:
    """A derivative may narrow rights but never widen them (SPEC.md 3.8).

    The ``none`` parent case is already a hard violation (derivatives forbidden),
    so the ordering check only compares the fine-tune-only / unrestricted tiers.
    """
    if (
        parent.derivatives is not None
        and parent.derivatives is not DerivativePolicy.none
        and child.derivatives is not None
        and _DERIV_RANK[child.derivatives] > _DERIV_RANK[parent.derivatives]
    ):
        violations.append(
            f"'{child_hash}' widens derivatives to '{child.derivatives.value}' "
            f"beyond parent '{parent_hash}' ('{parent.derivatives.value}')"
        )
    extra = set(child.permitted_environments) - set(parent.permitted_environments)
    if extra:
        violations.append(
            f"'{child_hash}' adds permitted_environments not granted by parent "
            f"'{parent_hash}': {', '.join(sorted(extra))}"
        )


def verify_lineage(
    manifests: Mapping[str, WeightCustodyManifest],
    leaf_hash: str,
    *,
    logged: Optional[Iterable[str]] = None,
    revoked: Optional[Iterable[str]] = None,
) -> LineageResult:
    """Resolve and check the lineage of *leaf_hash* within *manifests*.

    Args:
        manifests: manifests keyed by their ``weights_hash``.
        leaf_hash: the ``weights_hash`` whose lineage to verify.
        logged: if given, the ``weights_hash``es the caller has confirmed present
            and in-force in the transparency log; every manifest in the chain must
            be among them (SPEC.md 3.8 upstream-logged gating).
        revoked: ``weights_hash``es with a verified revocation; a revocation
            anywhere in the chain cascades to invalidate the leaf.
    """
    if leaf_hash not in manifests:
        return LineageResult(
            ok=False, violations=[f"leaf '{leaf_hash}' is not in the manifest set"]
        )

    logged_set = None if logged is None else {str(h) for h in logged}
    revoked_set = set() if revoked is None else {str(h) for h in revoked}

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
        _check_monotone_rights(
            current, manifest.release_terms, parent_hash,
            parent_manifest.release_terms, violations,
        )

        current = parent_hash

    # Sequential re-custody gates (SPEC.md 3.8), applied over the resolved chain.
    for h in chain:
        if h in revoked_set:
            violations.append(
                f"'{h}' in the lineage is revoked; revocation cascades to '{leaf_hash}'"
            )
    if logged_set is not None:
        for h in chain:
            if h not in logged_set:
                violations.append(
                    f"'{h}' in the lineage is not present/in-force in the transparency log"
                )

    return LineageResult(ok=not violations, chain=chain, violations=violations, notes=notes)
