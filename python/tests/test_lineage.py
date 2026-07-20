from __future__ import annotations

import copy

import pytest
from pydantic import ValidationError

from wcm import (
    Ed25519Signer,
    VerificationContext,
    WeightCustodyManifest,
    generate_ed25519,
    is_root,
    verify_lineage,
    verify_manifest,
)

ROOT = "sha256:" + "aa" * 32
CHILD = "sha256:" + "bb" * 32
GRANDCHILD = "sha256:" + "cc" * 32
MISSING = "sha256:" + "dd" * 32


def _manifest(example_dict, weights_hash, *, derived_from=None, derivatives=None, rights=None):
    d = copy.deepcopy(example_dict)
    d["weights_hash"] = weights_hash
    if derived_from is not None:
        d["derived_from"] = derived_from
    if derivatives is not None:
        d["release_terms"]["derivatives"] = derivatives
    if rights is not None:
        d["rights_holder"] = rights
    return WeightCustodyManifest.model_validate(d)


# -- structural lineage --------------------------------------------------------


def test_root_only(example_dict):
    root = _manifest(example_dict, ROOT)
    assert is_root(root)
    result = verify_lineage({ROOT: root}, ROOT)
    assert result.ok
    assert result.chain == [ROOT]
    assert result.depth == 0
    assert result.root == ROOT


def test_two_level_chain(example_dict):
    root = _manifest(example_dict, ROOT, derivatives="fine-tune-only")
    child = _manifest(example_dict, CHILD, derived_from=ROOT)
    result = verify_lineage({ROOT: root, CHILD: child}, CHILD)
    assert result.ok
    assert result.chain == [CHILD, ROOT]
    assert result.depth == 1
    assert result.root == ROOT


def test_three_level_chain(example_dict):
    root = _manifest(example_dict, ROOT, derivatives="unrestricted")
    child = _manifest(example_dict, CHILD, derived_from=ROOT, derivatives="fine-tune-only")
    grand = _manifest(example_dict, GRANDCHILD, derived_from=CHILD)
    result = verify_lineage({ROOT: root, CHILD: child, GRANDCHILD: grand}, GRANDCHILD)
    assert result.ok
    assert result.chain == [GRANDCHILD, CHILD, ROOT]
    assert result.depth == 2


def test_missing_parent(example_dict):
    child = _manifest(example_dict, CHILD, derived_from=MISSING)
    result = verify_lineage({CHILD: child}, CHILD)
    assert not result.ok
    assert any("not in the manifest set" in v for v in result.violations)


def test_leaf_not_in_set(example_dict):
    result = verify_lineage({}, CHILD)
    assert not result.ok


def test_forbidden_derivative(example_dict):
    root = _manifest(example_dict, ROOT, derivatives="none")
    child = _manifest(example_dict, CHILD, derived_from=ROOT)
    result = verify_lineage({ROOT: root, CHILD: child}, CHILD)
    assert not result.ok
    assert any("forbids derivatives" in v for v in result.violations)


def test_unspecified_policy_is_a_note_not_violation(example_dict):
    root = _manifest(example_dict, ROOT)  # no derivatives policy set
    child = _manifest(example_dict, CHILD, derived_from=ROOT)
    result = verify_lineage({ROOT: root, CHILD: child}, CHILD)
    assert result.ok
    assert any("unspecified" in n for n in result.notes)


def test_cycle_detected(example_dict):
    a = _manifest(example_dict, ROOT, derived_from=CHILD, derivatives="fine-tune-only")
    b = _manifest(example_dict, CHILD, derived_from=ROOT, derivatives="fine-tune-only")
    result = verify_lineage({ROOT: a, CHILD: b}, ROOT)
    assert not result.ok
    assert any("cycle" in v for v in result.violations)


def test_self_reference_rejected_at_model_level(example_dict):
    d = copy.deepcopy(example_dict)
    d["weights_hash"] = ROOT
    d["derived_from"] = ROOT
    with pytest.raises(ValidationError):
        WeightCustodyManifest.model_validate(d)


# -- lineage fields are under the signature ------------------------------------


def test_derived_from_is_signed(example_dict):
    child = _manifest(
        example_dict,
        CHILD,
        derived_from=ROOT,
        rights={"base": "example-builder", "derivative": "customer-co"},
    )
    builder, custodian = generate_ed25519(), generate_ed25519()
    signed = child.with_signatures(
        [
            Ed25519Signer(builder).sign(child.unsigned_dict(), role="builder", signer="example-builder"),
            Ed25519Signer(custodian).sign(child.unsigned_dict(), role="custodian", signer="opaque-systems"),
        ]
    )
    ctx = VerificationContext()
    ctx.add_key(builder.public_bytes)
    ctx.add_key(custodian.public_bytes)
    assert verify_manifest(signed, ctx).ok

    # Re-point the lineage after signing: signatures must break.
    tampered = signed.model_copy(update={"derived_from": GRANDCHILD})
    assert not verify_manifest(tampered, ctx).ok


def test_rights_holder_roundtrip(example_dict):
    m = _manifest(
        example_dict, CHILD, derived_from=ROOT, rights={"base": "example-builder"}
    )
    assert m.rights_holder is not None
    assert m.rights_holder.base == "example-builder"
    assert m.rights_holder.derivative is None
