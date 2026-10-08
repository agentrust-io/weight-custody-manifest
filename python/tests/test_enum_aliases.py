"""Deprecated enum spellings (0.31.0): still valid, same meaning, never rewritten.

``builder-and-opaque-joint`` and ``opaque-hosted`` were renamed to
``builder-and-custodian-joint`` and ``custodian-hosted``. The frozen v1 schema
keeps the old spellings valid, so a manifest signed with them keeps verifying.
"""
from __future__ import annotations

import json
import shutil
import warnings
from pathlib import Path

import pytest
from pydantic import ValidationError

from tests.conftest import EXAMPLES
from wcm import (
    CustodianType,
    Ed25519Signer,
    RevocationAuthority,
    VerificationContext,
    WeightCustodyManifest,
    generate_ed25519,
    verify_manifest,
)
from wcm.cli import main
from wcm.schema import manifest_schema

ALIASES = [
    (("release_policy", "revocation_authority"), "builder-and-opaque-joint",
     "builder-and-custodian-joint"),
    (("custody", "custodian_type"), "opaque-hosted", "custodian-hosted"),
]


def _set(doc: dict, path: tuple[str, str], value: str) -> None:
    doc[path[0]][path[1]] = value


def test_canonical_maps_alias_to_replacement() -> None:
    assert (
        RevocationAuthority.builder_and_opaque_joint.canonical
        is RevocationAuthority.builder_and_custodian_joint
    )
    assert CustodianType.opaque_hosted.canonical is CustodianType.hosted
    assert RevocationAuthority.builder_and_opaque_joint.deprecated
    assert CustodianType.opaque_hosted.deprecated
    for member in (*RevocationAuthority, *CustodianType):
        if not member.deprecated:
            assert member.canonical is member


def test_new_values_are_the_current_members() -> None:
    assert RevocationAuthority.builder_and_custodian_joint.value == "builder-and-custodian-joint"
    assert CustodianType.hosted.value == "custodian-hosted"


@pytest.mark.parametrize(("path", "old", "new"), ALIASES)
def test_alias_accepted_with_deprecation_warning(example_dict, path, old, new) -> None:
    _set(example_dict, path, old)
    with pytest.warns(DeprecationWarning, match=old):
        m = WeightCustodyManifest.model_validate(example_dict)
    value = getattr(getattr(m, path[0]), path[1])
    assert value.value == old  # kept as written, so the pre-image is unchanged
    assert value.canonical.value == new


@pytest.mark.parametrize(("path", "old", "new"), ALIASES)
def test_new_value_does_not_warn(example_dict, path, old, new) -> None:
    _set(example_dict, path, new)
    with warnings.catch_warnings():
        warnings.simplefilter("error", DeprecationWarning)
        WeightCustodyManifest.model_validate(example_dict)


@pytest.mark.parametrize(("path", "old", "new"), ALIASES)
def test_schema_accepts_both_spellings(example_dict, path, old, new) -> None:
    jsonschema = pytest.importorskip("jsonschema")
    validator = jsonschema.Draft202012Validator(manifest_schema())
    for value in (old, new):
        _set(example_dict, path, value)
        assert not list(validator.iter_errors(example_dict)), value


def test_omitted_revocation_authority_keeps_the_v1_default(example_dict) -> None:
    # The default is part of every pre-image that omits the field; it must not move.
    del example_dict["release_policy"]["revocation_authority"]
    with warnings.catch_warnings():
        warnings.simplefilter("error", DeprecationWarning)
        m = WeightCustodyManifest.model_validate(example_dict)
    assert m.release_policy.revocation_authority is RevocationAuthority.builder_and_opaque_joint
    assert m.unsigned_dict()["release_policy"]["revocation_authority"] == "builder-and-opaque-joint"
    assert manifest_schema()["$defs"]["ReleasePolicy"]["properties"]["revocation_authority"][
        "default"
    ] == "builder-and-opaque-joint"


@pytest.mark.parametrize("value", ["builder-and-opaque-joint", "builder-and-custodian-joint"])
def test_sovereign_rule_treats_alias_and_new_value_alike(example_dict, value) -> None:
    example_dict["release_policy"]["sovereign_profile"]["enabled"] = True
    example_dict["release_policy"]["sovereign_profile"]["sovereign_signer"] = "sov-team"
    example_dict["release_policy"]["revocation_authority"] = value
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        with pytest.raises(ValidationError, match="must be 'quorum'"):
            WeightCustodyManifest.model_validate(example_dict)


@pytest.mark.parametrize("value", ["opaque-hosted", "custodian-hosted"])
def test_byom_rule_treats_alias_and_new_value_alike(example_dict, value) -> None:
    example_dict["deployment_model"] = "byom-symmetric"
    example_dict["custody"]["custodian_type"] = value
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        with pytest.raises(ValidationError, match="byom-symmetric"):
            WeightCustodyManifest.model_validate(example_dict)


def test_manifest_signed_with_aliases_still_verifies(example_dict) -> None:
    for path, old, _ in ALIASES:
        _set(example_dict, path, old)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        m = WeightCustodyManifest.model_validate(example_dict)
        b, c = generate_ed25519(), generate_ed25519()
        doc = m.unsigned_dict()
        doc["signatures"] = [
            Ed25519Signer(b).sign(m.unsigned_dict(), role="builder", signer="example-builder"),
            Ed25519Signer(c).sign(m.unsigned_dict(), role="custodian", signer="example-custodian"),
        ]
        signed = WeightCustodyManifest.model_validate(json.loads(json.dumps(doc)))
    ctx = VerificationContext()
    ctx.add_key(b.public_bytes)
    ctx.add_key(c.public_bytes)
    assert verify_manifest(signed, ctx).ok


def test_with_current_values_fills_only_an_omitted_field(example_dict) -> None:
    del example_dict["release_policy"]["revocation_authority"]
    m = WeightCustodyManifest.model_validate(example_dict).with_current_values()
    assert (
        m.release_policy.revocation_authority
        is RevocationAuthority.builder_and_custodian_joint
    )
    # Explicit values, deprecated or not, are the author's choice and stay.
    example_dict["release_policy"]["revocation_authority"] = "builder-and-opaque-joint"
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        explicit = WeightCustodyManifest.model_validate(example_dict)
    assert explicit.with_current_values() is explicit


def test_with_current_values_leaves_a_signed_manifest_alone(example_dict) -> None:
    del example_dict["release_policy"]["revocation_authority"]
    m = WeightCustodyManifest.model_validate(example_dict)
    block = Ed25519Signer(generate_ed25519()).sign(
        m.unsigned_dict(), role="builder", signer="example-builder"
    )
    example_dict["signatures"] = [block]
    signed = WeightCustodyManifest.model_validate(example_dict)
    assert signed.with_current_values() is signed


def test_cli_sign_emits_the_new_value_for_an_omitted_field(tmp_path: Path) -> None:
    doc = json.loads((EXAMPLES / "manifest.example.json").read_text(encoding="utf-8"))
    del doc["release_policy"]["revocation_authority"]
    src = tmp_path / "m.json"
    src.write_text(json.dumps(doc), encoding="utf-8")
    key = tmp_path / "b"
    assert main(["keygen", "--out", str(key)]) == 0
    out = tmp_path / "signed.json"
    assert main(["sign", str(src), "--role", "builder", "--signer", "example-builder",
                 "--key-file", str(key), "--out", str(out)]) == 0
    signed = json.loads(out.read_text(encoding="utf-8"))
    assert signed["release_policy"]["revocation_authority"] == "builder-and-custodian-joint"


def test_example_uses_the_new_values() -> None:
    raw = (EXAMPLES / "manifest.example.json").read_text(encoding="utf-8")
    assert "builder-and-opaque-joint" not in raw
    assert "opaque-hosted" not in raw


def test_cli_sign_keeps_an_alias_the_author_wrote(tmp_path: Path) -> None:
    src = tmp_path / "m.json"
    shutil.copy(EXAMPLES / "manifest.example.json", src)
    doc = json.loads(src.read_text(encoding="utf-8"))
    doc["custody"]["custodian_type"] = "opaque-hosted"
    src.write_text(json.dumps(doc), encoding="utf-8")
    key = tmp_path / "b"
    assert main(["keygen", "--out", str(key)]) == 0
    out = tmp_path / "signed.json"
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        assert main(["sign", str(src), "--role", "builder", "--signer", "example-builder",
                     "--key-file", str(key), "--out", str(out)]) == 0
    assert json.loads(out.read_text(encoding="utf-8"))["custody"]["custodian_type"] == (
        "opaque-hosted"
    )
