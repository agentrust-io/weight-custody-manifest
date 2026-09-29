#!/usr/bin/python3
"""Fuzz manifest parsing and joint-signature verification.

A manifest arrives from whoever asks for a key. The property: parsing either
returns a model or raises ``ValidationError``, and ``verify_manifest`` on a
parsed manifest returns a result rather than raising, and never reports
``ok`` against a verification context that trusts no key.
"""
import sys

import atheris

with atheris.instrument_imports():
    from pydantic import ValidationError

    from wcm import VerificationContext, WeightCustodyManifest, verify_manifest

_EMPTY = VerificationContext()


def TestOneInput(data: bytes) -> None:
    try:
        manifest = WeightCustodyManifest.model_validate_json(data)
    except ValidationError:
        return
    result = verify_manifest(manifest, _EMPTY)
    if result.ok:
        raise AssertionError("manifest verified with no trusted keys")


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
