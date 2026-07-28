"""Provenance interop: cross-verify an OpenSSF model-signing signature (SPEC.md 3.9).

WCM is the custody-and-release layer; it does not itself sign the model files. A
manifest can carry a ``provenance.model_signing`` reference (see ``models``) to a
signature produced by OpenSSF model-signing. This module cryptographically checks
that reference: it verifies the model-signing signature over the model files and
binds it to the manifest by re-deriving the same ``signed_digest``.

model-signing is an optional dependency: install ``weight-custody-manifest[model-signing]``.

Scope: binding WCM's own ``weights_hash`` to the same physical artifact is the
caller's responsibility (the two hashes are computed differently). This function
proves that the referenced model-signing signature is genuine and covers exactly
the digest the manifest recorded; ``verify_manifest`` records the reference as a
non-blocking note.
"""
from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from typing import Any, Optional, Union

from .models import WeightCustodyManifest

_PathLike = Union[str, os.PathLike[str]]


@dataclass(frozen=True)
class ProvenanceResult:
    verified: bool
    reason: Optional[str] = None


def _require_model_signing() -> Any:
    try:
        import model_signing
    except ImportError as exc:
        raise ImportError(
            "model-signing is required for verify_provenance; install it with "
            'pip install "weight-custody-manifest[model-signing]"'
        ) from exc
    return model_signing


def model_signing_digest(model_path: _PathLike) -> str:
    """Derive WCM's stable digest of an OpenSSF model-signing manifest.

    model-signing hashes each model resource; this folds every resource descriptor
    (identifier, algorithm, hex digest), sorted, into one stable ``sha256:...``
    string so it is single-valued whatever the file count. Record it as
    ``provenance.model_signing.signed_digest`` when building a manifest;
    ``verify_provenance`` re-derives and compares it.
    """
    ms = _require_model_signing()
    hashed = ms.hashing.Config().hash(os.fspath(model_path))
    parts = [
        f"{rd.identifier}\x00{rd.digest.algorithm}\x00{rd.digest.digest_hex}"
        for rd in hashed.resource_descriptors()
    ]
    payload = "\x1e".join(sorted(parts)).encode("utf-8")
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def verify_provenance(
    manifest: WeightCustodyManifest,
    model_path: _PathLike,
    signature_path: _PathLike,
    *,
    public_key: _PathLike,
) -> ProvenanceResult:
    """Cryptographically verify the manifest's model-signing provenance.

    Two checks, both must pass:

      1. the OpenSSF model-signing signature at ``signature_path`` verifies over
         the model files at ``model_path`` under the elliptic-curve ``public_key``;
      2. the digest re-derived from those files equals the ``signed_digest``
         recorded in ``manifest.provenance.model_signing``, binding the manifest's
         reference to this exact artifact.

    Returns a ``ProvenanceResult``; ``verified`` is true only if both hold.
    """
    prov = manifest.provenance
    if prov is None or prov.model_signing is None:
        return ProvenanceResult(False, "manifest has no provenance.model_signing reference")

    ms = _require_model_signing()
    try:
        ms.verifying.Config().use_elliptic_key_verifier(
            public_key=os.fspath(public_key)
        ).verify(os.fspath(model_path), os.fspath(signature_path))
    except Exception as exc:  # model-signing raises ValueError (and others) on any mismatch
        return ProvenanceResult(False, f"model-signing signature did not verify: {exc}")

    actual = model_signing_digest(model_path)
    expected = prov.model_signing.signed_digest
    if actual != expected:
        return ProvenanceResult(
            False,
            f"signed_digest mismatch: manifest records {expected}, model files hash to {actual}",
        )
    return ProvenanceResult(True)
