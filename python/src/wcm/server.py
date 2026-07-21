"""Reference KBS HTTP surface (SPEC.md section 3.2). Requires the ``[server]`` extra.

    POST /challenge  -> {nonce, issued_at, expires_at}
    POST /release    -> {manifest, evidence} -> {released, key_b64|null, checks}
    GET  /health     -> {status: "ok"}

This is the reference protocol surface; it wraps the library ``KeyBrokerService``
with identical semantics. It is imported only as ``wcm.server`` (never by the
base package), so ``import wcm`` needs no web dependency.

Honest caveat: for the reference server, ``/release`` returns the decryption key
in the response body. A production KBS never does that — it wraps the key to the
requesting enclave's attested transport (the enclave proved its identity in the
same handshake). Do not deploy this as-is on an untrusted network.
"""
from __future__ import annotations

import base64
import json
import os
from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, ValidationError

from . import __version__
from .attestation import CompositeEvidence
from .kbs import KeyBrokerService
from .models import WeightCustodyManifest


class ReleaseRequest(BaseModel):
    manifest: dict[str, Any]  # a WeightCustodyManifest document
    evidence: dict[str, Any]  # a CompositeEvidence document


def create_app(kbs: KeyBrokerService) -> FastAPI:
    """Build a FastAPI app backed by *kbs* (which holds the keystore + policy)."""
    app = FastAPI(title="WCM reference KBS", version=__version__)

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/challenge")
    def challenge() -> dict[str, str]:
        c = kbs.issue_challenge()
        return {
            "nonce": c.nonce,
            "issued_at": c.issued_at.isoformat(),
            "expires_at": c.expires_at.isoformat(),
        }

    @app.post("/release")
    def release(req: ReleaseRequest) -> dict[str, Any]:
        try:
            manifest = WeightCustodyManifest.model_validate(req.manifest)
            evidence = CompositeEvidence.model_validate(req.evidence)
        except ValidationError as exc:
            raise HTTPException(status_code=422, detail=f"invalid manifest/evidence: {exc}")
        decision = kbs.verify_and_release(manifest, evidence)
        return {
            "released": decision.released,
            "key_b64": base64.b64encode(decision.key).decode() if decision.key else None,
            "checks": [
                {"name": c.name, "passed": c.passed, "detail": c.detail}
                for c in decision.checks
            ],
        }

    return app


def build_kbs_from_env() -> KeyBrokerService:
    """Construct a KeyBrokerService from environment config (for the container).

    ``WCM_KEYSTORE_FILE`` points at a JSON object mapping ``weights_hash`` ->
    base64 decryption key. Absent, the keystore is empty (health/challenge work;
    release always denies with ``key_available`` false). Keys are supplied at
    runtime (mounted secret / KMS), never baked into the image.
    """
    keystore: dict[str, bytes] = {}
    path = os.environ.get("WCM_KEYSTORE_FILE")
    if path:
        with open(path, "r", encoding="utf-8") as fh:
            raw = json.load(fh)
        keystore = {wh: base64.b64decode(k) for wh, k in raw.items()}
    return KeyBrokerService(keystore)


def app_from_env() -> FastAPI:
    """uvicorn factory entrypoint: ``uvicorn wcm.server:app_from_env --factory``."""
    return create_app(build_kbs_from_env())
