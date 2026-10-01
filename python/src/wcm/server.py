"""Reference KBS HTTP surface (SPEC.md section 3.2). Requires the ``[server]`` extra.

    POST /challenge  -> {nonce, issued_at, expires_at}
    POST /release    -> {manifest, evidence} -> {released, sealed_key_b64|null, checks}
    GET  /health     -> {status: "ok"}

This is the reference protocol surface; it wraps the library ``KeyBrokerService``
with identical semantics. It is imported only as ``wcm.server`` (never by the
base package), so ``import wcm`` needs no web dependency.

Channel binding: the enclave carries its attested transport public key in the
evidence (``cpu.transport_public_key``), and ``/release`` returns the key only as
``sealed_key_b64`` sealed to that key, never in the clear. A relayed quote (the
intra-handshake gap, CVE-2026-33697) therefore yields only ciphertext the relay
cannot open. The env-built KBS sets ``require_channel_binding=True``, so a
request without a transport key is denied.
"""
from __future__ import annotations

import base64
import json
import os
from typing import Any

from cryptography import x509
from ._certificates import load_pem_certificate
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, ValidationError

from . import __version__
from .attestation import CompositeEvidence
from .kbs import KeyBrokerService
from .models import WeightCustodyManifest
from .nvidia import build_gpu_verifier
from ._quote_verify import JsonQuoteParser, QuoteVerifier, TrustStore


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
            "sealed_key_b64": (
                base64.b64encode(decision.sealed_key).decode()
                if decision.sealed_key
                else None
            ),
            "checks": [
                {"name": c.name, "passed": c.passed, "detail": c.detail}
                for c in decision.checks
            ],
        }

    return app


_LAUNCH_OFFSET_ENV = "WCM_CPU_LAUNCH_MEASUREMENT_OFFSET"


def _launch_measurement_offset_from_env() -> int:
    """Read the byte offset of the 48-byte launch measurement in the report body.

    Required whenever ``WCM_CPU_TRUST_ROOT_FILE`` is set. Decimal or ``0x`` hex;
    0x90 for an AMD SEV-SNP attestation report.
    """
    raw = os.environ.get(_LAUNCH_OFFSET_ENV)
    if raw is None or not raw.strip():
        raise ValueError(
            f"WCM_CPU_TRUST_ROOT_FILE is set but {_LAUNCH_OFFSET_ENV} is not: the "
            "server must read the serving-image measurement from the signed "
            "report. Set it to the byte offset of the launch measurement in the "
            "report body (0x90 for an AMD SEV-SNP report)."
        )
    try:
        offset = int(raw.strip(), 0)
    except ValueError:
        raise ValueError(
            f"{_LAUNCH_OFFSET_ENV} must be a non-negative integer (decimal or 0x hex), "
            f"got {raw!r}"
        ) from None
    if offset < 0:
        raise ValueError(f"{_LAUNCH_OFFSET_ENV} must be non-negative, got {raw!r}")
    return offset


def build_kbs_from_env() -> KeyBrokerService:
    """Construct a KeyBrokerService from environment config (for the container).

    ``WCM_KEYSTORE_FILE`` points at a JSON object mapping ``weights_hash`` ->
    base64 decryption key. Absent, the keystore is empty (health/challenge work;
    release always denies with ``key_available`` false). Keys are supplied at
    runtime (mounted secret / KMS), never baked into the image.

    ``WCM_CPU_TRUST_ROOT_FILE`` enables CPU quote verification and requires
    ``WCM_CPU_LAUNCH_MEASUREMENT_OFFSET``: the serving-image measurement is
    taken from the signed report at that offset, and evidence whose report
    yields none is refused. Setting the root without the offset raises
    ``ValueError`` at startup.
    """
    keystore: dict[str, bytes] = {}
    path = os.environ.get("WCM_KEYSTORE_FILE")
    if path:
        with open(path, "r", encoding="utf-8") as fh:
            raw = json.load(fh)
        keystore = {wh: base64.b64decode(k) for wh, k in raw.items()}
    cpu_verifier = None
    root_path = os.environ.get("WCM_CPU_TRUST_ROOT_FILE")
    if root_path:
        # The serving-image check compares the manifest with the launch
        # measurement in the signed report, so the parser must know where that
        # measurement sits. Without it the only measurement left is the
        # evidence's structured serving_image_measurement field, which whoever
        # builds the evidence writes. Refuse to start rather than run that way.
        launch_offset = _launch_measurement_offset_from_env()
        with open(root_path, "rb") as fh:
            root = load_pem_certificate(fh.read())
        trust = TrustStore()
        trust.add_root(root)
        cpu_verifier = QuoteVerifier(
            JsonQuoteParser(launch_measurement_offset=launch_offset),
            trust,
            require_launch_measurement=True,
        )
    trusted_manifest_identities: set[str] = set()
    gpu_verifier = None
    gpu_root_path = os.environ.get("WCM_GPU_TRUST_ROOT_FILE")
    if gpu_root_path:
        with open(gpu_root_path, "rb") as fh:
            gpu_verifier = build_gpu_verifier(fh.read())
    manifest_identities_path = os.environ.get("WCM_TRUSTED_MANIFEST_IDENTITIES_FILE")
    if manifest_identities_path:
        with open(manifest_identities_path, "r", encoding="utf-8") as fh:
            configured_identities = json.load(fh)
        if not isinstance(configured_identities, list) or not all(
            isinstance(value, str) for value in configured_identities
        ):
            raise ValueError(
                "WCM_TRUSTED_MANIFEST_IDENTITIES_FILE must contain a JSON string array"
            )
        trusted_manifest_identities.update(configured_identities)
    # A network release surface must not silently downgrade to structural CPU
    # evidence. Without a trusted root it serves health/challenges but refuses
    # every release.
    return KeyBrokerService(
        keystore,
        cpu_quote_verifier=cpu_verifier,
        gpu_report_verifier=gpu_verifier,
        require_channel_binding=True,
        require_cpu_quote_verification=True,
        require_gpu_report_verification=True,
        trusted_manifest_identities=trusted_manifest_identities,
    )


def app_from_env() -> FastAPI:
    """uvicorn factory entrypoint: ``uvicorn wcm.server:app_from_env --factory``."""
    return create_app(build_kbs_from_env())
