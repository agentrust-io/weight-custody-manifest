"""Native-SNP receiver HTTP service; no plaintext model-key configuration.

Run one process per broker instance. Protect the service's ingress, code and
configuration in the approved image. This module does not create hardware
isolation or authenticate HTTP callers; provisioning envelopes authenticate the
owner and release evidence binds the recipient. Availability needs separate
admission/rate controls. Do not log request bodies or raw attestation evidence.
"""
from __future__ import annotations

import base64
import binascii
from datetime import datetime, timedelta
import os
from typing import Any

from cryptography.exceptions import InvalidSignature
from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from . import __version__
from ._challenge import Challenge
from ._hw_providers import SevSnpProvider
from ._seal import SealError
from .attestation import CompositeEvidence
from .broker_receiver import BrokerReceiver
from .models import WeightCustodyManifest
from .providers import AttestationUnavailableError
from .provisioning import ProvisioningEnvelope
from .server import ReleaseRequest


class ProvisioningReportRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    nonce: str = Field(pattern=r"^[0-9a-f]{64}$")
    issued_at: str = Field(max_length=40)
    expires_at: str = Field(max_length=40)

    @field_validator("issued_at", "expires_at")
    @classmethod
    def utc_time(cls, value: str) -> str:
        timestamp = datetime.fromisoformat(value)
        if timestamp.utcoffset() != timedelta(0):
            raise ValueError("UTC timestamp required")
        return value

    def challenge(self) -> Challenge:
        issued = datetime.fromisoformat(self.issued_at)
        expires = datetime.fromisoformat(self.expires_at)
        if expires <= issued:
            raise ValueError("challenge interval is invalid")
        return Challenge(self.nonce, issued, expires)


class ProvisioningInstallRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    nonce: str = Field(pattern=r"^[0-9a-f]{64}$")
    ciphertext_b64: str = Field(min_length=104, max_length=124)
    owner_signature_b64: str = Field(min_length=88, max_length=88)

    def envelope(self) -> ProvisioningEnvelope:
        ciphertext = _decode(self.ciphertext_b64)
        signature = _decode(self.owner_signature_b64)
        # Existing sealed-key format: header45 + tag16 + AES key16/24/32.
        if len(ciphertext) not in (77, 85, 93) or len(signature) != 64:
            raise ValueError("invalid provisioning envelope lengths")
        return ProvisioningEnvelope(self.nonce, ciphertext, signature)


def _decode(value: str) -> bytes:
    raw = base64.b64decode(value, validate=True)
    if base64.b64encode(raw).decode("ascii") != value:
        raise ValueError("canonical base64 required")
    return raw


def create_app(receiver: BrokerReceiver) -> FastAPI:
    """Serve one receiver; it begins unavailable for release until provisioned."""
    app = FastAPI(title="WCM provisioned broker receiver", version=__version__)
    provider = SevSnpProvider()

    @app.exception_handler(RequestValidationError)
    async def validation_error(_request: Request, _exc: RequestValidationError) -> JSONResponse:
        # Framework validation normally echoes rejected input, which can contain
        # accidental secrets. Keep every validation response input-independent.
        return JSONResponse(status_code=422, content={"detail": "invalid request"})

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/provisioning/report")
    def report(req: ProvisioningReportRequest) -> dict[str, str]:
        try:
            report_data = receiver.provisioning_report_data(req.challenge())
            raw = provider.provisioning_report(report_data)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="provisioning request rejected") from exc
        except AttestationUnavailableError as exc:
            raise HTTPException(status_code=503, detail="native SNP attestation unavailable") from exc
        except RuntimeError as exc:
            raise HTTPException(status_code=409, detail="broker cannot be provisioned in its current state") from exc
        return {"report_b64": base64.b64encode(raw).decode("ascii"),
                "transport_public_key": receiver.transport_public_key}

    @app.post("/provisioning/install")
    def install(req: ProvisioningInstallRequest) -> dict[str, bool]:
        try:
            envelope = req.envelope()
        except (ValueError, binascii.Error) as exc:
            raise HTTPException(status_code=422, detail="invalid provisioning envelope") from exc
        try:
            receiver.install(envelope)
        except (ValueError, InvalidSignature, SealError) as exc:
            raise HTTPException(status_code=400, detail="provisioning envelope rejected") from exc
        except RuntimeError as exc:
            raise HTTPException(status_code=409, detail="broker cannot install in its current state") from exc
        return {"installed": True}

    @app.post("/challenge")
    def challenge() -> dict[str, str]:
        try:
            issued = receiver.issue_challenge()
        except RuntimeError as exc:
            raise HTTPException(status_code=409, detail="broker is not ready for release") from exc
        return {"nonce": issued.nonce, "issued_at": issued.issued_at.isoformat(),
                "expires_at": issued.expires_at.isoformat()}

    @app.post("/release")
    def release(req: ReleaseRequest) -> dict[str, Any]:
        try:
            manifest = WeightCustodyManifest.model_validate(req.manifest)
            evidence = CompositeEvidence.model_validate(req.evidence)
        except ValidationError as exc:
            raise HTTPException(status_code=422, detail="invalid manifest or evidence") from exc
        try:
            decision = receiver.verify_and_release(manifest, evidence)
        except RuntimeError as exc:
            raise HTTPException(status_code=409, detail="broker is not ready for release") from exc
        return {
            "released": decision.released,
            "sealed_key_b64": base64.b64encode(decision.sealed_key).decode("ascii") if decision.sealed_key else None,
            "checks": [{"name": check.name, "passed": check.passed, "detail": check.detail}
                       for check in decision.checks],
        }

    return app


def app_from_env() -> FastAPI:
    """uvicorn wcm.broker_server:app_from_env --factory --workers 1."""
    from .provisioning_wire import load_broker_inputs

    path = os.environ.get("WCM_BROKER_CONFIG_FILE")
    if not path:
        raise ValueError("WCM_BROKER_CONFIG_FILE is required")
    configuration, policy = load_broker_inputs(path)
    return create_app(BrokerReceiver(configuration, policy))
