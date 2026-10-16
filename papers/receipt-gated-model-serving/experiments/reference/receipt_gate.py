"""Reference implementation of receipt-gated model serving.

Written for the technical report "Receipt-Gated Model Serving". It is a
compact, self-contained restatement of the mechanism the report evaluates, so
that a reader can reproduce every software experiment without access to the
evaluated source. It depends only on the Python standard library and the
`cryptography` package.

Three parts:

1. A hosting grant pins eight SHA-256 digests. Its own digest is the hosting
   session identifier.
2. A model host emits Ed25519-signed, hash-chained receipts: the first is the
   admission decision, later ones record lifecycle events such as revocation.
3. A manifest planner returns a bootstrap Pod that carries ciphertext and no
   key, and returns a Service (the routing object) only for a first receipt
   that verifies against an independently pinned key and matches every grant
   binding. A chained revocation receipt names the Service to delete.

The planner is deliberately stateless. Lifecycle memory belongs to the
controller that applies its manifests; see controller_experiment.py.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import hmac
import json
import re
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

RECEIPT_KIND = "receipt-gated-model-hosting/v1"
LABEL_PREFIX = "receipt-gate.example"
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
DNS_LABEL = re.compile(r"^[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?$")
IMAGE_DIGEST = re.compile(r"^[^\s]+@sha256:[0-9a-f]{64}$")
BINDING_FIELDS = ("tenant_fingerprint", "weights_hash", "encrypted_artifact_hash",
                  "workload_hash", "policy_hash", "transport_hash")
STATES = {"locked", "serving", "stopped", "revoked", "failed"}
UNSET = object()


def canonical(value: dict[str, Any]) -> bytes:
    """Sorted-key, compact JSON in UTF-8. Signed bytes and chain hashes use this."""
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha256(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def receipt_hash(receipt: dict[str, Any]) -> str:
    """Chain hash of a complete signed receipt, including its verification block."""
    return sha256(canonical(receipt))


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _unb64url(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def public_key_b64url(key: Ed25519PrivateKey) -> str:
    return _b64url(key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))


class RevocationReason(str, Enum):
    policy = "policy-revoked"
    attestation_key = "attestation-key-revoked"
    emergency = "emergency-revocation"


@dataclass(frozen=True)
class HostingGrant:
    """What the deployment approved. Every field is a lowercase sha256 digest."""
    session_nonce_hash: str
    tenant_fingerprint: str
    weights_hash: str
    encrypted_artifact_hash: str
    workload_hash: str
    policy_hash: str
    transport_hash: str
    receipt_signing_key_hash: str

    def __post_init__(self) -> None:
        for name, value in asdict(self).items():
            if not DIGEST.fullmatch(value):
                raise ValueError(f"{name} must be a lowercase sha256 digest")

    @property
    def session_id(self) -> str:
        return sha256(canonical(asdict(self)))

    def bindings(self) -> dict[str, str]:
        return asdict(self)


class ModelHost:
    """Emits the signed receipt chain for one hosting session.

    `release_key` stands in for attested key release (for example a key broker
    that checks hardware evidence). `wipe` must destroy key custody. Neither is
    implemented here; the receipts are what the planner consumes.
    """

    def __init__(self, grant: HostingGrant, signing_key: Ed25519PrivateKey, *,
                 release_key: Callable[[], bytes], wipe: Callable[[], None],
                 now: Callable[[], datetime] | None = None) -> None:
        raw = signing_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        if not hmac.compare_digest(sha256(raw), grant.receipt_signing_key_hash):
            raise ValueError("receipt signing key does not match the grant")
        self.grant, self._key, self._release, self._wipe = grant, signing_key, release_key, wipe
        self._now = now or (lambda: datetime.now(timezone.utc))
        self.state = "locked"
        self._sequence = 0
        self._previous: str | None = None

    @property
    def public_key_b64url(self) -> str:
        return public_key_b64url(self._key)

    def start(self, measured_bindings: dict[str, str]) -> dict[str, Any]:
        """Admission: compare measured bindings with the grant, then release the key."""
        if self.state != "locked":
            raise RuntimeError("a host starts once; recovery needs a new session")
        expected = self.grant.bindings()
        mismatched = sorted({k for k, v in expected.items()
                             if not hmac.compare_digest(measured_bindings.get(k, ""), v)}
                            | (set(measured_bindings) - set(expected)))
        if mismatched:
            self.state = "stopped"
            self._wipe()
            return self._emit("admission", False, "binding-mismatch:" + ",".join(mismatched))
        try:
            self._release()
        except Exception:
            self.state = "stopped"
            self._wipe()
            return self._emit("admission", False, "key-release-refused")
        self.state = "serving"
        return self._emit("admission", True, "admitted")

    def record_inference(self, request_id: str, prompt_digest: str, result_digest: str) -> dict[str, Any]:
        """Each served request extends the chain. Inference itself is out of scope here."""
        if self.state != "serving":
            return self._emit("inference", False, "host-not-serving")
        return self._emit("inference", True, "served",
                          request={"request_id": request_id, "prompt_digest": prompt_digest},
                          result_digest=result_digest)

    def revoke(self, reason: RevocationReason) -> dict[str, Any]:
        self._wipe()
        self.state = "revoked"
        return self._emit("lifecycle", False, RevocationReason(reason).value)

    def _emit(self, event: str, allowed: bool, reason: str, **extra: Any) -> dict[str, Any]:
        self._sequence += 1
        body = {
            "kind": RECEIPT_KIND, "session_id": self.grant.session_id, "sequence": self._sequence,
            "previous_receipt_hash": self._previous,
            "issued_at": self._now().astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
            "event": event, "state": self.state, "decision": "allow" if allowed else "deny", "reason": reason,
            **{f: getattr(self.grant, f) for f in BINDING_FIELDS}, **extra,
        }
        receipt = copy.deepcopy(body)
        receipt["verification"] = {"algorithm": "Ed25519", "public_key_b64url": self.public_key_b64url,
                                   "signature_b64url": _b64url(self._key.sign(canonical(body)))}
        self._previous = receipt_hash(receipt)
        return receipt


def verify_receipt(receipt: dict[str, Any], *, expected_previous_hash: Any = UNSET,
                   expected_public_key_b64url: str | None = None,
                   expected_session_id: str | None = None) -> tuple[bool, list[str]]:
    """Check shape, digests, chain position, pinned signer and Ed25519 signature."""
    failures: list[str] = []
    body = copy.deepcopy(receipt)
    verification = body.pop("verification", None)
    if body.get("kind") != RECEIPT_KIND:
        failures.append("unexpected receipt kind")
    if body.get("event") not in {"admission", "inference", "lifecycle"}:
        failures.append("invalid event")
    if body.get("decision") not in {"allow", "deny"}:
        failures.append("invalid decision")
    if body.get("state") not in STATES:
        failures.append("invalid host state")
    if not isinstance(body.get("sequence"), int) or body["sequence"] < 1:
        failures.append("sequence must be a positive integer")
    for field in ("session_id", *BINDING_FIELDS):
        if not DIGEST.fullmatch(str(body.get(field, ""))):
            failures.append(f"{field} must be a lowercase sha256 digest")
    previous = body.get("previous_receipt_hash")
    if previous is not None and not DIGEST.fullmatch(str(previous)):
        failures.append("previous_receipt_hash must be a lowercase sha256 digest")
    if expected_previous_hash is not UNSET and previous != expected_previous_hash:
        failures.append("receipt chain predecessor mismatch")
    if expected_session_id is not None and body.get("session_id") != expected_session_id:
        failures.append("hosting session identity mismatch")
    request = body.get("request")
    if request is not None and (not isinstance(request, dict) or set(request) != {"request_id", "prompt_digest"}
                                or not DIGEST.fullmatch(str(request.get("prompt_digest", "")))):
        failures.append("invalid request evidence")
    if "result_digest" in body and not DIGEST.fullmatch(str(body["result_digest"])):
        failures.append("result_digest must be a lowercase sha256 digest")
    known = {"kind", "session_id", "sequence", "previous_receipt_hash", "issued_at", "event", "state",
             "decision", "reason", "request", "result_digest", *BINDING_FIELDS}
    if set(body) - known:
        failures.append("unknown receipt fields: " + ",".join(sorted(set(body) - known)))
    if not isinstance(verification, dict) or verification.get("algorithm") != "Ed25519":
        failures.append("missing Ed25519 verification block")
        return False, failures
    if expected_public_key_b64url is not None and verification.get("public_key_b64url") != expected_public_key_b64url:
        failures.append("receipt signing key is not the independently pinned key")
    try:
        key = Ed25519PublicKey.from_public_bytes(_unb64url(verification["public_key_b64url"]))
        key.verify(_unb64url(verification["signature_b64url"]), canonical(body))
    except (KeyError, ValueError, InvalidSignature):
        failures.append("receipt signature invalid")
    return not failures, failures


@dataclass(frozen=True)
class KubernetesHostConfig:
    name: str
    namespace: str
    image: str
    runtime_class: str
    encrypted_model_claim: str
    container_args: tuple[str, ...]
    gpu_resource: str = "nvidia.com/gpu"
    port: int = 8600

    def __post_init__(self) -> None:
        for label in ("name", "namespace", "runtime_class", "encrypted_model_claim"):
            if not DNS_LABEL.fullmatch(getattr(self, label)):
                raise ValueError(f"{label} must be a Kubernetes DNS label")
        if not IMAGE_DIGEST.fullmatch(self.image):
            raise ValueError("image must be pinned by sha256 digest")
        if not self.container_args or not all(self.container_args):
            raise ValueError("container_args must be non-empty")


class AdmissionGatedPlanner:
    """Stateless planner: Pod first, Service only after a matching admission receipt."""

    def __init__(self, grant: HostingGrant, config: KubernetesHostConfig, *, receipt_public_key_b64url: str):
        self.grant, self.config, self._receipt_key = grant, config, receipt_public_key_b64url
        if sha256(_unb64url(receipt_public_key_b64url)) != grant.receipt_signing_key_hash:
            raise ValueError("pinned receipt key does not match the grant's receipt_signing_key_hash")
        # The selector label carries 64 bits of the session digest; the full identifier is an annotation.
        self.session_label = grant.session_id.removeprefix("sha256:")[:16]

    def _labels(self) -> dict[str, str]:
        return {"app.kubernetes.io/name": self.config.name, f"{LABEL_PREFIX}/hosting-session": self.session_label}

    def workload_manifest(self) -> dict[str, Any]:
        """Bootstrap Pod: digest-pinned image, ciphertext volume, no key, never restarted."""
        return {
            "apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": self.config.name, "namespace": self.config.namespace, "labels": self._labels(),
                         "annotations": {f"{LABEL_PREFIX}/session-id": self.grant.session_id,
                                         f"{LABEL_PREFIX}/workload-hash": self.grant.workload_hash,
                                         f"{LABEL_PREFIX}/encrypted-artifact-hash": self.grant.encrypted_artifact_hash}},
            "spec": {
                "runtimeClassName": self.config.runtime_class,
                "restartPolicy": "Never",
                "automountServiceAccountToken": False,
                "hostNetwork": False, "hostPID": False, "hostIPC": False,
                "securityContext": {"runAsNonRoot": True, "seccompProfile": {"type": "RuntimeDefault"}},
                "containers": [{
                    "name": "model-host", "image": self.config.image, "args": list(self.config.container_args),
                    "ports": [{"name": "http", "containerPort": self.config.port}],
                    "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                        "capabilities": {"drop": ["ALL"]}},
                    "resources": {"limits": {self.config.gpu_resource: 1}},
                    "volumeMounts": [{"name": "encrypted-model", "mountPath": "/model", "readOnly": True}],
                }],
                "volumes": [{"name": "encrypted-model", "persistentVolumeClaim": {
                    "claimName": self.config.encrypted_model_claim, "readOnly": True}}],
            },
        }

    def admission_failures(self, receipt: dict[str, Any]) -> list[str]:
        ok, failures = verify_receipt(receipt, expected_previous_hash=None,
                                      expected_public_key_b64url=self._receipt_key,
                                      expected_session_id=self.grant.session_id)
        if not ok:
            return failures
        expected = {"event": "admission", "sequence": 1, "state": "serving", "decision": "allow",
                    "reason": "admitted", **{f: getattr(self.grant, f) for f in BINDING_FIELDS}}
        for field, wanted in expected.items():
            actual = receipt.get(field)
            same = (hmac.compare_digest(actual, wanted) if isinstance(actual, str) and isinstance(wanted, str)
                    else actual == wanted)
            if not same:
                failures.append(f"admission {field} mismatch")
        return failures

    def service_manifest(self, admission_receipt: dict[str, Any]) -> dict[str, Any]:
        failures = self.admission_failures(admission_receipt)
        if failures:
            raise ValueError("admission receipt refused: " + "; ".join(failures))
        return {
            "apiVersion": "v1", "kind": "Service",
            "metadata": {"name": self.config.name, "namespace": self.config.namespace,
                         "annotations": {f"{LABEL_PREFIX}/admission-receipt-hash": receipt_hash(admission_receipt),
                                         f"{LABEL_PREFIX}/session-id": self.grant.session_id}},
            "spec": {"type": "ClusterIP", "selector": self._labels(),
                     "ports": [{"name": "http", "port": self.config.port, "targetPort": "http"}]},
        }

    def service_delete_target(self, revocation_receipt: dict[str, Any], *, expected_previous_hash: str) -> dict[str, Any]:
        ok, failures = verify_receipt(revocation_receipt, expected_previous_hash=expected_previous_hash,
                                      expected_public_key_b64url=self._receipt_key,
                                      expected_session_id=self.grant.session_id)
        if ok:
            for field, wanted in (("event", "lifecycle"), ("state", "revoked"), ("decision", "deny")):
                if revocation_receipt.get(field) != wanted:
                    failures.append(f"revocation {field} mismatch")
            if revocation_receipt.get("reason") not in {r.value for r in RevocationReason}:
                failures.append("revocation reason mismatch")
        if failures:
            raise ValueError("revocation receipt refused: " + "; ".join(failures))
        return {"apiVersion": "v1", "kind": "Service", "operation": "delete",
                "metadata": {"name": self.config.name, "namespace": self.config.namespace,
                             "annotations": {f"{LABEL_PREFIX}/revocation-receipt-hash": receipt_hash(revocation_receipt),
                                             f"{LABEL_PREFIX}/session-id": self.grant.session_id}}}
