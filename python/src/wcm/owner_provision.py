"""One-shot owner-side provisioning client; model keys never leave in plaintext.

Run ``python -m wcm.owner_provision CONFIG.json`` on the trusted owner host.
An HTTP acknowledgement is not evidence that the broker installed the key.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import ipaddress
import json
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ._certificates import load_pem_certificate
from .provisioning import OwnerProvisioner
from .provisioning_state import OwnerEpochStore
from .provisioning_wire import config_path, exact_fields, json_object, load_policy
from .deployment_identity import load_approval


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
        return None


def validate_url(url: Any, *, allow_loopback_http: bool = False) -> str:
    if not isinstance(url, str):
        raise ValueError("broker URL required")
    parsed = urlsplit(url)
    if not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("broker URL must have a host and no credentials, query or fragment")
    loopback = parsed.hostname == "localhost"
    try:
        loopback = loopback or ipaddress.ip_address(parsed.hostname).is_loopback
    except ValueError:
        pass
    if parsed.scheme != "https" and not (parsed.scheme == "http" and loopback and allow_loopback_http):
        raise ValueError("HTTPS required; loopback HTTP needs explicit development opt-in")
    return url.rstrip("/")


def _post(url: str, value: dict[str, Any]) -> dict[str, Any]:
    request = Request(url, data=json.dumps(value).encode(),
                      headers={"Content-Type": "application/json"}, method="POST")
    # Disable environment proxies and redirects. TLS uses the default verified
    # context; there is deliberately no insecure-TLS option.
    opener = build_opener(ProxyHandler({}), _NoRedirect())
    with opener.open(request, timeout=10) as response:  # nosec B310
        body = response.read(131073)
    if len(body) > 131072:
        raise ValueError("broker response exceeds size limit")
    return json_object(body)


def provision_from_file(path: str | Path, *, allow_loopback_http: bool = False) -> dict[str, Any]:
    path = Path(path).resolve()
    raw = json_object(path.read_bytes())
    exact_fields(raw, {"policy_file", "owner_signing_key_file", "amd_root_file", "broker_vcek_file",
                       "broker_intermediate_files", "model_key_file", "epoch_database",
                       "epoch_namespace", "broker_url"},
                 {"deployment_approval_file", "deployment_approval_identity"})
    base = path.parent
    url = validate_url(raw["broker_url"], allow_loopback_http=allow_loopback_http)
    if not isinstance(raw["epoch_namespace"], str) or not raw["epoch_namespace"]:
        raise ValueError("nonempty owner epoch namespace required")
    intermediates = raw["broker_intermediate_files"]
    if not isinstance(intermediates, list):
        raise ValueError("intermediate certificate path array required")
    policy = load_policy(config_path(base, raw["policy_file"]))
    approval = None
    if {"deployment_approval_file", "deployment_approval_identity"} & raw.keys():
        if not {"deployment_approval_file", "deployment_approval_identity"} <= raw.keys():
            raise ValueError("deployment approval requires both file and owner identity pin")
        approval = load_approval(config_path(base, raw["deployment_approval_file"]),
                                 raw["deployment_approval_identity"])
        approval.require_policy(policy)
    owner = OwnerProvisioner(
        policy,
        owner_signing_key=Ed25519PrivateKey.from_private_bytes(
            config_path(base, raw["owner_signing_key_file"]).read_bytes()),
        trusted_root=load_pem_certificate(config_path(base, raw["amd_root_file"]).read_bytes()),
        epoch_store=OwnerEpochStore(config_path(base, raw["epoch_database"]), raw["epoch_namespace"]),
        deployment_approval=approval,
    )
    vcek = load_pem_certificate(config_path(base, raw["broker_vcek_file"]).read_bytes())
    chain = [load_pem_certificate(config_path(base, item).read_bytes()) for item in intermediates]
    model_key = config_path(base, raw["model_key_file"]).read_bytes()
    if len(model_key) not in (16, 24, 32):
        raise ValueError("model key must have an AES key length")
    challenge = owner.issue_challenge()
    offered = _post(url + "/provisioning/report", {
        "nonce": challenge.nonce, "issued_at": challenge.issued_at.isoformat(),
        "expires_at": challenge.expires_at.isoformat(),
    })
    exact_fields(offered, {"report_b64", "transport_public_key"})
    if not isinstance(offered["report_b64"], str) or not isinstance(offered["transport_public_key"], str):
        raise ValueError("invalid broker report response")
    report = base64.b64decode(offered["report_b64"], validate=True)
    if len(report) != 1184:
        raise ValueError("native SNP report must be 1184 bytes")
    envelope = owner.provision(
        nonce=challenge.nonce, report=report, vcek=vcek, intermediates=chain,
        transport_public_key=offered["transport_public_key"], model_key=model_key,
    )
    acknowledged = _post(url + "/provisioning/install", {
        "nonce": envelope.nonce,
        "ciphertext_b64": base64.b64encode(envelope.ciphertext).decode(),
        "owner_signature_b64": base64.b64encode(envelope.owner_signature).decode(),
    })
    exact_fields(acknowledged, {"installed"})
    if acknowledged["installed"] is not True:
        raise ValueError("broker did not acknowledge installation")
    return {
        "protocol": "wcm/native-snp-owner-provision/v1",
        "epoch": policy.epoch, "policy_sha256": hashlib.sha256(policy.context()).hexdigest(),
        "report_sha256": hashlib.sha256(report).hexdigest(),
        "broker_acknowledged": True, "installation_proven": False,
        "deployment_approval_identity": approval.identity() if approval is not None else None,
        "application_identity_established": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("config", type=Path)
    parser.add_argument("--allow-loopback-http", action="store_true")
    args = parser.parse_args()
    try:
        receipt = provision_from_file(args.config, allow_loopback_http=args.allow_loopback_http)
    except Exception as exc:
        # Upstream errors and local file contents must not reach console logs.
        parser.exit(1, f"provisioning failed ({type(exc).__name__}); installation outcome unknown\n")
    print(json.dumps(receipt, sort_keys=True))


if __name__ == "__main__":
    main()
