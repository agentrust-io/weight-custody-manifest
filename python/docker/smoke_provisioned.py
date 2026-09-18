#!/usr/bin/env python3
"""Public-only fixture generation and no-hardware installed-service smoke test.

Run fixture generation with the installed image's dependencies. Private
certificate signing keys exist only transiently to construct synthetic public
certificates. No private keys or model keys are written to the fixture directory.
The owner public key is a fixed public test value, never a production identity.
"""
from __future__ import annotations

import argparse
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import time
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen


def fixture(directory: Path) -> None:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    from wcm.broker_receiver import BrokerEffectiveConfiguration
    from wcm.provisioning import BrokerProvisioningPolicy

    directory.mkdir(parents=True, exist_ok=True)
    root_key = ec.generate_private_key(ec.SECP384R1())
    leaf_key = ec.generate_private_key(ec.SECP384R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "synthetic-ci-root")])
    now = datetime.now(timezone.utc)

    def certificate(public_key: ec.EllipticCurvePublicKey, common_name: str, ca: bool) -> x509.Certificate:
        return (x509.CertificateBuilder()
                .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
                .issuer_name(name).public_key(public_key).serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=1))
                .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
                .sign(root_key, hashes.SHA384()))

    root = certificate(root_key.public_key(), "synthetic-ci-root", True)
    leaf = certificate(leaf_key.public_key(), "synthetic-ci-workload-vcek", False)
    # Public key from RFC 8032's first Ed25519 test vector; no owner private key.
    owner_public = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
    identity = "sha256:" + "cc" * 32
    config = BrokerEffectiveConfiguration(
        root.public_bytes(serialization.Encoding.DER), leaf.public_bytes(serialization.Encoding.DER),
        (), frozenset({identity}), owner_public,
    )
    policy = BrokerProvisioningPolicy(
        measurement_hex="11" * 48, configuration_sha256=config.digest(), weights_hash="sha256:" + "dd" * 32,
        epoch=1, guest_policy=0, minimum_tcb_le_hex="0101000000000101",
        required_platform_fields=frozenset({"ciphertext_hiding_en", "alias_check_complete"}),
        forbidden_platform_fields=frozenset({"smt_en"}),
    )
    policy_json = asdict(policy)
    for field in ("required_platform_fields", "forbidden_platform_fields"):
        policy_json[field] = sorted(policy_json[field])
    (directory / "cpu-root.pem").write_bytes(root.public_bytes(serialization.Encoding.PEM))
    (directory / "cpu-vcek.pem").write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
    (directory / "owner.pub").write_bytes(owner_public)
    (directory / "broker.json").write_text(json.dumps({
        "configuration": {"cpu_root_file": "cpu-root.pem", "cpu_vcek_file": "cpu-vcek.pem",
                          "cpu_intermediate_files": [], "trusted_manifest_identities": [identity],
                          "owner_public_key_file": "owner.pub"},
        "policy": policy_json,
    }, indent=2), encoding="utf-8")


def request(base: str, path: str, payload: dict[str, str] | None = None) -> tuple[int, dict[str, object]]:
    data = None if payload is None else json.dumps(payload).encode()
    req = Request(base + path, data=data, headers={"Content-Type": "application/json"})
    try:
        # check() restricts the initial URL to an HTTP loopback origin.
        with urlopen(req, timeout=2) as response:  # nosec B310
            return response.status, json.load(response)
    except HTTPError as exc:
        return exc.code, json.load(exc)


def check(base: str) -> None:
    parsed = urlsplit(base)
    if (parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}
            or parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path):
        raise ValueError("smoke endpoint must be an HTTP loopback origin")
    deadline = time.monotonic() + 30
    while True:
        try:
            status, body = request(base, "/health")
            if status == 200 and body == {"status": "ok"}:
                break
        except OSError:
            # A listening container port can reset/disconnect while uvicorn is
            # still starting. Retry only readiness GETs within this deadline;
            # provisioning/challenge POSTs below must remain single attempts.
            pass
        if time.monotonic() >= deadline:
            raise RuntimeError("provisioned image failed to start")
        time.sleep(0.2)
    status, _ = request(base, "/challenge", {})
    if status != 409:
        raise RuntimeError("unprovisioned broker issued a workload challenge")
    now = datetime.now(timezone.utc)
    status, body = request(base, "/provisioning/report", {
        "nonce": "aa" * 32, "issued_at": now.isoformat(),
        "expires_at": (now + timedelta(seconds=60)).isoformat(),
    })
    if status != 503 or body != {"detail": "native SNP attestation unavailable"}:
        raise RuntimeError("broker did not fail closed without native SNP hardware")
    if request(base, "/challenge", {})[0] != 409:
        raise RuntimeError("failed attestation enabled workload release")
    print("PASS: provisioned service starts without model keys; no-SNP request fails closed")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("fixture").add_argument("directory", type=Path)
    commands.add_parser("check").add_argument("base_url")
    args = parser.parse_args()
    if args.command == "fixture":
        fixture(args.directory)
    else:
        check(args.base_url)


if __name__ == "__main__":
    main()
