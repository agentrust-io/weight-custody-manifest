"""Fixed broker entry point for the provisional initramfs loader.

The configuration snapshot is untrusted data. Only the owner's authenticated
policy check authorizes provisioning. No file paths or Python options arrive
through the guest configuration channel.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization

from ._certificates import load_pem_certificate
from .broker_receiver import BrokerEffectiveConfiguration, BrokerReceiver
from .provisioning import BrokerProvisioningPolicy
from .provisioning_wire import exact_fields, json_object, policy_from_object, _strings

MAX_CONFIGURATION = 1024 * 1024


def guest_inputs(data: bytes) -> tuple[BrokerEffectiveConfiguration, BrokerProvisioningPolicy]:
    if not data or len(data) > MAX_CONFIGURATION:
        raise ValueError("guest configuration size rejected")
    raw = json_object(data)
    exact_fields(raw, {"configuration", "policy"})
    config = raw["configuration"]
    if not isinstance(config, dict):
        raise ValueError("configuration object required")
    exact_fields(config, {"cpu_root_pem", "cpu_vcek_pem", "cpu_intermediates_pem",
                          "trusted_manifest_identities", "owner_public_key_hex"}, {"gpu_root_pem"})

    def certificate(value: Any) -> bytes:
        if not isinstance(value, str):
            raise ValueError("PEM string required")
        return load_pem_certificate(value.encode("ascii")).public_bytes(serialization.Encoding.DER)

    key = config["owner_public_key_hex"]
    if not isinstance(key, str) or len(key) != 64 or bytes.fromhex(key).hex() != key:
        raise ValueError("canonical owner public key required")
    effective = BrokerEffectiveConfiguration(
        cpu_root_der=certificate(config["cpu_root_pem"]),
        cpu_vcek_der=certificate(config["cpu_vcek_pem"]),
        cpu_intermediate_ders=tuple(certificate(item) for item in _strings(config["cpu_intermediates_pem"])),
        trusted_manifest_identities=frozenset(_strings(config["trusted_manifest_identities"])),
        owner_public_key=bytes.fromhex(key),
        gpu_root_der=certificate(config["gpu_root_pem"]) if "gpu_root_pem" in config else None,
    )
    policy = policy_from_object(raw["policy"])
    if effective.digest() != policy.configuration_sha256:
        raise ValueError("effective guest configuration differs from policy")
    return effective, policy


def main() -> None:
    from .broker_server import create_app
    import uvicorn

    # No environment-derived paths, imports, log configuration or reload option.
    with Path("/run/config.json").open("rb") as source:
        config, policy = guest_inputs(source.read(MAX_CONFIGURATION + 1))
    app = create_app(BrokerReceiver(config, policy))
    # Intentional guest service listener; deployment ingress controls remain required.
    uvicorn.run(app, host="0.0.0.0", port=8080, workers=1, access_log=False,  # nosec B104
                log_config=None, proxy_headers=False)


if __name__ == "__main__":
    main()
