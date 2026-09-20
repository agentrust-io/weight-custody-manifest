"""Strict operator configuration for the reference provisioning service.

Paths are relative to the JSON file and are read once. Files and the process
must be protected by the deployment; this loader does not measure an image.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization

from ._certificates import load_pem_certificate
from .broker_receiver import BrokerEffectiveConfiguration
from .provisioning import BrokerProvisioningPolicy


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON member")
        result[key] = value
    return result


def json_object(data: str | bytes) -> dict[str, Any]:
    value = json.loads(data, object_pairs_hook=_unique_object)
    if not isinstance(value, dict):
        raise ValueError("JSON object required")
    return value


def exact_fields(value: dict[str, Any], required: set[str], optional: set[str] | None = None) -> None:
    if not required <= value.keys() or value.keys() - required - (optional or set()):
        raise ValueError("missing or unrecognized configuration fields")


def config_path(base: Path, value: Any) -> Path:
    if not isinstance(value, str) or not value:
        raise ValueError("nonempty file path required")
    return (base / value).resolve()


def _strings(value: Any) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) or not item for item in value):
        raise ValueError("JSON string array required")
    if len(set(value)) != len(value):
        raise ValueError("duplicate array member")
    return value


def policy_from_object(raw: Any) -> BrokerProvisioningPolicy:
    if not isinstance(raw, dict):
        raise ValueError("policy object required")
    exact_fields(raw, {
        "measurement_hex", "configuration_sha256", "weights_hash", "epoch", "guest_policy",
        "minimum_tcb_le_hex", "required_platform_fields", "forbidden_platform_fields",
    })
    values = dict(raw)
    for name in ("required_platform_fields", "forbidden_platform_fields"):
        values[name] = frozenset(_strings(raw[name]))
    return BrokerProvisioningPolicy(**values)


def load_policy(path: str | Path) -> BrokerProvisioningPolicy:
    return policy_from_object(json_object(Path(path).read_bytes()))


def load_broker_inputs(path: str | Path) -> tuple[BrokerEffectiveConfiguration, BrokerProvisioningPolicy]:
    path = Path(path).resolve()
    raw = json_object(path.read_bytes())
    exact_fields(raw, {"configuration", "policy"})
    config = raw["configuration"]
    if not isinstance(config, dict):
        raise ValueError("configuration object required")
    exact_fields(config, {"cpu_root_file", "cpu_vcek_file", "cpu_intermediate_files",
                          "trusted_manifest_identities", "owner_public_key_file"}, {"gpu_root_file"})

    def certificate(value: Any) -> bytes:
        return load_pem_certificate(config_path(path.parent, value).read_bytes()).public_bytes(
            serialization.Encoding.DER
        )

    effective = BrokerEffectiveConfiguration(
        cpu_root_der=certificate(config["cpu_root_file"]),
        cpu_vcek_der=certificate(config["cpu_vcek_file"]),
        cpu_intermediate_ders=tuple(certificate(item) for item in _strings(config["cpu_intermediate_files"])),
        trusted_manifest_identities=frozenset(_strings(config["trusted_manifest_identities"])),
        owner_public_key=config_path(path.parent, config["owner_public_key_file"]).read_bytes(),
        gpu_root_der=certificate(config["gpu_root_file"]) if "gpu_root_file" in config else None,
    )
    return effective, policy_from_object(raw["policy"])


def main() -> None:
    """Print the effective digest for owner review, without approving it."""
    import argparse

    parser = argparse.ArgumentParser(description="Compute a reference broker configuration digest")
    parser.add_argument("config", type=Path)
    args = parser.parse_args()
    try:
        configuration, _ = load_broker_inputs(args.config)
    except Exception as exc:
        parser.exit(1, f"configuration rejected ({type(exc).__name__})\n")
    print(configuration.digest())


if __name__ == "__main__":
    main()
