"""Owner-side deployment approval records, not proof of measured execution.

The provisional SNP adapter records an independently predicted launch digest.
It never learns an approved identity from a report supplied by the deployment.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import TYPE_CHECKING, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

if TYPE_CHECKING:
    from .provisioning import BrokerProvisioningPolicy

Role = Literal["firmware", "kernel", "initrd", "command_line", "application",
               "configuration", "measurement_tool"]
ROLES: tuple[Role, ...] = (
    "application", "command_line", "configuration", "firmware", "initrd", "kernel",
    "measurement_tool",
)
_DOMAIN = b"wcm/deployment-approval/v1\x00"


class _Frozen(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class ArtifactIdentity(_Frozen):
    role: Role
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    size: int = Field(gt=0)


class SnpLaunchParameters(_Frozen):
    """Inputs to the reviewed measurement tool; not guest self-report fields."""

    vmm_type: Literal["QEMU"]
    vcpus: int = Field(ge=1, le=1024)
    vcpu_type: str = Field(pattern=r"^[A-Za-z0-9_.-]{1,64}$")
    guest_features: str = Field(pattern=r"^0x(?:0|[1-9a-f][0-9a-f]{0,15})$")


class DeploymentApproval(_Frozen):
    """Immutable candidate approved and pinned on the independent owner host.

    Matching these fields establishes owner approval consistency. Boot coverage,
    artifact containment, launch-tool correctness and runtime immutability still
    need the validation described in docs/broker-deployment-identity.md.
    """

    profile: Literal["wcm/snp-direct-boot-initrd/v1"]
    artifacts: tuple[ArtifactIdentity, ...]
    launch: SnpLaunchParameters
    expected_measurement_hex: str = Field(pattern=r"^[0-9a-f]{96}$")
    effective_configuration_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    provisioning_policy_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def _roles(self) -> Self:
        if tuple(item.role for item in self.artifacts) != ROLES:
            raise ValueError("exact artifact roles in canonical order required")
        return self

    def canonical_bytes(self) -> bytes:
        return json.dumps(self.model_dump(mode="json"), sort_keys=True,
                          separators=(",", ":"), ensure_ascii=True).encode("ascii")

    def identity(self) -> str:
        return "sha256:" + hashlib.sha256(_DOMAIN + self.canonical_bytes()).hexdigest()

    def require_policy(self, policy: BrokerProvisioningPolicy) -> None:
        if (policy.measurement_hex != self.expected_measurement_hex
                or policy.configuration_sha256 != self.effective_configuration_sha256
                or hashlib.sha256(policy.context()).hexdigest() != self.provisioning_policy_sha256):
            raise ValueError("provisioning policy does not match deployment approval")

    def require_artifacts(self, artifacts: dict[str, Path]) -> None:
        """Compare supplied candidate bytes, including added/missing artifacts."""
        if set(artifacts) != set(ROLES):
            raise ValueError("exact deployment artifact set required")
        for expected in self.artifacts:
            if _artifact(expected.role, artifacts[expected.role]) != expected:
                raise ValueError("deployment artifact substitution rejected")


def _artifact(role: Role, path: Path) -> ArtifactIdentity:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
            size += len(block)
    return ArtifactIdentity(role=role, sha256=digest.hexdigest(), size=size)


def derive_approval(*, artifacts: dict[str, Path], launch: SnpLaunchParameters,
                    expected_measurement_hex: str,
                    policy: BrokerProvisioningPolicy) -> DeploymentApproval:
    """Hash approved local inputs before deployment, without reading any quote.

    expected_measurement_hex must come from independently running a reviewed
    launch-measurement tool. This function does not calculate the SNP digest.
    """
    if set(artifacts) != set(ROLES):
        raise ValueError("exact deployment artifact set required")
    approval = DeploymentApproval(
        profile="wcm/snp-direct-boot-initrd/v1",
        artifacts=tuple(_artifact(role, artifacts[role]) for role in ROLES),
        launch=launch, expected_measurement_hex=expected_measurement_hex,
        effective_configuration_sha256=policy.configuration_sha256,
        provisioning_policy_sha256=hashlib.sha256(policy.context()).hexdigest(),
    )
    approval.require_policy(policy)
    return approval


def load_approval(path: Path, expected_identity: str) -> DeploymentApproval:
    from .provisioning_wire import json_object

    # Parse duplicate members before Pydantic; ordinary JSON accepts last-wins.
    value = json_object(path.read_bytes())
    approval = DeploymentApproval.model_validate_json(json.dumps(value))
    if approval.identity() != expected_identity:
        raise ValueError("deployment approval identity does not match owner pin")
    return approval


def main() -> None:
    """Print a deterministic candidate from a trusted, local build input file."""
    from .provisioning_wire import config_path, exact_fields, json_object, load_policy

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("inputs", type=Path)
    parser.add_argument("--identity-only", action="store_true")
    parser.add_argument("--verify-approval", type=Path)
    parser.add_argument("--expected-identity")
    args = parser.parse_args()
    try:
        path = args.inputs.resolve()
        raw = json_object(path.read_bytes())
        exact_fields(raw, {"artifacts", "launch", "expected_measurement_hex", "policy_file"})
        if not isinstance(raw["artifacts"], dict):
            raise ValueError("artifact file mapping required")
        approval = derive_approval(
            artifacts={role: config_path(path.parent, value)
                       for role, value in raw["artifacts"].items()},
            launch=SnpLaunchParameters.model_validate(raw["launch"]),
            expected_measurement_hex=raw["expected_measurement_hex"],
            policy=load_policy(config_path(path.parent, raw["policy_file"])),
        )
        if args.verify_approval is not None or args.expected_identity is not None:
            if args.verify_approval is None or args.expected_identity is None:
                raise ValueError("verification requires an approval file and independent identity pin")
            approved = load_approval(args.verify_approval, args.expected_identity)
            if approval.identity() != approved.identity():
                raise ValueError("candidate deployment differs from approved identity")
    except Exception as exc:
        parser.exit(1, f"deployment approval rejected ({type(exc).__name__})\n")
    print(approval.identity() if args.identity_only else approval.canonical_bytes().decode("ascii"))


if __name__ == "__main__":
    main()
