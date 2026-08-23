from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

RECEIPT = (
    Path(__file__).parent
    / "fixtures/live-validation/weight-custody-manifest/azure-pcr23-2026-08-23/azure-pcr23.json"
)
HEX_256 = re.compile(r"[0-9a-f]{64}")


def test_azure_pcr23_hardware_receipt_is_pinned_and_fail_closed():
    value = json.loads(RECEIPT.read_text(encoding="utf-8"))

    assert value["kind"] == "wcm-azure-measured-launch/v1"
    assert value["classification"] == "sanitized public validation evidence"
    assert value["release_candidate"] == ("4b2bf79397eb1dd27c9dce9cfd467a0ef2f5739a")
    assert value["environment"]["provider"] == "Microsoft Azure"
    assert value["environment"]["confidential_vm_sku"] == "Standard_DC2as_v5"
    assert value["environment"]["cpu_tee"] == "AMD SEV-SNP"
    assert value["positive"] == {"verified": True, "reason": None}
    assert value["negative_wrong_measurement"] == {
        "verified": False,
        "reason": "TPM PCR digest does not match the approved workload measurement",
    }
    assert value["passed"] is True


def test_azure_pcr23_hardware_receipt_has_independent_digest_check():
    value = json.loads(RECEIPT.read_text(encoding="utf-8"))
    event_digest = bytes.fromhex(value["measurement"]["serving_image_sha256"])
    pcr_value = hashlib.sha256(bytes(32) + event_digest).digest()
    quote_digest = hashlib.sha256(pcr_value).hexdigest()

    assert value["measurement"]["expected_pcr23_sha256"] == quote_digest
    assert quote_digest != pcr_value.hex()
    assert all(HEX_256.fullmatch(item) for item in value["evidence"].values())


def test_azure_pcr23_hardware_receipt_contains_no_environment_identifiers():
    value = json.loads(RECEIPT.read_text(encoding="utf-8"))
    serialized = json.dumps(value).lower()
    forbidden_keys = {
        "subscription",
        "subscription_id",
        "tenant",
        "tenant_id",
        "resource_group",
        "resource_id",
        "hostname",
        "host_name",
        "ip",
        "ip_address",
        "hcl",
        "certificate",
        "token",
        "customer",
    }

    def keys(item: object) -> set[str]:
        if isinstance(item, dict):
            return set(item) | {key for child in item.values() for key in keys(child)}
        if isinstance(item, list):
            return {key for child in item for key in keys(child)}
        return set()

    assert keys(value).isdisjoint(forbidden_keys)
    assert "opaque" not in serialized
    assert not re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", serialized)
