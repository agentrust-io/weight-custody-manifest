import json

import pytest

from wcm.guest_broker import guest_inputs, MAX_CONFIGURATION
from wcm.provisioning_wire import load_broker_inputs
from tests.test_owner_provision import bundle  # noqa: F401


def inline(broker_path):
    raw = json.loads(broker_path.read_text())
    base = broker_path.parent
    old = raw["configuration"]
    raw["configuration"] = {
        "cpu_root_pem": (base / old["cpu_root_file"]).read_text(),
        "cpu_vcek_pem": (base / old["cpu_vcek_file"]).read_text(),
        "cpu_intermediates_pem": [],
        "trusted_manifest_identities": old["trusted_manifest_identities"],
        "owner_public_key_hex": (base / old["owner_public_key_file"]).read_bytes().hex(),
    }
    return raw


def test_inline_data_matches_independent_file_configuration(bundle):
    expected = load_broker_inputs(bundle[0])
    actual = guest_inputs(json.dumps(inline(bundle[0])).encode())
    assert actual == expected


@pytest.mark.parametrize("attack", ["path", "import", "key", "policy", "extra", "duplicate", "large", "empty"])
def test_guest_data_cannot_select_code_or_claim_different_configuration(bundle, attack):
    raw = inline(bundle[0])
    if attack == "path":
        raw["configuration"]["cpu_root_file"] = "/outside"
    elif attack == "import":
        raw["configuration"]["PYTHONPATH"] = "/run"
    elif attack == "key":
        raw["configuration"]["owner_public_key_hex"] = "44" * 32
    elif attack == "policy":
        raw["policy"]["configuration_sha256"] = "55" * 32
    elif attack == "extra":
        raw["entrypoint"] = "os.system"
    data = json.dumps(raw).encode()
    if attack == "duplicate":
        data = b'{"policy":{},' + data[1:]
    elif attack == "large":
        data = b" " * (MAX_CONFIGURATION + 1)
    elif attack == "empty":
        data = b""
    with pytest.raises(ValueError):
        guest_inputs(data)
