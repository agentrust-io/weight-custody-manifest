"""The captures behind the adapter change, checked rather than described.

Every number the change rests on is derived here from the committed files, so
a reviewer does not have to take a commit message or a PR body on trust, and a
refreshed capture that disagrees fails the suite.
"""
from __future__ import annotations

import base64
import json
import pathlib
import re

CAPTURES = pathlib.Path(__file__).parent / "fixtures" / "nvidia" / "cc-mode"


def _load(name: str) -> dict:
    return json.loads((CAPTURES / name).read_text(encoding="utf-8"))


def test_no_opaque_field_moves_with_the_only_guest_operable_control() -> None:
    """The GPUs ready state is the one confidential-compute control a guest has."""
    on = _load("cc-on-h100.json")
    before = on["report"]["fields"]
    after = on["ready_state_off"]["report"]["fields"]

    assert set(before) == set(after)
    moved = [tag for tag in before if before[tag]["hex"] != after[tag]["hex"]]
    assert moved == [], f"fields moved with the ready state: {moved}"
    assert len(before) == 16


def test_a_device_with_the_mode_off_answers_everything_except_attestation() -> None:
    """Which is what separates an unavailable feature from a blocked interface."""
    off = _load("cc-off-h100.json")["nvml_calls"]

    assert off["attestation_report"]["answered"] is False
    assert off["gpu_certificate"]["answered"] is False
    assert off["protected_memory"]["answered"] is True
    assert off["mem_size_info"]["answered"] is True


def test_the_certificate_chain_confirms_the_report_parse() -> None:
    """Two separately signed structures agreeing on one firmware measurement.

    The opaque layout was solved from the bytes rather than read from a
    specification, so it is worth confirming from a second direction before
    anything is concluded from it.
    """
    from cryptography import x509

    on = _load("cc-on-h100.json")
    pem = base64.b64decode(on["cert_chain_b64"]).decode("utf-8", "replace")
    certs = re.findall(
        r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", pem, re.S
    )
    assert len(certs) == 5

    leaf = x509.load_pem_x509_certificate(certs[0].encode())
    dice = next(
        extension for extension in leaf.extensions
        if extension.oid.dotted_string == "2.23.133.5.4.1"
    ).value.value

    assert on["report"]["fields"]["20"]["hex"] in dice.hex()


def test_no_appraisal_claim_concerns_confidential_compute_mode() -> None:
    """The claim names as the service returned them, counted here not in prose."""
    appraisal = _load("appraisal-claims.json")

    assert appraisal["detached_claim_count"] == 22
    assert len(appraisal["detached_claims"]) == 22
    assert appraisal["overall_claims"] == [
        "x-nvidia-overall-att-result", "x-nvidia-ver"
    ]
    named = [
        claim for claim in appraisal["detached_claims"] + appraisal["overall_claims"]
        if "cc" in claim.lower() or "confidential" in claim.lower()
    ]
    assert named == [], f"a claim may concern the mode: {named}"


def test_the_captures_record_what_they_do_not_establish() -> None:
    """The limits travel with the evidence, not only with the pull request."""
    limits = " ".join(_load("manifest.json")["what_this_does_not_establish"])

    assert "every verified report" in limits
    assert "driver" in limits
    assert "host-side control" in limits
