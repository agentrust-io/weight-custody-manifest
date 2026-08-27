"""The committed protected-runtime receipt, re-verified offline.

Issues #78 and #79 both say the same thing in different words: the algorithms
are implemented and unit-tested, and what is missing is evidence from a real
protected runtime rather than a more persuasive simulation. This is that
evidence, captured on an Azure SEV-SNP confidential VM
(`Standard_DC2ads_v5`, eastus, AMD EPYC 7763, `Memory Encryption Features
active: AMD SEV`) by `tools/capture_protected_runtime.py`, and re-checked here
without a network or a VM.

What the capture adds over the unit tests:

  The swept pages were SEV-SNP-encrypted guest DRAM, mlock'd so the region under
  test could not page out to disk, at 65536 pages rather than the 64 a unit test
  uses.

  The sweep challenge was derived from a live vTPM attestation report read from
  NV index 0x01400001, not from a locally invented string.

  The lease lapsed because time passed, not because a test called zeroize. The
  runtime then refused the next operation on its own.

What it does not add, and the receipt says so in its own text so a reader who
finds the JSON alone still gets it: nothing about physical memory extraction. A
sweep running inside the guest cannot observe a DDR interposer outside it.
TEE.fail and BadRAM are unaffected, and SPEC.md section 3.6 is unchanged.
"""
from __future__ import annotations

import json
import pathlib

import pytest

from wcm import RuntimeEvent, RuntimeRecord, verify_runtime_record_chain

RECEIPT = (
    pathlib.Path(__file__).parent
    / "fixtures"
    / "protected-runtime"
    / "protected-runtime-receipt.json"
)


@pytest.fixture(scope="module")
def receipt() -> dict:
    return json.loads(RECEIPT.read_text(encoding="utf-8"))


def test_captured_on_a_guest_reporting_active_memory_encryption(receipt) -> None:
    guest = receipt["guest"]

    assert "EPYC" in guest["cpu_model"]
    assert guest["kernel"].endswith("-azure-fde")


def test_the_sweep_challenge_came_from_a_live_attestation(receipt) -> None:
    """A locally invented nonce would make the sweep unbound to this guest."""
    attestation = receipt["attestation"]

    assert attestation["hcl_report_available"] is True
    assert attestation["hcl_report_bytes"] > 2000
    assert attestation["nonce_derivation"] == "sha256(HCL report)"
    assert receipt["memory_sweep"]["nonce_source"] == "vtpm-attestation"


def test_the_raw_attestation_report_is_not_in_the_receipt(receipt) -> None:
    """It carries platform identifiers. The digest is what the claim needs."""
    rendered = json.dumps(receipt)

    assert "hcl_report_b64" not in rendered
    assert "report_bytes_b64" not in rendered
    assert len(receipt["attestation"]["hcl_report_sha256"]) == 64


def test_the_sweep_covered_real_protected_memory_at_scale(receipt) -> None:
    sweep = receipt["memory_sweep"]

    assert sweep["bytes"] == 256 * 1024 * 1024
    assert sweep["pages"] == 65536
    assert sweep["page_size"] == 4096
    # Without mlock a region this size pages out under exactly the write
    # pressure a sweep creates, and the thing swept stops being resident memory.
    assert sweep["locked_in_ram"] is True


def test_the_sweep_verified_and_found_no_aliasing(receipt) -> None:
    sweep = receipt["memory_sweep"]

    assert sweep["verified"] is True
    assert sweep["aliasing_detected"] is False


def test_the_sweep_negatives_were_exercised_on_the_same_hardware(receipt) -> None:
    """A pass alone does not show the check can fail."""
    sweep = receipt["memory_sweep"]

    assert sweep["negative_tampered_readback_rejected"] is True
    assert sweep["negative_wrong_key_rejected"] is True


def test_the_lease_lapsed_because_time_passed(receipt) -> None:
    """#78's actual question: does the runtime stop on its own?"""
    custody = receipt["custody_chain"]

    assert custody["lapsed_on_its_own"] is True
    assert custody["state_after_lapse"] == "wiped"
    assert custody["operation_after_wipe_refused_with"] == "KeyWipedError"


def test_the_custody_chain_reverifies_offline_from_the_committed_records(receipt) -> None:
    """The strongest part: the signatures are checked here, not trusted.

    Everything else in this receipt is the capture's own report of what it saw.
    These records carry signatures, so this test re-runs the verification rather
    than reading a boolean the capture wrote.
    """
    custody = receipt["custody_chain"]
    records = [RuntimeRecord(**entry) for entry in custody["records"]]

    verified, reason = verify_runtime_record_chain(
        records, custody["runtime_public_key_b64url"], require_terminal_sequence=True
    )

    assert verified, reason
    assert reason == "valid terminal runtime record chain"


def test_the_chain_has_the_terminal_shape_the_spec_requires(receipt) -> None:
    assert receipt["custody_chain"]["chain_events"] == [
        RuntimeEvent.lease_started.value,
        RuntimeEvent.lapse_detected.value,
        RuntimeEvent.wipe_requested.value,
        RuntimeEvent.wipe_completed.value,
        RuntimeEvent.process_terminated.value,
    ]


def test_a_truncated_chain_from_this_capture_is_rejected_offline(receipt) -> None:
    """What a SIGKILL would have left. Re-checked here, not taken on trust."""
    custody = receipt["custody_chain"]
    records = [RuntimeRecord(**entry) for entry in custody["records"]]

    verified, _ = verify_runtime_record_chain(
        records[:3], custody["runtime_public_key_b64url"], require_terminal_sequence=True
    )

    assert not verified


def test_a_record_removed_from_the_middle_is_rejected_offline(receipt) -> None:
    custody = receipt["custody_chain"]
    records = [RuntimeRecord(**entry) for entry in custody["records"]]

    verified, reason = verify_runtime_record_chain(
        [records[0], *records[2:]],
        custody["runtime_public_key_b64url"],
        require_terminal_sequence=False,
    )

    assert not verified
    assert "contiguous" in reason or "previous hash" in reason


def test_another_key_cannot_verify_this_chain(receipt) -> None:
    from wcm import generate_ed25519, runtime_public_key

    custody = receipt["custody_chain"]
    records = [RuntimeRecord(**entry) for entry in custody["records"]]

    verified, _ = verify_runtime_record_chain(
        records,
        runtime_public_key(generate_ed25519().private_key),
        require_terminal_sequence=True,
    )

    assert not verified


def test_both_sections_carry_their_own_limits(receipt) -> None:
    """A reader who finds this JSON without the docs must still get the caveat."""
    sweep_limits = receipt["memory_sweep"]["limits"]
    custody_limits = receipt["custody_chain"]["limits"]

    assert "TEE.fail" in sweep_limits and "3.6" in sweep_limits
    assert "physical memory extraction" in sweep_limits
    assert "does not demonstrate" in custody_limits
