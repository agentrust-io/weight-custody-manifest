"""The TDX platform floor: what is appraised, and what is carried untouched.

Every positive here runs against `tdx_quote_gcp.json`, a real capture, with the
negatives built by editing a copy of that body, so the offsets are exercised
against bytes Intel produced rather than bytes this test invented.

The test that matters most is the one that asserts *nothing* happens: editing
byte 2 of `TEE_TCB_SVN` must not move the verdict. Two captures in this
repository report `0d 01 08` and `0d 01 04`, the same SEAM SVN 13 with a
different byte 2, so whatever byte 2 tracks it is not the SEAM module version.
The carried-not-judged rule is the easiest thing here to lose in a later
refactor, and this is the cheapest way to notice.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from wcm.platform_floor import (
    FloorAppraisal,
    FloorCheck,
    FloorState,
    PlatformFloor,
    appraise_tdx,
)
from wcm.tdx import TD_ATTR_DEBUG, TdxReport, parse_tdx_quote

FIXTURES = Path(__file__).parent / "fixtures"
GCP = FIXTURES / "tdx_quote_gcp.json"
AZURE = FIXTURES / "tdx_quote_azure.json"


def _report(path: Path = GCP) -> TdxReport:
    doc = json.loads(path.read_text(encoding="utf-8"))
    return parse_tdx_quote(base64.b64decode(doc["quote_b64"])).report


def _edited(report: TdxReport, **over: object) -> TdxReport:
    """A copy of a real report with one field changed."""
    return TdxReport(
        report_data=over.get("report_data", report.report_data),  # type: ignore[arg-type]
        mrtd=over.get("mrtd", report.mrtd),  # type: ignore[arg-type]
        tee_tcb_svn=over.get("tee_tcb_svn", report.tee_tcb_svn),  # type: ignore[arg-type]
        td_attributes=over.get("td_attributes", report.td_attributes),  # type: ignore[arg-type]
        raw=over.get("raw", report.raw),  # type: ignore[arg-type]
    )


# ---- the fields land on the report -----------------------------------


def test_both_fields_are_parsed_onto_the_report() -> None:
    """snp.py parses policy, vmpl and reported_tcb. The asymmetry was the issue."""
    report = _report()
    assert len(report.tee_tcb_svn) == 16
    assert report.seam_svn == report.tee_tcb_svn[0]
    assert isinstance(report.td_attributes, int)


def test_the_offsets_cross_check_against_the_parser_on_the_same_bytes() -> None:
    """What makes trusting the rest of the layout reasonable.

    The two fields sit inside a body whose layout this parser already agrees
    with, rather than in a layout the issue asserted.
    """
    doc = json.loads(GCP.read_text(encoding="utf-8"))
    quote = base64.b64decode(doc["quote_b64"])
    report = parse_tdx_quote(quote).report
    body = quote[48 : 48 + 584]
    assert report.report_data == body[520:584]
    assert report.mrtd == body[136:184]
    assert report.tee_tcb_svn == body[0:16]
    assert report.td_attributes == int.from_bytes(body[120:128], "little")


def test_the_two_captures_share_a_seam_svn_and_differ_at_byte_two() -> None:
    """The finding the carried-not-judged rule rests on."""
    gcp, azure = _report(GCP), _report(AZURE)
    assert gcp.seam_svn == azure.seam_svn == 13
    assert gcp.tee_tcb_svn[2] != azure.tee_tcb_svn[2]
    assert gcp.tee_tcb_svn[1] == azure.tee_tcb_svn[1] == 1


def test_the_docstring_says_carried_and_not_judged_in_those_words() -> None:
    """The next reader will assume a parsed field is an appraised one."""
    assert "carried and not judged" in (TdxReport.__doc__ or "")


# ---- the appraisal ---------------------------------------------------



def test_floor_met() -> None:
    appraisal = appraise_tdx(_report(), PlatformFloor(seam_svn=13))
    assert appraisal.ok
    assert all(c.state is FloorState.passed for c in appraisal.checks)


def test_floor_above_the_hardware() -> None:
    appraisal = appraise_tdx(_report(), PlatformFloor(seam_svn=20))
    assert not appraisal.ok
    svn = next(c for c in appraisal.checks if c.name.endswith("seam_svn"))
    assert svn.state is FloorState.failed
    assert "13" in svn.reason and "20" in svn.reason


def test_debug_set_is_refused() -> None:
    """The analogue of the SEV-SNP guest-policy debug bit."""
    report = _edited(_report(), td_attributes=_report().td_attributes | TD_ATTR_DEBUG)
    appraisal = appraise_tdx(report, PlatformFloor(seam_svn=13))
    assert not appraisal.ok
    debug = next(c for c in appraisal.checks if c.name.endswith("debug"))
    assert debug.state is FloorState.failed
    assert "readable from outside" in debug.reason


def test_a_body_too_short_for_the_offset_fails_rather_than_passing() -> None:
    report = _edited(_report(), tee_tcb_svn=b"")
    appraisal = appraise_tdx(report, PlatformFloor(seam_svn=13))
    svn = next(c for c in appraisal.checks if c.name.endswith("seam_svn"))
    assert svn.state is FloorState.failed
    assert "cannot be read" in svn.reason


# ---- three states, and an abstention that names its reason -----------


def test_no_floor_supplied_abstains_and_names_the_vendor() -> None:
    """Not a silent pass. "Not configured" read as green is the failure mode."""
    appraisal = appraise_tdx(_report(), PlatformFloor())
    svn = next(c for c in appraisal.checks if c.name.endswith("seam_svn"))
    assert svn.state is FloorState.not_evaluated
    assert "intel-tdx" in svn.reason
    assert not appraisal.ok


def test_an_abstention_is_never_rounded_up_to_verified() -> None:
    assert not FloorCheck("x", FloorState.not_evaluated, "why").ok
    assert FloorCheck("x", FloorState.passed, "why").ok


def test_an_appraisal_that_only_abstained_is_not_ok() -> None:
    appraisal = appraise_tdx(_report(), PlatformFloor(seam_svn=None, forbid_debug=False))
    assert all(c.state is FloorState.not_evaluated for c in appraisal.checks)
    assert not appraisal.ok
    assert appraisal.evaluated == []


def test_every_abstention_carries_a_reason() -> None:
    """"Not evaluated" with no reason is the same useless answer in a different
    colour."""
    appraisal = appraise_tdx(_report(), PlatformFloor(seam_svn=None, forbid_debug=False))
    assert all(c.reason.strip() for c in appraisal.checks)


# ---- staleness: beside the verdict, and stateless --------------------


def test_staleness_is_the_shape_agreed() -> None:
    report = _edited(_report(), tee_tcb_svn=bytes([15]) + _report().tee_tcb_svn[1:])
    appraisal = appraise_tdx(report, PlatformFloor(seam_svn=13))
    assert appraisal.staleness == {"floor": 13, "reported": 15, "floor_behind": True}


def test_a_floor_behind_the_fleet_does_not_fail_the_release() -> None:
    """Operator hygiene, not a fault in the artifact being appraised. Refusing a
    sound platform over a stale policy file would be the wrong failure."""
    report = _edited(_report(), tee_tcb_svn=bytes([15]) + _report().tee_tcb_svn[1:])
    appraisal = appraise_tdx(report, PlatformFloor(seam_svn=13))
    assert appraisal.staleness["floor_behind"] is True
    assert appraisal.ok


def test_staleness_sits_beside_the_verdict_never_inside_it() -> None:
    rendered = appraise_tdx(_report(), PlatformFloor(seam_svn=13)).as_dict()
    assert "staleness" in rendered
    assert all("staleness" not in check for check in rendered["checks"])


def test_no_watermark_is_kept_between_appraisals() -> None:
    """Stateless on purpose. A stored high-water mark needs somewhere to live
    and gives an attacker something to poison: one run against a platform
    reporting a high SVN would move it for everything appraised afterwards."""
    high = _edited(_report(), tee_tcb_svn=bytes([15]) + _report().tee_tcb_svn[1:])
    appraise_tdx(high, PlatformFloor(seam_svn=13))
    again = appraise_tdx(_report(), PlatformFloor(seam_svn=13))
    assert again.staleness == {"floor": 13, "reported": 13, "floor_behind": False}


def test_an_abstention_reports_no_staleness() -> None:
    """There is no floor to be behind."""
    assert appraise_tdx(_report(), PlatformFloor()).staleness is None


# ---- the carried bytes are carried and not judged --------------------


def test_editing_byte_two_makes_no_difference_to_the_verdict() -> None:
    """The test that must fail when someone starts appraising the rest.

    Two captures here report the same SEAM SVN 13 with byte 2 at 8 and at 4, so
    anything that compared the array whole would order them on a byte nobody
    can name.
    """
    base = _report()
    floor = PlatformFloor(seam_svn=13)
    before = appraise_tdx(base, floor)

    svn = bytearray(base.tee_tcb_svn)
    svn[2] ^= 0xFF
    after = appraise_tdx(_edited(base, tee_tcb_svn=bytes(svn)), floor)

    assert after.ok == before.ok is True
    assert [c.as_dict() for c in after.checks] == [c.as_dict() for c in before.checks]
    assert after.staleness == before.staleness


def test_editing_any_carried_byte_makes_no_difference() -> None:
    """Byte 0 is the only one appraised, so every other index is inert."""
    base = _report()
    floor = PlatformFloor(seam_svn=13)
    expected = appraise_tdx(base, floor).as_dict()
    for index in range(1, 16):
        svn = bytearray(base.tee_tcb_svn)
        svn[index] ^= 0xFF
        got = appraise_tdx(_edited(base, tee_tcb_svn=bytes(svn)), floor).as_dict()
        assert got == expected, "byte %d changed the verdict" % index


def test_editing_a_carried_attribute_bit_makes_no_difference() -> None:
    """Bit 28 is set on every capture here and nobody has established what it
    means, so it is not a bit to refuse a release over."""
    base = _report()
    floor = PlatformFloor(seam_svn=13)
    expected = appraise_tdx(base, floor).as_dict()
    flipped = _edited(base, td_attributes=base.td_attributes ^ (1 << 28))
    assert appraise_tdx(flipped, floor).as_dict() == expected


def test_byte_zero_is_the_one_that_does_move_the_verdict() -> None:
    """The counterpart, so the test above cannot pass by appraising nothing."""
    base = _report()
    floor = PlatformFloor(seam_svn=13)
    low = _edited(base, tee_tcb_svn=bytes([1]) + base.tee_tcb_svn[1:])
    assert appraise_tdx(base, floor).ok
    assert not appraise_tdx(low, floor).ok


# ---- no VMPL analogue is invented ------------------------------------


def test_nothing_is_emitted_for_a_property_tdx_does_not_have() -> None:
    """Emitting nothing is better than a check that always passes."""
    appraisal = appraise_tdx(_report(), PlatformFloor(seam_svn=13))
    assert not any("vmpl" in c.name.lower() for c in appraisal.checks)
    assert not hasattr(PlatformFloor(), "vmpl")


def test_forbid_debug_is_shared_rather_than_vendor_specific() -> None:
    """One operator intent expressed by two vendors."""
    assert "forbid_debug" in PlatformFloor.__dataclass_fields__
    assert not any(
        name.startswith(("tdx_", "intel_")) for name in PlatformFloor.__dataclass_fields__
    )


def test_a_quote_that_will_not_parse_fails_with_the_parse_error() -> None:
    """Failed, not abstained. Bytes that are not a quote have not been shown to
    meet anything, and reporting that as not evaluated would let it aggregate
    beside a platform nobody had a floor for."""
    from wcm.platform_floor import appraise_tdx_quote

    appraisal = appraise_tdx_quote(b"not a quote", PlatformFloor(seam_svn=13))
    assert not appraisal.ok
    assert appraisal.checks[0].state is FloorState.failed
    assert "does not parse" in appraisal.checks[0].reason


def test_a_real_quote_appraises_through_the_bytes_entry_point() -> None:
    from wcm.platform_floor import appraise_tdx_quote

    doc = json.loads(GCP.read_text(encoding="utf-8"))
    quote = base64.b64decode(doc["quote_b64"])
    assert appraise_tdx_quote(quote, PlatformFloor(seam_svn=13)).ok


def test_a_short_body_names_the_length_found() -> None:
    report = _edited(_report(), tee_tcb_svn=b"")
    svn = next(
        c
        for c in appraise_tdx(report, PlatformFloor(seam_svn=13)).checks
        if c.name.endswith("seam_svn")
    )
    assert "0 bytes" in svn.reason
