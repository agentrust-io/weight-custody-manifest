"""The third TDX capture, and what having three points establishes.

Two captures cannot separate firmware movement from platform difference and
three can, which is the whole reason this one was contributed. It is an external
capture, labelled as such in the fixture, and no appraisal rule rests on it
alone: every threshold in the suite comes from the two captures this project
took itself.

The fields are read as raw slices of the TD report body rather than through any
parsed attribute, so this fixture stands on its own and can land before or after
the parser change in #117 without either waiting on the other.
"""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives.serialization import Encoding

from wcm._quote_verify import TrustStore
from wcm.tdx import parse_tdx_quote, verify_tdx_quote

FIXTURES = Path(__file__).parent / "fixtures"
SEAM15 = FIXTURES / "tdx_quote_gcp_seam15.json"
GCP = FIXTURES / "tdx_quote_gcp.json"
AZURE = FIXTURES / "tdx_quote_azure.json"


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def test_the_capture_is_labelled_as_external() -> None:
    """Two of these fixtures are this project's and one is not. A fixture set
    where that distinction is invisible is worse than one where it is written
    down."""
    doc = _load(SEAM15)
    assert doc["provenance"] == "external"
    assert doc["contributed_by"]
    assert "provenance" not in _load(GCP)


def test_the_capture_carries_its_own_provenance() -> None:
    """A reader three years from now needs to know what this is a capture of."""
    capture = _load(SEAM15)["capture"]
    assert capture["kernel"] == "7.0.0-1011-gcp"
    assert capture["instance_type"] == "c3-standard-4"
    assert capture["captured_at"].startswith("2026-")
    assert "configfs TSM directly" in capture["method"]


def test_the_capture_verifies_end_to_end() -> None:
    doc = _load(SEAM15)
    quote = base64.b64decode(doc["quote_b64"])
    parsed = parse_tdx_quote(quote)
    root = next(
        c for c in [parsed.pck_leaf, *parsed.pck_intermediates] if c.subject == c.issuer
    )
    assert (
        hashlib.sha256(root.public_bytes(Encoding.DER)).hexdigest()
        == doc["intel_sgx_root_ca_sha256"]
    )
    store = TrustStore()
    store.add_root(root)
    result = verify_tdx_quote(quote, store, expected_nonce=doc["expected_nonce"])
    assert result.verified, result.reason


def _body(path: Path) -> bytes:
    """The 584-byte TD report body, straight out of the quote."""
    return base64.b64decode(_load(path)["quote_b64"])[48 : 48 + 584]


def test_the_offsets_cross_check_against_the_parser_on_these_bytes() -> None:
    """What makes trusting the rest of the layout reasonable, on this capture
    too rather than only on the ones already here."""
    quote = base64.b64decode(_load(SEAM15)["quote_b64"])
    report = parse_tdx_quote(quote).report
    body = quote[48 : 48 + 584]
    assert report.report_data == body[520:584]
    assert report.mrtd == body[136:184]


def test_three_captures_separate_firmware_from_platform() -> None:
    """The finding the carried-not-judged rule rests on.

    Byte 0 moves on its own: 13 on both existing captures and 15 here, with
    byte 1 at 1 throughout. Byte 2 differs across all three, so whatever it
    tracks it is not the SEAM module version.
    """
    svn = {name: _body(path)[0:16] for name, path in
           (("gcp", GCP), ("azure", AZURE), ("seam15", SEAM15))}
    assert svn["gcp"][0] == svn["azure"][0] == 13
    assert svn["seam15"][0] == 15
    assert all(v[1] == 1 for v in svn.values())
    assert len({v[2] for v in svn.values()}) == 3


def test_no_appraisal_threshold_is_taken_from_this_capture() -> None:
    """It is the third point that separates two axes, not the basis for a
    floor. Every threshold in the suite comes from the captures this project
    took itself."""
    here = Path(__file__)
    referencing = [
        p.name
        for p in here.parent.rglob("*.py")
        if p != here and "tdx_quote_gcp_seam15" in p.read_text(encoding="utf-8")
    ]
    assert referencing == [], referencing
    assert "No appraisal rule rests on this capture alone." in _load(SEAM15)["note"]
