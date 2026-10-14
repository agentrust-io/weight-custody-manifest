"""The DCAP v4 framing around the signed bytes, held to what real quotes carry.

Every real TDX quote in ``tests/fixtures`` has the same framing outside the
signed header and TD report:

- the signature section is exactly 128 bytes of signature and attestation
  key, a 6-byte certification-data header of type 6 (QE report certification
  data), and that many bytes of certification data;
- the certification data is exactly the 384-byte QE report, its 64-byte
  signature, 2 + 32 bytes of QE authentication data and one PCK entry of type
  5 (PEM PCK chain), with nothing after it;
- the bytes after the signature section are all zero.

Measured padding after the signature section, all zero bytes:

    tdx_quote_azure.json (Azure DCes_v6)          5006 bytes, 70 padding
    tdx_quote_gcp.json (GCP c3-standard-4)        8000 bytes, 3061 padding
    the SEAM SVN 15 GCP capture (c3-standard-4)   8000 bytes, 3065 padding

So length equality is not required: the captured buffers hold zero-filled
bytes after the declared quote, and those are accepted for compatibility.
The fields checked here sit outside the signed data, and nothing the verifier
trusts is read from them unauthenticated: the attestation key signs the header
and TD report, the QE report binds that key, and the PCK chain signs the QE
report. The checks refuse layouts no real quote has, as a ``QuoteFormatError``
that ``verify_tdx_quote`` turns into a denial.
"""

from __future__ import annotations

import base64
import hashlib
import json
import struct
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization

from wcm import TrustStore, parse_tdx_quote, verify_tdx_quote
from wcm._quote_verify import QuoteFormatError

FIXTURES = Path(__file__).parent / "fixtures"
REAL = sorted(FIXTURES.glob("tdx_quote_*.json"))
AZURE = FIXTURES / "tdx_quote_azure.json"
INTEL_SGX_ROOT_CA_SHA256 = "44a0196b2b99f889b8e149e95b807a350e7424964399e885a7cbb8ccfab674d3"

_SIGNED = 48 + 584
_SIG_START = _SIGNED + 4


def _load(path: Path) -> tuple[bytes, dict]:
    doc = json.loads(path.read_text(encoding="utf-8"))
    return base64.b64decode(doc["quote_b64"]), doc


def _trust(quote: bytes) -> TrustStore:
    parsed = parse_tdx_quote(quote)
    root = next(c for c in [parsed.pck_leaf, *parsed.pck_intermediates] if c.subject == c.issuer)
    assert hashlib.sha256(root.public_bytes(serialization.Encoding.DER)).hexdigest() == (
        INTEL_SGX_ROOT_CA_SHA256
    )
    store = TrustStore()
    store.add_root(root)
    return store


def _layout(quote: bytes) -> dict[str, int]:
    sig_len = struct.unpack_from("<I", quote, _SIGNED)[0]
    cd_type, cd_size = struct.unpack_from("<HI", quote, _SIG_START + 128)
    cd_start = _SIG_START + 134
    auth = struct.unpack_from("<H", quote, cd_start + 384 + 64)[0]
    pck_header = cd_start + 384 + 64 + 2 + auth
    pck_type, pck_size = struct.unpack_from("<HI", quote, pck_header)
    return {
        "sig_len": sig_len,
        "cd_type_offset": _SIG_START + 128,
        "cd_type": cd_type,
        "cd_size_offset": _SIG_START + 130,
        "cd_size": cd_size,
        "pck_type_offset": pck_header,
        "pck_type": pck_type,
        "pck_end": pck_header + 6 + pck_size,
        "padding": len(quote) - (_SIG_START + sig_len),
    }


def _put_u16(quote: bytes, offset: int, value: int) -> bytes:
    return quote[:offset] + struct.pack("<H", value) + quote[offset + 2 :]


def _put_u32(quote: bytes, offset: int, value: int) -> bytes:
    return quote[:offset] + struct.pack("<I", value) + quote[offset + 4 :]


@pytest.mark.filterwarnings("ignore::DeprecationWarning")
@pytest.mark.parametrize("path", REAL, ids=[p.name for p in REAL])
def test_every_real_quote_has_this_framing_and_still_verifies(path: Path) -> None:
    quote, doc = _load(path)
    layout = _layout(quote)
    assert layout["cd_type"] == 6 and layout["pck_type"] == 5
    assert layout["sig_len"] == 134 + layout["cd_size"]
    assert layout["pck_end"] == _SIG_START + layout["sig_len"]
    assert layout["padding"] > 0
    assert quote[_SIG_START + layout["sig_len"] :] == bytes(layout["padding"])
    result = verify_tdx_quote(quote, _trust(quote), expected_nonce=doc["expected_nonce"])
    assert result.verified, result.reason


def test_recorded_padding_measurements() -> None:
    padding = {p.name: _layout(_load(p)[0])["padding"] for p in REAL}
    assert padding["tdx_quote_azure.json"] == 70
    assert padding["tdx_quote_gcp.json"] == 3061
    assert sorted(padding.values()) == [70, 3061, 3065]


def _mutations(quote: bytes) -> dict[str, bytes]:
    layout = _layout(quote)
    sig_end = _SIG_START + layout["sig_len"]
    return {
        "outer type 6 -> 5": _put_u16(quote, layout["cd_type_offset"], 5),
        "inner PCK type 5 -> 6": _put_u16(quote, layout["pck_type_offset"], 6),
        "inner PCK type 5 -> 3": _put_u16(quote, layout["pck_type_offset"], 3),
        "nonzero byte in the padding": quote[:-1] + b"\x01",
        "nonzero byte at the start of the padding": (
            quote[:sig_end] + b"\x01" + quote[sig_end + 1 :]
        ),
        "signature section shortened, payload kept": _put_u32(
            quote, _SIGNED, layout["sig_len"] - 1
        ),
        "signature section shortened by 100, payload kept": _put_u32(
            quote, _SIGNED, layout["sig_len"] - 100
        ),
        "signature section past the end": _put_u32(quote, _SIGNED, len(quote)),
        "cd size one larger": _put_u32(quote, layout["cd_size_offset"], layout["cd_size"] + 1),
        "cd size one smaller": _put_u32(quote, layout["cd_size_offset"], layout["cd_size"] - 1),
        # Both lengths grow by one into the zero padding: sizes agree, but the
        # certification data then holds a byte the PCK entry does not account for.
        "cd and section grown by a padding byte": _put_u32(
            _put_u32(quote, _SIGNED, layout["sig_len"] + 1),
            layout["cd_size_offset"],
            layout["cd_size"] + 1,
        ),
    }


@pytest.mark.filterwarnings("ignore::DeprecationWarning")
@pytest.mark.parametrize("label", sorted(_mutations(_load(AZURE)[0])))
def test_framing_mutations_of_a_real_quote_are_refused(label: str) -> None:
    quote, _ = _load(AZURE)
    trust = _trust(quote)
    mutated = _mutations(quote)[label]
    with pytest.raises(QuoteFormatError):
        parse_tdx_quote(mutated)
    result = verify_tdx_quote(mutated, trust, expected_nonce=None)
    assert not result.verified and result.reason


def test_refusal_reasons_name_the_field() -> None:
    quote, _ = _load(AZURE)
    m = _mutations(quote)
    expected = {
        "outer type 6 -> 5": "unexpected QE certification-data type 5 (want 6)",
        "inner PCK type 5 -> 3": "unexpected PCK cert-data type 3 (want 5)",
        "nonzero byte in the padding": "nonzero bytes after the TDX signature section",
        "cd size one larger": "QE certification data size does not match the signature section",
        "cd and section grown by a padding byte": (
            "unexpected bytes after the PCK cert chain in the QE certification data"
        ),
        "signature section past the end": "TDX signature section truncated",
    }
    for label, reason in expected.items():
        with pytest.raises(QuoteFormatError, match=reason.replace("(", r"\(").replace(")", r"\)")):
            parse_tdx_quote(m[label])
