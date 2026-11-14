"""RFC 8785 JSON Canonicalization Scheme (JCS).

Reference: https://www.rfc-editor.org/rfc/rfc8785

Single canonicalization entry point for all signing and hashing in the WCM
reference SDK. The joint builder+custodian signature pre-image (SPEC.md
section 3.1) is the RFC 8785 canonical form of the manifest's signed fields,
so signer and verifier must produce byte-identical output.

Adapted from the agentrust-io/agent-manifest SDK's canonicalizer (Apache-2.0),
kept deliberately in sync with the rest of the family so a manifest signed by
one tool verifies under another.

Rules:
  - Null-valued optional fields are EXCLUDED from canonical form by default.
  - Object keys must be strings and are sorted by UTF-16 code units
    (RFC 8785 section 3.2.3).
  - Strings (values and keys) must already be NFC; anything else is refused
    rather than normalized, so distinct inputs never share a pre-image.
  - Lone UTF-16 surrogates are rejected in keys and values.
  - Python integers must be in the SDK's safe integer domain, +/- (2**53 - 1).
    This exact-integer interoperability policy follows RFC 7493 section 2.2;
    it is not a magnitude limit on floating-point values in RFC 8785.
    Finite floats retain their existing serialization behavior. A float may
    already have lost integer precision before reaching this function.

For larger exact integers, agree a string representation with consumers and
the applicable schema before creating new signed/logged statements. Do not
cast to float to bypass the integer policy. Changing a number to a string
changes the signed preimage; existing signatures and log history cannot be
silently migrated. This policy does not establish full float JCS conformance.
"""
from __future__ import annotations

import hashlib
import math
import unicodedata
from typing import Any


_MAX_DEPTH = 64  # prevent RecursionError from deeply nested JSON
_MAX_SAFE_INTEGER = 9007199254740991  # RFC 7493 §2.2; RFC 8785 Appendix B note 1
_SURROGATE_MESSAGE = "lone UTF-16 surrogate is not valid I-JSON / RFC 8785"


def canonicalize(obj: Any, *, exclude_none: bool = True) -> bytes:
    """Return RFC 8785 canonical JSON bytes for *obj*.

    Args:
        obj: Any JSON-serializable Python value.
        exclude_none: When True (default), mapping entries whose value is
            None are omitted. Set False only to round-trip against external
            producers that emit explicit null fields.

    Returns:
        UTF-8 encoded bytes with no trailing newline.

    Raises:
        TypeError: If *obj* contains a non-serializable type or non-string key.
        ValueError: If an integer exceeds the SDK safe integer domain, a float
            is NaN or Infinity, a string is non-NFC or contains a lone UTF-16
            surrogate, or nesting exceeds the maximum.
    """
    return _serialize(obj, exclude_none=exclude_none, depth=0).encode("utf-8")


def canonical_hash(
    obj: Any, *, algorithm: str = "sha256", exclude_none: bool = True
) -> str:
    """Canonicalize *obj* and return a prefixed hex digest.

    Returns:
        String in HashValue format: ``"sha256:<64-hex>"`` or
        ``"shake256:<64-hex>"``.
    """
    data = canonicalize(obj, exclude_none=exclude_none)
    if algorithm == "sha256":
        digest = hashlib.sha256(data).hexdigest()
    elif algorithm == "shake256":
        digest = hashlib.shake_256(data).hexdigest(32)  # 256-bit = 32 bytes
    else:
        raise ValueError(
            f"Unsupported algorithm {algorithm!r}. Use 'sha256' or 'shake256'."
        )
    return f"{algorithm}:{digest}"


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _serialize(obj: Any, *, exclude_none: bool, depth: int) -> str:
    if depth > _MAX_DEPTH:
        raise ValueError(
            f"JSON nesting depth exceeds maximum of {_MAX_DEPTH}."
        )
    if obj is None:
        return "null"
    if isinstance(obj, bool):
        # bool must precede int: bool is an int subclass in Python.
        return "true" if obj else "false"
    if isinstance(obj, int):
        if not -_MAX_SAFE_INTEGER <= obj <= _MAX_SAFE_INTEGER:
            raise ValueError(
                f"integer is outside the SDK safe integer domain (+/-{_MAX_SAFE_INTEGER}); "
                "use a schema-agreed string representation for exact large values, "
                "not a float cast"
            )
        return str(obj)
    if isinstance(obj, float):
        return _float_to_str(obj)
    if isinstance(obj, str):
        return _quote(obj)
    if isinstance(obj, (list, tuple)):
        return (
            "["
            + ",".join(
                _serialize(v, exclude_none=exclude_none, depth=depth + 1) for v in obj
            )
            + "]"
        )
    if isinstance(obj, dict):
        return _serialize_dict(obj, exclude_none=exclude_none, depth=depth + 1)
    raise TypeError(
        f"Object of type {type(obj).__name__!r} is not JSON-serializable under RFC 8785"
    )


def _utf16_sort_key(s: str) -> bytes:
    # RFC 8785 section 3.2.3 sorts keys by UTF-16 code units, NOT Unicode code
    # points. They agree on the BMP but differ for supplementary-plane chars
    # (e.g. emoji), whose lead surrogate 0xD800-0xDBFF sorts below 0xE000-0xFFFF.
    # Sorting by the big-endian UTF-16 encoding reproduces code-unit order.
    return s.encode("utf-16-be", "surrogatepass")


def _serialize_dict(d: dict[str, Any], *, exclude_none: bool, depth: int) -> str:
    for k in d:
        if not isinstance(k, str):
            raise TypeError(
                f"JSON object key of type {type(k).__name__!r} is not a string under RFC 8785"
            )
    parts: list[str] = []
    for k in sorted(d.keys(), key=_utf16_sort_key):
        v = d[k]
        if exclude_none and v is None:
            # An omitted key never reaches _quote, so refuse a surrogate here.
            if any(0xD800 <= ord(ch) <= 0xDFFF for ch in k):
                raise ValueError(_SURROGATE_MESSAGE)
            continue
        parts.append(
            _quote(k) + ":" + _serialize(v, exclude_none=exclude_none, depth=depth)
        )
    return "{" + ",".join(parts) + "}"


def _quote(s: str) -> str:
    """Serialize a Python string as a JSON string per RFC 8785 section 3.2.2.2.

    Refuses any string that is not already in NFC. Normalizing instead would
    map two distinct inputs to one pre-image, so a signature over one would
    verify for the other (GHSA-99p4). For NFC input the output is exactly
    RFC 8785, which does not normalize.
    """
    if not unicodedata.is_normalized("NFC", s):
        raise ValueError(
            "string is not NFC-normalized; normalize it before signing "
            f"(first 40 chars: {s[:40]!r})"
        )
    buf: list[str] = ['"']
    for ch in s:
        cp = ord(ch)
        if ch == '"':
            buf.append('\\"')
        elif ch == "\\":
            buf.append("\\\\")
        elif ch == "\b":
            buf.append("\\b")
        elif ch == "\f":
            buf.append("\\f")
        elif ch == "\n":
            buf.append("\\n")
        elif ch == "\r":
            buf.append("\\r")
        elif ch == "\t":
            buf.append("\\t")
        elif cp <= 0x001F or 0x007F <= cp <= 0x009F or cp in (0x2028, 0x2029):
            # Control characters and ECMAScript line terminators.
            buf.append(f"\\u{cp:04x}")
        elif 0xD800 <= cp <= 0xDFFF:
            raise ValueError(_SURROGATE_MESSAGE)
        else:
            buf.append(ch)
    buf.append('"')
    return "".join(buf)


def _float_to_str(f: float) -> str:
    """Serialize a float per RFC 8785 section 3.2.2.3 (ECMAScript numbers).

    Raises:
        ValueError: If *f* is NaN or Infinity (not permitted by RFC 8785).
    """
    if math.isnan(f) or math.isinf(f):
        raise ValueError(f"RFC 8785 does not permit NaN or Infinity ({f!r})")
    if f == math.floor(f) and abs(f) < 1e15:
        return str(int(f))
    s = repr(f)
    if "e" in s and "e+" not in s and "e-" not in s:
        s = s.replace("e", "e+")
    return s
