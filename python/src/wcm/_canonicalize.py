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
  - Object keys are sorted by UTF-16 code units (RFC 8785 section 3.2.3).
  - Strings (values and keys) must already be NFC; anything else is refused
    rather than normalized, so distinct inputs never share a pre-image.
"""
from __future__ import annotations

import hashlib
import math
import unicodedata
from typing import Any


_MAX_DEPTH = 64  # prevent RecursionError from deeply nested JSON


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
        TypeError: If *obj* contains a non-serializable type.
        ValueError: If a float is NaN or Infinity, or nesting exceeds the max.
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
    return s.encode("utf-16-be")


def _serialize_dict(d: dict[str, Any], *, exclude_none: bool, depth: int) -> str:
    parts: list[str] = []
    for k in sorted(d.keys(), key=_utf16_sort_key):
        v = d[k]
        if exclude_none and v is None:
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
        elif cp <= 0x001F:
            # JSON escapes the remaining U+0000..U+001F controls only.
            buf.append(f"\\u{cp:04x}")
        else:
            buf.append(ch)
    buf.append('"')
    return "".join(buf)


def _digits_and_exponent(abs_repr: str) -> tuple[str, int]:
    """Decompose a non-negative ``repr(float)`` string into (digits, n).

    ``digits`` is the shortest round-trip significant-digit string (no
    leading or trailing zeros) and ``n`` is the decimal exponent such that
    the value equals ``0.<digits> * 10**n`` the (s, n) pair used by the
    ECMA-262 Number::toString algorithm that RFC 8785 §3.2.2.3 mandates.
    """
    if "e" in abs_repr:
        mantissa, exp_str = abs_repr.split("e")
        exp = int(exp_str)
    else:
        mantissa, exp = abs_repr, 0
    int_part, _, frac_part = mantissa.partition(".")

    if int_part.strip("0"):
        # Leading zeros (if any) can only appear alongside a zero int_part;
        # a nonzero int_part is never zero-padded by repr().
        digits = (int_part + frac_part).rstrip("0") or "0"
        n = len(int_part) + exp
    else:
        # int_part is "0" (or empty): the value is < 1 (before exp scaling),
        # so significant digits start partway through frac_part.
        stripped = frac_part.lstrip("0")
        if not stripped:
            return "0", 1  # the value is exactly zero
        leading_zeros = len(frac_part) - len(stripped)
        digits = stripped.rstrip("0") or "0"
        n = exp - leading_zeros
    return digits, n


def _float_to_str(f: float) -> str:
    """Serialize a float per RFC 8785 §3.2.2.3 (ECMAScript number formatting).

    Implements the ECMA-262 Number::toString placement rule directly off the
    (digits, n) decomposition, rather than reusing Python's own `repr()`
    notation choice: Python and ECMAScript pick fixed vs. exponential form at
    different magnitude thresholds (e.g. Python already switches to
    exponential at 1e16, ECMAScript only at 1e21) and Python's `repr()`
    zero-pads single-digit exponents (``1e-07``) where ECMAScript never does
    (``1e-7``). Producing a divergent byte string here would make signatures
    computed by this implementation unverifiable against any spec-conformant
    RFC 8785 canonicalizer over a manifest containing that float.

    Raises:
        ValueError: If *f* is NaN or Infinity (not permitted by RFC 8785).
    """
    if math.isnan(f) or math.isinf(f):
        raise ValueError(f"RFC 8785 does not permit NaN or Infinity ({f!r})")
    if f == 0.0:
        return "0"

    sign = "-" if math.copysign(1.0, f) < 0 else ""
    digits, n = _digits_and_exponent(repr(abs(f)))
    k = len(digits)

    if k <= n <= 21:
        body = digits + "0" * (n - k)
    elif 0 < n <= 21:
        body = digits[:n] + "." + digits[n:]
    elif -6 < n <= 0:
        body = "0." + "0" * (-n) + digits
    else:
        mantissa = digits[0] + ("." + digits[1:] if k > 1 else "")
        e = n - 1
        body = f"{mantissa}e{'+' if e >= 0 else '-'}{abs(e)}"
    return sign + body
