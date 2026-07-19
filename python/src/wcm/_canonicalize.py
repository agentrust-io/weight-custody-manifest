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
  - Object keys are sorted by Unicode code point (RFC 8785 section 3.2.3).
  - Strings are NFC-normalized before escaping.
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


def _serialize_dict(d: dict[str, Any], *, exclude_none: bool, depth: int) -> str:
    # RFC 8785 section 3.2.3: sort keys by Unicode code point. Python's default
    # str ordering is code-point order, so no special collation is needed.
    parts: list[str] = []
    for k in sorted(d.keys()):
        v = d[k]
        if exclude_none and v is None:
            continue
        parts.append(
            _quote(k) + ":" + _serialize(v, exclude_none=exclude_none, depth=depth)
        )
    return "{" + ",".join(parts) + "}"


def _quote(s: str) -> str:
    """Serialize a Python string as a JSON string per RFC 8785 section 3.2.2.2.

    Applies NFC normalization before escaping.
    """
    s = unicodedata.normalize("NFC", s)
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
