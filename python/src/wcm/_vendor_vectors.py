"""Conformance vectors carrying evidence from real vendor silicon.

The quote vectors in ``vectors/gate/`` use a synthetic PKI. They prove an
implementation verifies a chain, a report signature and a ``REPORT_DATA``
binding, and they prove nothing about whether it can parse a real AMD, Intel or
NVIDIA quote, because every certificate in them is one this project minted.

A ``vendor`` vector closes that. Four rules, each because a synthetic chain
satisfies it already.

**The anchor is named, not carried.** A chain carrying its own anchor proves
internal consistency, which the synthetic PKI already proves, and the point of a
vendor capture is to be about the vendor. The vector names a root by the digest
of its DER and carries leaf and intermediates inline; the runner resolves the
root from a store it was given and fails with ``root not staged`` rather than
fetching. Where a vendor does not publish a root in a form a runner can stage,
the vector says so in ``chain.root_limit`` rather than letting the chain anchor
itself quietly.

One rule, for every vendor, with no exception. A TDX quote carries a copy of its
PCK chain inside the signed bytes and would verify without the vector's chain
fields ever being read, so the runner checks the carried chain against the named
root before handing the evidence to the format's own verifier. Otherwise the
fields would be decorative on that one vendor and the strip case would report a
refusal nobody performed.

**The binding is declared.** Real captures do not uniformly echo a caller nonce:
Azure's SEV-SNP path binds ``REPORT_DATA`` to the vTPM attestation key, so there
is no caller freshness in it at all. Each capture states which of four bindings
it asserts, and an unrecognised kind is a hard failure rather than a skip,
because a runner that skips what it does not understand reports a pass it never
performed.

**The clock is injected for scoring.** The scored tier evaluates at the vector's
``now``, so a score does not change as certificates age. A live tier evaluates
at wall time and is reported without being scored. ``not_after`` of the
shortest-lived certificate is required in every vector, which is what makes "no
refresh process for a 2032 problem" a decision rather than an oversight, and it
is **derived from the chain and compared** rather than taken on the vector's
word: required is not the same as checked, and ``expired-at-now`` is the case
that depends on the value being right.

**Refusals are a matrix, applied to every capture**, so a new capture cannot
arrive with only a happy path. The untrusted root is one certificate shipped
with the suite rather than invented per vector: an anchor that legitimately
verifies and a VCEK rejected on serial policy before chain logic runs both look
like passes, and every runner should fail that case for the same reason. Reasons
are matched on a substring, never an exact message.

**The pinning rule.** A vector must not pin a digest of the report, nor the full
report bytes. It may pin the verification outcome, the chain identity, and the
binding check. The reason travels with the rule, because the rule without it
gets relaxed by whoever finds it inconvenient: three ranges of an H200 report
move between calls, and the 32 bytes at ``[3565, 3597)`` change even under an
identical nonce, so a pin built by diffing two reports taken under *different*
nonces looks stable and is not. That is a method note rather than a numbers
note, and it is the part that stops the next person repeating it.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Optional

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

from ._certificates import load_pem_certificate
from ._quote_verify import (
    QuoteVerification,
    QuoteVerifier,
    TrustStore,
    verify_cert_chain,
)

# Private to _quote_verify, used for the one path that verifier does not offer:
# chain and report signature with no REPORT_DATA check at all. See
# _verify_unbound for why an empty nonce is not the same thing.
from ._quote_verify import _verify_report_signature
from .nvidia import NvidiaGpuVerifier
from .snp import SnpQuoteParser
from .tdx import verify_tdx_quote

__all__ = [
    "BINDING_KINDS",
    "EVIDENCE_FORMATS",
    "REFUSAL_CASES",
    "ROOTS_ENV",
    "RootStore",
    "VendorOutcome",
    "VendorVectorError",
    "evaluate_vendor",
    "live_check",
    "load_root_store",
    "roots_dir",
]


class VendorVectorError(Exception):
    """The vector itself is unusable, as distinct from the capture failing.

    Kept separate from a verification failure on purpose. "This vector declares
    a binding kind nobody implements" and "this report does not verify" are
    different findings, and collapsing them lets a malformed vector read as a
    detected attack.
    """


#: What a capture asserts about ``REPORT_DATA``, declared rather than assumed.
BINDING_KINDS = frozenset(
    {
        # REPORT_DATA equals sha256(nonce).
        "nonce-digest",
        # REPORT_DATA equals sha256(nonce || transport key), which is what stops
        # a relay swapping in its own transport key.
        "nonce-and-transport",
        # Bound to a platform key, as on the Azure SEV-SNP vTPM path. No caller
        # freshness at all.
        "attestation-key",
        # The capture proves signature and chain and nothing about freshness.
        # It earns a place because some real captures are exactly that, and a
        # format that cannot say so will have a nonce invented for it.
        "none",
    }
)

#: The kinds that assert the caller chose the freshness.
_NONCE_KINDS = frozenset({"nonce-digest", "nonce-and-transport"})

EVIDENCE_FORMATS = frozenset(
    {"sev-snp-report", "tdx-quote", "nvidia-attestation-report"}
)

#: Applied to every accepting capture, by the runner rather than the contributor.
REFUSAL_CASES = (
    "wrong-binding",
    "tampered-report",
    "tampered-signature",
    "stripped-chain",
    "out-of-chain-root",
    "expired-at-now",
)

#: Where a runner points the suite at roots it has staged.
ROOTS_ENV = "WCM_CONFORMANCE_ROOTS"

#: Subject of the one untrusted anchor the suite ships.
_OUT_OF_CHAIN_SUBJECT = "wcm-conformance-out-of-chain-root"


def roots_dir() -> Path:
    """Locate the root store shipped with the suite.

    Mirrors ``vectors_dir``: the packaged copy first, then a search upward for
    the repository's ``conformance/roots``.
    """
    packaged = Path(__file__).parent / "_conformance" / "roots"
    if packaged.is_dir():
        return packaged
    here = Path(__file__).resolve()
    for parent in here.parents:
        candidate = parent / "conformance" / "roots"
        if candidate.is_dir():
            return candidate
    raise FileNotFoundError(
        "conformance roots not found in the installed package or any enclosing "
        f"checkout (looked next to {Path(__file__).parent} and in every parent's "
        "conformance/roots)"
    )


def _split_pem(blob: bytes) -> list[bytes]:
    out: list[bytes] = []
    buf = b""
    for line in blob.splitlines(True):
        buf += line
        if b"END CERTIFICATE" in line:
            out.append(buf)
            buf = b""
    return out


def _der_sha256(cert: x509.Certificate) -> str:
    return "sha256:" + hashlib.sha256(cert.public_bytes(Encoding.DER)).hexdigest()


@dataclass(frozen=True)
class RootStore:
    """Roots a runner has staged, indexed by the digest of their DER.

    Indexed by digest rather than by subject because a subject is a claim in the
    certificate and a digest is the certificate. Two roots can share a common
    name; they cannot share a digest.
    """

    by_digest: dict[str, x509.Certificate]

    def resolve(self, der_sha256: str) -> x509.Certificate:
        cert = self.by_digest.get(der_sha256)
        if cert is None:
            raise VendorVectorError(
                f"root not staged: {der_sha256}. Stage it and point "
                f"{ROOTS_ENV} at the directory holding it. The suite does not "
                "fetch roots."
            )
        return cert

    def out_of_chain(self) -> x509.Certificate:
        """The one untrusted anchor every runner is given.

        Shipped rather than invented per vector, because both obvious ways to
        invent it quietly test nothing: an anchor from the capture's own chain
        verifies correctly, and a VCEK is rejected on serial policy before any
        chain logic runs.
        """
        for cert in self.by_digest.values():
            if _OUT_OF_CHAIN_SUBJECT in cert.subject.rfc4514_string():
                return cert
        raise VendorVectorError(
            "the suite's out-of-chain root is not in the root store, so the "
            "untrusted-root case cannot be run"
        )


def load_root_store(extra_dirs: Optional[list[Path]] = None) -> RootStore:
    """Load the suite's roots plus anything the runner has staged.

    Staged directories come from ``WCM_CONFORMANCE_ROOTS`` unless supplied
    directly. A directory that does not exist is skipped rather than raising:
    the failure a runner should see names the root a vector asked for, not a
    missing directory.
    """
    dirs: list[Path] = []
    try:
        dirs.append(roots_dir())
    except FileNotFoundError:
        pass
    if extra_dirs is not None:
        dirs.extend(extra_dirs)
    else:
        raw = os.environ.get(ROOTS_ENV, "")
        dirs.extend(Path(p) for p in raw.split(os.pathsep) if p)

    by_digest: dict[str, x509.Certificate] = {}
    for directory in dirs:
        if not directory.is_dir():
            continue
        for path in sorted(directory.glob("*.pem")):
            for pem in _split_pem(path.read_bytes()):
                try:
                    cert = x509.load_pem_x509_certificate(pem)
                except ValueError:
                    continue
                by_digest.setdefault(_der_sha256(cert), cert)
    return RootStore(by_digest)


def _chain_certificates(vector: dict[str, Any], root: x509.Certificate) -> list[x509.Certificate]:
    """Every certificate the capture's path depends on, anchor included."""
    chain = vector["chain"]
    certs = [
        load_pem_certificate(chain["leaf_pem"].encode(), allow_non_positive_serial=True)
    ]
    certs.extend(
        load_pem_certificate(pem.encode()) for pem in chain.get("intermediates_pem", [])
    )
    certs.append(root)
    return certs


def _check_not_after(vector: dict[str, Any], root: x509.Certificate) -> None:
    """The recorded horizon must be the one the chain actually asserts.

    Required is not the same as checked. A value that is merely close disables
    the expiry case silently: the mutation steps the clock past a date no
    certificate expires on, everything still verifies, and the case reports a
    refusal it never performed.

    The earliest expiry in the chain is the binding one, because a path is valid
    only while every certificate on it is. Reading the leaf alone would miss an
    intermediate that expires first, which is what a vendor rotation produces.
    """
    certs = _chain_certificates(vector, root)
    earliest = min(cert.not_valid_after_utc for cert in certs)
    recorded = _parse_clock(vector["validity"]["not_after"], "validity.not_after")
    if recorded != earliest:
        raise VendorVectorError(
            "validity.not_after is "
            + recorded.isoformat()
            + " but the earliest expiry in this chain is "
            + earliest.isoformat()
            + "; a recorded horizon that is only close turns expired-at-now off"
        )


def _parse_clock(value: str, field: str) -> datetime:
    try:
        moment = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise VendorVectorError(
            f"{field} is not a readable timestamp: {value!r}"
        ) from exc
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment


def _just_after(not_after: str) -> datetime:
    """The first instant a certificate is no longer valid.

    A microsecond rather than a second, so the matrix applies to every capture
    including one whose chain runs to the end of representable time. Every
    NVIDIA certificate in this repository is valid until 9999-12-31T23:59:59,
    where a one-second step overflows and a one-microsecond step does not.
    Validity is an inclusive comparison against not_after, so the smallest
    representable step past it is outside the window.
    """
    moment = _parse_clock(not_after, "validity.not_after")
    try:
        return moment + timedelta(microseconds=1)
    except OverflowError as exc:  # pragma: no cover - only at datetime.max exactly
        raise VendorVectorError(
            "validity.not_after is "
            + not_after
            + ", which is the last representable instant, so there is no clock "
            "at which this chain is expired"
        ) from exc


def _channel_binding(binding: dict[str, Any]) -> bytes:
    raw = binding.get("transport_public_key_b64url")
    if raw is None:
        return b""
    padding = "=" * (-len(raw) % 4)
    return base64.urlsafe_b64decode(raw + padding)


def _expected_nonce(binding: dict[str, Any]) -> Optional[str]:
    """The nonce a verifier should demand, or None where none is asserted.

    ``attestation-key`` and ``none`` return None. That is not a weaker check
    written loosely: on those captures ``REPORT_DATA`` is bound to something the
    caller did not choose, so demanding a nonce would fail every time and prove
    nothing about the implementation.
    """
    value = binding.get("nonce_hex")
    return str(value) if value is not None else None


def _verify_unbound(
    parser: Any, quote_b64: str, trust: TrustStore, now: datetime
) -> QuoteVerification:
    """Chain and report signature, and deliberately no REPORT_DATA check.

    For the ``attestation-key`` and ``none`` kinds. Passing an empty nonce would
    not express this: that computes sha256(b"") and compares, so a capture whose
    REPORT_DATA is bound to a platform key fails a check it was never making a
    claim about. The reason says what was and was not established, so a pass
    here cannot be read as freshness.
    """
    try:
        parsed = parser.parse(quote_b64)
    except Exception as exc:  # noqa: BLE001 - any parse failure is a refusal
        return QuoteVerification(False, str(exc))
    chain_error = verify_cert_chain(parsed.leaf, parsed.intermediates, trust, now)
    if chain_error is not None:
        return QuoteVerification(False, chain_error)
    try:
        _verify_report_signature(parsed)
    except Exception:  # noqa: BLE001 - a bad signature is a refusal, not a crash
        return QuoteVerification(
            False, "report signature does not verify under the leaf key"
        )
    return QuoteVerification(
        True, "chain and report signature verified; no caller freshness asserted"
    )


def _build_verifier(
    vector: dict[str, Any], root: x509.Certificate
) -> Callable[[Optional[str], bytes, datetime], QuoteVerification]:
    """Return a callable that verifies this vector's evidence.

    One shape for three vendor formats, so the refusal matrix can be applied
    uniformly rather than per vendor.
    """
    evidence = vector["evidence"]
    fmt = evidence["format"]
    if fmt not in EVIDENCE_FORMATS:
        raise VendorVectorError(
            f"unrecognised evidence format {fmt!r}; known: "
            + ", ".join(sorted(EVIDENCE_FORMATS))
        )

    chain = vector["chain"]
    trust = TrustStore()
    trust.add_root(root)

    # A VCEK carries a non-positive serial, which certificate policy rejects
    # before any chain logic runs. That is the documented escape hatch for a
    # provider leaf whose path and signature are still verified, and it is used
    # for the leaf only: an anchor accepted under it would be a record-carried
    # root, which the policy exists to refuse.
    leaf = load_pem_certificate(
        chain["leaf_pem"].encode(), allow_non_positive_serial=True
    )
    intermediates = [
        load_pem_certificate(pem.encode()) for pem in chain.get("intermediates_pem", [])
    ]
    chain_pem = chain["leaf_pem"] + "".join(chain.get("intermediates_pem", []))

    def carried_chain_error(now: datetime) -> Optional[str]:
        """The carried chain must reach the named root, for every vendor.

        Some formats carry a copy of their chain inside the evidence and would
        verify without ever reading these fields. Checking them here is what
        keeps the chain the vector carries load-bearing rather than decorative,
        so stripping the intermediates fails on a TDX capture for the same
        reason it fails on an SEV-SNP one.
        """
        return verify_cert_chain(leaf, intermediates, trust, now)

    if fmt == "tdx-quote":
        quote_bytes = base64.b64decode(evidence["report_b64"])

        def verify_tdx(
            nonce: Optional[str], binding_bytes: bytes, now: datetime
        ) -> QuoteVerification:
            carried = carried_chain_error(now)
            if carried is not None:
                return QuoteVerification(False, carried)
            return verify_tdx_quote(
                quote_bytes,
                trust,
                expected_nonce=nonce,
                channel_binding=binding_bytes,
                now=now,
            )

        return verify_tdx

    if fmt == "nvidia-attestation-report":
        # The vector keeps the report and its chain apart, because the chain
        # rule is the same for every vendor. The SDK's GPU verifier wants them
        # bundled the way the device presents them, so the runner assembles the
        # container rather than the format bending to one vendor's packaging.
        gpu = NvidiaGpuVerifier(trust)
        container = base64.b64encode(
            json.dumps(
                {"report_b64": evidence["report_b64"], "cert_chain_pem": chain_pem}
            ).encode()
        ).decode()

        def verify_gpu(
            nonce: Optional[str], binding_bytes: bytes, now: datetime
        ) -> QuoteVerification:
            del binding_bytes  # GPU reports carry no transport binding
            if nonce is None:
                return QuoteVerification(
                    False,
                    "a GPU report binds a caller nonce; a capture asserting no "
                    "freshness cannot be verified through this path",
                )
            return gpu.verify(container, expected_nonce=nonce, now=now)

        return verify_gpu

    parser: Any = SnpQuoteParser(leaf, intermediates)
    verifier = QuoteVerifier(parser, trust)

    def verify_cpu(
        nonce: Optional[str], binding_bytes: bytes, now: datetime
    ) -> QuoteVerification:
        if nonce is None:
            return _verify_unbound(parser, evidence["report_b64"], trust, now)
        return verifier.verify(
            evidence["report_b64"],
            expected_nonce=nonce,
            channel_binding=binding_bytes,
            now=now,
        )

    return verify_cpu


#: Exactly what a vendor vector may contain, at every level. Closed rather than
#: open, because that is the pinning rule: a vector must not carry a digest of
#: the report or the full report bytes, and the way to guarantee that is to
#: leave nowhere to put one. An open object states the rule and enforces
#: nothing.
_ALLOWED: dict[str, frozenset[str]] = {
    "": frozenset(
        {
            "id", "level", "kind", "description", "expect",
            "capture", "evidence", "chain", "binding", "validity", "refusals",
        }
    ),
    "capture": frozenset({"vendor", "technology", "part", "tcb", "captured_at", "source"}),
    "evidence": frozenset({"format", "report_b64"}),
    "chain": frozenset({"leaf_pem", "intermediates_pem", "root", "root_source", "root_limit"}),
    "chain.root": frozenset({"id", "der_sha256"}),
    "binding": frozenset({"kind", "nonce_hex", "transport_public_key_b64url", "note"}),
    "validity": frozenset({"now", "not_after"}),
}

#: Fields a capture must record. Without them a vector that starts failing is
#: unattributable, and nobody can tell whether the implementation regressed or
#: the platform moved.
_REQUIRED_CAPTURE = ("vendor", "technology", "part", "captured_at", "source")


def _reject_unknown(vector: dict[str, Any]) -> None:
    for path, allowed in _ALLOWED.items():
        node: Any = vector
        for part in (p for p in path.split(".") if p):
            node = node.get(part) if isinstance(node, dict) else None
        if not isinstance(node, dict):
            continue
        unknown = sorted(set(node) - allowed)
        if unknown:
            where = path or "(root)"
            raise VendorVectorError(
                "unknown field at " + where + ": " + ", ".join(unknown)
                + ". A vendor vector may not pin a digest of the report nor the "
                "full report bytes; it may pin the verification outcome, the "
                "chain identity, and the binding check."
            )


def _validate_shape(vector: dict[str, Any]) -> None:
    """The checks that are about the vector rather than about the capture.

    This is the reference validator. ``schema/wcm-vendor-vector-v1.schema.json``
    is the same rules in machine-readable form, published for implementations in
    other languages, and a test asserts the two agree. Validation lives here
    rather than behind jsonschema because that is a development dependency: a
    runner that needed it would fail on an ordinary install.
    """
    _reject_unknown(vector)

    if vector.get("expect") != "accept":
        raise VendorVectorError(
            "a vendor vector is a capture, so expect must be 'accept'. Its "
            "negatives are the refusal matrix the runner derives, not a "
            "hand-written reject vector."
        )

    missing_top = [k for k in ("capture", "evidence", "chain", "binding", "validity")
                   if k not in vector]
    if missing_top:
        raise VendorVectorError("vector is missing: " + ", ".join(missing_top))

    missing_capture = [k for k in _REQUIRED_CAPTURE if not vector["capture"].get(k)]
    if missing_capture:
        raise VendorVectorError(
            "capture provenance is required; missing: " + ", ".join(missing_capture)
        )

    binding = vector["binding"]
    kind = binding.get("kind")
    if kind not in BINDING_KINDS:
        raise VendorVectorError(
            f"unrecognised binding kind {kind!r}; known: "
            + ", ".join(sorted(BINDING_KINDS))
        )
    if kind in _NONCE_KINDS and not binding.get("nonce_hex"):
        raise VendorVectorError(f"binding kind {kind!r} requires nonce_hex")
    if kind == "nonce-and-transport" and not binding.get("transport_public_key_b64url"):
        raise VendorVectorError(
            "binding kind 'nonce-and-transport' requires transport_public_key_b64url"
        )

    chain = vector["chain"]
    for field in ("leaf_pem", "intermediates_pem", "root", "root_source"):
        if field not in chain:
            raise VendorVectorError("chain." + field + " is required")
    if set(chain["root"]) != {"id", "der_sha256"}:
        raise VendorVectorError("chain.root must carry exactly id and der_sha256")

    for field in ("now", "not_after"):
        if field not in vector["validity"]:
            raise VendorVectorError("validity." + field + " is required, not optional")

    declared = vector.get("refusals", {})
    missing = sorted(set(REFUSAL_CASES) - set(declared))
    if missing:
        raise VendorVectorError(
            "the refusal matrix applies to every capture; missing: " + ", ".join(missing)
        )
    for case, entry in declared.items():
        # An empty substring is contained in every string, so a case declaring
        # one would count any refusal, including one for a reason that has
        # nothing to do with its mutation.
        if not str(entry.get("reason_contains", "")).strip():
            raise VendorVectorError(
                "refusals." + case + ".reason_contains must be non-empty"
            )


@dataclass(frozen=True)
class VendorOutcome:
    """What the runner concluded, and what it could not conclude.

    ``refusals`` records each derived mutation and whether the implementation
    refused it for the declared reason. A capture that verifies and whose
    mutations all still verify has demonstrated a parser, not a verifier.
    """

    verified: bool
    reason: str
    refusals: dict[str, tuple[bool, str]]


def _signed_body_offset(raw: bytearray, vector: dict[str, Any]) -> int:
    """A byte inside the material a report signature covers.

    Asked of the format rather than guessed. A TDX quote is mostly certification
    data that no signature covers, so a flip in "the middle" leaves every check
    passing and the case reports a refusal it never performed.
    """
    fmt = vector["evidence"]["format"]
    if fmt == "tdx-quote":
        # Header (48) then the TD report body (584).
        return 48 + 584 // 2
    if fmt == "sev-snp-report":
        from .snp import _SIG_OFFSET  # noqa: PLC0415 - local, to keep the import graph flat

        return int(_SIG_OFFSET) // 2
    return max(1, len(raw) // 2)


def _signature_offset(raw: bytearray, vector: dict[str, Any]) -> int:
    """Where the signature starts in the captured bytes.

    Asked of the format for the same reason: an SEV-SNP report carries reserved
    bytes after its signature field, so flipping the last byte leaves the signed
    material and the signature both intact.
    """
    fmt = vector["evidence"]["format"]
    if fmt == "sev-snp-report":
        from .snp import _SIG_OFFSET  # noqa: PLC0415 - local, to keep the import graph flat

        return int(_SIG_OFFSET)
    if fmt == "tdx-quote":
        # Header (48), TD report (584), the four-byte signature-data length,
        # then the attestation-key signature itself.
        return 48 + 584 + 4
    return max(0, len(raw) - 96)


def _mutate(vector: dict[str, Any], case: str) -> dict[str, Any]:
    """One vector, one lie. Deep-copied so a mutation cannot leak sideways."""
    out = copy.deepcopy(vector)
    evidence = out["evidence"]
    chain = out["chain"]

    if case == "wrong-binding":
        if out["binding"].get("kind") in _NONCE_KINDS:
            nonce = str(out["binding"]["nonce_hex"])
            out["binding"]["nonce_hex"] = f"{int(nonce[:2], 16) ^ 0xFF:02x}" + nonce[2:]
        else:
            # There is no caller nonce to spoil, so assert the binding the
            # capture explicitly does not make. A runner that accepts this has
            # invented freshness the capture never proved.
            out["binding"] = {"kind": "nonce-digest", "nonce_hex": "00" * 32}
    elif case == "tampered-report":
        raw = bytearray(base64.b64decode(evidence["report_b64"]))
        raw[_signed_body_offset(raw, vector)] ^= 0xFF
        evidence["report_b64"] = base64.b64encode(bytes(raw)).decode()
    elif case == "tampered-signature":
        raw = bytearray(base64.b64decode(evidence["report_b64"]))
        raw[_signature_offset(raw, vector)] ^= 0xFF
        evidence["report_b64"] = base64.b64encode(bytes(raw)).decode()
    elif case == "stripped-chain":
        chain["intermediates_pem"] = []
    elif case == "out-of-chain-root":
        pass  # the caller swaps the anchor instead
    elif case == "expired-at-now":
        out["validity"]["now"] = _just_after(out["validity"]["not_after"]).isoformat()
    else:  # pragma: no cover - REFUSAL_CASES is the only caller
        raise VendorVectorError(f"unknown refusal case {case!r}")
    return out


def _run_matrix(
    vector: dict[str, Any],
    store: RootStore,
    root: x509.Certificate,
    now: datetime,
) -> dict[str, tuple[bool, str]]:
    """Apply every refusal case, and report which refused for the right reason."""
    declared = vector["refusals"]
    out: dict[str, tuple[bool, str]] = {}
    for case in REFUSAL_CASES:
        expected_substring = declared[case]["reason_contains"]
        mutated = _mutate(vector, case)
        anchor = store.out_of_chain() if case == "out-of-chain-root" else root
        when = (
            _parse_clock(mutated["validity"]["now"], "validity.now")
            if case == "expired-at-now"
            else now
        )
        try:
            verify = _build_verifier(mutated, anchor)
            result = verify(
                _expected_nonce(mutated["binding"]),
                _channel_binding(mutated["binding"]),
                when,
            )
            refused, reason = (not result.verified), (result.reason or "")
        except VendorVectorError:
            raise
        except Exception as exc:  # noqa: BLE001 - a parser raising is still a refusal
            refused, reason = True, str(exc)
        # Substring, never an exact message, or the corpus becomes a change
        # detector for wording.
        out[case] = (refused and expected_substring in reason, reason)
    return out


def evaluate_vendor(
    vector: dict[str, Any], *, store: Optional[RootStore] = None
) -> VendorOutcome:
    """Evaluate one vendor vector at its injected clock, with the matrix."""
    _validate_shape(vector)
    store = store if store is not None else load_root_store()
    root = store.resolve(vector["chain"]["root"]["der_sha256"])
    _check_not_after(vector, root)
    now = _parse_clock(vector["validity"]["now"], "validity.now")

    verify = _build_verifier(vector, root)
    binding = vector["binding"]
    result = verify(_expected_nonce(binding), _channel_binding(binding), now)

    refusals = _run_matrix(vector, store, root, now)
    return VendorOutcome(result.verified, result.reason or "", refusals)


def live_check(
    vector: dict[str, Any],
    *,
    store: Optional[RootStore] = None,
    now: Optional[datetime] = None,
) -> tuple[bool, str]:
    """Evaluate the same capture at wall time, for the unscored live tier.

    This is where a capture ageing out becomes visible. It is deliberately not
    scored: a conformance result that changes because a certificate expired says
    nothing about the implementation being scored.
    """
    _validate_shape(vector)
    store = store if store is not None else load_root_store()
    root = store.resolve(vector["chain"]["root"]["der_sha256"])
    current = now if now is not None else datetime.now(timezone.utc)
    verify = _build_verifier(vector, root)
    binding = vector["binding"]
    result = verify(_expected_nonce(binding), _channel_binding(binding), current)
    return result.verified, result.reason or ""
