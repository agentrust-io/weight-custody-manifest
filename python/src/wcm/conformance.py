"""The WCM conformance suite: levels, error codes, and a vector runner.

An implementation claims a *level*. A level is a set of requirements plus the
vectors that check them, and the vectors are language-neutral JSON, so an
implementation in any language can be scored the same way (see
``conformance/README.md``).

Two modes:

- **Reference self-test.** ``run_reference()`` evaluates every vector with this
  SDK and checks both the verdict and the ``WCM-*`` code. This is what proves the
  reference implementation conforms to its own suite, and it is what catches a
  vector whose expectation drifts from the code.
- **External scoring.** ``score_results()`` takes the results another
  implementation produced from the same vectors and reports per-level pass/fail.

All four levels are vectored. L1 and L4 ask questions about documents; L2 and L3
ask what a system does over time, so their vectors are ordered scenarios with an
injected clock and named nonces (see ``_eval_gate`` / ``_eval_custody``).

Honest scope, since a green run should not be read as more than it is: L2 covers
the **policy gate** (nonce freshness and single use, platform, tier, serving-image
status and prefer-current, composite CPU-to-GPU binding, memory fingerprint,
revocation freshness, channel binding, key availability). It does **not** yet
cover cryptographic quote verification, signature and certificate chain against a
vendor root, which needs raw hardware evidence and trust anchors rather than the
declarative evidence these vectors carry. Those two codes are listed in
``NOT_YET_VECTORED_CODES`` so the gap is visible rather than merely absent.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Optional

from pydantic import ValidationError

from ._verify import VerificationContext, verify_manifest
from .lineage import verify_lineage
from .models import WeightCustodyManifest

# ---------------------------------------------------------------------------
# Levels
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Level:
    """A conformance level: what it requires, and what checks it."""

    id: str
    title: str
    requires: str
    #: Vector kinds that check this level. Empty means the level is specified but
    #: not yet vectored, and an implementation cannot currently be scored on it.
    kinds: tuple[str, ...]

    @property
    def vectored(self) -> bool:
        return bool(self.kinds)


LEVELS: dict[str, Level] = {
    "L1": Level(
        id="L1",
        title="Manifest and joint signature",
        requires=(
            "Accept exactly the manifests SPEC.md 3.1 defines as valid and reject "
            "the rest, including the cross-field rules; and verify the joint "
            "signature, meaning every required role present, every signature "
            "verifying against a key the verifier trusts for that algorithm, and "
            "the sovereign role satisfied only by the declared sovereign_signer."
        ),
        kinds=("manifest", "signature"),
    ),
    "L2": Level(
        id="L2",
        title="Attestation-gated release",
        requires=(
            "Gate key release on composite evidence (SPEC.md 3.2): single-use KBS "
            "nonce, platform and assurance tier, serving-image measurement with "
            "prefer-current and hard-fail on revoked, CPU-to-GPU nonce binding, "
            "memory-fingerprint challenge where the posture requires it, "
            "attestation-revocation freshness, quote signature and certificate "
            "chain, and channel binding so the released key is sealed to the "
            "attested transport key rather than returned on the channel."
        ),
        kinds=("gate",),
    ),
    "L3": Level(
        id="L3",
        title="Runtime custody",
        requires=(
            "Enforce the wipe-on-lapse floor (SPEC.md 3.2, 3.3): zeroize the key "
            "when the attestation lease lapses rather than suspending use, require "
            "re-attestation when the operation budget is exhausted without wiping, "
            "renew on successful re-attestation, and report the trusted-time floor "
            "actually in force instead of implying a stronger one."
        ),
        kinds=("custody",),
    ),
    "L4": Level(
        id="L4",
        title="Derivative lineage",
        requires=(
            "Resolve a lineage chain and enforce SPEC.md 3.4 and 3.8: terminate on "
            "cycles and unresolvable parents, forbid a derivative of a parent that "
            "forbids derivatives, keep rights monotone down the chain, gate on "
            "every upstream manifest being logged, and cascade revocation from any "
            "chain member to the leaf."
        ),
        kinds=("lineage",),
    ),
}

VECTORED_LEVELS = tuple(lid for lid, lvl in LEVELS.items() if lvl.vectored)
DECLARED_ONLY_LEVELS = tuple(lid for lid, lvl in LEVELS.items() if not lvl.vectored)

# ---------------------------------------------------------------------------
# Error codes
# ---------------------------------------------------------------------------

#: The registry. Also published as ``conformance/codes.md``; a test keeps the two
#: in agreement, so an implementation can rely on either.
CODES: dict[str, str] = {
    # L1, structural (SPEC.md 3.1)
    "WCM-L1-0001": "unknown field (no object in the manifest accepts extra properties)",
    "WCM-L1-0002": "a required field is absent",
    "WCM-L1-0003": "hash value is not sha256/shake256 with 64 lowercase hex characters",
    "WCM-L1-0004": "value outside the permitted set for its field",
    "WCM-L1-0005": "list is empty where at least one entry is required",
    "WCM-L1-0006": "retire_after is absent on a retiring measurement, or present on one that is not retiring",
    "WCM-L1-0007": "sovereign profile is inconsistent (enabled without quorum, or without a sovereign_signer)",
    "WCM-L1-0008": "deployment_model contradicts custody.custodian_type",
    "WCM-L1-0009": "derived_from equals the manifest's own weights_hash (self-derivation)",
    # L1, joint signature
    "WCM-L1-0101": "a required signature role has no valid signature",
    "WCM-L1-0102": "signature does not verify over the manifest pre-image",
    "WCM-L1-0103": "signature key_id is not trusted by the verifier",
    "WCM-L1-0104": "signature algorithm does not match the algorithm its key is trusted for",
    "WCM-L1-0105": "sovereign signature is not from the declared sovereign_signer",
    # L2, attestation-gated release
    "WCM-L2-0001": "KBS nonce is unknown, expired, or already used",
    "WCM-L2-0002": "platform is not in required_hw_platform",
    "WCM-L2-0003": "assurance tier is below required_assurance_tier",
    "WCM-L2-0004": "serving-image measurement is not in accepted_measurements",
    "WCM-L2-0005": "a retiring serving image was released while a current one was available",
    "WCM-L2-0006": "serving-image measurement is revoked",
    "WCM-L2-0007": "GPU report is absent while required_gpu_measurement is set",
    "WCM-L2-0008": "CPU and GPU evidence do not echo the same nonce",
    "WCM-L2-0009": "memory-fingerprint challenge is absent or failed in a posture that requires it",
    "WCM-L2-0010": "attestation-revocation check is absent or staler than the policy allows",
    "WCM-L2-0011": "quote signature or certificate chain does not verify to a trusted root",
    "WCM-L2-0012": "REPORT_DATA does not bind the challenge nonce",
    "WCM-L2-0013": "released key is not sealed to the attested transport key (channel binding)",
    "WCM-L2-0014": "a retiring serving image was released past its retire_after",
    "WCM-L2-0015": "GPU measurement does not match required_gpu_measurement.rim_pin",
    "WCM-L2-0016": "the attestation key is listed as revoked",
    "WCM-L2-0017": "no key is held for this weights_hash",
    # L3, runtime custody
    "WCM-L3-0001": "key was usable after the attestation lease lapsed (must be zeroized, not suspended)",
    "WCM-L3-0002": "operation budget was exhausted without requiring re-attestation",
    "WCM-L3-0003": "successful re-attestation did not renew the lease or reset the budget",
    "WCM-L3-0004": "reported trusted-time floor is stronger than the one actually in force",
    # L4, derivative lineage
    "WCM-L4-0001": "a manifest in the chain is not in the manifest set",
    "WCM-L4-0002": "the lineage chain contains a cycle",
    "WCM-L4-0003": "a derivative exists of a parent whose derivatives policy is none",
    "WCM-L4-0004": "a derivative widens rights beyond its parent (non-monotone)",
    "WCM-L4-0005": "a manifest in the chain is not present or in force in the transparency log",
    "WCM-L4-0006": "a manifest in the chain is revoked; revocation cascades to the leaf",
}


#: Codes that name a way an implementation can be WRONG, rather than an outcome it
#: reports. Nothing raises "your re-attestation failed to renew the lease": the
#: suite concludes it when a step that should have succeeded raises instead. They
#: are registered so a report can cite them, and they are exempt from the
#: "every code on a vectored level is exercised by a vector" check, because a
#: vector can never *expect* them.
DIAGNOSTIC_ONLY_CODES = frozenset(
    {
        "WCM-L3-0003",  # concluded when a post-reattest operation is refused
        "WCM-L3-0004",  # concluded when the reported time floor is too strong
    }
)

#: Reportable codes with no vector yet, listed so a gap is visible instead of merely
#: absent. Empty: every reportable code is now exercised. The mechanism stays,
#: because the honest way to add a code ahead of its vector is to declare the gap
#: rather than leave it implicit. A test asserts nothing is added silently.
NOT_YET_VECTORED_CODES: frozenset[str] = frozenset()

#: Requirements the suite does not cover, in prose, for the ones that are not a
#: whole code. Printed on every full run, because a limit nobody reads is not a
#: disclosed limit. Keep each entry to what an implementer would need to know.
COVERAGE_NOTES: tuple[str, ...] = (
    "GPU-side cryptographic verification is not vectored. The L2 quote vectors "
    "verify the CPU quote (chain, signature, REPORT_DATA binding) through the "
    "reference JSON container. The NVIDIA path is a different verifier over a real "
    "device chain, and the H100 fixture in the SDK's own tests is what covers it "
    "today; a vector would need the device chain and the raw-nonce-at-offset-4 "
    "convention expressed in the corpus.",
    "Quote vectors use a synthetic PKI, not vendor roots. They prove an "
    "implementation verifies a chain, a signature and a nonce binding correctly. "
    "They do NOT prove it can parse a real AMD, Intel or NVIDIA quote, which is "
    "vendor-format work the SDK covers with committed real-silicon fixtures.",
)


def level_of_code(code: str) -> str:
    """``'WCM-L4-0002'`` -> ``'L4'``."""
    parts = code.split("-")
    if len(parts) != 3 or parts[0] != "WCM" or parts[1] not in LEVELS:
        raise ValueError(f"not a WCM conformance code: {code!r}")
    return parts[1]


# ---------------------------------------------------------------------------
# Vector loading
# ---------------------------------------------------------------------------


def vectors_dir() -> Path:
    """Locate the vector corpus.

    Packaged copy first, then a search upward for the repo-root ``conformance/``
    directory, which covers a git checkout and an unpacked sdist alike.
    """
    packaged = Path(__file__).parent / "_conformance" / "vectors"
    if packaged.is_dir():
        return packaged
    here = Path(__file__).resolve()
    for parent in here.parents:
        candidate = parent / "conformance" / "vectors"
        if candidate.is_dir():
            return candidate
    raise FileNotFoundError(
        "conformance vectors not found in the installed package or any enclosing "
        f"checkout (looked next to {Path(__file__).parent} and in every parent's "
        "conformance/vectors)"
    )


def load_vectors(
    *, level: Optional[str] = None, kind: Optional[str] = None
) -> list[dict[str, Any]]:
    """Every vector, optionally filtered by level or kind, ordered by id."""
    if level is not None and level not in LEVELS:
        raise ValueError(f"unknown level {level!r}; known: {', '.join(LEVELS)}")
    root = vectors_dir()
    vectors: list[dict[str, Any]] = []
    for kind_dir in sorted(p for p in root.iterdir() if p.is_dir()):
        if kind is not None and kind_dir.name != kind:
            continue
        for path in sorted(kind_dir.glob("*.json")):
            vector = json.loads(path.read_text(encoding="utf-8"))
            if level is not None and vector["level"] != level:
                continue
            vectors.append(vector)
    return vectors


# ---------------------------------------------------------------------------
# Evaluating a vector with the reference implementation
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Verdict:
    """What an implementation concluded about one vector."""

    verdict: str  # "accept" | "reject"
    code: Optional[str] = None  # required when verdict == "reject"
    detail: str = ""


def _first_code(candidates: Iterable[tuple[bool, str]]) -> Optional[str]:
    """First code whose condition holds, in the caller's priority order."""
    for holds, code in candidates:
        if holds:
            return code
    return None


def _structural_code(exc: ValidationError) -> tuple[Optional[str], str]:
    """Map a Pydantic validation failure onto a structural L1 code.

    The mapping is by error ``type`` where Pydantic gives one, and by our own
    validator message text where it does not (every ``value_error`` below comes
    from a message this package owns in ``models.py``). That is only safe because
    ``tests/test_conformance.py`` asserts the reference derives each reject
    vector's declared code, so changing one of those messages fails loudly rather
    than silently reclassifying an error.
    """
    by_type = {
        "extra_forbidden": "WCM-L1-0001",
        "missing": "WCM-L1-0002",
        "too_short": "WCM-L1-0005",
        "enum": "WCM-L1-0004",
        "literal_error": "WCM-L1-0004",
    }
    value_error_markers = (
        ("Invalid hash value", "WCM-L1-0003"),
        ("HashValue must be a string", "WCM-L1-0003"),
        ("retire_after", "WCM-L1-0006"),
        ("derived_from must not equal", "WCM-L1-0009"),
        ("byom-symmetric", "WCM-L1-0008"),
        ("sovereign_profile", "WCM-L1-0007"),
    )
    details: list[str] = []
    code: Optional[str] = None
    for err in exc.errors():
        loc = ".".join(str(part) for part in err["loc"])
        details.append(f"{loc}: {err['msg']}")
        if code is not None:
            continue
        mapped = by_type.get(err["type"])
        if mapped is None and err["type"] == "value_error":
            for marker, candidate in value_error_markers:
                if marker in err["msg"]:
                    mapped = candidate
                    break
        code = mapped
    return code, "; ".join(details)


def _eval_manifest(vector: dict[str, Any]) -> Verdict:
    try:
        WeightCustodyManifest.model_validate(vector["manifest"])
    except ValidationError as exc:
        code, detail = _structural_code(exc)
        return Verdict("reject", code, detail)
    return Verdict("accept", None, "manifest is structurally valid")


def _context_from(trusted_keys: list[dict[str, Any]]) -> VerificationContext:
    context = VerificationContext()
    for entry in trusted_keys:
        algorithm = entry["algorithm"]
        if algorithm == "Ed25519":
            context.add_key_b64url(entry["public_key"])
        else:
            raise ValueError(
                f"vector trusts a {algorithm!r} key, which the reference runner does "
                "not load yet (only Ed25519 is used by the current L1 vectors)"
            )
    return context


def _eval_signature(vector: dict[str, Any]) -> Verdict:
    try:
        manifest = WeightCustodyManifest.model_validate(vector["manifest"])
    except ValidationError as exc:
        # A signature vector's manifest must itself be structurally valid, or the
        # vector is testing the wrong thing.
        return Verdict("reject", None, f"vector manifest is not valid: {exc}")

    result = verify_manifest(manifest, _context_from(vector["trusted_keys"]))
    if result.ok:
        return Verdict("accept", None, "all required roles verified")

    reasons = [r.reason or "" for r in result.signatures if not r.valid]
    joined = " | ".join(reasons + result.errors)

    def any_reason(marker: str) -> bool:
        return any(marker in reason for reason in reasons)

    # Priority matters: an untrusted key also leaves its role unsatisfied, and the
    # specific cause is the more useful report.
    code = _first_code(
        (
            (any_reason("untrusted key_id"), "WCM-L1-0103"),
            (any_reason("algorithm mismatch"), "WCM-L1-0104"),
            (any_reason("signature verification failed"), "WCM-L1-0102"),
            (
                any("sovereign_signer" in e for e in result.errors),
                "WCM-L1-0105",
            ),
            (bool(result.missing_roles), "WCM-L1-0101"),
        )
    )
    return Verdict("reject", code, joined or "verification failed")


def _eval_lineage(vector: dict[str, Any]) -> Verdict:
    manifests = {}
    for raw in vector["manifests"]:
        manifest = WeightCustodyManifest.model_validate(raw)
        manifests[str(manifest.weights_hash)] = manifest

    result = verify_lineage(
        manifests,
        vector["leaf"],
        logged=vector.get("logged"),
        revoked=vector.get("revoked"),
    )
    if result.ok:
        return Verdict("accept", None, f"chain depth {result.depth}")

    joined = " | ".join(result.violations)
    code = _first_code(
        (
            ("cycle detected" in joined, "WCM-L4-0002"),
            ("is not in the manifest set" in joined, "WCM-L4-0001"),
            ("forbids derivatives" in joined, "WCM-L4-0003"),
            ("widens derivatives" in joined, "WCM-L4-0004"),
            ("adds permitted_environments" in joined, "WCM-L4-0004"),
            ("is revoked" in joined, "WCM-L4-0006"),
            ("transparency log" in joined, "WCM-L4-0005"),
        )
    )
    return Verdict("reject", code, joined)


# ---------------------------------------------------------------------------
# L2 and L3: scenario vectors
# ---------------------------------------------------------------------------
#
# L1 and L4 ask a question about a document. L2 and L3 ask what a system does over
# time: a nonce is single-use, a lease lapses, an operation budget runs down. So
# their vectors are ordered SCENARIOS, and every source of nondeterminism is
# either injected or named:
#
#   - the clock is supplied by the vector and only moves on an explicit
#     advance_clock step, so "the lease lapsed" is a fact about the scenario
#     rather than about how long the test took to run;
#   - nonces are generated by the implementation (they must be unpredictable, so
#     a vector cannot hardcode them), and a `challenge` step binds one to a name
#     that later steps reference as "$name". A literal value where a reference
#     would go is how a never-issued nonce is expressed.
#
# That keeps the vectors language-neutral: an implementation in any language walks
# the steps, performs each operation, and compares the outcome.


class _ScenarioError(Exception):
    """A step's outcome did not match, with the code the reference derived."""

    def __init__(self, step_index: int, detail: str, code: Optional[str] = None) -> None:
        super().__init__(detail)
        self.step_index = step_index
        self.detail = detail
        self.code = code


def _clock(start: str) -> tuple[Any, Any]:
    """A mutable injected clock: returns (now_callable, advance_callable)."""
    from datetime import datetime, timedelta

    state = {"now": datetime.fromisoformat(start)}

    def now() -> Any:
        return state["now"]

    def advance(seconds: float) -> None:
        state["now"] = state["now"] + timedelta(seconds=seconds)

    return now, advance


def _resolve(value: Any, bindings: dict[str, str]) -> Any:
    """Substitute "$name" references to nonces bound by a challenge step."""
    if isinstance(value, str) and value.startswith("$"):
        name = value[1:]
        if name not in bindings:
            raise ValueError(f"step references unbound nonce '{value}'")
        return bindings[name]
    if isinstance(value, dict):
        return {k: _resolve(v, bindings) for k, v in value.items()}
    if isinstance(value, list):
        return [_resolve(v, bindings) for v in value]
    return value


_GATE_CODES: tuple[tuple[str, tuple[str, ...], str], ...] = (
    # (check name, substrings that must appear in the detail, code).
    # An empty substring tuple matches any detail for that check.
    ("nonce_fresh", (), "WCM-L2-0001"),
    ("cpu_platform_allowed", (), "WCM-L2-0002"),
    ("assurance_tier", (), "WCM-L2-0003"),
    ("serving_image", ("not in accepted_measurements",), "WCM-L2-0004"),
    ("serving_image", ("prefer-current",), "WCM-L2-0005"),
    ("serving_image", ("revoked",), "WCM-L2-0006"),
    ("serving_image", ("retire_after",), "WCM-L2-0014"),
    ("gpu", ("absent",), "WCM-L2-0007"),
    ("gpu", ("nonce echo",), "WCM-L2-0008"),
    ("gpu", ("rim_pin",), "WCM-L2-0015"),
    ("memory_fingerprint", (), "WCM-L2-0009"),
    ("attestation_revocation", ("is revoked",), "WCM-L2-0016"),
    ("attestation_revocation", ("cache",), "WCM-L2-0010"),
    ("cpu_quote_verified", ("nonce",), "WCM-L2-0012"),
    ("cpu_quote_verified", (), "WCM-L2-0011"),
    ("gpu_report_verified", ("nonce",), "WCM-L2-0012"),
    ("gpu_report_verified", (), "WCM-L2-0011"),
    ("channel_binding", (), "WCM-L2-0013"),
    ("key_available", (), "WCM-L2-0017"),
)


def _gate_code(failures: list[Any]) -> tuple[Optional[str], str]:
    """Map the gate's first failing check onto an L2 code.

    Matched most-specific-first within a check name, since one check reports
    several distinct failures (serving_image alone covers not-accepted,
    prefer-current, revoked, and past-retire_after).
    """
    detail = "; ".join(f"{c.name}: {c.detail or 'failed'}" for c in failures)
    for check in failures:
        for name, markers, code in _GATE_CODES:
            if check.name != name:
                continue
            text = check.detail or ""
            if all(marker in text for marker in markers):
                return code, detail
    return None, detail


def _mint_quote(recipe: dict[str, Any], bindings: dict[str, str]) -> str:
    """Build a quote container from a vector's recipe.

    Quote vectors are recipes, not fixed artifacts, for one unavoidable reason: a
    quote's REPORT_DATA has to bind the nonce, and the nonce is generated at
    scenario time (it must be unpredictable, so a committed vector cannot know it).
    A pre-baked quote could therefore only ever demonstrate a mismatch.

    So the vector carries the chain, a test signing key, and a *description* of
    what REPORT_DATA should bind, and the runner assembles the quote. The ask on an
    implementation is that it can sign a report body, which any language with
    ECDSA can do. The container shape is JsonQuoteParser's, documented in
    conformance/README.md, so nothing here is Python-specific.
    """
    import base64
    import hashlib

    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    binding = recipe["report_data"]
    nonce_hex = _resolve(binding["nonce"], bindings)
    material = bytes.fromhex(nonce_hex)
    transport = binding.get("transport_public_key")
    if transport:
        material += bytes.fromhex(transport)
    report_data = hashlib.sha256(material).digest()

    offset = int(recipe.get("report_data_offset", 0))
    body = (
        bytes(offset)
        + report_data
        + bytes.fromhex(recipe.get("trailing_body_hex", "00" * 32))
    )

    key = serialization.load_pem_private_key(
        recipe["leaf_key_pem"].encode(), password=None
    )
    if not isinstance(key, ec.EllipticCurvePrivateKey):
        # Narrowed rather than cast: a vector carrying an RSA or Ed25519 key would
        # otherwise fail deep inside sign() with an unhelpful error.
        raise ValueError(
            "quote recipes sign with an EC key (ECDSA/SHA-256); got "
            f"{type(key).__name__}"
        )
    signature = key.sign(body, ec.ECDSA(hashes.SHA256()))

    if recipe.get("tamper_report_after_signing"):
        # Flip a byte outside REPORT_DATA, so the chain and the binding are intact
        # and only the signature can catch it.
        mutable = bytearray(body)
        mutable[-1] ^= 0xFF
        body = bytes(mutable)

    document = {
        "report_b64": base64.b64encode(body).decode(),
        "signature_b64": base64.b64encode(signature).decode(),
        "leaf_pem": recipe["leaf_pem"],
        "intermediates_pem": recipe.get("intermediates_pem", []),
        "report_data_offset": offset,
    }
    return base64.b64encode(json.dumps(document).encode()).decode()


def _build_cpu_quote_verifier(config: dict[str, Any]) -> Any:
    from ._quote_verify import JsonQuoteParser, QuoteVerifier, TrustStore

    parser_name = config.get("parser", "json")
    if parser_name != "json":
        raise ValueError(
            f"vector asks for the {parser_name!r} quote parser; only the reference "
            "'json' container is used by the current vectors"
        )
    trust = TrustStore()
    for pem in config["trusted_roots_pem"]:
        trust.add_root_pem(pem)
    return QuoteVerifier(JsonQuoteParser(), trust)


def _eval_gate(vector: dict[str, Any]) -> Verdict:
    from .attestation import CompositeEvidence
    from .kbs import KeyBrokerService
    from .renewal import manifest_identity

    manifest = WeightCustodyManifest.model_validate(vector["manifest"])
    config = vector.get("kbs", {})
    now, advance = _clock(config.get("clock", "2026-01-01T00:00:00+00:00"))

    keystore = {
        str(h): bytes.fromhex(k) for h, k in (config.get("keystore") or {}).items()
    }
    kbs = KeyBrokerService(
        keystore,
        challenge_ttl_seconds=int(config.get("challenge_ttl_seconds", 300)),
        now=now,
        revoked_attestation_keys=config.get("revoked_attestation_keys"),
        max_attestation_cache_age_seconds=int(
            config.get("max_attestation_cache_age_seconds", 600)
        ),
        require_channel_binding=bool(config.get("require_channel_binding", False)),
        # The language-neutral v1 vectors predate the signed protected-runtime
        # transcript and intentionally evaluate only declarative gate semantics.
        # Production KBS construction defaults this compatibility escape hatch
        # off and fails closed without a policy-pinned sweep key.
        allow_legacy_memory_fingerprint=True,
        trusted_manifest_identities={manifest_identity(manifest)},
        cpu_quote_verifier=(
            _build_cpu_quote_verifier(config["cpu_quote_verifier"])
            if "cpu_quote_verifier" in config
            else None
        ),
    )

    bindings: dict[str, str] = {}
    for index, step in enumerate(vector["steps"]):
        op = step["op"]
        if op == "challenge":
            bindings[step["as"]] = kbs.issue_challenge().nonce
        elif op == "advance_clock":
            advance(float(step["seconds"]))
        elif op == "release":
            raw = _resolve(step["evidence"], bindings)
            # A cpu.quote recipe is assembled here, since it has to bind the nonce
            # this scenario just issued.
            recipe = raw.get("cpu", {}).pop("quote", None)
            if recipe is not None:
                raw["cpu"]["quote_b64"] = _mint_quote(recipe, bindings)
            evidence = CompositeEvidence.model_validate(raw)
            decision = kbs.verify_and_release(manifest, evidence)
            want = step["expect"]
            if want == "allow":
                if not decision.released:
                    code, detail = _gate_code(decision.failures)
                    raise _ScenarioError(index, f"expected allow, denied: {detail}", code)
                form = step.get("key_form", "clear")
                got_form = "sealed" if decision.sealed_key is not None else "clear"
                if form != got_form:
                    raise _ScenarioError(
                        index, f"expected the key {form}, got it {got_form}"
                    )
            else:
                if decision.released:
                    raise _ScenarioError(index, "expected deny, the gate released the key")
                code, detail = _gate_code(decision.failures)
                return Verdict("reject", code, f"step {index}: {detail}")
        else:
            raise ValueError(f"unknown gate step op {op!r}")

    return Verdict("accept", None, "every step behaved as the scenario requires")


def _eval_custody(vector: dict[str, Any]) -> Verdict:
    from .custody import (
        EnclaveSession,
        KeyWipedError,
        ReattestationRequired,
        parse_cadence,
    )

    manifest = WeightCustodyManifest.model_validate(vector["manifest"])
    config = vector["custody"]
    now, advance = _clock(config.get("clock", "2026-01-01T00:00:00+00:00"))
    session = EnclaveSession(
        bytes.fromhex(config["key"]),
        cadence_seconds=parse_cadence(manifest.custody.attestation_cadence),
        trusted_time_source=manifest.release_policy.trusted_time_source,
        max_operations=config.get("max_operations"),
        weights_hash=str(manifest.weights_hash),
        now=now,
    )

    def _run(index: int, step: dict[str, Any], action: Any) -> Optional[Verdict]:
        """Run *action*, scoring it against the step's expectation."""
        want = step.get("expect", "ok")
        try:
            action()
        except KeyWipedError as exc:
            if want == "ok":
                raise _ScenarioError(
                    index, f"expected success, key was wiped: {exc}", "WCM-L3-0001"
                ) from exc
            return Verdict("reject", "WCM-L3-0001", f"step {index}: {exc}")
        except ReattestationRequired as exc:
            if want == "ok":
                raise _ScenarioError(
                    index,
                    f"expected success, re-attestation was demanded: {exc}",
                    "WCM-L3-0002",
                ) from exc
            return Verdict("reject", "WCM-L3-0002", f"step {index}: {exc}")
        if want != "ok":
            raise _ScenarioError(index, f"expected {want}, the operation succeeded")
        return None

    for index, step in enumerate(vector["steps"]):
        op = step["op"]
        if op == "advance_clock":
            advance(float(step["seconds"]))
        elif op == "use_key":
            done = _run(index, step, session.use_key)
            if done is not None:
                return done
        elif op == "reattest":
            done = _run(index, step, session.reattest)
            if done is not None:
                return done
        elif op == "tick":
            session.tick()
            want_state = step.get("state")
            if want_state is not None and session.state.value != want_state:
                raise _ScenarioError(
                    index, f"expected state {want_state}, got {session.state.value}"
                )
        elif op == "assert_state":
            if session.state.value != step["state"]:
                raise _ScenarioError(
                    index, f"expected state {step['state']}, got {session.state.value}"
                )
        elif op == "assert_time_floor":
            # A floor stronger than the source supports is the misreport in
            # WCM-L3-0004: the guarantee would be read as bounded when it is not.
            if session.time_floor.value != step["floor"]:
                raise _ScenarioError(
                    index,
                    f"expected time floor {step['floor']}, got {session.time_floor.value}",
                    "WCM-L3-0004",
                )
        elif op == "assert_operations_remaining":
            # A method, unlike its sibling property operations_used. Inconsistent,
            # but it is published API and this is not the PR to break it in.
            got = session.operations_remaining()
            if got != step["remaining"]:
                raise _ScenarioError(
                    index,
                    f"expected {step['remaining']} operations remaining, got {got}",
                    "WCM-L3-0003",
                )
        else:
            raise ValueError(f"unknown custody step op {op!r}")

    return Verdict("accept", None, "every step behaved as the scenario requires")


def _eval_vendor(vector: dict[str, Any]) -> Verdict:
    """Evaluate a capture taken from real vendor silicon.

    Two things have to hold for an accepting capture, and only the first of them
    is what people expect. The capture must verify at the vector's injected
    clock, and every mutation in the refusal matrix must be refused for the
    declared reason. A capture that verifies while its tampered twin also
    verifies has demonstrated a parser rather than a verifier, which is the
    whole reason the matrix is derived here rather than contributed.

    A vector the runner cannot use at all, most often a root nobody staged,
    fails with that reason rather than being skipped. Silence about a vector is
    not evidence of passing it.

    Vendor vectors are accept-only. A hand-written reject vector would compete
    with the derived matrix, and it could not be scored honestly either: this
    evaluator has no WCM code vocabulary, so the suite's rule that a reject must
    carry the declared code would have had nothing real to compare against.
    """
    from ._vendor_vectors import VendorVectorError, evaluate_vendor

    try:
        outcome = evaluate_vendor(vector)
    except VendorVectorError as exc:
        return Verdict("reject", None, str(exc))

    if not outcome.verified:
        return Verdict("reject", None, outcome.reason)
    unrefused = sorted(case for case, (ok, _) in outcome.refusals.items() if not ok)
    if unrefused:
        return Verdict(
            "reject",
            None,
            "the capture verified but these mutations were not refused for the "
            "declared reason: " + ", ".join(unrefused),
        )
    return Verdict("accept")


_EVALUATORS = {
    "manifest": _eval_manifest,
    "signature": _eval_signature,
    "lineage": _eval_lineage,
    "gate": _eval_gate,
    "custody": _eval_custody,
    "vendor": _eval_vendor,
}


def evaluate(vector: dict[str, Any]) -> Verdict:
    """Evaluate one vector with this SDK."""
    evaluator = _EVALUATORS.get(vector["kind"])
    if evaluator is None:
        raise ValueError(f"no evaluator for vector kind {vector['kind']!r}")
    try:
        return evaluator(vector)
    except _ScenarioError as exc:
        # A scenario step that should have succeeded did not. That is an "accept"
        # vector failing, reported with the code the failure diagnoses, so the
        # report says which requirement broke rather than only that one did.
        return Verdict("reject", exc.code, f"step {exc.step_index}: {exc.detail}")


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Outcome:
    """One vector's result, scored against its expectation."""

    vector_id: str
    level: str
    kind: str
    expected: str
    expected_code: Optional[str]
    actual: Optional[str]
    actual_code: Optional[str]
    passed: bool
    reason: str = ""


@dataclass(frozen=True)
class LevelReport:
    level: str
    vectored: bool
    outcomes: list[Outcome] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.outcomes)

    @property
    def passed(self) -> int:
        return sum(1 for o in self.outcomes if o.passed)

    @property
    def failures(self) -> list[Outcome]:
        return [o for o in self.outcomes if not o.passed]

    @property
    def ok(self) -> bool:
        """A level with no vectors is not passed; it is unscoreable."""
        return self.vectored and self.total > 0 and not self.failures


@dataclass(frozen=True)
class SuiteReport:
    levels: list[LevelReport]
    #: Levels that exist in the specification but have no vectors, so nothing
    #: here can be read as evidence about them.
    unscoreable: list[str] = field(default_factory=list)
    #: Vendor captures evaluated against the wall clock rather than the vector's
    #: own: (vector id, verified, reason). Reported, never scored. This is where
    #: a capture ageing out becomes visible without degrading anyone's result.
    live: list[tuple[str, bool, str]] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return all(report.ok for report in self.levels) and bool(self.levels)

    def render(self) -> str:
        lines: list[str] = []
        for report in self.levels:
            level = LEVELS[report.level]
            status = "PASS" if report.ok else "FAIL"
            lines.append(
                f"{report.level}  {status}  {report.passed}/{report.total}  {level.title}"
            )
            for failure in report.failures:
                got = failure.actual or "error"
                if failure.actual_code:
                    got = f"{got} ({failure.actual_code})"
                want = failure.expected
                if failure.expected_code:
                    want = f"{want} ({failure.expected_code})"
                lines.append(f"        {failure.vector_id}: expected {want}, got {got}")
                if failure.reason:
                    lines.append(f"          {failure.reason}")
        for level_id in self.unscoreable:
            lines.append(
                f"{level_id}  n/a   0/0     {LEVELS[level_id].title} "
                "(specified, no vectors yet: not covered by this run)"
            )
        if self.live:
            aged = [entry for entry in self.live if not entry[1]]
            lines.append("")
            lines.append(
                f"live  {len(self.live) - len(aged)}/{len(self.live)} vendor captures "
                "verify against the wall clock (reported, not scored)"
            )
            for vector_id, _, reason in aged:
                lines.append(f"        {vector_id}: {reason}")
        return "\n".join(lines)


def _score(vector: dict[str, Any], got: Optional[Verdict], reason: str = "") -> Outcome:
    expected = vector["expect"]
    expected_code = vector.get("code")
    if got is None:
        return Outcome(
            vector_id=vector["id"],
            level=vector["level"],
            kind=vector["kind"],
            expected=expected,
            expected_code=expected_code,
            actual=None,
            actual_code=None,
            passed=False,
            reason=reason or "no result reported for this vector",
        )
    passed = got.verdict == expected
    detail = got.detail
    if passed and expected == "reject":
        # A reject is only correct if the implementation rejected it for the
        # declared reason. Otherwise a blanket "reject everything" would pass.
        if got.code != expected_code:
            passed = False
            detail = (
                f"rejected, but reported {got.code or 'no code'} rather than "
                f"{expected_code}. {got.detail}"
            )
    return Outcome(
        vector_id=vector["id"],
        level=vector["level"],
        kind=vector["kind"],
        expected=expected,
        expected_code=expected_code,
        actual=got.verdict,
        actual_code=got.code,
        passed=passed,
        reason="" if passed else detail,
    )


def _group(outcomes: list[Outcome], levels: Iterable[str]) -> list[LevelReport]:
    reports = []
    for level_id in levels:
        matching = [o for o in outcomes if o.level == level_id]
        if matching:
            reports.append(
                LevelReport(level=level_id, vectored=LEVELS[level_id].vectored, outcomes=matching)
            )
    return reports


def live_tier(vectors: list[dict[str, Any]]) -> list[tuple[str, bool, str]]:
    """Evaluate every vendor capture against the wall clock.

    Separate from the score on purpose. Certificates expire, and a conformance
    result that changed as they aged would say nothing about the implementation
    it was scoring. This is the tier where "this capture aged out" is visible,
    and somebody has to read it for the absence of a refresh process to stay a
    decision rather than becoming an oversight.
    """
    from ._vendor_vectors import VendorVectorError, live_check

    results: list[tuple[str, bool, str]] = []
    for vector in vectors:
        if vector.get("kind") != "vendor":
            continue
        try:
            ok, reason = live_check(vector)
        except VendorVectorError as exc:
            ok, reason = False, str(exc)
        results.append((str(vector["id"]), ok, reason))
    return results


def run_reference(*, level: Optional[str] = None) -> SuiteReport:
    """Evaluate the vectors with this SDK and score the results."""
    vectors = load_vectors(level=level)
    outcomes = [_score(v, evaluate(v)) for v in vectors]
    wanted = [level] if level else list(LEVELS)
    return SuiteReport(
        levels=_group(outcomes, wanted),
        unscoreable=[lid for lid in wanted if not LEVELS[lid].vectored],
        live=live_tier(vectors),
    )


def score_results(results: dict[str, Any], *, level: Optional[str] = None) -> SuiteReport:
    """Score another implementation's results file against the vectors.

    ``results`` is the documented shape (``conformance/README.md``):

        {"implementation": "my-wcm 0.3.0",
         "results": [{"id": "accept-minimal", "verdict": "accept"},
                     {"id": "reject-cycle", "verdict": "reject",
                      "code": "WCM-L4-0002"}]}

    A vector with no entry counts as a failure rather than being skipped: silence
    about a vector is not evidence of passing it.
    """
    reported: dict[str, dict[str, Any]] = {}
    for entry in results.get("results", []):
        reported[str(entry["id"])] = entry

    vectors = load_vectors(level=level)
    live = live_tier(vectors)
    known = {v["id"] for v in vectors}
    outcomes: list[Outcome] = []
    for vector in vectors:
        entry = reported.get(vector["id"])
        if entry is None:
            outcomes.append(_score(vector, None))
            continue
        verdict = str(entry.get("verdict", ""))
        if verdict not in ("accept", "reject"):
            outcomes.append(
                _score(vector, None, reason=f"verdict must be accept or reject, got {verdict!r}")
            )
            continue
        code = entry.get("code")
        outcomes.append(
            _score(vector, Verdict(verdict, code, str(entry.get("detail", ""))))
        )

    unknown = sorted(set(reported) - known)
    wanted = [level] if level else list(LEVELS)
    report = SuiteReport(
        levels=_group(outcomes, wanted),
        unscoreable=[lid for lid in wanted if not LEVELS[lid].vectored],
        # About the captures rather than about the answers, so it is reported
        # when scoring another implementation too.
        live=live,
    )
    if unknown:
        # Not a failure: it may be a newer suite. Surfaced so it is not invisible.
        report.levels.append(
            LevelReport(
                level=wanted[0],
                vectored=True,
                outcomes=[
                    Outcome(
                        vector_id=vector_id,
                        level=wanted[0],
                        kind="unknown",
                        expected="a known vector id",
                        expected_code=None,
                        actual="not in this vector corpus",
                        actual_code=None,
                        passed=False,
                        reason="result reported for a vector this suite does not have",
                    )
                    for vector_id in unknown
                ],
            )
        )
    return report
