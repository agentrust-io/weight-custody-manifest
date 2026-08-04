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

Honest scope, restated wherever it can be missed: **only L1 and L4 have vectors.**
L2 (attestation-gated release) and L3 (runtime custody) are specified as
requirements here and in ``conformance/README.md``, but they are protocol
behaviour over live state (single-use nonces, keys, clocks, operation counters)
rather than static documents, and no vector corpus for them exists yet. A green
run reports the levels it actually covered and says so; it is not a claim of full
protocol conformance.
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
        kinds=(),
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
        kinds=(),
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
    # L2, attestation-gated release (declared; no vectors yet)
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
    # L3, runtime custody (declared; no vectors yet)
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


_EVALUATORS = {
    "manifest": _eval_manifest,
    "signature": _eval_signature,
    "lineage": _eval_lineage,
}


def evaluate(vector: dict[str, Any]) -> Verdict:
    """Evaluate one vector with this SDK."""
    evaluator = _EVALUATORS.get(vector["kind"])
    if evaluator is None:
        raise ValueError(f"no evaluator for vector kind {vector['kind']!r}")
    return evaluator(vector)


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


def run_reference(*, level: Optional[str] = None) -> SuiteReport:
    """Evaluate the vectors with this SDK and score the results."""
    vectors = load_vectors(level=level)
    outcomes = [_score(v, evaluate(v)) for v in vectors]
    wanted = [level] if level else list(LEVELS)
    return SuiteReport(
        levels=_group(outcomes, wanted),
        unscoreable=[lid for lid in wanted if not LEVELS[lid].vectored],
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
