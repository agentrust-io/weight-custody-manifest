"""A caller-supplied firmware floor, and an appraisal that can abstain (#117).

``snp.py`` parses the fields a firmware-floor appraisal needs. ``tdx.py`` now
parses the Intel equivalents. What was missing is somewhere for an operator to
say what it will accept, and a result shape that can say "I checked nothing"
distinctly from "I checked and it passed".

**One floor object, not a second mechanism.** The SEV-SNP floor is caller
supplied, so the Intel one is too, and they are the same object. ``forbid_debug``
is deliberately shared: the SEV-SNP guest-policy debug bit and the TDX
``TDATTRIBUTES`` debug bit are one operator intent expressed by two vendors, and
a caller who forbids debug means it on both. Everything else stays vendor
specific, because the units are not comparable.

**Three states, and an abstention that says which platform.** Two states force
every unappraisable platform into a silent pass, which is how "not configured"
ends up reading as green to anyone aggregating results. ``NOT_EVALUATED`` always
carries a reason naming what was missing; an abstention with no reason is the
same useless answer in a different colour.

**Staleness sits beside the verdict, never inside it.** A floor that no longer
excludes anything is operator hygiene rather than a fault in the release being
appraised, so refusing a sound platform over it would be the wrong failure. The
observation is stateless and per appraisal: this module keeps no watermark,
because a stored high-water mark needs somewhere to live and gives an attacker
something to poison. One run against a platform reporting a high SVN would move
it for everything appraised afterwards, leaving either a fleet that looks stale
when it is not or a floor that looks current when it is not. Aggregating these
observations into a fleet view is the caller's job, because only the caller
knows what its fleet is.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

from .tdx import TD_ATTR_DEBUG, TdxReport

__all__ = [
    "FloorState",
    "FloorCheck",
    "PlatformFloor",
    "FloorAppraisal",
    "appraise_tdx",
    "appraise_tdx_quote",
]


class FloorState(str, Enum):
    """What an appraisal concluded, with abstention as its own answer.

    A caller aggregating these must not round ``not_evaluated`` up to verified.
    """

    passed = "passed"
    failed = "failed"
    not_evaluated = "not_evaluated"


@dataclass(frozen=True)
class FloorCheck:
    """One property appraised, or one reason it was not."""

    name: str
    state: FloorState
    reason: str

    @property
    def ok(self) -> bool:
        """True only for a check that ran and passed.

        Deliberately not true for ``not_evaluated``: that is the rounding this
        type exists to prevent.
        """
        return self.state is FloorState.passed

    def as_dict(self) -> dict[str, str]:
        return {"name": self.name, "state": self.state.value, "reason": self.reason}


@dataclass(frozen=True)
class PlatformFloor:
    """What an operator will accept, per vendor, supplied by the caller.

    ``seam_svn`` is the Intel firmware floor and is compared against byte 0 of
    ``TEE_TCB_SVN`` and nothing else. ``forbid_debug`` is shared with SEV-SNP on
    purpose; it is one operator intent that two vendors express differently.

    A field left as ``None`` is an abstention rather than a floor of zero. "No
    floor supplied for this vendor" and "a floor every platform meets" are
    different statements, and only one of them should read as a pass.
    """

    seam_svn: Optional[int] = None
    forbid_debug: bool = True


@dataclass(frozen=True)
class FloorAppraisal:
    """The verdict, and the staleness observation beside it.

    ``staleness`` is never folded into ``ok``. A floor behind the fleet is a
    fact about the policy file, not about the artifact being appraised.
    """

    platform: str
    checks: list[FloorCheck] = field(default_factory=list)
    staleness: Optional[dict[str, Any]] = None

    @property
    def ok(self) -> bool:
        """True when every check ran and passed.

        An appraisal that only abstained is not ok, because nothing was
        established.
        """
        return bool(self.checks) and all(check.ok for check in self.checks)

    @property
    def evaluated(self) -> list[FloorCheck]:
        return [c for c in self.checks if c.state is not FloorState.not_evaluated]

    def as_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "platform": self.platform,
            "checks": [c.as_dict() for c in self.checks],
            "ok": self.ok,
        }
        if self.staleness is not None:
            out["staleness"] = self.staleness
        return out


def _staleness(floor_value: int, reported: int) -> dict[str, Any]:
    """The observation, computed from what this appraisal already holds.

    No store, nothing to poison, and nothing carried between runs.
    """
    return {"floor": floor_value, "reported": reported, "floor_behind": reported > floor_value}


def appraise_tdx(report: TdxReport, floor: PlatformFloor) -> FloorAppraisal:
    """Appraise an Intel TDX report against a caller-supplied floor.

    Reads byte 0 of ``TEE_TCB_SVN`` and bit 0 of ``TDATTRIBUTES``. The rest of
    both fields is carried and not judged, which is the whole of the restraint
    this appraisal is built on: a byte whose meaning nobody has established is
    not a byte to refuse a release over.

    There is no VMPL analogue on TDX and none is invented here. Emitting nothing
    is better than a check that always passes.
    """
    checks: list[FloorCheck] = []
    staleness: Optional[dict[str, Any]] = None

    if len(report.tee_tcb_svn) < 1:
        # Failed, not abstained, and it names the length found. A body too short
        # for the offset is a broken artifact rather than a missing policy, and
        # the two must not read the same.
        checks.append(
            FloorCheck(
                "intel-tdx.seam_svn",
                FloorState.failed,
                "TEE_TCB_SVN is %d bytes, so the SEAM module SVN cannot be read"
                % len(report.tee_tcb_svn),
            )
        )
    elif floor.seam_svn is None:
        checks.append(
            FloorCheck(
                "intel-tdx.seam_svn",
                FloorState.not_evaluated,
                "no seam_svn floor supplied for intel-tdx; the platform reports "
                + str(report.seam_svn),
            )
        )
    else:
        reported = report.seam_svn
        met = reported >= floor.seam_svn
        checks.append(
            FloorCheck(
                "intel-tdx.seam_svn",
                FloorState.passed if met else FloorState.failed,
                "SEAM module SVN %d %s the floor of %d"
                % (reported, "meets" if met else "is below", floor.seam_svn),
            )
        )
        staleness = _staleness(floor.seam_svn, reported)

    if floor.forbid_debug:
        debug_on = bool(report.td_attributes & TD_ATTR_DEBUG)
        checks.append(
            FloorCheck(
                "intel-tdx.debug",
                FloorState.failed if debug_on else FloorState.passed,
                "TDATTRIBUTES sets DEBUG, so the TD's memory is readable from "
                "outside it"
                if debug_on
                else "TDATTRIBUTES has DEBUG clear",
            )
        )
    else:
        checks.append(
            FloorCheck(
                "intel-tdx.debug",
                FloorState.not_evaluated,
                "the floor does not forbid debug, so TDATTRIBUTES bit 0 was not "
                "appraised",
            )
        )

    return FloorAppraisal(platform="intel-tdx", checks=checks, staleness=staleness)


def appraise_tdx_quote(quote: bytes, floor: PlatformFloor) -> FloorAppraisal:
    """Appraise raw quote bytes, so a quote that will not parse is an answer.

    ``appraise_tdx`` takes a report a caller has already parsed, which cannot
    express "these bytes are not a quote". That is a failure rather than an
    abstention: an artifact that will not parse has not been shown to meet
    anything, and reporting it as not evaluated would let it aggregate beside a
    platform nobody had a floor for.
    """
    from .tdx import parse_tdx_quote
    from ._quote_verify import QuoteFormatError

    try:
        parsed = parse_tdx_quote(quote)
    except QuoteFormatError as exc:
        return FloorAppraisal(
            platform="intel-tdx",
            checks=[
                FloorCheck(
                    "intel-tdx.quote",
                    FloorState.failed,
                    "quote does not parse: " + str(exc),
                )
            ],
        )
    return appraise_tdx(parsed.report, floor)
