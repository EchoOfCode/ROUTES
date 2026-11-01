"""The remediation workflow: stages, valid transitions and evidence-based verdicts.

Pure Python with no database or network dependency, so the API, the worker
and the tests all apply exactly the same rules. The database stores the
results (``remediations.stage``, ``remediation_findings.resolution``,
``remediations.verdict``); this module decides which values are allowed.

The verdict is never a score. A finding counts as fixed only when every
mandatory gate passed on real evidence:

  1. the testbench was validated: it reproduced the original vulnerability;
  2. the candidate patch passed every security and functional test;
  3. an independent rescan of the patched code no longer reports the finding
     and reports no new finding;
  4. all of the above came from a real sandbox, not a simulated runner.

Anything less is ``inconclusive``, ``human_review`` or ``failed``. A model
saying "fixed", a skipped test or an infrastructure error never counts.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class Stage(StrEnum):
    QUEUED = "queued"
    PREPARING_CONTEXT = "preparing_context"
    REDACTING = "redacting"
    ANALYSIS = "analysis"
    PLANNING = "planning"
    GENERATING_TESTS = "generating_tests"
    VALIDATING_TESTS = "validating_tests"
    BASELINE_VERIFICATION = "baseline_verification"
    GENERATING_PATCH = "generating_patch"
    VALIDATING_PATCH = "validating_patch"
    BUILDING = "building"
    TESTING = "testing"
    ANALYSING_FAILURE = "analysing_failure"
    RETRYING = "retrying"
    POST_REMEDIATION_ANALYSIS = "post_remediation_analysis"
    COMPLETED = "completed"
    HUMAN_REVIEW = "human_review"
    INCONCLUSIVE = "inconclusive"
    FAILED = "failed"
    CANCELLED = "cancelled"


TERMINAL_STAGES: frozenset[Stage] = frozenset(
    {Stage.COMPLETED, Stage.HUMAN_REVIEW, Stage.INCONCLUSIVE, Stage.FAILED, Stage.CANCELLED}
)

# Forward edges of the happy path and of the correction loop. Every
# non-terminal stage may additionally move to any terminal stage except
# COMPLETED (see can_transition): a run can be cancelled, fail, or end
# inconclusive / in human review from anywhere, but it can only *complete*
# after post-remediation analysis.
_FORWARD: dict[Stage, frozenset[Stage]] = {
    Stage.QUEUED: frozenset({Stage.PREPARING_CONTEXT}),
    Stage.PREPARING_CONTEXT: frozenset({Stage.REDACTING}),
    # PREPARING_CONTEXT is also where the next patch batch of a multi-finding
    # run starts, after the previous batch ended either way.
    Stage.REDACTING: frozenset({Stage.ANALYSIS, Stage.PREPARING_CONTEXT}),
    Stage.ANALYSIS: frozenset({Stage.PLANNING}),
    Stage.PLANNING: frozenset({Stage.GENERATING_TESTS}),
    Stage.GENERATING_TESTS: frozenset({Stage.BASELINE_VERIFICATION}),
    # Baseline: run the new tests against the original code. Validation then
    # decides whether the testbench is trustworthy; if not, regenerate it.
    Stage.BASELINE_VERIFICATION: frozenset({Stage.VALIDATING_TESTS}),
    Stage.VALIDATING_TESTS: frozenset({Stage.ANALYSIS, Stage.GENERATING_PATCH, Stage.PREPARING_CONTEXT}),
    Stage.GENERATING_PATCH: frozenset({Stage.VALIDATING_PATCH}),
    Stage.VALIDATING_PATCH: frozenset({Stage.BUILDING, Stage.TESTING, Stage.ANALYSING_FAILURE}),
    Stage.BUILDING: frozenset({Stage.TESTING, Stage.ANALYSING_FAILURE}),
    Stage.TESTING: frozenset({Stage.POST_REMEDIATION_ANALYSIS, Stage.ANALYSING_FAILURE}),
    # The self-edge is the combined rescan of every accepted batch at the end
    # of a multi-batch run.
    Stage.POST_REMEDIATION_ANALYSIS: frozenset({Stage.COMPLETED, Stage.ANALYSING_FAILURE,
                                                Stage.PREPARING_CONTEXT, Stage.POST_REMEDIATION_ANALYSIS}),
    Stage.ANALYSING_FAILURE: frozenset({Stage.RETRYING, Stage.PREPARING_CONTEXT,
                                        Stage.POST_REMEDIATION_ANALYSIS}),
    Stage.RETRYING: frozenset({Stage.GENERATING_PATCH}),
}

# A crashed worker's run is resumed from the start of context preparation;
# everything already persisted (attempt numbers in particular) still counts.
RESUMABLE_FROM: frozenset[Stage] = frozenset(set(_FORWARD) - {Stage.QUEUED})


class InvalidTransition(ValueError):
    pass


def can_transition(current: str, new: str, *, resume: bool = False) -> bool:
    cur, nxt = Stage(current), Stage(new)
    if cur in TERMINAL_STAGES:
        return False
    if resume:
        return nxt is Stage.PREPARING_CONTEXT and cur in RESUMABLE_FROM
    if nxt in TERMINAL_STAGES and nxt is not Stage.COMPLETED:
        return True
    return nxt in _FORWARD.get(cur, frozenset())


def check_transition(current: str, new: str, *, resume: bool = False) -> None:
    if not can_transition(current, new, resume=resume):
        raise InvalidTransition(f"remediation cannot move from {current!r} to {new!r}")


class Verdict(StrEnum):
    VERIFIED_FIXED = "verified_fixed"
    PARTIALLY_REMEDIATED = "partially_remediated"
    HUMAN_REVIEW = "human_review"
    INCONCLUSIVE = "inconclusive"
    FAILED = "failed"
    CANCELLED = "cancelled"


class Resolution(StrEnum):
    """Per-finding outcome of one run: the single canonical resolution status
    (``remediation_findings.resolution``)."""

    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    VERIFIED_FIXED = "verified_fixed"
    NOT_FIXED = "not_fixed"
    HUMAN_REVIEW = "human_review"
    INCONCLUSIVE = "inconclusive"
    CANCELLED = "cancelled"
    FAILED = "failed"


ACTIVE_RESOLUTIONS = frozenset({Resolution.PENDING, Resolution.IN_PROGRESS})


class EvidenceGrade(StrEnum):
    SANDBOX = "sandbox"        # executed in a real isolated sandbox
    SIMULATED = "simulated"    # canned or scripted runner: never proof of a fix


class FailureCategory(StrEnum):
    APPLICATION = "application"        # the patch or the application failed
    INFRASTRUCTURE = "infrastructure"  # sandbox, queue, model provider, database
    POLICY = "policy"                  # a safety rule refused to proceed
    TIMEOUT = "timeout"


# Mapping to the legacy coarse status the existing frontend understands.
LEGACY_STATUS = {
    Verdict.VERIFIED_FIXED: "succeeded",
    Verdict.PARTIALLY_REMEDIATED: "needs_human_review",
    Verdict.HUMAN_REVIEW: "needs_human_review",
    Verdict.INCONCLUSIVE: "needs_human_review",
    Verdict.FAILED: "failed",
    Verdict.CANCELLED: "cancelled",
}
LEGACY_FINDING_STATUS = {
    Resolution.VERIFIED_FIXED: "fixed",
    Resolution.PENDING: "open",
    Resolution.IN_PROGRESS: "retrying",
    Resolution.NOT_FIXED: "needs_human_review",
    Resolution.HUMAN_REVIEW: "needs_human_review",
    Resolution.INCONCLUSIVE: "needs_human_review",
    Resolution.CANCELLED: "open",
    Resolution.FAILED: "open",
}
VERDICT_STAGE = {
    Verdict.VERIFIED_FIXED: Stage.COMPLETED,
    Verdict.PARTIALLY_REMEDIATED: Stage.HUMAN_REVIEW,
    Verdict.HUMAN_REVIEW: Stage.HUMAN_REVIEW,
    Verdict.INCONCLUSIVE: Stage.INCONCLUSIVE,
    Verdict.FAILED: Stage.FAILED,
    Verdict.CANCELLED: Stage.CANCELLED,
}


@dataclass
class FindingEvidence:
    """What the database recorded for one finding of a run."""

    testbench_validated: bool = False
    baseline_reproduced: bool = False
    verification_passed: bool = False
    reanalysis_fingerprint_gone: bool = False
    reanalysis_new_findings: int = 0
    reanalysis_ran: bool = False
    evidence_grade: str | None = None
    attempts_exhausted: bool = False
    oscillation: bool = False
    unsupported_reason: str | None = None
    human_review_reason: str | None = None
    infrastructure_error: str | None = None
    cancelled: bool = False


@dataclass
class FindingDecision:
    resolution: Resolution
    reason: str
    gates: dict[str, bool] = field(default_factory=dict)


def decide_finding(e: FindingEvidence) -> FindingDecision:
    gates = {
        "testbench_validated": e.testbench_validated and e.baseline_reproduced,
        "verification_passed": e.verification_passed,
        "reanalysis_confirmed": e.reanalysis_ran and e.reanalysis_fingerprint_gone,
        "no_new_findings": e.reanalysis_ran and e.reanalysis_new_findings == 0,
        "real_sandbox_evidence": e.evidence_grade == EvidenceGrade.SANDBOX,
    }
    if e.cancelled:
        return FindingDecision(Resolution.CANCELLED, "The run was cancelled.", gates)
    if all(gates.values()):
        return FindingDecision(Resolution.VERIFIED_FIXED, "Every mandatory gate passed.", gates)
    if e.infrastructure_error:
        return FindingDecision(Resolution.FAILED, e.infrastructure_error, gates)
    if e.human_review_reason:
        return FindingDecision(Resolution.HUMAN_REVIEW, e.human_review_reason, gates)
    if e.unsupported_reason:
        return FindingDecision(Resolution.INCONCLUSIVE, e.unsupported_reason, gates)
    if not gates["testbench_validated"]:
        return FindingDecision(Resolution.INCONCLUSIVE,
                               "No testbench could be validated against the original code, so a fix "
                               "cannot be verified.", gates)
    passed_without_real_evidence = (gates["verification_passed"] and gates["reanalysis_confirmed"]
                                    and gates["no_new_findings"])
    if passed_without_real_evidence:
        return FindingDecision(Resolution.INCONCLUSIVE,
                               "The candidate passed, but only in a simulated sandbox runner; that is "
                               "not evidence of a fix.", gates)
    if e.oscillation:
        return FindingDecision(Resolution.HUMAN_REVIEW,
                               "The fix generator repeated the same candidate; a person needs to decide.", gates)
    if e.attempts_exhausted:
        return FindingDecision(Resolution.HUMAN_REVIEW,
                               "Every allowed patch attempt was used without passing all gates.", gates)
    return FindingDecision(Resolution.NOT_FIXED, "The candidate did not pass every mandatory gate.", gates)


def decide_run(resolutions: list[str], *, cancelled: bool = False,
               infrastructure_error: str | None = None) -> tuple[Verdict, str]:
    """Combine per-finding resolutions into the run's verdict."""
    if cancelled:
        return Verdict.CANCELLED, "The run was cancelled."
    if not resolutions:
        return Verdict.FAILED, infrastructure_error or "The run had no findings."
    res = [Resolution(r) for r in resolutions]
    fixed = sum(1 for r in res if r is Resolution.VERIFIED_FIXED)
    if fixed == len(res):
        return Verdict.VERIFIED_FIXED, "Every targeted finding passed all mandatory gates."
    if fixed:
        return Verdict.PARTIALLY_REMEDIATED, f"{fixed} of {len(res)} targeted findings were verified fixed."
    if infrastructure_error or all(r is Resolution.FAILED for r in res):
        return Verdict.FAILED, infrastructure_error or "Remediation failed for every targeted finding."
    if any(r in (Resolution.HUMAN_REVIEW, Resolution.NOT_FIXED) for r in res):
        return Verdict.HUMAN_REVIEW, "Automated attempts did not produce a verified fix."
    if any(r is Resolution.CANCELLED for r in res):
        return Verdict.CANCELLED, "The run was cancelled."
    return Verdict.INCONCLUSIVE, "Verification could not establish whether a fix works."
