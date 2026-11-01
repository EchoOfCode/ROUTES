import itertools

import pytest

from routes_shared.redaction import redact_for_llm, unredacted_secret_count
from routes_shared.remediation_workflow import (
    LEGACY_STATUS,
    TERMINAL_STAGES,
    VERDICT_STAGE,
    FindingEvidence,
    InvalidTransition,
    Resolution,
    Stage,
    Verdict,
    can_transition,
    check_transition,
    decide_finding,
    decide_run,
)

HAPPY = ["queued", "preparing_context", "redacting", "analysis", "planning", "generating_tests",
         "baseline_verification", "validating_tests", "generating_patch", "validating_patch", "testing",
         "post_remediation_analysis", "completed"]


def test_happy_path_and_correction_loop_are_valid():
    for a, b in itertools.pairwise(HAPPY):
        check_transition(a, b)
    for a, b in [("testing", "analysing_failure"), ("analysing_failure", "retrying"), ("retrying", "generating_patch"),
                 ("validating_patch", "building"), ("building", "testing"), ("validating_tests", "analysis")]:
        check_transition(a, b)


@pytest.mark.parametrize("a,b", [("queued", "testing"), ("queued", "completed"), ("testing", "completed"),
                                 ("generating_patch", "testing"), ("completed", "failed"), ("cancelled", "queued"),
                                 ("analysing_failure", "generating_patch")])
def test_invalid_transitions_are_rejected(a, b):
    with pytest.raises(InvalidTransition):
        check_transition(a, b)


def test_any_active_stage_can_end_but_only_analysis_can_complete():
    for stage in Stage:
        if stage in TERMINAL_STAGES:
            assert not any(can_transition(stage, t) for t in Stage)
            continue
        for end in (Stage.FAILED, Stage.CANCELLED, Stage.INCONCLUSIVE, Stage.HUMAN_REVIEW):
            assert can_transition(stage, end)
        assert can_transition(stage, Stage.COMPLETED) == (stage is Stage.POST_REMEDIATION_ANALYSIS)


def test_resume_only_restarts_context_preparation_of_an_active_run():
    assert can_transition("testing", "preparing_context", resume=True)
    assert not can_transition("testing", "generating_patch", resume=True)
    assert not can_transition("completed", "preparing_context", resume=True)


def full_evidence(**over) -> FindingEvidence:
    e = FindingEvidence(testbench_validated=True, baseline_reproduced=True, verification_passed=True,
                        reanalysis_ran=True, reanalysis_fingerprint_gone=True, reanalysis_new_findings=0,
                        evidence_grade="sandbox")
    for k, v in over.items():
        setattr(e, k, v)
    return e


def test_verified_fixed_needs_every_gate():
    assert decide_finding(full_evidence()).resolution is Resolution.VERIFIED_FIXED
    for gate in ({"testbench_validated": False}, {"baseline_reproduced": False}, {"verification_passed": False},
                 {"reanalysis_ran": False}, {"reanalysis_fingerprint_gone": False}, {"reanalysis_new_findings": 1},
                 {"evidence_grade": "simulated"}, {"evidence_grade": None}):
        assert decide_finding(full_evidence(**gate)).resolution is not Resolution.VERIFIED_FIXED, gate


def test_non_fix_outcomes_are_distinguished():
    assert decide_finding(full_evidence(evidence_grade="simulated")).resolution is Resolution.INCONCLUSIVE
    assert decide_finding(full_evidence(testbench_validated=False)).resolution is Resolution.INCONCLUSIVE
    assert decide_finding(full_evidence(verification_passed=False, attempts_exhausted=True)).resolution \
        is Resolution.HUMAN_REVIEW
    assert decide_finding(full_evidence(verification_passed=False, oscillation=True)).resolution \
        is Resolution.HUMAN_REVIEW
    assert decide_finding(full_evidence(verification_passed=False, infrastructure_error="sandbox down")).resolution \
        is Resolution.FAILED
    assert decide_finding(full_evidence(verification_passed=False, unsupported_reason="zip")).resolution \
        is Resolution.INCONCLUSIVE
    assert decide_finding(full_evidence(cancelled=True)).resolution is Resolution.CANCELLED


def test_a_hint_can_never_turn_missing_evidence_into_a_fix():
    e = FindingEvidence(oscillation=False, attempts_exhausted=False)
    assert decide_finding(e).resolution is not Resolution.VERIFIED_FIXED


def test_run_verdicts():
    assert decide_run(["verified_fixed", "verified_fixed"])[0] is Verdict.VERIFIED_FIXED
    assert decide_run(["verified_fixed", "inconclusive"])[0] is Verdict.PARTIALLY_REMEDIATED
    assert decide_run(["human_review", "inconclusive"])[0] is Verdict.HUMAN_REVIEW
    assert decide_run(["inconclusive"])[0] is Verdict.INCONCLUSIVE
    assert decide_run(["failed", "failed"])[0] is Verdict.FAILED
    assert decide_run(["inconclusive"], infrastructure_error="db down")[0] is Verdict.FAILED
    assert decide_run(["verified_fixed"], cancelled=True)[0] is Verdict.CANCELLED
    assert decide_run([])[0] is Verdict.FAILED
    for v in Verdict:
        assert v in LEGACY_STATUS and v in VERDICT_STAGE


def test_redaction_verification_ignores_placeholders_and_catches_leftovers():
    code = 'const apiKey = "AKIAABCDEFGHIJKLMNOP";\nconst password = "hunter2hunter2";\n'
    redacted, mapping = redact_for_llm(code)
    assert len(mapping) == 2 and unredacted_secret_count(redacted) == 0
    assert unredacted_secret_count(code) >= 2
    assert unredacted_secret_count('const token = "abcd…[redacted]";') == 0
    assert unredacted_secret_count("") == 0
