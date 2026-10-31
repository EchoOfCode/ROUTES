"""Unit tests for the remediation loop controller (S8c), against fake LLM
HTTP transports and a scripted FakeSandboxRunner - no real network calls,
no real sandbox execution.
"""

import json

import httpx

from routes_shared.remediation import Snapshot
from worker.gate_library import known_bad_fixes_for
from worker.llm.client import LLMClient
from worker.loop import run_remediation_loop
from worker.sandbox.fake import FakeSandboxRunner
from worker.sandbox.runner import SandboxRunResult, SourceRef, TestResult

FINDING = {
    "id": "f1", "fingerprint": "fp-original", "rule_id": "routes.sqli.pg-tainted-query",
    "title": "User input used to build a SQL query",
    "plain_description": "Input reaches a database query without parameterisation.",
}
SNAPSHOT = Snapshot(
    file="app/api/search/route.ts", start_line=1, end_line=5,
    code=(
        "export async function GET(request) {\n"
        '  const q = request.nextUrl.searchParams.get("q") ?? "";\n'
        "  const result = await pool.query(`SELECT * FROM products WHERE name ILIKE '%${q}%'`);\n"
        "  return NextResponse.json(result.rows);\n"
        "}\n"
    ),
)
SOURCE_REF = SourceRef(kind="zip", upload_id="u-1")
N_BAD_FIXES = len(known_bad_fixes_for(FINDING["rule_id"]))

LLM_A_CONTENT = json.dumps({"prompt_for_fix": "Parameterise the query.", "testbench": "test('exploit', () => {})"})


def _candidate(tag: int) -> str:
    # The tag lands in real code (not a comment): normalize_snippet() strips
    # comments/whitespace before hashing, so a comment-only difference would
    # hash identically and falsely look like oscillation.
    return (
        "```ts\n"
        "export async function GET(request) {\n"
        f"  const _attempt = {tag};\n"
        '  const q = request.nextUrl.searchParams.get("q") ?? "";\n'
        "  const result = await pool.query('SELECT * FROM products WHERE name ILIKE $1', [`%${q}%`]);\n"
        "  return NextResponse.json(result.rows);\n"
        "}\n"
        "```"
    )


def _sequenced_client(contents: list[str]) -> LLMClient:
    remaining = list(contents)

    def handler(request: httpx.Request) -> httpx.Response:
        if not remaining:
            raise AssertionError("ran out of scripted LLM responses")
        return httpx.Response(200, json={"choices": [{"message": {"content": remaining.pop(0)}}]})

    return LLMClient(endpoint="http://fake/v1/chat/completions", api_key="k", model="m",
                     transport=httpx.MockTransport(handler))


def _gated_ok() -> SandboxRunResult:
    """One correct gate-phase result: exploit fails, benign passes."""
    return SandboxRunResult(
        status="failed",
        tests=[TestResult(name="exploit blocked", category="exploit", passed=False, message="exploit succeeded"),
              TestResult(name="benign works", category="benign", passed=True)],
    )


def _gate_phase_results() -> list[SandboxRunResult]:
    return [_gated_ok() for _ in range(1 + N_BAD_FIXES)]


def _verify_pass() -> SandboxRunResult:
    return SandboxRunResult(
        status="passed",
        tests=[TestResult(name="exploit blocked", category="exploit", passed=True),
              TestResult(name="benign works", category="benign", passed=True)],
    )


def _verify_fail() -> SandboxRunResult:
    return SandboxRunResult(
        status="failed",
        tests=[TestResult(name="exploit blocked", category="exploit", passed=False),
              TestResult(name="benign works", category="benign", passed=True)],
    )


def _rescan(fingerprints: list[str]) -> SandboxRunResult:
    return SandboxRunResult(status="passed", rescan_fingerprints=fingerprints)


def test_fixed_on_the_first_try():
    sandbox = FakeSandboxRunner(_gate_phase_results() + [_verify_pass(), _rescan([])])

    outcome = run_remediation_loop(
        finding=FINDING, snapshot=SNAPSHOT, llm_a_client=_sequenced_client([LLM_A_CONTENT]),
        llm_b_client=_sequenced_client([_candidate("1")]), sandbox_runner=sandbox, source_ref=SOURCE_REF,
        baseline_fingerprints=set(), max_rounds=5, stagnation_rounds=2,
    )

    assert outcome.status == "fixed"
    assert len(outcome.rounds) == 1
    assert outcome.rounds[0].rescan_diff == {"fingerprint_gone": True, "new_fingerprints": []}


def test_fixed_on_the_second_try_after_feedback():
    sandbox = FakeSandboxRunner(_gate_phase_results() + [_verify_fail(), _verify_pass(), _rescan([])])

    outcome = run_remediation_loop(
        finding=FINDING, snapshot=SNAPSHOT, llm_a_client=_sequenced_client([LLM_A_CONTENT]),
        llm_b_client=_sequenced_client([_candidate("1"), _candidate("2")]), sandbox_runner=sandbox,
        source_ref=SOURCE_REF, baseline_fingerprints=set(), max_rounds=5, stagnation_rounds=2,
    )

    assert outcome.status == "fixed"
    assert len(outcome.rounds) == 2
    assert outcome.rounds[0].failure_output  # round 1 recorded why it failed
    assert outcome.rounds[1].rescan_diff["fingerprint_gone"] is True


def test_never_fixes_ends_in_needs_human_review_not_a_hang():
    sandbox = FakeSandboxRunner(_gate_phase_results() + [_verify_fail(), _verify_fail(), _verify_fail()])

    outcome = run_remediation_loop(
        finding=FINDING, snapshot=SNAPSHOT, llm_a_client=_sequenced_client([LLM_A_CONTENT]),
        llm_b_client=_sequenced_client([_candidate("1"), _candidate("2"), _candidate("3")]), sandbox_runner=sandbox,
        source_ref=SOURCE_REF, baseline_fingerprints=set(), max_rounds=3, stagnation_rounds=2,
    )

    assert outcome.status == "needs_human_review"
    assert "3 rounds" in outcome.reason
    assert len(outcome.rounds) == 3


def test_rescan_still_showing_the_original_fingerprint_counts_as_not_fixed():
    sandbox = FakeSandboxRunner(_gate_phase_results() + [_verify_pass(), _rescan(["fp-original"])])

    outcome = run_remediation_loop(
        finding=FINDING, snapshot=SNAPSHOT, llm_a_client=_sequenced_client([LLM_A_CONTENT]),
        llm_b_client=_sequenced_client([_candidate("1")]), sandbox_runner=sandbox, source_ref=SOURCE_REF,
        baseline_fingerprints=set(), max_rounds=1, stagnation_rounds=2,
    )

    assert outcome.status == "needs_human_review"
    assert outcome.rounds[0].rescan_diff["fingerprint_gone"] is False


def test_a_new_fingerprint_appearing_counts_as_not_fixed():
    sandbox = FakeSandboxRunner(_gate_phase_results() + [_verify_pass(), _rescan(["new-fp"])])

    outcome = run_remediation_loop(
        finding=FINDING, snapshot=SNAPSHOT, llm_a_client=_sequenced_client([LLM_A_CONTENT]),
        llm_b_client=_sequenced_client([_candidate("1")]), sandbox_runner=sandbox, source_ref=SOURCE_REF,
        baseline_fingerprints=set(), max_rounds=1, stagnation_rounds=2,
    )

    assert outcome.status == "needs_human_review"
    assert outcome.rounds[0].rescan_diff == {"fingerprint_gone": True, "new_fingerprints": ["new-fp"]}


def test_gate_never_passing_is_needs_human_review_before_any_round():
    bad_original = SandboxRunResult(
        status="passed",
        tests=[TestResult(name="exploit blocked", category="exploit", passed=True),
              TestResult(name="benign works", category="benign", passed=True)],
    )
    sandbox = FakeSandboxRunner([bad_original, bad_original, bad_original])

    outcome = run_remediation_loop(
        finding=FINDING, snapshot=SNAPSHOT, llm_a_client=_sequenced_client([LLM_A_CONTENT] * 3),
        llm_b_client=_sequenced_client([]), sandbox_runner=sandbox, source_ref=SOURCE_REF,
        baseline_fingerprints=set(), max_rounds=5, stagnation_rounds=2,
    )

    assert outcome.status == "needs_human_review"
    assert "gate" in outcome.reason
    assert outcome.rounds == []


def test_oscillation_stops_early_on_a_repeated_candidate():
    sandbox = FakeSandboxRunner(_gate_phase_results() + [_verify_fail()])

    outcome = run_remediation_loop(
        finding=FINDING, snapshot=SNAPSHOT, llm_a_client=_sequenced_client([LLM_A_CONTENT]),
        llm_b_client=_sequenced_client([_candidate("same"), _candidate("same")]), sandbox_runner=sandbox,
        source_ref=SOURCE_REF, baseline_fingerprints=set(), max_rounds=5, stagnation_rounds=2,
    )

    assert outcome.status == "needs_human_review"
    assert "oscillation" in outcome.reason
    assert len(outcome.rounds) == 2  # stopped at round 2, never reached round 3+


def test_cancellation_is_checked_before_each_round():
    sandbox = FakeSandboxRunner(_gate_phase_results())  # no verify/rescan calls expected

    outcome = run_remediation_loop(
        finding=FINDING, snapshot=SNAPSHOT, llm_a_client=_sequenced_client([LLM_A_CONTENT]),
        llm_b_client=_sequenced_client([]), sandbox_runner=sandbox, source_ref=SOURCE_REF,
        baseline_fingerprints=set(), max_rounds=5, stagnation_rounds=2, should_cancel=lambda: True,
    )

    assert outcome.status == "cancelled"
    assert outcome.rounds == []  # cancelled before round 1 even called LLM B


def test_fixed_on_the_first_try_records_the_candidate_code():
    sandbox = FakeSandboxRunner(_gate_phase_results() + [_verify_pass(), _rescan([])])
    candidate = _candidate(1)

    outcome = run_remediation_loop(
        finding=FINDING, snapshot=SNAPSHOT, llm_a_client=_sequenced_client([LLM_A_CONTENT]),
        llm_b_client=_sequenced_client([candidate]), sandbox_runner=sandbox, source_ref=SOURCE_REF,
        baseline_fingerprints=set(), max_rounds=5, stagnation_rounds=2,
    )

    assert outcome.status == "fixed"
    assert outcome.rounds[0].candidate_code is not None
    assert "_attempt = 1" in outcome.rounds[0].candidate_code
