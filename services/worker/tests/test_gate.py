"""Unit tests for the testbench gate (S7): deterministic, no LLM."""

from routes_shared.remediation import Snapshot, Testbench

from worker.gate import run_gate
from worker.gate_library import known_bad_fixes_for
from worker.sandbox.fake import FakeSandboxRunner
from worker.sandbox.runner import SandboxRunResult, TestResult

FINDING = {"id": "f1", "rule_id": "routes.sqli.pg-tainted-query", "title": "User input used to build a SQL query"}
SNAPSHOT = Snapshot(file="app/api/search/route.ts", start_line=1, end_line=5, code="...original vulnerable code...")
TESTBENCH = Testbench(path="app/api/search/route.test.ts", content="...glue code...")
BAD_FIXES = known_bad_fixes_for(FINDING["rule_id"])


def _correctly_vulnerable() -> SandboxRunResult:
    return SandboxRunResult(
        status="failed",
        tests=[TestResult(name="exploit is blocked", category="exploit", passed=False, message="exploit succeeded"),
              TestResult(name="normal input still works", category="benign", passed=True)],
    )


def _incorrectly_looks_fixed() -> SandboxRunResult:
    return SandboxRunResult(
        status="passed",
        tests=[TestResult(name="exploit is blocked", category="exploit", passed=True),
              TestResult(name="normal input still works", category="benign", passed=True)],
    )


def test_known_bad_fix_library_has_sqli_entries():
    assert len(BAD_FIXES) >= 3


def test_gate_passes_when_testbench_correctly_identifies_everything():
    results = [_correctly_vulnerable() for _ in range(1 + len(BAD_FIXES))]
    runner = FakeSandboxRunner(results)

    result = run_gate(runner, FINDING, SNAPSHOT, TESTBENCH)

    assert result.passed is True
    assert result.failed_check is None
    assert len(runner.calls) == 1 + len(BAD_FIXES)
    assert [label for label, _ in result.runs] == ["original"] + [f.name for f in BAD_FIXES]


def test_gate_rejects_when_exploit_does_not_fail_on_original_code():
    runner = FakeSandboxRunner([_incorrectly_looks_fixed()])

    result = run_gate(runner, FINDING, SNAPSHOT, TESTBENCH)

    assert result.passed is False
    assert "original code" in result.failed_check
    assert "exploit test" in result.failed_check
    assert len(runner.calls) == 1  # never got to checking known-bad-fixes


def test_gate_rejects_when_benign_does_not_pass_on_original_code():
    broken_benign = SandboxRunResult(
        status="failed",
        tests=[TestResult(name="exploit is blocked", category="exploit", passed=False),
              TestResult(name="normal input still works", category="benign", passed=False, message="crashed")],
    )
    runner = FakeSandboxRunner([broken_benign])

    result = run_gate(runner, FINDING, SNAPSHOT, TESTBENCH)

    assert result.passed is False
    assert "benign test" in result.failed_check


def test_gate_rejects_when_a_known_bad_fix_is_not_caught():
    assert len(BAD_FIXES) >= 2, "test assumes at least 2 known-bad-fixes"
    results = [_correctly_vulnerable(), _correctly_vulnerable(), _incorrectly_looks_fixed()]
    runner = FakeSandboxRunner(results)

    result = run_gate(runner, FINDING, SNAPSHOT, TESTBENCH)

    assert result.passed is False
    assert BAD_FIXES[1].name in result.failed_check
    assert len(runner.calls) == 3  # stopped at the failing known-bad-fix, never checked the rest


def test_gate_rejects_on_an_errored_run():
    runner = FakeSandboxRunner([SandboxRunResult(status="error", error_reason="missing_stub:pg")])

    result = run_gate(runner, FINDING, SNAPSHOT, TESTBENCH)

    assert result.passed is False
    assert "original code" in result.failed_check
