"""The testbench gate (S7): deterministic, no LLM. A testbench earns trust
only if it (a) correctly identifies the *original* code as vulnerable -
exploit assertions fail, benign assertions pass - and (b) still identifies
every known-bad fix in the per-class library (gate_library.py) as
vulnerable. If either check doesn't hold, the testbench itself is
untrustworthy, not the finding fixed; regenerating it and eventually marking
needs_human_review is round-level state owned by S8's loop controller, not
this module - this module only answers "does this testbench pass the gate,
and if not, which specific check failed."
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field

from routes_shared.remediation import Snapshot, Testbench

from worker.gate_library import known_bad_fixes_for
from worker.sandbox.runner import SandboxFile, SandboxRunner, SandboxRunRequest, SandboxRunResult


@dataclass
class GateResult:
    passed: bool
    failed_check: str | None = None
    runs: list[tuple[str, SandboxRunResult]] = field(default_factory=list)
    # The testbench to use from here on, when the gate removed tests that
    # cannot detect anything (e.g. a functional test failing on the original).
    testbench: Testbench | None = None
    # False when regenerating the testbench cannot change the outcome (the
    # original application does not build, the baseline is deterministic).
    retryable: bool = True
    dropped_tests: list[str] = field(default_factory=list)


def _request(finding_id: str, file: str, code: str, testbench: Testbench) -> SandboxRunRequest:
    return SandboxRunRequest(
        run_id=str(uuid.uuid4()), finding_id=finding_id, round_no=0,
        files=[SandboxFile(path=file, content=code)],
        testbench=SandboxFile(path=testbench.path, content=testbench.content),
    )


def _exploit_correctly_failed_and_benign_passed(result: SandboxRunResult) -> str | None:
    """Returns None if correct (vulnerable code should fail exploit
    assertions, pass benign ones), else a reason string."""
    if result.status == "error" or not result.tests:
        return f"run errored or produced no test results ({result.error_reason or result.status})"
    exploit = [t for t in result.tests if t.category == "exploit"]
    benign = [t for t in result.tests if t.category == "benign"]
    passing_exploits = [t.name for t in exploit if t.passed]
    if passing_exploits:
        return f"exploit test(s) did not fail against vulnerable code: {passing_exploits}"
    failing_benign = [t.name for t in benign if not t.passed]
    if failing_benign:
        return f"benign test(s) did not pass against vulnerable code: {failing_benign}"
    return None


def run_gate(runner: SandboxRunner, finding: dict, snapshot: Snapshot, testbench: Testbench) -> GateResult:
    custom = runner.baseline_gate(finding, snapshot, testbench)
    if custom is not None:
        return custom
    finding_id = str(finding.get("id", ""))
    runs: list[tuple[str, SandboxRunResult]] = []

    original_result = runner.run(_request(finding_id, snapshot.file, snapshot.code, testbench))
    runs.append(("original", original_result))
    reason = _exploit_correctly_failed_and_benign_passed(original_result)
    if reason is not None:
        return GateResult(passed=False, failed_check=f"original code: {reason}", runs=runs)

    for bad_fix in (known_bad_fixes_for(finding.get("rule_id", "")) if runner.supports_known_bad_gate else []):
        result = runner.run(_request(finding_id, snapshot.file, bad_fix.code, testbench))
        runs.append((bad_fix.name, result))
        if result.status == "error" or not result.tests:
            return GateResult(passed=False,
                              failed_check=f"known-bad-fix '{bad_fix.name}': run errored or produced no results",
                              runs=runs)
        exploit = [t for t in result.tests if t.category == "exploit"]
        passing_exploits = [t.name for t in exploit if t.passed]
        if passing_exploits:
            return GateResult(
                passed=False,
                failed_check=(f"known-bad-fix '{bad_fix.name}' was not caught as still vulnerable "
                              f"(exploit test(s) incorrectly passed: {passing_exploits})"),
                runs=runs,
            )

    return GateResult(passed=True, runs=runs)
