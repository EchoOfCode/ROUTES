"""FakeSandboxRunner: returns a pre-configured canned result every time, and
records every request it was given - for tests, and for the demo's offline
mode. Four canned scenarios, as specified: pass, fail, timeout, missing_stub.
"""

from __future__ import annotations

from worker.sandbox.runner import SandboxRunRequest, SandboxRunner, SandboxRunResult, TestResult


class FakeSandboxRunner(SandboxRunner):
    def __init__(self, result: SandboxRunResult) -> None:
        self.result = result
        self.calls: list[SandboxRunRequest] = []

    def run(self, request: SandboxRunRequest) -> SandboxRunResult:
        self.calls.append(request)
        return self.result


def canned_pass() -> SandboxRunResult:
    return SandboxRunResult(
        status="passed",
        tests=[
            TestResult(name="exploit payload is rejected", category="exploit", passed=True),
            TestResult(name="normal input still works", category="benign", passed=True),
        ],
        stdout="2 passed, 0 failed", duration_ms=120,
    )


def canned_fail(message: str = "exploit payload was not rejected") -> SandboxRunResult:
    return SandboxRunResult(
        status="failed",
        tests=[
            TestResult(name="exploit payload is rejected", category="exploit", passed=False, message=message),
            TestResult(name="normal input still works", category="benign", passed=True),
        ],
        stdout="1 passed, 1 failed", duration_ms=110,
    )


def canned_timeout() -> SandboxRunResult:
    return SandboxRunResult(status="timeout", stderr="exceeded the time limit", duration_ms=30_000,
                            error_reason="timeout")


def canned_missing_stub(module: str) -> SandboxRunResult:
    return SandboxRunResult(status="error", stderr=f"Cannot find module '{module}'", duration_ms=50,
                            error_reason=f"missing_stub:{module}")
