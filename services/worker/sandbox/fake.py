"""FakeSandboxRunner: returns a pre-configured canned result every time, and
records every request it was given - for tests, and for the demo's offline
mode. Four canned scenarios, as specified: pass, fail, timeout, missing_stub.

Also accepts a *list* of results, returned one per call in order (S7's gate
makes several calls per finding - against the original code, then each
known-bad-fix - and needs a different scripted outcome for each one).
"""

from __future__ import annotations

from worker.sandbox.runner import SandboxRunRequest, SandboxRunner, SandboxRunResult, TestResult


class FakeSandboxRunner(SandboxRunner):
    def __init__(self, result: SandboxRunResult | list[SandboxRunResult]) -> None:
        self._scripted = list(result) if isinstance(result, list) else None
        self._single = None if isinstance(result, list) else result
        self.calls: list[SandboxRunRequest] = []

    def run(self, request: SandboxRunRequest) -> SandboxRunResult:
        self.calls.append(request)
        if self._scripted is not None:
            if not self._scripted:
                raise AssertionError("FakeSandboxRunner ran out of scripted results")
            return self._scripted.pop(0)
        return self._single


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
