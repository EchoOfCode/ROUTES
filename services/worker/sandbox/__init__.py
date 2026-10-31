from worker.sandbox.fake import FakeSandboxRunner, canned_fail, canned_missing_stub, canned_pass, canned_timeout
from worker.sandbox.real import RealSandboxRunner
from worker.sandbox.runner import SandboxFile, SandboxRunner, SandboxRunRequest, SandboxRunResult, TestResult

RUNNER_KINDS = ("fake", "real")


def build_sandbox_runner(kind: str, *, manager_url: str = "", manager_token: str = "") -> SandboxRunner:
    """The actual switch point: which SandboxRunner is used is this one
    config-driven choice, never a code change at the call site."""
    if kind == "fake":
        return FakeSandboxRunner(canned_pass())
    if kind == "real":
        return RealSandboxRunner(manager_url=manager_url, manager_token=manager_token)
    raise ValueError(f"Unknown sandbox runner kind {kind!r}; expected one of {RUNNER_KINDS}.")


__all__ = [
    "SandboxRunner",
    "SandboxRunRequest",
    "SandboxFile",
    "SandboxRunResult",
    "TestResult",
    "FakeSandboxRunner",
    "canned_pass",
    "canned_fail",
    "canned_timeout",
    "canned_missing_stub",
    "RealSandboxRunner",
    "RUNNER_KINDS",
    "build_sandbox_runner",
]
