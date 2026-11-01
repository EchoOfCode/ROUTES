from worker.sandbox.fake import FakeSandboxRunner, canned_fail, canned_missing_stub, canned_pass, canned_timeout
from worker.sandbox.real import RealSandboxRunner
from worker.sandbox.runner import SandboxFile, SandboxRunner, SandboxRunRequest, SandboxRunResult, SourceRef, TestResult

RUNNER_KINDS = ("fake", "build_run", "real")


def build_sandbox_runner(kind: str, *, manager_url: str = "", manager_token: str = "",
                         cache_dir: str = "/tmp/routes-verify") -> SandboxRunner:
    """The actual switch point: which SandboxRunner is used is this one
    config-driven choice, never a code change at the call site.

    "build_run" verifies in the real Build & Run sandbox (the same engine as
    `routes verify`). "real" is kept as an alias for it: the run kind the old
    RealSandboxRunner requested ("remediate_verify") never existed."""
    if kind == "fake":
        return FakeSandboxRunner(canned_pass())
    if kind in ("build_run", "real"):
        from worker.sandbox.buildrun import BuildRunSandboxRunner

        return BuildRunSandboxRunner(manager_url=manager_url, manager_token=manager_token, cache_dir=cache_dir)
    raise ValueError(f"Unknown sandbox runner kind {kind!r}; expected one of {RUNNER_KINDS}.")


__all__ = [
    "SandboxRunner",
    "SandboxRunRequest",
    "SandboxFile",
    "SourceRef",
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
