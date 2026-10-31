"""The SandboxRunner interface. The sandbox that actually executes a
testbench is owned by someone else and treated as a black box here - the
loop (S8) depends only on this interface; see docs/sandbox-contract.md.

`status` is a raw mechanical signal ("did the test run complete cleanly"),
never a security verdict: running a testbench against the *original*
vulnerable code is expected to report status="failed" (an exploit assertion
was not blocked) - that is the desired outcome at that point in the gate,
not an infrastructure problem. Interpreting `tests[].category` against
`status` is the caller's job (S7's gate, S8's loop), not the runner's.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field

STATUSES = ("passed", "failed", "error", "timeout", "killed")
CATEGORIES = ("exploit", "benign")


@dataclass
class SandboxFile:
    path: str
    content: str


@dataclass
class SourceRef:
    """How a real backend can re-fetch the base repo to rescan against -
    only needed for a rescan (running the full detector on the patched
    tree), not for a gate/verify call, which operates purely on the
    snapshot's single file in isolation and needs no repo access at all."""

    kind: str  # "github" | "zip"
    owner: str | None = None
    repo: str | None = None
    ref: str | None = None
    upload_id: str | None = None


@dataclass
class SandboxRunRequest:
    run_id: str
    finding_id: str
    round_no: int
    files: list[SandboxFile]
    testbench: SandboxFile
    timeout_s: int = 30
    memory_mb: int = 256
    # Set only when this call is a rescan (see SourceRef); omitted for a
    # plain gate/verify call.
    source_ref: SourceRef | None = None


@dataclass
class TestResult:
    name: str
    category: str  # "exploit" | "benign"
    passed: bool
    message: str = ""


@dataclass
class SandboxRunResult:
    status: str  # one of STATUSES
    tests: list[TestResult] = field(default_factory=list)
    stdout: str = ""
    stderr: str = ""
    duration_ms: int = 0
    error_reason: str | None = None  # e.g. "missing_stub:pg"
    # Populated only when the request carried a source_ref (a rescan): every
    # finding fingerprint detected on the patched tree. None when no rescan
    # was requested - never an empty list standing in for "not run".
    rescan_fingerprints: list[str] | None = None


class SandboxRunner(ABC):
    @abstractmethod
    def run(self, request: SandboxRunRequest) -> SandboxRunResult:
        """Execute `request.testbench` against `request.files` and report
        what happened. Must never raise for an expected failure mode
        (a test failing, a timeout, a missing stub, the sandbox rejecting
        the request) - those are all SandboxRunResult outcomes, not
        exceptions. Only raise for a genuine bug in the runner itself."""
