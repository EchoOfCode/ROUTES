"""BuildRunSandboxRunner: real dynamic verification for the remediation loop.

Uses the shared verification service (`routes_core.verification`), i.e. the
same Sandbox Manager ``build_run`` engine as `routes verify`: a fresh,
isolated environment per call (registry-only install with scripts off, then
no network; synthetic PostgreSQL; production build and start; the trusted
test runner on a private network), always cleaned up by the manager.

Request mapping:
  - no patch, no source_ref    -> baseline of the original revision
  - patch                       -> candidate verification (patch applied to a
                                   temporary copy inside the sandbox)
  - source_ref (+ patch)        -> post-remediation static analysis of the
                                   patched tree (analyzer sandbox)

The testbench is a declarative ROUTES test plan (JSON), not code: whether a
test passed is decided only by the trusted test runner.
"""

from __future__ import annotations

import json
import logging
from dataclasses import asdict
from pathlib import Path

from routes_core.engine import EngineClient, EngineUnavailable
from routes_core.sources import SourceSpec
from routes_core.verification import BuildVerification, failure_summary, reanalyse, sha256_file, verify_build

from worker.gate import GateResult
from worker.sandbox.runner import SandboxRunner, SandboxRunRequest, SandboxRunResult, SourceRef, TestResult

log = logging.getLogger("routes.worker.buildrun")


class SourceUnavailable(Exception):
    """The original source cannot be reconstructed exactly (unsupported)."""


def source_spec(ref: SourceRef) -> SourceSpec:
    if ref.kind == "github":
        if not ref.commit_sha:
            raise SourceUnavailable("The assessment did not record the exact source commit, so the original "
                                    "revision cannot be reconstructed. Re-run the assessment.")
        return SourceSpec("github", f"github.com/{ref.owner}/{ref.repo}@{ref.commit_sha[:12]}",
                          owner=ref.owner, repo=ref.repo, ref=ref.commit_sha)
    if ref.kind in ("archive", "zip") and ref.archive_path and ref.sha256:
        path = Path(ref.archive_path)
        if not path.is_file() or sha256_file(path) != ref.sha256:
            raise SourceUnavailable("The retained source archive is missing or no longer matches its hash.")
        return SourceSpec("zip", path.name, path=path)
    raise SourceUnavailable("No immutable copy of the original source is retained for this project.")


def _tests(v: BuildVerification) -> list[TestResult]:
    return [TestResult(name=c.name or c.id, category="exploit" if c.category == "security" else "benign",
                       passed=c.status == "passed", message="; ".join(c.reasons[:3]), outcome=c.status)
            for c in v.cases]


def _evidence(v: BuildVerification) -> dict:
    data = asdict(v)
    data.pop("cases", None)
    return data


def to_result(v: BuildVerification) -> SandboxRunResult:
    """Map engine evidence onto the loop's result shape. A build or startup
    failure is an application outcome ("failed", no tests); anything the
    engine could not complete is "error"."""
    evidence = _evidence(v)
    duration = int((v.duration_seconds or 0) * 1000)
    if v.verification == "VERIFIED_RUN" and not v.isolation_violations:
        return SandboxRunResult(status="passed", tests=_tests(v), duration_ms=duration, evidence=evidence)
    if v.verification == "TESTS_FAILED":
        return SandboxRunResult(status="failed", tests=_tests(v), duration_ms=duration, evidence=evidence,
                                error_reason=failure_summary(v))
    if v.verification == "BUILD_FAILED":
        return SandboxRunResult(status="failed", tests=[], duration_ms=duration, evidence=evidence,
                                error_reason=failure_summary(v))
    status = "timeout" if v.run_status == "timeout" else ("killed" if v.run_status == "cancelled" else "error")
    return SandboxRunResult(status=status, tests=_tests(v), duration_ms=duration, evidence=evidence,
                            error_reason=failure_summary(v) or v.verification)


class BuildRunSandboxRunner(SandboxRunner):
    kind = "build_run"
    evidence_grade = "sandbox"
    supports_known_bad_gate = False

    def __init__(self, *, manager_url: str = "", manager_token: str = "", cache_dir: str = "/tmp/routes-verify",
                 client: EngineClient | None = None, poll_seconds: float | None = None) -> None:
        self.client = client or EngineClient(manager_url or None, manager_token or None, timeout=60.0)
        self.cache_dir = Path(cache_dir)
        self.poll_seconds = poll_seconds
        self.source: SourceRef | None = None
        self.should_cancel = None

    def bind(self, source: SourceRef, should_cancel=None) -> None:  # noqa: ANN001
        """The original source every call of this run is built from."""
        self.source = source
        self.should_cancel = should_cancel

    def close(self) -> None:
        http = getattr(self.client, "client", None)
        if http is not None:
            http.close()

    # ---------------------------------------------------------------- runs
    def _verify(self, plan: dict, patch: str | None) -> BuildVerification | SandboxRunResult:
        if self.source is None:
            return SandboxRunResult(status="error", error_reason="no source bound to the runner")
        try:
            spec = source_spec(self.source)
        except SourceUnavailable as exc:
            return SandboxRunResult(status="error", error_reason=f"unsupported: {exc}")
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        try:
            v = verify_build(self.client, source=spec, plan=plan, patch=patch, cache_dir=self.cache_dir,
                             requested_by="routes-remediation", should_cancel=self.should_cancel,
                             poll_seconds=self.poll_seconds)
        except EngineUnavailable as exc:
            return SandboxRunResult(status="error", error_reason=f"sandbox engine unavailable: {exc}")
        except ValueError as exc:  # rejected request (invalid plan or patch)
            return SandboxRunResult(status="error", error_reason=f"verification request rejected: {exc}")
        expected = self.source.commit_sha
        if expected and v.commit and v.commit != expected:
            return SandboxRunResult(status="error", evidence=_evidence(v),
                                    error_reason=f"the sandbox built commit {v.commit[:12]}, not {expected[:12]}")
        if patch and v.verification != "DYNAMIC_VERIFICATION_UNSUPPORTED" and v.build != "not_run" \
                and not v.patch_applied:
            return SandboxRunResult(status="error", evidence=_evidence(v),
                                    error_reason="the engine did not confirm that the candidate patch was applied")
        return v

    def run(self, request: SandboxRunRequest) -> SandboxRunResult:
        if request.source_ref is not None:
            return self._rescan(request)
        try:
            plan = json.loads(request.testbench.content)
        except ValueError:
            return SandboxRunResult(status="error", error_reason="the testbench is not a ROUTES test plan")
        if request.patch is None and request.round_no > 0:
            return SandboxRunResult(status="error", error_reason="a candidate verification needs a patch")
        v = self._verify(plan, request.patch)
        return v if isinstance(v, SandboxRunResult) else to_result(v)

    def _rescan(self, request: SandboxRunRequest) -> SandboxRunResult:
        try:
            spec = source_spec(self.source or request.source_ref)
        except SourceUnavailable as exc:
            return SandboxRunResult(status="error", error_reason=f"unsupported: {exc}")
        try:
            r = reanalyse(self.client, source=spec, patch=request.patch, cache_dir=self.cache_dir,
                          should_cancel=self.should_cancel,
                          poll_seconds=self.poll_seconds if self.poll_seconds is not None else 2.0)
        except EngineUnavailable as exc:
            return SandboxRunResult(status="error", error_reason=f"sandbox engine unavailable: {exc}")
        evidence = {"run_id": r.run_id, "status": r.status, "commit": r.commit, "patch_applied": r.patch_applied,
                    "findings": len(r.findings)}
        if r.fingerprints is None:
            return SandboxRunResult(status="error", error_reason=r.error or "rescan failed", evidence=evidence)
        findings = [{k: f.get(k) for k in ("fingerprint", "rule_id", "file", "endpoint", "method", "line")}
                    for f in r.findings if f.get("fingerprint")]
        return SandboxRunResult(status="passed", rescan_fingerprints=r.fingerprints, rescan_findings=findings,
                                evidence=evidence)

    # --------------------------------------------------------- baseline gate
    def baseline_gate(self, finding: dict, snapshot, testbench) -> GateResult:  # noqa: ANN001
        """Build and test the original revision with the plan.

        Valid when the original application builds, starts, and at least one
        deterministic security test *fails* (the vulnerability is reproduced;
        an error is not a reproduction). Non-security tests that do not pass
        on the original code cannot detect a regression, so they are removed
        from the plan used for candidates and recorded as rejected."""
        try:
            plan = json.loads(testbench.content)
        except ValueError:
            return GateResult(passed=False, failed_check="the testbench is not a ROUTES test plan", retryable=False)
        v = self._verify(plan, None)
        if isinstance(v, SandboxRunResult):
            return GateResult(passed=False, failed_check=f"baseline could not run: {v.error_reason}",
                              runs=[("original", v)], retryable=False)
        result = to_result(v)
        runs = [("original", result)]
        if v.verification == "BUILD_FAILED":
            return GateResult(passed=False, runs=runs, retryable=False,
                              failed_check=f"the original application could not be built or started: {v.error}")
        if v.infrastructure_failure:
            return GateResult(passed=False, runs=runs, retryable=False,
                              failed_check=f"baseline verification was inconclusive ({v.verification}): {v.error}")
        reproduced = [c for c in v.cases if c.category == "security" and c.status == "failed"]
        if not reproduced:
            return GateResult(passed=False, runs=runs, retryable=False,
                              failed_check="the security tests did not reproduce the vulnerability on the original "
                                           "code, so a fix cannot be verified")
        unreliable = {c.id for c in v.cases if c.status != "passed" and c.category != "security"} | \
                     {c.id for c in v.cases if c.category == "security" and c.status == "error"}
        kept = [t for t in plan.get("tests", []) if t.get("id") not in unreliable]
        pruned = {**plan, "tests": kept}
        effective = type(testbench)(path=testbench.path, content=json.dumps(pruned, sort_keys=True))
        dropped_names = sorted(c.name or c.id for c in v.cases if c.id in unreliable)
        return GateResult(passed=True, runs=runs, testbench=effective, retryable=False, dropped_tests=dropped_names)
