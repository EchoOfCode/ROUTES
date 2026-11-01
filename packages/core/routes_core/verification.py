"""Shared dynamic verification service.

One implementation, two consumers: the CLI (`routes verify`) and the
remediation worker both go through the Sandbox Manager's ``build_run`` run
kind (via `routes_core.buildrun`) and its ``source`` run kind for rescans.
Nothing here builds, runs or analyses code itself; it submits runs to the
engine and turns the engine's evidence into typed results.

    v = verify_build(client, source=spec, plan=plan, patch=diff, cache_dir=home)
    v.verification     # VERIFIED_RUN | TESTS_FAILED | BUILD_FAILED | DYNAMIC_VERIFICATION_UNSUPPORTED | INCONCLUSIVE
    v.cases            # every test outcome, decided by the trusted test runner
    r = reanalyse(client, source=spec, patch=diff, cache_dir=home)
    r.fingerprints     # findings on the patched tree, or None if the rescan did not complete
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from routes_shared.redaction import redact_text

from routes_core.buildrun import BuildRunRequest, submit, wait
from routes_core.engine import EngineClient
from routes_core.runner import poll_run
from routes_core.sources import SourceSpec

REANALYSIS_DEADLINE = 1500
# Build-run outcomes that say something about the *candidate* (build or start
# broke, tests failed) as opposed to the environment or the engine.
APPLICATION_OUTCOMES = frozenset({"VERIFIED_RUN", "TESTS_FAILED", "BUILD_FAILED"})


@dataclass
class CaseResult:
    id: str
    name: str
    category: str          # security | functional | edge | health
    status: str            # passed | failed | error (decided by the test runner, never here)
    http_status: int | None = None
    duration_ms: int = 0
    reasons: list[str] = field(default_factory=list)
    excerpt: str = ""


@dataclass
class BuildVerification:
    run_id: str | None
    run_status: str                 # engine run status: completed | failed | timeout | cancelled
    verification: str               # Verification enum value
    error: str | None
    failed_stage: str | None
    build: str                      # passed | failed | not_run | interrupted
    startup: str
    database: str                   # ready | failed | not_needed | not_run
    cases: list[CaseResult]
    cleanup: dict | None
    commit: str | None
    patch_applied: bool
    isolation_violations: list[str]
    duration_seconds: float | None
    started_at: float | None = None
    finished_at: float | None = None
    log_tail: str = ""              # end of the failed stage's output (redacted), e.g. the compiler error

    @property
    def passed(self) -> bool:
        """Every test ran and passed, in a clean, isolated, cleaned-up run."""
        return (self.verification == "VERIFIED_RUN" and bool(self.cases)
                and all(c.status == "passed" for c in self.cases) and not self.isolation_violations)

    @property
    def infrastructure_failure(self) -> bool:
        return self.verification not in APPLICATION_OUTCOMES


def parse_build_run(state: dict) -> BuildVerification:
    result = state.get("result") or {}
    stages = result.get("stages") or {}
    app = result.get("application") or {}
    db = stages.get("database") or {}
    source = stages.get("source") or {}
    isolation = result.get("isolation") or {}
    violations = [f"{p.get('host')}:{p.get('port')}" for p in (isolation.get("test_runner") or [])
                  if isinstance(p, dict) and not p.get("ok")]
    cases = [CaseResult(id=str(c.get("id", "")), name=str(c.get("name", "")), category=str(c.get("category", "")),
                        status=c.get("status") if c.get("status") in ("passed", "failed", "error") else "error",
                        http_status=c.get("http_status"), duration_ms=int(c.get("duration_ms") or 0),
                        reasons=[str(r) for r in (c.get("reasons") or [])][:10],
                        excerpt=redact_text(c.get("response_excerpt") or "", max_length=300))
             for c in (result.get("cases") or []) if isinstance(c, dict)]
    db_status = db.get("status") or ("not_needed" if stages else "not_run")
    return BuildVerification(
        run_id=state.get("id"), run_status=state.get("status") or "failed",
        verification=result.get("verification") or "INCONCLUSIVE",
        error=redact_text(result.get("error") or state.get("error") or "", max_length=500) or None,
        failed_stage=result.get("failed_stage"), build=app.get("build") or "not_run",
        startup=app.get("startup") or "not_run", database=str(db_status), cases=cases, cleanup=state.get("cleanup"),
        commit=source.get("commit"), patch_applied=bool((source.get("patch") or {}).get("applied")),
        isolation_violations=violations, duration_seconds=result.get("duration_seconds"),
        started_at=state.get("created_at"), finished_at=state.get("finished_at"),
        log_tail=_stage_tail(result.get("failed_stage"), stages),
    )


def _stage_tail(failed_stage: str | None, stages: dict, max_lines: int = 25) -> str:
    stage = stages.get(failed_stage or "") or {}
    text = str(stage.get("log_tail") or stage.get("app_log_tail") or stage.get("error") or "")
    lines = [ln for ln in text.strip().splitlines() if ln.strip()][-max_lines:]
    return redact_text("\n".join(ln[:240] for ln in lines), max_length=3000)


def verify_build(client: EngineClient, *, source: SourceSpec, plan: dict, patch: str | None, cache_dir: Path,
                 requested_by: str = "routes", should_cancel: Callable[[], bool] | None = None,
                 on_state: Callable[[dict], None] | None = None, poll_seconds: float | None = None
                 ) -> BuildVerification:
    """Build, start and test `source` (optionally with `patch`) in a fresh,
    isolated environment, and return the engine's evidence."""
    run = submit(client, BuildRunRequest(source=source, test_plan=plan, patch=patch, requested_by=requested_by),
                 cache_dir=cache_dir)
    final = wait(client, run, on_state=on_state, should_cancel=should_cancel, poll_seconds=poll_seconds)
    return parse_build_run(final)


def failure_summary(v: BuildVerification, *, limit: int = 2500) -> str:
    """Actual, sanitised failure evidence for the correction step: what broke
    and how each failing test differed from what was expected."""
    parts: list[str] = []
    if v.verification == "BUILD_FAILED":
        parts.append(f"The candidate failed at the {v.failed_stage or 'build'} stage: {v.error or 'no detail'}")
        if v.log_tail:
            parts.append(f"End of the {v.failed_stage or 'build'} output:\n{v.log_tail}")
    elif v.infrastructure_failure:
        parts.append(f"Verification could not complete ({v.verification}): {v.error or 'no detail'}")
    for c in v.cases:
        if c.status != "passed":
            parts.append(f"[{c.category}] {c.name}: {c.status}; " + "; ".join(c.reasons[:3]))
    return redact_text("\n".join(parts), max_length=limit)


@dataclass
class Reanalysis:
    run_id: str | None
    status: str
    fingerprints: list[str] | None     # None: the rescan did not complete; never an empty stand-in
    findings: list[dict]
    commit: str | None
    patch_applied: bool
    error: str | None


def reanalyse(client: EngineClient, *, source: SourceSpec, patch: str | None, cache_dir: Path,
              should_cancel: Callable[[], bool] | None = None, poll_seconds: float = 2.0) -> Reanalysis:
    """Run the full static analysis (Semgrep, tree-sitter, data flow) on the
    source with `patch` applied inside the analyzer sandbox."""
    spec: dict = {"kind": "source", "patch": patch}
    if source.is_github:
        spec.update(source="github", owner=source.owner, repo=source.repo, ref=source.ref)
    elif source.kind == "zip" and source.path is not None:
        spec.update(source="zip", upload_id=client.upload_zip(source.path)["upload_id"])
    else:
        return Reanalysis(None, "unsupported", None, [], None, False, "This source cannot be re-analysed.")
    run = client.start(spec)
    final = poll_run(client, run, deadline_seconds=REANALYSIS_DEADLINE, should_cancel=should_cancel,
                     poll_seconds=poll_seconds)
    result = final.get("result") or {}
    status = final.get("status") or "failed"
    error = redact_text(final.get("error") or "", max_length=500) or None
    applied = bool(result.get("patch_applied"))
    if status != "completed" or not isinstance(result.get("findings"), list):
        return Reanalysis(final.get("id"), status, None, [], result.get("source_commit"), applied,
                          error or "The rescan did not complete.")
    if patch and not applied:
        return Reanalysis(final.get("id"), "failed", None, [], result.get("source_commit"), False,
                          "The analyzer did not confirm that the candidate patch was applied.")
    findings = [f for f in result["findings"] if isinstance(f, dict)]
    return Reanalysis(final.get("id"), status, [str(f.get("fingerprint")) for f in findings if f.get("fingerprint")],
                      findings, result.get("source_commit"), applied, None)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()
