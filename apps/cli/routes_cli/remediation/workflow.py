"""The CLI remediation workflow: one finding at a time, through the stages of
``routes_shared.remediation_workflow`` (the same state machine the worker uses).

Per finding::

    preparing_context ─ redacting ─ analysis ─ planning ─ generating_tests
      ─ baseline_verification ─ validating_tests
      ┌─► generating_patch ─ validating_patch ─ building ─ testing ─ post_remediation_analysis ─► verdict
      └── retrying ◄─ analysing_failure ◄──────────(any check failed, attempts left)

* Context: the exact region the analyzer recorded, read from the pinned source.
* Model A plans the fix; ROUTES generates the security tests itself
  (``routes_core.testplan``) and adds Model A's GET/HEAD functional tests.
* Baseline: the original is built and tested in the sandbox. The vulnerability
  must be *reproduced* (a security test fails) for the testbench to count;
  functional tests that fail on the original are dropped.
* Correction loop (``max_attempts``, default 3): Model B writes the region, ROUTES
  validates it and derives the diff, the engine builds and tests the patched
  copy, then re-runs the full static analysis on it. Any failure is fed back to
  Model B as sanitised evidence. The same candidate twice in a row stops the
  loop (oscillation).
* Verdict: ``decide_finding`` on the recorded evidence. ``verified_fixed`` needs
  a reproduced baseline, a passing sandbox run and a confirming rescan.

When the application cannot be built in the sandbox (or has no runtime test for
this class of finding), the loop still runs with the static rescan as its check,
but the verdict can then only be ``inconclusive``: that is reported, never hidden.

With several findings, the accepted patches are combined and checked together
(one build-and-test run and one rescan), like the worker's combined rescan.
"""

from __future__ import annotations

import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field

from routes_core.engine import EngineClient
from routes_core.testplan import generate, runtime_check, vuln_class
from routes_core.verification import (
    BuildVerification,
    failure_summary,
    reanalyse,
    verify_build,
)
from routes_shared.buildrun import PatchRejected, TestPlan, validate_patch
from routes_shared.fingerprint import finding_identity, match_reanalysis
from routes_shared.patching import unified_diff
from routes_shared.remediation_workflow import (
    EvidenceGrade,
    FindingEvidence,
    Resolution,
    Stage,
    can_transition,
    decide_finding,
    decide_run,
)

from routes_cli.remediation.llm import (
    ChatClient,
    FixPlan,
    LLMError,
    generate_patch,
    plan_fix,
    validate_candidate,
)
from routes_cli.remediation.source import RemediationSource, RemediationSourceError

DEFAULT_MAX_ATTEMPTS = 3
STAGNATION_ROUNDS = 2

# Display steps of one finding, in order, and the attempt sub-steps.
STEPS = ("context", "plan", "testbench", "baseline", "loop", "verdict")
ATTEMPT_STEPS = ("patch", "validate", "sandbox", "rescan")
BUILD_PHASES = {"CREATED", "SOURCE_READY", "DEPENDENCIES_INSTALLING", "DATABASE_STARTING", "BUILDING",
                "APPLICATION_STARTING"}


class Cancelled(Exception):
    pass


class InfrastructureError(Exception):
    pass


# ------------------------------------------------------------------- state
@dataclass
class Step:
    status: str = "pending"      # pending | running | done | warn | failed | skipped
    detail: str = ""


@dataclass
class Attempt:
    no: int
    steps: dict[str, Step] = field(default_factory=lambda: {k: Step() for k in ATTEMPT_STEPS})
    live: str = ""               # what the engine is doing right now
    outcome: str | None = None   # passed | failed | rejected | oscillation | error
    failure: str = ""
    candidate_hash: str | None = None
    patch: str = ""
    sandbox: dict | None = None
    rescan: dict | None = None
    started_at: float = field(default_factory=time.time)


@dataclass
class FindingRun:
    seq: int
    title: str
    type: str
    severity: str
    rule_id: str
    file: str
    line: int
    fingerprint: str
    max_attempts: int
    vuln_class: str = ""
    runtime_check: str | None = None     # what the runtime security test checks; None: rescan only
    stage: str = Stage.QUEUED.value
    stage_history: list[tuple[str, float]] = field(default_factory=list)
    steps: dict[str, Step] = field(default_factory=lambda: {k: Step() for k in STEPS})
    attempts: list[Attempt] = field(default_factory=list)
    mode: str = "sandbox"        # sandbox | static (no runtime verification possible)
    mode_reason: str = ""
    region: dict | None = None
    plan: dict | None = None
    testbench: dict | None = None
    baseline: dict | None = None
    resolution: str | None = None
    reason: str = ""
    gates: dict[str, bool] = field(default_factory=dict)
    accepted_patch: str = ""
    accepted_region: tuple[int, int, str] | None = None   # start, end, replacement code

    @property
    def label(self) -> str:
        return f"#{self.seq:02d} {self.title}"


@dataclass
class RemediationRun:
    id: str
    source: str
    findings: list[FindingRun]
    started_at: float = field(default_factory=time.time)
    finished_at: float | None = None
    current: int = 0
    combined: Step = field(default_factory=lambda: Step(status="skipped"))
    combined_detail: dict | None = None
    combined_patch: str = ""
    verdict: str | None = None
    verdict_reason: str = ""
    models: dict = field(default_factory=dict)
    error: str | None = None

    @property
    def active(self) -> bool:
        return self.finished_at is None

    def to_dict(self) -> dict:
        from dataclasses import asdict

        d = asdict(self)
        for f in d["findings"]:
            f.pop("accepted_region", None)
        return d


class Listener:
    """UI hooks. ``changed`` after every state change, ``log`` for a line of
    narrative (printed as-is by the plain renderer)."""

    def changed(self, run: RemediationRun) -> None: ...

    def log(self, line: str) -> None: ...


# ---------------------------------------------------------------- workflow
@dataclass
class Services:
    engine: Callable[[], EngineClient]
    model_a: ChatClient
    model_b: ChatClient
    source: RemediationSource
    cache_dir: object
    poll_seconds: float | None = None


class Workflow:
    def __init__(self, services: Services, assessment, findings: list, *, max_attempts: int = DEFAULT_MAX_ATTEMPTS,
                 listener: Listener | None = None, should_cancel: Callable[[], bool] | None = None):
        self.s = services
        self.assessment = assessment
        self.targets = findings
        self.listener = listener or Listener()
        self.should_cancel = should_cancel or (lambda: False)
        self.run = RemediationRun(
            id=time.strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:6], source=services.source.label,
            findings=[FindingRun(seq=f.seq, title=f.title, type=f.type, severity=f.severity, rule_id=f.rule_id,
                                 file=f.file or "", line=f.line or 0, fingerprint=f.fingerprint,
                                 max_attempts=max_attempts, vuln_class=vuln_class(_finding_dict(f)))
                      for f in findings],
            models={"A": services.model_a.model, "B": services.model_b.model})
        self.routes = list((assessment.source_result.routes if assessment.source_result else None) or [])
        self.baseline_identities = {f.fingerprint: finding_identity(_finding_dict(f)) for f in assessment.findings}
        self._client: EngineClient | None = None
        self.allowed_modules = _project_modules(services.source)

    # -------------------------------------------------------------- helpers
    def _changed(self) -> None:
        self.listener.changed(self.run)

    def _log(self, text: str) -> None:
        self.listener.log(text)

    def _check_cancel(self) -> None:
        if self.should_cancel():
            raise Cancelled

    def _stage(self, fr: FindingRun, stage: Stage) -> None:
        if fr.stage == stage.value:
            return
        if not can_transition(fr.stage, stage.value):
            raise RuntimeError(f"invalid remediation transition {fr.stage} -> {stage.value}")
        fr.stage = stage.value
        fr.stage_history.append((stage.value, time.time()))
        self._changed()

    def _step(self, fr: FindingRun, name: str, status: str, detail: str | None = None) -> None:
        st = fr.steps[name]
        st.status = status
        if detail is not None:
            st.detail = detail
        self._changed()

    def _astep(self, a: Attempt, name: str, status: str, detail: str | None = None) -> None:
        st = a.steps[name]
        st.status = status
        if detail is not None:
            st.detail = detail
        self._changed()

    @property
    def client(self) -> EngineClient:
        if self._client is None:
            self._client = self.s.engine()
        return self._client

    def _build(self, plan: dict, patch: str | None, on_phase: Callable[[str], None]) -> BuildVerification:
        from routes_core.buildrun import PHASE_LABELS

        def on_state(state: dict) -> None:
            hist = state.get("phase_history") or []
            phase = hist[-1]["phase"] if hist else state.get("phase") or ""
            events = state.get("events") or []
            msg = events[-1].get("message", "") if events else ""
            label = PHASE_LABELS.get(phase, phase.replace("_", " ").lower())
            self._live = f"{label}" + (f" · {msg[:70]}" if msg and phase == "TESTING" else "")
            on_phase(phase)
            self._changed()

        v = verify_build(self.client, source=self.s.source.spec, plan=plan, patch=patch,
                         cache_dir=self.s.cache_dir, requested_by="routes-cli-remediation",
                         should_cancel=self.should_cancel, on_state=on_state, poll_seconds=self.s.poll_seconds)
        if v.run_status == "cancelled" and self.should_cancel():
            raise Cancelled
        return v

    # ------------------------------------------------------------------ run
    def execute(self) -> RemediationRun:
        run = self.run
        try:
            for i, (finding, fr) in enumerate(zip(self.targets, run.findings)):
                run.current = i
                self._log(f"[{i + 1}/{len(run.findings)}] {fr.label} ({fr.file}:{fr.line})")
                self._changed()
                self._finding(finding, fr)
            self._combined()
        except Cancelled:
            for fr in run.findings:
                if fr.resolution is None:
                    self._finish(fr, FindingEvidence(cancelled=True))
            self._log("Cancelled.")
        finally:
            resolutions = [fr.resolution for fr in run.findings if fr.resolution]
            cancelled = any(fr.resolution == Resolution.CANCELLED for fr in run.findings)
            verdict, reason = decide_run(resolutions, cancelled=cancelled and not any(
                fr.resolution == Resolution.VERIFIED_FIXED for fr in run.findings))
            run.verdict, run.verdict_reason = verdict.value, reason
            run.finished_at = time.time()
            if self._client is not None:
                self._client.close()
            self.s.source.close()
            self._changed()
        return run

    def _finding(self, finding, fr: FindingRun) -> None:
        ev = FindingEvidence(evidence_grade=EvidenceGrade.SANDBOX.value)
        try:
            self._check_cancel()
            # 1. Context + redaction
            self._stage(fr, Stage.PREPARING_CONTEXT)
            self._step(fr, "context", "running", "reading the analysed code")
            region = self.s.source.region(finding)
            snap = region.snapshot
            fr.region = {"file": snap.file, "start_line": snap.start_line, "end_line": snap.end_line,
                         "exact": region.exact}
            self._stage(fr, Stage.REDACTING)
            self._step(fr, "context", "done" if region.exact else "warn",
                       f"{snap.file} lines {snap.start_line}-{snap.end_line}"
                       + ("" if region.exact else " (window around the line: re-run the analysis for exact bounds)"))

            # 2. Model A
            self._check_cancel()
            self._stage(fr, Stage.ANALYSIS)
            self._step(fr, "plan", "running", f"Model A ({self.s.model_a.model}) is analysing the root cause")
            plan = plan_fix(self.s.model_a, {**_finding_dict(finding), "vuln_class": fr.vuln_class}, snap)
            self._stage(fr, Stage.PLANNING)
            fr.plan = plan.summary()
            self._step(fr, "plan", "done", _short(plan.root_cause or plan.prompt_for_fix, 110)
                       + (f" · {plan.secrets_redacted} secret(s) redacted" if plan.secrets_redacted else ""))
            self._log(f"  Model A: {_short(plan.root_cause or plan.prompt_for_fix, 160)}")

            # 3. Testbench
            self._check_cancel()
            self._stage(fr, Stage.GENERATING_TESTS)
            self._step(fr, "testbench", "running", "generating security and functional tests")
            test_plan = self._testbench(finding, fr, plan)

            # 4. Baseline on the original code
            self._check_cancel()
            self._stage(fr, Stage.BASELINE_VERIFICATION)
            frozen = self._baseline(fr, test_plan, ev)
            self._stage(fr, Stage.VALIDATING_TESTS)

            # 5. Correction loop
            self._loop(finding, fr, snap, plan, frozen, ev)
        except Cancelled:
            raise
        except (RemediationSourceError, LLMError) as exc:
            ev.human_review_reason = None
            ev.infrastructure_error = str(exc)
            self._fail_running_step(fr, str(exc))
            self._log(f"  stopped: {exc}")
        except InfrastructureError as exc:
            ev.infrastructure_error = str(exc)
            self._fail_running_step(fr, str(exc))
            self._log(f"  stopped: {exc}")
        self._finish(fr, ev)

    def _fail_running_step(self, fr: FindingRun, detail: str) -> None:
        for name in STEPS:
            if fr.steps[name].status == "running":
                self._step(fr, name, "failed", _short(detail, 160))
        for a in fr.attempts:
            for name in ATTEMPT_STEPS:
                if a.steps[name].status == "running":
                    self._astep(a, name, "failed", _short(detail, 120))
                    a.outcome = a.outcome or "error"

    # ------------------------------------------------------------ testbench
    def _testbench(self, finding, fr: FindingRun, plan: FixPlan) -> dict:
        fd = _finding_dict(finding)
        gen = generate(self.routes, [fd])
        fr.runtime_check, no_check_reason = runtime_check(fd, self.routes)
        tests = []
        for t in gen.plan["tests"]:
            if t["category"] == "security":
                t = {**t, "id": f"f{fr.seq:02d}-{t['id']}"[:64]}
            tests.append(t)
        ids = {t["id"] for t in tests}
        tests += [t for t in plan.functional_tests if t["id"] not in ids]
        test_plan = {**gen.plan, "tests": tests}
        TestPlan.model_validate(test_plan)
        counts = _counts(tests)
        fr.testbench = {"tests": len(tests), **counts, "notes": gen.notes[:5],
                        "rejected_model_tests": plan.rejected_tests}
        detail = ", ".join(f"{n} {k}" for k, n in counts.items())
        if counts.get("security"):
            self._step(fr, "testbench", "done", f"{detail} · runtime check: {fr.runtime_check}")
        else:
            fr.mode_reason = f"there is no runtime security test ({no_check_reason})"
            self._step(fr, "testbench", "warn", f"{detail} · no runtime security test: {no_check_reason}; the "
                                                "static rescan is the security check")
        return test_plan

    # ------------------------------------------------------------- baseline
    def _baseline(self, fr: FindingRun, test_plan: dict, ev: FindingEvidence) -> dict | None:
        """Returns the frozen test plan for candidates, or None in static mode."""
        self._step(fr, "baseline", "running", "building the ORIGINAL code in the sandbox")
        self._live = ""

        def on_phase(_p: str) -> None:
            fr.steps["baseline"].detail = f"original code · {self._live}" if self._live else "original code"

        v = self._build(test_plan, None, on_phase)
        fr.baseline = _build_summary(v)
        if v.verification == "BUILD_FAILED" or v.verification == "DYNAMIC_VERIFICATION_UNSUPPORTED" \
                or v.infrastructure_failure:
            why = {"BUILD_FAILED": f"the original application did not build/start in the sandbox "
                                   f"({v.failed_stage or 'build'}: {_short(v.error or '', 100)})",
                   "DYNAMIC_VERIFICATION_UNSUPPORTED": "dynamic verification is not supported for this project"
                   }.get(v.verification, f"the sandbox could not run the original ({_short(v.error or '', 100)})")
            fr.mode, fr.mode_reason = "static", why
            self._step(fr, "baseline", "warn", f"{why} → static rescan only")
            self._log(f"  baseline: {why}; continuing with static rescans only")
            return None
        security = [c for c in v.cases if c.category == "security"]
        reproduced = [c for c in security if c.status == "failed"]
        ev.testbench_validated = bool(security)
        ev.baseline_reproduced = bool(reproduced)
        keep_ids = {c.id for c in v.cases if c.category == "security" or c.status == "passed"}
        dropped = [c.name for c in v.cases if c.id not in keep_ids]
        frozen = {**test_plan, "tests": [t for t in test_plan["tests"] if t["id"] in keep_ids]}
        fr.testbench = {**(fr.testbench or {}), "dropped_on_baseline": dropped, "frozen": len(frozen["tests"])}
        if not frozen["tests"]:
            fr.mode, fr.mode_reason = "static", "no test passed on the original application"
            self._step(fr, "baseline", "warn", "no usable test on the original → static rescan only")
            return None
        if reproduced:
            detail = f"vulnerability REPRODUCED: {len(reproduced)}/{len(security)} security test(s) fail on the original"
            status = "done"
        elif security:
            detail = "the original passed every security test: the vulnerability was NOT reproduced"
            fr.mode_reason = "the baseline did not reproduce the vulnerability, so the tests cannot prove a fix"
            status = "warn"
        else:
            detail = "the original builds and runs (regression baseline only)"
            status = "warn"
        if dropped:
            detail += f" · {len(dropped)} functional test(s) dropped (fail on the original)"
        self._step(fr, "baseline", status, detail)
        self._log(f"  baseline: {detail}")
        return frozen

    # ---------------------------------------------------------- correction
    def _loop(self, finding, fr: FindingRun, snap, plan: FixPlan, frozen: dict | None, ev: FindingEvidence) -> None:
        original_file = self.s.source.read(snap.file)
        previous_failure: str | None = None
        hashes: list[str] = []
        self._step(fr, "loop", "running", f"attempt 1 of {fr.max_attempts}")
        for no in range(1, fr.max_attempts + 1):
            self._check_cancel()
            if no > 1:
                self._stage(fr, Stage.RETRYING)
            self._stage(fr, Stage.GENERATING_PATCH)
            a = Attempt(no=no)
            fr.attempts.append(a)
            fr.steps["loop"].detail = f"attempt {no} of {fr.max_attempts}"
            self._log(f"  attempt {no}/{fr.max_attempts}")

            # Model B
            self._astep(a, "patch", "running", f"Model B ({self.s.model_b.model}) is writing the fix")
            cand = generate_patch(self.s.model_b, plan, snap, previous_failure=previous_failure,
                                  verification=fr.runtime_check, allowed_modules=self.allowed_modules)
            a.candidate_hash = cand.hash
            self._astep(a, "patch", "done", f"{len(cand.code.splitlines())} lines")

            # Validation
            self._stage(fr, Stage.VALIDATING_PATCH)
            self._astep(a, "validate", "running")
            hashes.append(cand.hash)
            if len(hashes) >= STAGNATION_ROUNDS and len(set(hashes[-STAGNATION_ROUNDS:])) == 1:
                a.outcome, a.failure = "oscillation", "Model B returned the same candidate again"
                self._astep(a, "validate", "failed", a.failure)
                self._stage(fr, Stage.ANALYSING_FAILURE)
                ev.oscillation = True
                ev.human_review_reason = "The fix generator repeated the same candidate; a person needs to decide."
                self._log(f"    ✗ {a.failure} (oscillation) → stopping the loop")
                self._step(fr, "loop", "failed", f"oscillation after {no} attempt(s)")
                return
            candidate_file = _replace_region(original_file, snap.start_line, snap.end_line, cand.code)
            problems = validate_candidate(snap.file, original_file, candidate_file, snap.code, cand.code,
                                          allowed_modules=self.allowed_modules)
            diff = _line_endings_of(original_file, unified_diff(snap.file, snap.start_line, snap.code, cand.code)) \
                if not problems else ""
            if not problems:
                try:
                    validate_patch(diff)
                except PatchRejected as exc:
                    problems = [f"The derived patch is invalid: {exc}"]
            a.patch = diff
            if problems:
                a.outcome, a.failure = "rejected", "; ".join(problems)
                self._astep(a, "validate", "failed", _short(a.failure, 120))
                for k in ("sandbox", "rescan"):
                    self._astep(a, k, "skipped")
                self._stage(fr, Stage.ANALYSING_FAILURE)
                previous_failure = "The candidate was rejected before testing: " + a.failure
                self._log(f"    ✗ rejected: {a.failure}")
                continue
            changed = sum(1 for ln in diff.splitlines() if ln[:1] in "+-" and not ln.startswith(("+++", "---")))
            self._astep(a, "validate", "done", f"diff OK · {changed} line(s) changed")

            # Sandbox build + tests on the patched copy
            self._check_cancel()
            if frozen is None:
                self._stage(fr, Stage.TESTING)
                self._astep(a, "sandbox", "skipped", fr.mode_reason)
            else:
                self._stage(fr, Stage.BUILDING)
                self._astep(a, "sandbox", "running", "building the patched copy")
                self._live = ""

                def on_phase(phase: str, a=a) -> None:
                    if phase not in BUILD_PHASES and fr.stage == Stage.BUILDING.value:
                        self._stage(fr, Stage.TESTING)
                    a.steps["sandbox"].detail = self._live

                v = self._build(frozen, diff, on_phase)
                a.sandbox = _build_summary(v)
                if v.infrastructure_failure:
                    raise InfrastructureError(f"The sandbox could not verify the candidate ({v.verification}): "
                                              f"{_short(v.error or 'no detail', 160)}")
                if not v.patch_applied:
                    raise InfrastructureError("The engine did not confirm that the candidate patch was applied.")
                if not v.passed:
                    a.outcome, a.failure = "failed", failure_summary(v)
                    passed = sum(1 for c in v.cases if c.status == "passed")
                    detail = (f"{v.verification}: {passed}/{len(v.cases)} tests passed" if v.cases
                              else f"{v.verification}: {_short(v.error or '', 90)}")
                    self._astep(a, "sandbox", "failed", detail)
                    self._astep(a, "rescan", "skipped")
                    self._stage(fr, Stage.ANALYSING_FAILURE)
                    previous_failure = a.failure
                    self._log(f"    ✗ sandbox: {detail}")
                    continue
                if fr.stage == Stage.BUILDING.value:
                    self._stage(fr, Stage.TESTING)
                self._astep(a, "sandbox", "done", f"built, started · {len(v.cases)}/{len(v.cases)} tests passed")
                ev.verification_passed = True

            # Rescan of the patched tree
            self._check_cancel()
            self._stage(fr, Stage.POST_REMEDIATION_ANALYSIS)
            self._astep(a, "rescan", "running", "full static analysis of the patched code")
            outcome = self._rescan(diff, {fr.fingerprint})
            a.rescan = outcome
            ev.reanalysis_ran = True
            ev.reanalysis_fingerprint_gone = not outcome["targeted_still_present"]
            ev.reanalysis_new_findings = len(outcome["new"])
            if outcome["targeted_still_present"] or outcome["new"]:
                bits = []
                if outcome["targeted_still_present"]:
                    bits.append("the analyzer still reports the original finding in the patched code")
                if outcome["new"]:
                    bits.append(f"the patch introduced {len(outcome['new'])} new finding(s): "
                                + "; ".join(outcome["new_titles"][:3]))
                a.outcome, a.failure = "failed", "; ".join(bits)
                self._astep(a, "rescan", "failed", _short(a.failure, 120))
                self._stage(fr, Stage.ANALYSING_FAILURE)
                previous_failure = "Static re-analysis of the patched code: " + a.failure
                self._log(f"    ✗ rescan: {a.failure}")
                continue
            self._astep(a, "rescan", "done", "finding gone · no new findings")
            a.outcome = "passed"
            fr.accepted_patch = diff
            fr.accepted_region = (snap.start_line, snap.end_line, cand.code)
            self._step(fr, "loop", "done", f"passed on attempt {no} of {fr.max_attempts}")
            self._log(f"    ✓ attempt {no} passed every check")
            if frozen is None or not ev.baseline_reproduced:
                ev.unsupported_reason = (f"The patch passed every check that could run, but {fr.mode_reason}, so "
                                         "the fix is not proven by a runtime test.")
            return
        ev.attempts_exhausted = True
        ev.human_review_reason = (f"Every allowed patch attempt ({fr.max_attempts}) was used without passing all "
                                  "checks.")
        self._step(fr, "loop", "failed", f"{fr.max_attempts} attempt(s) used, none passed")

    def _rescan(self, patch: str, targeted: set[str]) -> dict:
        r = reanalyse(self.client, source=self.s.source.rescan_spec(), patch=patch, cache_dir=self.s.cache_dir,
                      should_cancel=self.should_cancel, poll_seconds=self.s.poll_seconds or 2.0)
        if r.status == "cancelled" and self.should_cancel():
            raise Cancelled
        if r.fingerprints is None:
            raise InfrastructureError(f"The rescan did not complete: {r.error or r.status}")
        after = [(str(f.get("fingerprint")), finding_identity(f)) for f in r.findings if f.get("fingerprint")]
        m = match_reanalysis(self.baseline_identities, targeted, after)
        titles = {str(f.get("fingerprint")): f"{f.get('title')} ({f.get('file')}:{f.get('line')})" for f in r.findings}
        return {"run_id": r.run_id, "findings_after": len(after), "resolved": m["resolved"],
                "remaining": len(m["remaining"]), "new": m["new"], "new_titles": [titles.get(fp, fp) for fp in m["new"]],
                "targeted_still_present": m["targeted_still_present"]}

    # -------------------------------------------------------------- verdict
    def _finish(self, fr: FindingRun, ev: FindingEvidence) -> None:
        decision = decide_finding(ev)
        fr.resolution, fr.reason, fr.gates = decision.resolution.value, decision.reason, decision.gates
        if fr.resolution not in (Resolution.VERIFIED_FIXED, Resolution.INCONCLUSIVE):
            fr.accepted_patch, fr.accepted_region = "", None
        terminal = {Resolution.VERIFIED_FIXED: Stage.COMPLETED, Resolution.INCONCLUSIVE: Stage.INCONCLUSIVE,
                    Resolution.FAILED: Stage.FAILED, Resolution.CANCELLED: Stage.CANCELLED}.get(
            decision.resolution, Stage.HUMAN_REVIEW)
        if terminal is Stage.COMPLETED and fr.stage != Stage.POST_REMEDIATION_ANALYSIS.value:
            terminal = Stage.INCONCLUSIVE    # defensive: only a confirmed rescan may complete
        if can_transition(fr.stage, terminal.value):
            self._stage(fr, terminal)
        for name in STEPS[:-1]:
            if fr.steps[name].status in ("pending", "running"):
                self._step(fr, name, "skipped" if fr.steps[name].status == "pending" else "failed")
        status = {"verified_fixed": "done", "inconclusive": "warn", "cancelled": "skipped"}.get(fr.resolution, "failed")
        self._step(fr, "verdict", status, f"{fr.resolution.upper().replace('_', ' ')} · {fr.reason}")
        self._log(f"  verdict: {fr.resolution} - {fr.reason}")

    # ------------------------------------------------------------- combined
    def _combined(self) -> None:
        run = self.run
        accepted = [fr for fr in run.findings if fr.accepted_region]
        run.combined_patch = _combine(self.s.source, accepted) if accepted else ""
        if len(accepted) < 2:
            return
        self._check_cancel()
        run.combined = Step("running", f"checking the {len(accepted)} accepted patches together")
        self._log(f"Combined check of {len(accepted)} patches")
        self._changed()
        problems: list[str] = []
        sandboxed = [fr for fr in accepted if fr.mode == "sandbox"]
        detail: dict = {}
        try:
            if sandboxed:
                plan = _union_plans(self.routes, self.targets, accepted)
                self._live = ""

                def on_phase(_p: str) -> None:
                    run.combined.detail = f"build & test of the combined patch · {self._live}"

                v = self._build(plan, run.combined_patch, on_phase)
                detail["sandbox"] = _build_summary(v)
                if not v.passed:
                    problems.append("the combined patch did not pass the sandbox tests: " + _short(failure_summary(v), 200))
            run.combined.detail = "rescan of the combined patch"
            self._changed()
            outcome = self._rescan(run.combined_patch, {fr.fingerprint for fr in accepted})
            detail["rescan"] = outcome
            if outcome["targeted_still_present"] or outcome["new"]:
                problems.append("the combined rescan does not confirm the fixes")
        except InfrastructureError as exc:
            problems.append(str(exc))
        run.combined_detail = detail
        if problems:
            run.combined = Step("failed", "; ".join(problems))
            for fr in accepted:
                fr.resolution = Resolution.HUMAN_REVIEW.value
                fr.reason = ("Each patch passed on its own, but the patches combined did not: "
                             + "; ".join(problems))
                fr.steps["verdict"] = Step("failed", f"HUMAN REVIEW · {fr.reason}")
            self._log(f"  ✗ combined: {'; '.join(problems)}")
        else:
            run.combined = Step("done", "the combined patch builds, passes every test and the rescan confirms it")
            self._log("  ✓ combined patch confirmed")
        self._changed()

    _live: str = ""


# ------------------------------------------------------------------ helpers
def _finding_dict(f) -> dict:
    return {"id": f.seq, "type": f.type, "status": f.status, "title": f.title, "file": f.file, "line": f.line,
            "endpoint": f.endpoint, "method": f.method, "rule_id": f.rule_id, "fingerprint": f.fingerprint,
            "plain_description": f.plain_description, "recommendation": f.recommendation,
            "technical_details": f.technical_details or {}}


def _project_modules(source: RemediationSource) -> set[str]:
    """Packages the project already depends on: importing them is not a new dependency."""
    import json

    try:
        pkg = json.loads(source.read("package.json"))
    except (RemediationSourceError, ValueError, OSError):
        return set()
    out: set[str] = set()
    for key in ("dependencies", "devDependencies", "peerDependencies"):
        if isinstance(pkg.get(key), dict):
            out.update(pkg[key])
    return out


def _short(text: str, n: int) -> str:
    text = " ".join((text or "").split())
    return text if len(text) <= n else text[:n - 1] + "…"


def _counts(tests: list[dict]) -> dict[str, int]:
    out: dict[str, int] = {}
    for t in tests:
        out[t["category"]] = out.get(t["category"], 0) + 1
    return dict(sorted(out.items(), key=lambda kv: ("security", "functional", "edge", "health").index(kv[0])))


def _build_summary(v: BuildVerification) -> dict:
    return {"run_id": v.run_id, "verification": v.verification, "build": v.build, "startup": v.startup,
            "database": v.database, "patch_applied": v.patch_applied, "error": v.error, "failed_stage": v.failed_stage,
            "commit": v.commit, "duration_seconds": v.duration_seconds,
            "cases": [{"id": c.id, "name": c.name, "category": c.category, "status": c.status,
                       "reasons": c.reasons[:3]} for c in v.cases],
            "isolation_violations": v.isolation_violations,
            "cleanup": (v.cleanup or {}).get("status") if isinstance(v.cleanup, dict) else v.cleanup}


def _line_endings_of(content: str, diff: str) -> str:
    """Give the diff's context/removed/added lines the file's own line endings.

    A file checked out with CRLF (Git on Windows) only matches a patch whose lines
    end in CRLF too; the sandbox applies patches strictly, without whitespace fuzz.
    Header and hunk lines stay LF, as `git apply` expects."""
    if "\r\n" not in content:
        return diff
    out = []
    for line in diff.split("\n"):
        body = line[:1] in (" ", "-", "+") and not line.startswith(("--- ", "+++ "))
        out.append(line + "\r" if body and not line.endswith("\r") else line)
    return "\n".join(out)


def _split(content: str) -> tuple[list[str], bool]:
    text = content.replace("\r\n", "\n")
    trailing = text.endswith("\n")
    lines = text.split("\n")
    if trailing:
        lines = lines[:-1]
    return lines, trailing


def _replace_region(content: str, start: int, end: int, code: str) -> str:
    lines, trailing = _split(content)
    lines[start - 1:end] = code.rstrip("\n").split("\n")
    return "\n".join(lines) + ("\n" if trailing else "")


def _combine(source: RemediationSource, accepted: list[FindingRun]) -> str:
    """One diff with every accepted region replacement, per file. Overlapping
    regions keep the first finding's patch only."""
    by_file: dict[str, list[FindingRun]] = {}
    for fr in accepted:
        by_file.setdefault(fr.file, []).append(fr)
    parts: list[str] = []
    for file, frs in by_file.items():
        original = source.read(file)
        lines, _trailing = _split(original)
        taken: list[tuple[int, int]] = []
        chosen = []
        for fr in frs:
            s, e, _ = fr.accepted_region
            if any(not (e < ts or s > te) for ts, te in taken):
                fr.reason += " (overlaps another finding's patch; apply it separately)"
                continue
            taken.append((s, e))
            chosen.append(fr)
        new_lines = list(lines)
        for fr in sorted(chosen, key=lambda x: x.accepted_region[0], reverse=True):
            s, e, code = fr.accepted_region
            new_lines[s - 1:e] = code.rstrip("\n").split("\n")
        parts.append(_line_endings_of(original, unified_diff(file, 1, "\n".join(lines), "\n".join(new_lines))))
    return "".join(parts)


def _union_plans(routes: list[dict], targets: list, accepted: list[FindingRun]) -> dict:
    seqs = {fr.seq for fr in accepted}
    findings = [_finding_dict(f) for f in targets if f.seq in seqs]
    gen = generate(routes, findings)
    TestPlan.model_validate(gen.plan)
    return gen.plan
