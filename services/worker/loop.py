"""The remediation loop controller (S8c).

Scoped to ONE finding per job, per the explicit simplification agreed
before building this: the pipeline's cross-finding batching step (grouping
fixes from many findings into one sandbox call) was dropped in favor of the
existing per-finding job/schema (see docs/PROGRESS.md, S8 design note).
"The number of open findings has not dropped for 2 rounds" (a multi-finding
stop rule) is adapted here to single-finding granularity as oscillation:
the same candidate fix repeating STAGNATION_ROUNDS times in a row.

Per run:
  1. Establish the testbench once: call LLM A, gate it (S7) against the
     original code, regenerating via LLM A up to 2 more times on gate
     failure (3 attempts total). If it never gates, NEEDS_HUMAN_REVIEW
     naming the gate's failed_check. Once gated, the same testbench is
     reused for every round (rule 6: frozen before the fix is generated).
  2. Per round (up to MAX_ROUNDS): get a candidate fix - in round 1 from
     the deterministic known-bad -> known-good table (S10c) if an entry
     covers this rule, otherwise from LLM B (already parse/dependency/
     network validated, S6) - then verify it in the sandbox
     (every exploit test must now pass, every benign test must still
     pass), then rescan the patched tree - success (rule 4) requires all
     of: verify passed, the original fingerprint is gone from the rescan,
     and no new fingerprint appeared.
  3. Stop: success -> FIXED. The same candidate hash repeating
     STAGNATION_ROUNDS times in a row -> NEEDS_HUMAN_REVIEW (oscillation).
     MAX_ROUNDS exhausted -> NEEDS_HUMAN_REVIEW. A cancellation request
     (checked via `should_cancel` at the top of each round) -> CANCELLED.
     Otherwise the previous round's (redacted) failure detail is fed into
     the next LLM B call.
"""

from __future__ import annotations

import hashlib
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field

from routes_shared.fingerprint import finding_identity, match_reanalysis, normalize_snippet
from routes_shared.patching import unified_diff
from routes_shared.remediation import FixConstraints, Snapshot, Testbench

from worker.fix_table import lookup_fix
from worker.gate import GateResult, run_gate
from worker.llm.client import LLMClient
from worker.llm.llm_a import LlmAResult, call_llm_a
from worker.llm.llm_b import call_llm_b
from worker.sandbox.runner import SandboxFile, SandboxRunner, SandboxRunRequest, SandboxRunResult, SourceRef

MAX_TESTBENCH_ATTEMPTS = 3  # 1 initial + 2 regenerations, per "regenerate (max 2)"


class LoopObserver:
    """Hooks the job uses to persist every step as it happens. The loop
    itself stays free of database code; every hook is a no-op here. A hook
    may raise to stop the loop (for example when the worker lost its lease)."""

    def stage(self, stage: str) -> None: ...

    def testbench_generated(self, attempt: int, llm_a_result: LlmAResult, testbench: Testbench) -> None: ...

    def gate_finished(self, attempt: int, testbench: Testbench, gate_result: GateResult) -> None: ...

    def round_started(self, round_no: int) -> None: ...

    def candidate_ready(self, round_no: int, record: RoundRecord, errors: list[str]) -> list[str] | None:
        """Return extra validation problems (e.g. the candidate is not a valid
        patch within the batch's file scope): the candidate is then rejected
        before it reaches a sandbox."""

    def verified(self, round_no: int, request: SandboxRunRequest, result: SandboxRunResult) -> None: ...

    def rescanned(self, round_no: int, request: SandboxRunRequest, result: SandboxRunResult) -> None: ...

    def round_finished(self, record: RoundRecord, passed: bool) -> None: ...


@dataclass
class RoundRecord:
    round_no: int
    candidate_hash: str | None = None
    candidate_code: str | None = None
    test_results: dict = field(default_factory=dict)
    rescan_diff: dict = field(default_factory=dict)
    failure_output: str | None = None
    fix_source: str | None = None  # "llm_b" | "fix_table:<entry>"
    fix_note: str | None = None    # what a fix-table rewrite changed


@dataclass
class LoopOutcome:
    status: str  # "fixed" | "needs_human_review" | "cancelled"
    reason: str | None = None
    rounds: list[RoundRecord] = field(default_factory=list)


def _testbench_path(file: str) -> str:
    if "." in file.rsplit("/", 1)[-1]:
        base, _, ext = file.rpartition(".")
        return f"{base}.test.{ext}"
    return f"{file}.test"


def _candidate_hash(code: str) -> str:
    return hashlib.sha256(normalize_snippet(code).encode()).hexdigest()[:32]


class _Cancelled(Exception):
    pass


TestbenchFactory = Callable[[LLMClient, dict, Snapshot], "tuple[LlmAResult, Testbench]"]


def default_testbench(llm_a_client: LLMClient, finding: dict, snapshot: Snapshot) -> tuple[LlmAResult, Testbench]:
    """S7: LLM A writes a JS testbench for the snapshot's function."""
    llm_a_result = call_llm_a(llm_a_client, finding, snapshot)
    return llm_a_result, Testbench(path=_testbench_path(snapshot.file), content=llm_a_result.testbench)


def _establish_testbench(llm_a_client: LLMClient, sandbox_runner: SandboxRunner, finding: dict,
                         snapshot: Snapshot, observer: LoopObserver | None = None,
                         should_cancel: Callable[[], bool] | None = None,
                         testbench_factory: TestbenchFactory | None = None
                         ) -> tuple[LlmAResult, Testbench] | GateResult | None:
    """Calls LLM A and gates the testbench (S7), regenerating on gate
    failure up to MAX_TESTBENCH_ATTEMPTS total tries (fewer when the gate
    says regenerating cannot help). Returns (LlmAResult, Testbench) once
    gated, else the last failing GateResult."""
    observer = observer or LoopObserver()
    factory = testbench_factory or default_testbench
    last: GateResult | None = None
    for attempt in range(1, MAX_TESTBENCH_ATTEMPTS + 1):
        if should_cancel is not None and should_cancel():
            raise _Cancelled
        observer.stage("analysis")
        llm_a_result, testbench = factory(llm_a_client, finding, snapshot)
        observer.testbench_generated(attempt, llm_a_result, testbench)
        observer.stage("baseline_verification")
        gate_result = run_gate(sandbox_runner, finding, snapshot, testbench)
        observer.stage("validating_tests")
        observer.gate_finished(attempt, testbench, gate_result)
        if gate_result.passed:
            return llm_a_result, gate_result.testbench or testbench
        last = gate_result
        if not gate_result.retryable:
            break
    return last


def run_remediation_loop(*, finding: dict, snapshot: Snapshot, llm_a_client: LLMClient, llm_b_client: LLMClient,
                         sandbox_runner: SandboxRunner, source_ref: SourceRef, baseline_fingerprints: set[str],
                         max_rounds: int = 3, stagnation_rounds: int = 2,
                         should_cancel: Callable[[], bool] | None = None,
                         observer: LoopObserver | None = None, first_round: int = 1,
                         testbench_factory: TestbenchFactory | None = None,
                         baseline_identities: dict[str, tuple] | None = None) -> LoopOutcome:
    """`first_round` > 1 resumes a batch whose earlier attempts were already
    used; they still count against `max_rounds`."""
    observer = observer or LoopObserver()
    try:
        established = _establish_testbench(llm_a_client, sandbox_runner, finding, snapshot, observer, should_cancel,
                                           testbench_factory)
    except _Cancelled:
        return LoopOutcome(status="cancelled", reason="cancelled by request")
    if not isinstance(established, tuple):
        detail = f": {established.failed_check}" if established is not None and established.failed_check else ""
        return LoopOutcome(status="needs_human_review", reason=f"the testbench did not pass the gate{detail}")
    llm_a_result, testbench = established

    constraints = FixConstraints(file=snapshot.file, start_line=snapshot.start_line, end_line=snapshot.end_line)
    original_fingerprint = finding.get("fingerprint")
    finding_id = str(finding.get("id", ""))

    rounds: list[RoundRecord] = []
    previous_failure: str | None = None
    recent_hashes: list[str] = []

    for round_no in range(first_round, max_rounds + 1):
        if should_cancel is not None and should_cancel():
            return LoopOutcome(status="cancelled", reason="cancelled by request", rounds=rounds)

        if round_no > first_round:
            observer.stage("retrying")
        observer.stage("generating_patch")
        observer.round_started(round_no)
        record = RoundRecord(round_no=round_no)

        # "Prefer a lookup table of known-bad -> known-good fixes and call
        # LLM B only when no entry applies." Round 1 only: the table is
        # deterministic, so re-running it after its candidate failed would
        # produce the identical code and burn a round on a guaranteed
        # oscillation. Rounds 2+ go to LLM B with the table's failure as
        # context.
        table_hit = lookup_fix(finding.get("rule_id", ""), snapshot.code) if round_no == 1 else None
        if table_hit is not None:
            candidate_code = table_hit.fixed_code
            record.fix_source = f"fix_table:{table_hit.entry}"
            record.fix_note = table_hit.note
        else:
            llm_b_result = call_llm_b(llm_b_client, llm_a_result, snapshot, constraints,
                                      previous_failure=previous_failure)
            if not llm_b_result.valid:
                record.failure_output = "; ".join(llm_b_result.errors)
                record.fix_source = "llm_b"
                observer.stage("validating_patch")
                observer.candidate_ready(round_no, record, list(llm_b_result.errors))
                observer.stage("analysing_failure")
                observer.round_finished(record, False)
                rounds.append(record)
                previous_failure = record.failure_output
                recent_hashes = []  # an invalid response is not a repeatable candidate
                continue
            candidate_code = llm_b_result.fixed_code
            record.fix_source = "llm_b"

        candidate_hash = _candidate_hash(candidate_code)
        record.candidate_hash = candidate_hash
        record.candidate_code = candidate_code
        recent_hashes.append(candidate_hash)
        observer.stage("validating_patch")
        oscillating = len(recent_hashes) >= stagnation_rounds and len(set(recent_hashes[-stagnation_rounds:])) == 1
        problems = observer.candidate_ready(round_no, record,
                                            ["oscillation: identical candidate repeated"] if oscillating else [])
        if problems and not oscillating:
            record.failure_output = "the candidate was rejected as a patch: " + "; ".join(problems)
            previous_failure = record.failure_output
            observer.stage("analysing_failure")
            observer.round_finished(record, False)
            rounds.append(record)
            continue
        if oscillating:
            record.failure_output = "oscillation: identical candidate repeated"
            observer.stage("analysing_failure")
            observer.round_finished(record, False)
            rounds.append(record)
            return LoopOutcome(status="needs_human_review",
                               reason="oscillation: the same candidate was produced again", rounds=rounds)

        observer.stage("testing")
        candidate_patch = unified_diff(snapshot.file, snapshot.start_line, snapshot.code, candidate_code)
        verify_request = SandboxRunRequest(
            run_id=str(uuid.uuid4()), finding_id=finding_id, round_no=round_no,
            files=[SandboxFile(path=snapshot.file, content=candidate_code)],
            testbench=SandboxFile(path=testbench.path, content=testbench.content),
            patch=candidate_patch,
        )
        verify_result = sandbox_runner.run(verify_request)
        observer.verified(round_no, verify_request, verify_result)
        record.test_results = {
            "status": verify_result.status,
            "tests": [{"name": t.name, "category": t.category, "passed": t.passed, "message": t.message}
                      for t in verify_result.tests],
        }
        verify_ok = (verify_result.status != "error" and bool(verify_result.tests)
                    and all(t.passed for t in verify_result.tests))
        if not verify_ok:
            reason = verify_result.error_reason or "exploit and/or benign assertions did not pass"
            record.failure_output = reason
            observer.stage("analysing_failure")
            observer.round_finished(record, False)
            rounds.append(record)
            previous_failure = reason
            continue

        observer.stage("post_remediation_analysis")
        rescan_request = SandboxRunRequest(
            run_id=str(uuid.uuid4()), finding_id=finding_id, round_no=round_no,
            files=[SandboxFile(path=snapshot.file, content=candidate_code)],
            testbench=SandboxFile(path=testbench.path, content=testbench.content),
            source_ref=source_ref, patch=candidate_patch,
        )
        rescan_result = sandbox_runner.run(rescan_request)
        observer.rescanned(round_no, rescan_request, rescan_result)
        rescan_fps = set(rescan_result.rescan_fingerprints or [])
        fingerprint_gone = original_fingerprint not in rescan_fps
        known = baseline_fingerprints | ({original_fingerprint} if original_fingerprint else set())
        new_fingerprints = sorted(rescan_fps - known)
        if baseline_identities is not None and rescan_result.rescan_findings is not None:
            m = match_reanalysis(baseline_identities, {original_fingerprint} if original_fingerprint else set(),
                                 [(f["fingerprint"], finding_identity(f)) for f in rescan_result.rescan_findings])
            fingerprint_gone = not m["targeted_still_present"]
            new_fingerprints = m["new"]
        record.rescan_diff = {"fingerprint_gone": fingerprint_gone, "new_fingerprints": new_fingerprints}
        rounds.append(record)

        if fingerprint_gone and not new_fingerprints:
            observer.round_finished(record, True)
            return LoopOutcome(status="fixed", rounds=rounds)

        reason_bits = []
        if not fingerprint_gone:
            reason_bits.append("the original finding is still present after rescanning")
        if new_fingerprints:
            reason_bits.append(f"new finding(s) appeared: {new_fingerprints}")
        previous_failure = "; ".join(reason_bits)
        record.failure_output = previous_failure
        observer.stage("analysing_failure")
        observer.round_finished(record, False)

    return LoopOutcome(status="needs_human_review", reason=f"did not succeed within {max_rounds} rounds",
                       rounds=rounds)
