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

from routes_shared.fingerprint import normalize_snippet
from routes_shared.remediation import FixConstraints, Snapshot, Testbench

from worker.fix_table import lookup_fix
from worker.gate import run_gate
from worker.llm.client import LLMClient
from worker.llm.llm_a import LlmAResult, call_llm_a
from worker.llm.llm_b import call_llm_b
from worker.sandbox.runner import SandboxFile, SandboxRunner, SandboxRunRequest, SourceRef

MAX_TESTBENCH_ATTEMPTS = 3  # 1 initial + 2 regenerations, per "regenerate (max 2)"


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


def _establish_testbench(llm_a_client: LLMClient, sandbox_runner: SandboxRunner, finding: dict,
                         snapshot: Snapshot) -> tuple[LlmAResult, Testbench] | None:
    """Calls LLM A and gates the testbench (S7), regenerating on gate
    failure up to MAX_TESTBENCH_ATTEMPTS total tries. Returns
    (LlmAResult, Testbench) once gated, or None if it never passes."""
    for _ in range(MAX_TESTBENCH_ATTEMPTS):
        llm_a_result = call_llm_a(llm_a_client, finding, snapshot)
        testbench = Testbench(path=_testbench_path(snapshot.file), content=llm_a_result.testbench)
        gate_result = run_gate(sandbox_runner, finding, snapshot, testbench)
        if gate_result.passed:
            return llm_a_result, testbench
    return None


def run_remediation_loop(*, finding: dict, snapshot: Snapshot, llm_a_client: LLMClient, llm_b_client: LLMClient,
                         sandbox_runner: SandboxRunner, source_ref: SourceRef, baseline_fingerprints: set[str],
                         max_rounds: int = 5, stagnation_rounds: int = 2,
                         should_cancel: Callable[[], bool] | None = None) -> LoopOutcome:
    established = _establish_testbench(llm_a_client, sandbox_runner, finding, snapshot)
    if established is None:
        return LoopOutcome(status="needs_human_review",
                           reason="the testbench did not pass the gate after 2 regeneration attempts")
    llm_a_result, testbench = established

    constraints = FixConstraints(file=snapshot.file, start_line=snapshot.start_line, end_line=snapshot.end_line)
    original_fingerprint = finding.get("fingerprint")
    finding_id = str(finding.get("id", ""))

    rounds: list[RoundRecord] = []
    previous_failure: str | None = None
    recent_hashes: list[str] = []

    for round_no in range(1, max_rounds + 1):
        if should_cancel is not None and should_cancel():
            return LoopOutcome(status="cancelled", reason="cancelled by request", rounds=rounds)

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
        if len(recent_hashes) >= stagnation_rounds and len(set(recent_hashes[-stagnation_rounds:])) == 1:
            record.failure_output = "oscillation: identical candidate repeated"
            rounds.append(record)
            return LoopOutcome(status="needs_human_review",
                               reason="oscillation: the same candidate was produced again", rounds=rounds)

        verify_result = sandbox_runner.run(SandboxRunRequest(
            run_id=str(uuid.uuid4()), finding_id=finding_id, round_no=round_no,
            files=[SandboxFile(path=snapshot.file, content=candidate_code)],
            testbench=SandboxFile(path=testbench.path, content=testbench.content),
        ))
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
            rounds.append(record)
            previous_failure = reason
            continue

        rescan_result = sandbox_runner.run(SandboxRunRequest(
            run_id=str(uuid.uuid4()), finding_id=finding_id, round_no=round_no,
            files=[SandboxFile(path=snapshot.file, content=candidate_code)],
            testbench=SandboxFile(path=testbench.path, content=testbench.content),
            source_ref=source_ref,
        ))
        rescan_fps = set(rescan_result.rescan_fingerprints or [])
        fingerprint_gone = original_fingerprint not in rescan_fps
        known = baseline_fingerprints | ({original_fingerprint} if original_fingerprint else set())
        new_fingerprints = sorted(rescan_fps - known)
        record.rescan_diff = {"fingerprint_gone": fingerprint_gone, "new_fingerprints": new_fingerprints}
        rounds.append(record)

        if fingerprint_gone and not new_fingerprints:
            return LoopOutcome(status="fixed", rounds=rounds)

        reason_bits = []
        if not fingerprint_gone:
            reason_bits.append("the original finding is still present after rescanning")
        if new_fingerprints:
            reason_bits.append(f"new finding(s) appeared: {new_fingerprints}")
        previous_failure = "; ".join(reason_bits)

    return LoopOutcome(status="needs_human_review", reason=f"did not succeed within {max_rounds} rounds",
                       rounds=rounds)
