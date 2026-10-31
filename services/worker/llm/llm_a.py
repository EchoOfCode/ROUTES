"""LLM A: given a finding and its snapshot, writes (a) the prompt LLM B will
receive and (b) the testbench glue code - in a single call, never shown the
real secret values (rule 1), with its own output redacted again before it is
used anywhere downstream (pipeline step 4: LLM A's output could itself echo
something sensitive back).

Rule 5, relaxed: LLM A still writes the testbench from the report and
snapshot, but its prompt must include a short fixed list of known exploit
payloads for the finding's vuln class (routes/worker/llm/payloads.py) - "must
include these, may add more based on the report." No assembly code and no
enforcement beyond the prompt; that is a deliberate, narrower scope than the
original "payloads never chosen by an LLM" wording.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from routes_shared.redaction import redact_for_llm
from routes_shared.remediation import Snapshot

from worker.llm.client import LLMClient, LLMError
from worker.llm.payloads import payloads_for

SYSTEM_PROMPT = (
    "You are a security engineer preparing a fix request for another engineer. "
    "You will be given a security finding and a redacted code snapshot - secrets "
    "are already replaced with placeholders like <SECRET_1>; copy them through "
    "verbatim if you reference them, never guess or invent what they might be.\n\n"
    "Respond with ONLY a JSON object with exactly two string fields:\n"
    '"prompt_for_fix": a clear, specific instruction describing what is wrong and '
    "how to fix it, referencing the snapshot.\n"
    '"testbench": a JS/TS test file that imports and calls the function in the '
    "snapshot - exploit-payload tests that must fail against the vulnerable code, "
    "and benign-input tests that must pass against both the vulnerable and fixed "
    "code.\nNo prose outside the JSON object."
)


@dataclass
class LlmAResult:
    prompt_for_fix: str
    testbench: str
    redacted_snapshot_code: str
    placeholder_map: dict[str, str]


def call_llm_a(client: LLMClient, finding: dict, snapshot: Snapshot) -> LlmAResult:
    redacted_code, snapshot_map = redact_for_llm(snapshot.code)
    payloads = payloads_for(finding.get("rule_id", ""))
    payload_instruction = ""
    if payloads:
        payload_list = "\n".join(f"- {p!r}" for p in payloads)
        payload_instruction = (
            f"\n\nKnown exploit payloads for this vulnerability class - your exploit "
            f"tests must include at least these; you may add more based on the "
            f"specific report:\n{payload_list}"
        )
    user_prompt = (
        f"Finding: {finding.get('title')}\n"
        f"Rule: {finding.get('rule_id')}\n"
        f"Why it's a problem: {finding.get('plain_description')}\n"
        f"File: {snapshot.file}, lines {snapshot.start_line}-{snapshot.end_line}\n\n"
        f"Redacted code snapshot:\n```\n{redacted_code}\n```"
        f"{payload_instruction}"
    )
    raw = client.complete([
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": user_prompt},
    ])
    try:
        parsed = json.loads(raw)
        prompt_for_fix = parsed["prompt_for_fix"]
        testbench = parsed["testbench"]
    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        raise LLMError(f"LLM A did not return the expected JSON shape: {exc}") from exc
    if not isinstance(prompt_for_fix, str) or not isinstance(testbench, str):
        raise LLMError("LLM A's prompt_for_fix/testbench must both be strings.")

    # Redact LLM A's own output again (pipeline step 4) before it goes
    # anywhere else - it could have echoed something sensitive back.
    redacted_prompt, prompt_map = redact_for_llm(prompt_for_fix)
    redacted_testbench, testbench_map = redact_for_llm(testbench)
    merged_map = {**snapshot_map, **prompt_map, **testbench_map}
    return LlmAResult(prompt_for_fix=redacted_prompt, testbench=redacted_testbench,
                      redacted_snapshot_code=redacted_code, placeholder_map=merged_map)
