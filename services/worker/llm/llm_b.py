"""LLM B: given LLM A's prompt and the redacted snapshot, writes the fixed
code - a different model from A (rule 6). The response is validated before
real secrets are restored via the placeholder map; an invalid response never
reaches restore()."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from routes_shared.redaction import restore
from routes_shared.remediation import FixConstraints, Snapshot

from worker.llm.client import LLMClient
from worker.llm.llm_a import LlmAResult
from worker.llm.validation import validate_fix

SYSTEM_PROMPT = (
    "You are a software engineer fixing a security issue. You will be given "
    "instructions and a redacted code snapshot - secrets are placeholders like "
    "<SECRET_1>; copy them through verbatim, never invent a real value.\n\n"
    "Respond with ONLY the complete replacement code for the snapshot, as a "
    "single code block. No prose, no explanation, nothing outside the code block."
)

_CODE_FENCE_RE = re.compile(r"```[a-zA-Z]*\n(.*?)```", re.DOTALL)


@dataclass
class LlmBResult:
    fixed_code: str | None
    valid: bool
    errors: list[str] = field(default_factory=list)


def _extract_code(raw: str) -> str:
    m = _CODE_FENCE_RE.search(raw)
    return (m.group(1) if m else raw).strip()


def call_llm_b(client: LLMClient, llm_a_result: LlmAResult, snapshot: Snapshot,
               constraints: FixConstraints) -> LlmBResult:
    user_prompt = (
        f"{llm_a_result.prompt_for_fix}\n\n"
        f"Redacted snapshot to replace (file {snapshot.file}, lines "
        f"{snapshot.start_line}-{snapshot.end_line}):\n```\n{llm_a_result.redacted_snapshot_code}\n```"
    )
    raw = client.complete([
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": user_prompt},
    ])
    candidate = _extract_code(raw)
    restored_candidate = restore(candidate, llm_a_result.placeholder_map)

    errors = validate_fix(constraints.file, snapshot.code, restored_candidate,
                          forbid_new_dependencies=constraints.forbid_new_dependencies,
                          forbid_network_calls=constraints.forbid_network_calls)
    if errors:
        return LlmBResult(fixed_code=None, valid=False, errors=errors)
    return LlmBResult(fixed_code=restored_candidate, valid=True)
