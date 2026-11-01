"""Model A, structured mode (used with the real Build & Run verifier).

Model A returns a typed remediation plan: root cause, strategy, expected
behaviour, security and functional test *scenarios*, regression risks, the
context it relied on, and optionally a few functional HTTP tests in the
ROUTES test-plan format. It does not write the security tests: those are
generated deterministically by ROUTES (routes_core.testplan) from the
finding's traced data flow, so a weak model cannot weaken the gate.

Every field is validated. A missing or invalid optional field stays None;
nothing is filled in on the model's behalf. Proposed functional tests are
schema-validated, restricted to GET/HEAD, and still have to pass on the
original application (baseline) before they are trusted.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

from pydantic import BaseModel, Field, ValidationError

from routes_shared.buildrun import TestCase
from routes_shared.redaction import redact_for_llm

from worker.llm.client import LLMClient, LLMError
from worker.llm.llm_a import LlmAResult

PROMPT_TEMPLATE_VERSION = "llm_a_plan/2026.11.1"
MAX_FUNCTIONAL_TESTS = 8

SYSTEM_PROMPT = (
    "You are a security engineer planning the fix of one confirmed vulnerability in a web application. "
    "You get the finding and a redacted code snapshot; secrets are placeholders like <SECRET_1>; copy them "
    "verbatim, never invent values.\n\n"
    "Respond with ONLY a JSON object with these fields:\n"
    '"prompt_for_fix" (string, required): precise instructions for the engineer who will rewrite the snapshot.\n'
    '"root_cause" (string): why the code is vulnerable.\n'
    '"expected_behaviour" (string): how the endpoint must behave after the fix, for normal and malicious input.\n'
    '"security_test_scenarios" (array of strings): attacks the fix must withstand.\n'
    '"functional_test_scenarios" (array of strings): normal behaviour the fix must preserve.\n'
    '"regression_risks" (array of strings): what a careless fix could break.\n'
    '"required_context" (array of strings): code outside the snapshot the fix depends on.\n'
    '"functional_tests" (array, at most 8): HTTP checks of normal behaviour, each '
    '{"id": "short-id", "name": "...", "method": "GET", "path": "/api/...", "query": {"k": "v"}, '
    '"expect_status": [200]}. Only GET requests; benign input only.\n'
    "No prose outside the JSON object."
)


class _FunctionalTest(BaseModel):
    id: str = Field(pattern=r"^[A-Za-z0-9._-]{1,40}$")
    name: str = Field(max_length=200)
    method: str = "GET"
    path: str = Field(max_length=500)
    query: dict[str, str] = Field(default_factory=dict)
    expect_status: list[int] = Field(min_length=1, max_length=10)


class _Plan(BaseModel):
    prompt_for_fix: str = Field(min_length=1, max_length=8000)
    root_cause: str | None = Field(default=None, max_length=4000)
    expected_behaviour: str | None = Field(default=None, max_length=4000)
    security_test_scenarios: list[str] | None = Field(default=None, max_length=20)
    functional_test_scenarios: list[str] | None = Field(default=None, max_length=20)
    regression_risks: list[str] | None = Field(default=None, max_length=20)
    required_context: list[str] | None = Field(default=None, max_length=20)
    functional_tests: list[dict] | None = None


@dataclass
class StructuredLlmAResult(LlmAResult):
    root_cause: str | None = None
    expected_behaviour: str | None = None
    security_test_scenarios: list[str] | None = None
    functional_test_scenarios: list[str] | None = None
    regression_risks: list[str] | None = None
    required_context: list[str] | None = None
    functional_tests: list[dict] = field(default_factory=list)   # validated TestCase dicts
    rejected_tests: list[str] = field(default_factory=list)      # why proposed tests were refused
    template_version: str = PROMPT_TEMPLATE_VERSION


def _optional(raw: dict, key: str, kind: type):
    """One optional field, kept only if it has the right type: an invalid
    field is dropped, not repaired or invented."""
    value = raw.get(key)
    if kind is str:
        return value.strip() if isinstance(value, str) and value.strip() else None
    if isinstance(value, list) and all(isinstance(v, str) for v in value):
        return [v.strip() for v in value if v.strip()][:20] or None
    return None


def _functional(raw_tests, rejected: list[str]) -> list[dict]:
    out: list[dict] = []
    if not isinstance(raw_tests, list):
        return out
    for item in raw_tests[:MAX_FUNCTIONAL_TESTS]:
        try:
            t = _FunctionalTest.model_validate(item)
            if t.method.upper() not in ("GET", "HEAD"):
                raise ValueError("only GET/HEAD functional tests are accepted")
            case = TestCase.model_validate({
                "id": f"ai-{t.id}"[:64], "name": t.name, "category": "functional",
                "request": {"method": t.method.upper(), "path": t.path, "query": t.query},
                "expect": {"status": t.expect_status},
            })
        except (ValidationError, ValueError, TypeError) as exc:
            rejected.append(f"{(item or {}).get('id', '?') if isinstance(item, dict) else '?'}: "
                            f"{str(exc).splitlines()[0][:120]}")
            continue
        out.append(case.model_dump(by_alias=True))
    return out


def call_llm_a_plan(client: LLMClient, finding: dict, snapshot) -> StructuredLlmAResult:  # noqa: ANN001
    redacted_code, snapshot_map = redact_for_llm(snapshot.code)
    user_prompt = (
        f"Finding: {finding.get('title')}\n"
        f"Rule: {finding.get('rule_id')}\n"
        f"Endpoint: {finding.get('method') or ''} {finding.get('endpoint') or 'unknown'}\n"
        f"Why it's a problem: {finding.get('plain_description')}\n"
        f"File: {snapshot.file}, lines {snapshot.start_line}-{snapshot.end_line}\n\n"
        f"Redacted code snapshot:\n```\n{redacted_code}\n```"
    )
    raw_text = client.complete([{"role": "system", "content": SYSTEM_PROMPT}, {"role": "user", "content": user_prompt}])
    try:
        raw = json.loads(raw_text)
        plan = _Plan.model_validate({"prompt_for_fix": raw.get("prompt_for_fix")})
    except (json.JSONDecodeError, ValidationError, AttributeError) as exc:
        raise LLMError(f"LLM A did not return the expected JSON shape: {str(exc).splitlines()[0][:200]}") from exc
    redacted_prompt, prompt_map = redact_for_llm(plan.prompt_for_fix)
    rejected: list[str] = []
    result = StructuredLlmAResult(
        prompt_for_fix=redacted_prompt, testbench="", redacted_snapshot_code=redacted_code,
        placeholder_map={**snapshot_map, **prompt_map},
        root_cause=_optional(raw, "root_cause", str), expected_behaviour=_optional(raw, "expected_behaviour", str),
        security_test_scenarios=_optional(raw, "security_test_scenarios", list),
        functional_test_scenarios=_optional(raw, "functional_test_scenarios", list),
        regression_risks=_optional(raw, "regression_risks", list),
        required_context=_optional(raw, "required_context", list),
        functional_tests=_functional(raw.get("functional_tests"), rejected), rejected_tests=rejected,
    )
    return result
