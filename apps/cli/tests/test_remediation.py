"""`routes remediate`: the staged workflow end to end against a scripted engine
and scripted models (no Docker, no network).

The engine fake decides test outcomes the way the real one does - from the test
plan it was sent and whether a patch was applied - and the rescan returns the
findings of the "patched tree" the test scripts.
"""

from __future__ import annotations

import json

import httpx
import pytest
from routes_cli.remediation import llm as llm_mod

import tests.conftest as cf
from tests.test_commands import invoke

HEADER = 'import { pool } from "@/lib/db";\n\n'
HANDLER = (
    "export async function GET(req) {\n"
    '  const q = new URL(req.url).searchParams.get("q");\n'
    "  const sql = `SELECT * FROM products WHERE name = '${q}'`;\n"
    "  const r = await pool.query(sql);\n"
    "  return Response.json(r.rows);\n"
    "}\n"
)
ROUTE = HEADER + HANDLER
# The handler starts near the top of the file, so the snapshot includes the imports (lines 1-8).
FIXED = HEADER + (
    "export async function GET(req) {\n"
    '  const q = new URL(req.url).searchParams.get("q");\n'
    "  const r = await pool.query('SELECT * FROM products WHERE name = $1', [q]);\n"
    "  return Response.json(r.rows);\n"
    "}"
)
WRONG = HEADER + (
    "export async function GET(req) {\n"
    '  const q = new URL(req.url).searchParams.get("q").replace("--", "");\n'
    "  const r = await pool.query(`SELECT * FROM products WHERE name = '${q}'`);\n"
    "  return Response.json(r.rows);\n"
    "}"
)
WITH_IMPORT = 'import sqlstring from "sqlstring";\n' + FIXED
AUTH_FIXED = ('import { pool } from "@/lib/db";\nimport { auth } from "@/auth";\n\n'
              "export async function GET(req) {\n"
              "  const session = await auth();\n"
              "  if (!session?.user) return new Response('Unauthorized', { status: 401 });\n"
              + HANDLER.split("\n", 1)[1].rstrip("\n"))
NEXT_CONFIG = "module.exports = {\n  reactStrictMode: true,\n};\n"
NEXT_CONFIG_FIXED = (
    "module.exports = {\n  reactStrictMode: true,\n  async headers() {\n    return [{ source: '/:path*', headers: [\n"
    "      { key: 'Content-Security-Policy', value: \"default-src 'self'\" },\n"
    "      { key: 'X-Frame-Options', value: 'DENY' },\n    ] }];\n  },\n};")
PAGE = ("export default function Page({ html }) {\n"
        "  return <div dangerouslySetInnerHTML={{ __html: html }} />;\n}\n")
PAGE_FIXED = "export default function Page({ html }) {\n  return <div>{html}</div>;\n}"

PLAN = {"prompt_for_fix": "Use a parameterised query ($1) for q.", "root_cause": "q is interpolated into SQL.",
        "expected_behaviour": "Quotes in q are data.", "functional_tests": [
            {"id": "search-ok", "name": "search works", "method": "GET", "path": "/api/search",
             "query": {"q": "shoe"}, "expect_status": [200]},
            {"id": "bad", "name": "writes", "method": "DELETE", "path": "/api/x", "expect_status": [200]}]}


@pytest.fixture()
def app_project(tmp_path, monkeypatch):
    root = tmp_path / "shop"
    (root / "app/api/search").mkdir(parents=True)
    (root / "app/api/search/route.ts").write_text(ROUTE, newline="\n")
    (root / "app/page.tsx").write_text(PAGE, newline="\n")
    (root / "next.config.js").write_text(NEXT_CONFIG, newline="\n")
    (root / "package.json").write_text('{"dependencies": {"next": "15.0.0", "pg": "8.0.0"}}')
    result = json.loads(json.dumps(cf.SOURCE_RESULT))
    sqli = result["findings"][0]
    sqli["technical_details"]["source"] = {"kind": "query", "name": "q"}
    sqli["snapshot"] = {"file": "app/api/search/route.ts", "start_line": 3, "end_line": 8, "code": "..."}
    common = {"status": "potential", "confidence": "medium", "plain_description": "x", "evidence_summary": "x",
              "recommendation": "x"}
    result["findings"] += [
        {**common, "type": "Broken Access Control", "severity": "medium", "file": "app/api/search/route.ts",
         "line": 3, "endpoint": "/api/search", "method": "GET", "rule_id": "routes.a01.unprotected-db-route",
         "title": "Database read endpoint with no authentication check", "technical_details": {"cwe": "CWE-306"},
         "snapshot": {"file": "app/api/search/route.ts", "start_line": 3, "end_line": 8, "code": "..."}},
        {**common, "type": "Insecure Configuration", "severity": "low", "file": "next.config.js", "line": None,
         "endpoint": None, "method": None, "rule_id": "routes.config.missing-security-headers",
         "title": "Security response headers are not configured",
         "technical_details": {"missing_headers": ["content-security-policy", "x-frame-options"]}},
        {**common, "type": "Cross-Site Scripting", "severity": "medium", "file": "app/page.tsx", "line": 2,
         "endpoint": None, "method": None, "rule_id": "routes.xss.dangerously-set-inner-html",
         "title": "HTML inserted without sanitising", "technical_details": {"cwe": "CWE-79"}},
    ]
    monkeypatch.setattr(cf, "SOURCE_RESULT", result)
    return root


class Script:
    """What the engine and the models will do, in order."""

    def __init__(self, *, candidates, sandbox=(), rescans=(), baseline="reproduced", fixes="routes.sqli"):
        self.candidates = list(candidates)      # Model B replies (code)
        self.sandbox = list(sandbox)            # "pass" | "fail" per candidate build
        self.rescans = list(rescans)            # "fixed" | "present" per rescan
        self.baseline = baseline                # reproduced | not_reproduced | build_failed
        self.fixes = fixes                      # rule prefix a "fixed" rescan no longer reports
        self.prompts_b: list[str] = []
        self.specs: list[dict] = []
        self.stored: list[dict] = []            # findings of the analysed assessment (fingerprints)

    def seq(self, rule: str) -> str:
        return f"{next(f['seq'] for f in self.stored if f['rule_id'] == rule):02d}"


class RemediationEngine:
    def __init__(self, script: Script):
        self.s = script
        self.runs: dict[str, dict] = {}

    def health(self):
        return {"status": "ok"}

    def upload_zip(self, path):
        return {"upload_id": "00000000-0000-4000-8000-000000000001"}

    def start(self, spec):
        rid = f"r{len(self.runs) + 1}"
        self.s.specs.append(spec)
        self.runs[rid] = spec
        return {"id": rid, "status": "pending"}

    def get(self, rid):
        spec = self.runs[rid]
        if spec["kind"] == "build_run":
            return self._build(rid, spec)
        outcome = self.s.rescans.pop(0)
        findings = [{**f} for f in self.s.stored if outcome == "present" or not f["rule_id"].startswith(self.s.fixes)]
        return {"id": rid, "status": "completed", "finished_at": 1.0,
                "result": {"findings": findings, "patch_applied": bool(spec.get("patch"))}}

    def _build(self, rid, spec):
        tests = spec["test_plan"]["tests"]
        if spec.get("patch") is None:
            if self.s.baseline == "build_failed":
                result = {"verification": "BUILD_FAILED", "failed_stage": "build", "error": "next build failed",
                          "application": {"build": "failed"}, "cases": []}
            else:
                sec = "failed" if self.s.baseline == "reproduced" else "passed"
                cases = [{"id": t["id"], "name": t["name"], "category": t["category"],
                          "status": sec if t["category"] == "security" else
                          ("failed" if t["id"] == "ai-search-ok" else "passed")} for t in tests]
                result = {"verification": "TESTS_FAILED" if sec == "failed" else "VERIFIED_RUN", "cases": cases,
                          "application": {"build": "passed", "startup": "passed"}}
        else:
            ok = self.s.sandbox.pop(0) == "pass"
            cases = [{"id": t["id"], "name": t["name"], "category": t["category"],
                      "status": "passed" if ok or t["category"] != "security" else "failed",
                      "reasons": [] if ok else ["status 500 is in status_not"]} for t in tests]
            result = {"verification": "VERIFIED_RUN" if ok else "TESTS_FAILED", "cases": cases,
                      "application": {"build": "passed", "startup": "passed"},
                      "stages": {"source": {"patch": {"applied": True, "files": ["app/api/search/route.ts"]}}}}
        hist = [{"phase": p} for p in ("CREATED", "BUILDING", "TESTING", "COMPLETED", "CLEANED_UP")]
        return {"id": rid, "kind": "build_run", "status": "completed", "phase_history": hist, "events": [],
                "finished_at": 2.0, "result": result}

    def cancel(self, rid):
        pass

    def close(self):
        pass


@pytest.fixture()
def remediation(engine, app_project, monkeypatch):
    """Analyse the project with the regular fake engine, then switch to the
    scripted remediation engine and models."""
    r = invoke("analyze", str(app_project))
    assert r.exit_code == 0, r.output

    def setup(script: Script):
        from routes_cli.context import Context
        from routes_storage import repo

        ctx = Context.load()
        with ctx.session() as db:
            a = repo.latest_finished(db, None)
            script.stored = [{"seq": f.seq, "fingerprint": f.fingerprint, "rule_id": f.rule_id, "file": f.file, "line": f.line,
                              "endpoint": f.endpoint, "method": f.method, "title": f.title} for f in a.findings]
        monkeypatch.setattr(Context, "engine_client", lambda self: RemediationEngine(script))

        def handler(request: httpx.Request) -> httpx.Response:
            body = json.loads(request.content)
            system, user = body["messages"][0]["content"], body["messages"][1]["content"]
            if system.startswith("You are a security engineer planning"):
                content = json.dumps(PLAN)
            else:
                script.prompts_b.append(user)
                content = "```ts\n" + script.candidates.pop(0) + "\n```"
            return httpx.Response(200, json={"choices": [{"message": {"content": content}}]})

        original = llm_mod.ChatClient.__init__
        monkeypatch.setattr(llm_mod.ChatClient, "__init__",
                            lambda self, config, **kw: original(self, config, transport=httpx.MockTransport(handler)))
        for role in ("A", "B"):
            monkeypatch.setenv(f"LLM_{role}_API_KEY", "test-key")
            monkeypatch.setenv(f"LLM_{role}_ENDPOINT", f"http://llm.test/{role}")
            monkeypatch.setenv(f"LLM_{role}_MODEL", f"model-{role.lower()}")
        return script

    return setup


def _run(*args):
    r = invoke("remediate", *args, "--yes", "--json")
    return r, json.loads(r.stdout[r.stdout.index("{"):])


def test_loop_retries_with_feedback_and_verifies_the_fix(remediation, app_project, routes_home):
    s = remediation(Script(candidates=[WRONG, FIXED], sandbox=["fail", "pass"], rescans=["fixed"]))
    r, run = _run(s.seq("routes.sqli.pg-tainted-query"))
    assert r.exit_code == 0, r.output
    f = run["findings"][0]
    assert run["verdict"] == "verified_fixed" and f["resolution"] == "verified_fixed"
    # The analyzer's function bounds (3-8), widened to the top of the file so imports can be added.
    assert f["region"] == {"file": "app/api/search/route.ts", "start_line": 1, "end_line": 8, "exact": True}
    assert f["vuln_class"] == "SQL injection" and "pg_sleep" in f["runtime_check"]
    assert [a["outcome"] for a in f["attempts"]] == ["failed", "passed"]
    stages = [st for st, _ in f["stage_history"]]
    assert stages[:9] == ["preparing_context", "redacting", "analysis", "planning", "generating_tests",
                          "baseline_verification", "validating_tests", "generating_patch", "validating_patch"]
    assert "analysing_failure" in stages and "retrying" in stages and stages[-1] == "completed"
    # The baseline reproduced the vulnerability; the functional test that failed on the original was dropped,
    # and Model A's DELETE test was refused.
    assert "REPRODUCED" in f["steps"]["baseline"]["detail"]
    assert f["testbench"]["dropped_on_baseline"] == ["search works"]
    assert f["plan"]["rejected_tests"] and f["gates"] == {k: True for k in f["gates"]}
    # Attempt 2's prompt carried attempt 1's sanitised failure evidence.
    assert "previous attempt was rejected" in s.prompts_b[1] and "security" in s.prompts_b[1]
    # Baseline without a patch, two candidates with one, and a rescan of the accepted patch.
    kinds = [(sp["kind"], bool(sp.get("patch"))) for sp in s.specs]
    assert kinds == [("build_run", False), ("build_run", True), ("build_run", True), ("source", True)]
    folder = routes_home / "reports" / "remediations" / run["id"]
    patch = (folder / "combined.diff").read_text()
    assert "+  const r = await pool.query('SELECT * FROM products WHERE name = $1', [q]);" in patch
    assert (app_project / "app/api/search/route.ts").read_text() == ROUTE   # the developer's file is untouched


def test_oscillation_stops_the_loop_for_human_review(remediation):
    s = remediation(Script(candidates=[WRONG, WRONG], sandbox=["fail"]))
    r, run = _run(s.seq("routes.sqli.pg-tainted-query"))
    f = run["findings"][0]
    assert r.exit_code == 3 and f["resolution"] == "human_review" and "same candidate" in f["reason"]
    assert [a["outcome"] for a in f["attempts"]] == ["failed", "oscillation"]


def test_invalid_candidate_never_reaches_the_sandbox(remediation):
    s = remediation(Script(candidates=[WITH_IMPORT]))
    _r, run = _run(s.seq("routes.sqli.pg-tainted-query"), "--attempts", "1")
    f = run["findings"][0]
    assert f["attempts"][0]["outcome"] == "rejected" and "new imports" in f["attempts"][0]["failure"]
    assert f["resolution"] == "human_review"
    assert [sp.get("patch") for sp in s.specs] == [None]    # only the baseline ran


def test_unbuildable_app_falls_back_to_rescan_and_is_only_inconclusive(remediation):
    s = remediation(Script(candidates=[FIXED], rescans=["fixed"], baseline="build_failed"))
    r, run = _run(s.seq("routes.sqli.pg-tainted-query"))
    f = run["findings"][0]
    assert f["mode"] == "static" and f["attempts"][0]["outcome"] == "passed"
    assert f["resolution"] == "inconclusive" and r.exit_code == 3
    assert [sp["kind"] for sp in s.specs] == ["build_run", "source"]


def test_engine_unavailable_stops_before_any_model_call(remediation, monkeypatch):
    s = remediation(Script(candidates=[]))
    from routes_cli.context import Context
    from routes_core.engine import EngineUnavailable

    class Down(RemediationEngine):
        def health(self):
            raise EngineUnavailable("down")

    monkeypatch.setattr(Context, "engine_client", lambda self: Down(s))
    r = invoke("remediate", "01", "--yes")
    assert r.exit_code == 1 and "engine is not reachable" in r.output and s.prompts_b == []


def test_non_interactive_needs_ids_and_confirmation(remediation):
    remediation(Script(candidates=[]))
    assert "finding numbers or --all" in invoke("remediate").output
    assert "--yes" in invoke("remediate", "01").output
    assert "No finding 99" in invoke("remediate", "99", "--yes").output


async def test_tui_remediate_confirms_shows_the_pipeline_and_the_verdict(remediation):
    from routes_cli.tui.modals import ConfirmModal

    from tests.test_tui import make_app, type_text, wait_for

    s = remediation(Script(candidates=[WRONG, FIXED], sandbox=["fail", "pass"], rescans=["fixed"]))
    app = make_app()
    async with app.run_test(size=(140, 60)) as pilot:
        await type_text(pilot, f"/remediate {s.seq('routes.sqli.pg-tainted-query')}")
        await pilot.press("enter")
        assert await wait_for(pilot, lambda: isinstance(app.screen, ConfirmModal), 10)
        assert s.specs == [] and s.prompts_b == []           # nothing runs before confirmation
        await pilot.press("tab", "enter")                    # "Start"
        assert await wait_for(pilot, lambda: app.view_name == "remediated", 20)
        await pilot.pause(0.5)                               # let the result view mount and render
        text = app.export_screenshot().replace("&#160;", " ")
        assert "VERIFIED" in text and "FIXED" in text and "Attempt" in text
        assert "combined.diff" in str(app.query_one("#hint").render())


# ------------------------------------------------- every class through the loop
def _security_tests(s: Script) -> list[dict]:
    baseline = next(sp for sp in s.specs if sp["kind"] == "build_run" and not sp.get("patch"))
    return [t for t in baseline["test_plan"]["tests"] if t["category"] == "security"]


def test_access_control_fix_is_verified_by_an_anonymous_request(remediation):
    rule = "routes.a01.unprotected-db-route"
    s = remediation(Script(candidates=[AUTH_FIXED], sandbox=["pass"], rescans=["fixed"], fixes=rule))
    _r, run = _run(s.seq(rule))
    f = run["findings"][0]
    assert f["vuln_class"] == "Access control" and f["resolution"] == "verified_fixed", f["reason"]
    (probe,) = _security_tests(s)
    assert (probe["request"]["method"], probe["request"]["path"]) == ("GET", "/api/search")
    assert not probe["request"]["headers"] and 401 in probe["expect"]["status"]      # anonymous: no credentials
    # Importing the project's own auth helper is allowed (not a new dependency), and Model B was told
    # what the sandbox would check.
    assert "an anonymous request must be rejected" in s.prompts_b[0]
    assert '+import { auth } from "@/auth";' in f["attempts"][0]["patch"]


def test_missing_security_headers_fix_is_verified_by_a_header_check(remediation):
    rule = "routes.config.missing-security-headers"
    s = remediation(Script(candidates=[NEXT_CONFIG_FIXED], sandbox=["pass"], rescans=["fixed"], fixes=rule))
    _r, run = _run(s.seq(rule))
    f = run["findings"][0]
    assert f["vuln_class"] == "Misconfiguration" and f["resolution"] == "verified_fixed", f["reason"]
    assert f["region"] == {"file": "next.config.js", "start_line": 1, "end_line": 3, "exact": True}  # whole file
    (probe,) = _security_tests(s)
    assert probe["expect"]["headers_present"] == ["content-security-policy", "x-frame-options"]


def test_browser_side_xss_runs_the_loop_on_the_rescan_and_says_why_it_is_inconclusive(remediation):
    rule = "routes.xss.dangerously-set-inner-html"
    s = remediation(Script(candidates=[PAGE_FIXED], sandbox=["pass"], rescans=["fixed"], fixes=rule))
    r, run = _run(s.seq(rule))
    f = run["findings"][0]
    assert f["vuln_class"] == "XSS" and f["runtime_check"] is None
    assert "no runtime security test" in f["steps"]["testbench"]["detail"]
    assert "rendered in the browser" in f["steps"]["testbench"]["detail"]
    assert f["attempts"][0]["outcome"] == "passed" and f["resolution"] == "inconclusive" and r.exit_code == 3
    assert _security_tests(s) == []


def test_picker_groups_findings_by_class(remediation):
    remediation(Script(candidates=[]))
    from rich.console import Console
    from routes_cli import actions
    from routes_cli.context import Context
    from routes_cli.main import _pick_findings

    con = Console(record=True, width=160, color_system=None)
    import typer
    orig = typer.prompt
    typer.prompt = lambda *a, **k: "0"
    try:
        assert _pick_findings(con, actions.latest(Context.load())) is None
    finally:
        typer.prompt = orig
    text = con.export_text()
    for label in ("SQL injection", "XSS", "Access control", "Misconfiguration"):
        assert label in text
    assert "next.config.js" in text
