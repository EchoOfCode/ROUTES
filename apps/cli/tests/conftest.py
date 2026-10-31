"""Test fixtures: an isolated ROUTES_HOME and a scripted in-process engine.

The fake engine implements the same methods as ``routes_core.engine.EngineClient``
and replays realistic run states (events, then a result) so the CLI and TUI
are exercised end to end without Docker. Live-engine checks are in
``scripts/cli_e2e.py``.
"""

from __future__ import annotations

import threading
from pathlib import Path

import pytest

from routes_core.engine import EngineRejected, EngineUnavailable

SECRET_VALUE = "AKIAQWERTYUIOPASDFGH"
TOKEN = "github_pat_" + "T" * 60

DISCOVERY_EVENTS = [
    {"stage": "validating", "message": "Checking http://shop.test"},
    {"stage": "checking_integration", "message": "Looking for /.well-known/routes.json"},
    {"stage": "discovering_pages", "message": "Crawling", "data": {"pages_done": 0, "page_limit": 25}},
    {"stage": "discovering_pages", "message": "3 of up to 25 pages inspected", "data": {"pages_done": 3, "page_limit": 25}},
    {"stage": "inspecting_javascript", "message": "Inspecting 2 script files"},
    {"stage": "identifying_endpoints", "message": "Checking for public API specifications"},
    {"stage": "detecting_technologies", "message": "Summarising technology evidence"},
]
DISCOVERY_RESULT = {
    "target_url": "http://shop.test/", "hostname": "shop.test",
    "manifest": {"checked": True, "detected": True, "valid": True},
    "pages": [{"url": "http://shop.test/", "status_code": 200, "title": "Shop"},
              {"url": "http://shop.test/login", "status_code": 200, "is_login": True},
              {"url": "http://shop.test/gone", "status_code": 404, "error": "HTTP 404"}],
    "endpoints": [{"method": "GET", "url": "http://shop.test/api/search", "path": "/api/search",
                   "origin": "js_reference", "evidence": "fetch('/api/search')"}],
    "technologies": [{"name": "Next.js", "category": "framework", "confidence": "high", "evidence": ["x-powered-by"]}],
    "stack": {"framework": "Next.js", "confidence": "high"},
}
SOURCE_EVENTS = [
    {"stage": "retrieving_source", "message": "Retrieving source code"},
    {"stage": "extracting", "message": "Validating and extracting the ZIP archive"},
    {"stage": "extracting", "message": "4 files extracted", "data": {"files": 4}},
    {"stage": "profiling", "message": "Profiling repository"},
    {"stage": "running_static_rules", "message": "Running static security rules"},
    {"stage": "running_static_rules", "message": "Static rules reported 1 potential issue", "data": {"static_matches": 1}},
    {"stage": "analysing_structure", "message": "Parsing 3 files"},
    {"stage": "tracing_data_flow", "message": "1 route traced", "data": {"routes": 1, "sqli_flows": 1}},
]
SOURCE_RESULT = {
    "source_kind": "zip", "support_status": "supported", "support_reason": "Next.js with pg",
    "profile": {"framework": "Next.js", "framework_version": "15.0.0", "runtime": "Node.js", "database_libraries": ["pg"]},
    "routes": [{"path": "/api/search", "methods": ["GET"], "file": "app/api/search/route.ts", "line": 3, "router": "app"}],
    "findings": [
        {"type": "SQL Injection", "status": "potential", "severity": "high", "confidence": "high",
         "title": "User input used to build a SQL query", "file": "app/api/search/route.ts", "line": 6,
         "endpoint": "/api/search", "method": "GET", "rule_id": "routes.sqli.pg-tainted-query",
         "plain_description": "Input from the URL query parameter \"q\" is inserted into a database query.",
         "evidence_summary": "Untrusted q reaches pool.query() at app/api/search/route.ts:6.",
         "technical_details": {"cwe": "CWE-89", "flow": ["q = searchParams.get('q')", "sql = `...${q}`"]},
         "recommendation": "Pass user input as query parameters ($1)."},
        {"type": "Hardcoded Secret", "status": "potential", "severity": "high", "confidence": "high",
         "title": "AWS access key in source", "file": "config/aws.js", "line": 3, "rule_id": "routes.secrets.aws-access-key",
         "plain_description": "An AWS key is written in the code.",
         "evidence_summary": f"AWS key {SECRET_VALUE} in config/aws.js",
         "recommendation": "Rotate the key and load it from the environment."},
    ],
}


class FakeEngine:
    """Shared state for all FakeEngineClient instances in one test."""

    def __init__(self):
        self.lock = threading.Lock()
        self.runs: dict[str, dict] = {}
        self.specs: list[dict] = []
        self.credentials: dict[str, str] = {}
        self.uploads: list[dict] = []
        self.cancelled: list[str] = []
        self.available = True
        self.reject_discovery: str | None = None
        self.fail_source: str | None = None
        self.hold = threading.Event()   # when cleared, runs stay "running" (for cancel tests)
        self.hold.set()
        self.counter = 0

    def client(self):
        return FakeEngineClient(self)


class FakeEngineClient:
    def __init__(self, engine: FakeEngine):
        self.e = engine

    def _check(self):
        if not self.e.available:
            raise EngineUnavailable("The Sandbox Manager is not reachable at http://127.0.0.1:8190.")

    def health(self):
        self._check()
        return {"status": "ok", "docker": True, "gateway": True, "active_runs": 0}

    def put_credential(self, secret, scope):
        self._check()
        handle = f"h{len(self.e.credentials)}"
        self.e.credentials[handle] = secret
        return handle

    def upload_zip(self, path):
        self._check()
        data = Path(path).read_bytes()
        if not data.startswith(b"PK"):
            raise EngineRejected("The file is not a valid ZIP archive.")
        self.e.uploads.append({"size": len(data), "path": str(path)})
        return {"upload_id": "00000000-0000-4000-8000-%012d" % len(self.e.uploads), "size": len(data), "sha256": "x"}

    def start(self, spec):
        self._check()
        if spec["kind"] == "build_run":
            with self.e.lock:
                self.e.counter += 1
                rid = f"run{self.e.counter}"
                self.e.specs.append(dict(spec))
                self.e.runs[rid] = {"spec": spec, "build": True, "step": 0, "cancel": False}
            return {"id": rid, "kind": "build_run", "status": "pending", "phase": "CREATED",
                    "phase_history": [], "events": []}
        if spec["kind"] == "discovery" and self.e.reject_discovery:
            raise EngineRejected(self.e.reject_discovery)
        with self.e.lock:
            self.e.counter += 1
            rid = f"run{self.e.counter}"
            self.e.specs.append(dict(spec))
            events = DISCOVERY_EVENTS if spec["kind"] == "discovery" else SOURCE_EVENTS
            result = DISCOVERY_RESULT if spec["kind"] == "discovery" else SOURCE_RESULT
            self.e.runs[rid] = {"spec": spec, "events": events, "result": result, "step": 0, "cancel": False}
        return {"id": rid, "status": "pending", "events": []}

    def get(self, run_id):
        r = self.e.runs[run_id]
        if r.get("build"):
            return self._build_state(run_id, r)
        if r["cancel"]:
            return {"id": run_id, "status": "cancelled", "events": r["events"][:r["step"]], "error": "Cancelled.",
                    "finished_at": 1.0}
        if r["step"] < len(r["events"]) or not self.e.hold.is_set():
            r["step"] = min(r["step"] + 1, len(r["events"]))
            return {"id": run_id, "status": "running", "events": r["events"][:r["step"]], "finished_at": None}
        if r["spec"]["kind"] == "source" and self.e.fail_source:
            return {"id": run_id, "status": "failed", "events": r["events"], "error": self.e.fail_source,
                    "finished_at": 2.0}
        return {"id": run_id, "status": "completed", "events": r["events"], "result": r["result"],
                "network_summary": {"requests": 5, "allowed": 5, "denied": 0}, "finished_at": 2.0}

    def _build_state(self, run_id, r):
        hist = lambda names: [{"phase": n, "at": float(i)} for i, n in enumerate(names)]  # noqa: E731
        if r["cancel"]:
            names = BUILD_PHASES[:max(r["step"], 1)] + ["CANCELLED", "CLEANED_UP"]
            return {"id": run_id, "kind": "build_run", "status": "cancelled", "phase": "CLEANED_UP",
                    "phase_history": hist(names), "events": [], "error": "Cancelled.", "finished_at": 3.0,
                    "result": {"verification": "INCONCLUSIVE", "status": "cancelled", "error": "Cancelled."}}
        limit = len(BUILD_PHASES) - 2 if not self.e.hold.is_set() else len(BUILD_PHASES)
        r["step"] = min(r["step"] + 1, limit)
        names = BUILD_PHASES[:r["step"]]
        events = [{"stage": "testing", "message": "1/2 tests", "data": {"tests_total": 2, "tests_done": 1,
                                                                        "tests_failed": 0}}] if "TESTING" in names else []
        done = r["step"] == len(BUILD_PHASES)
        state = {"id": run_id, "kind": "build_run", "status": "completed" if done else "running",
                 "phase": names[-1], "phase_history": hist(names), "events": events,
                 "finished_at": 4.0 if done else None,
                 "network_summary": {"allowed": 15, "denied": 0, "destinations": ["registry.npmjs.org:443"]}}
        if done:
            state["result"] = {**BUILD_RESULT, "run_id": run_id}
        return state

    def cancel(self, run_id):
        self.e.cancelled.append(run_id)
        self.e.runs[run_id]["cancel"] = True

    def discard_credential(self, handle):
        self.e.credentials.pop(handle, None)

    def close(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        pass


BUILD_PHASES = ["CREATED", "SOURCE_READY", "DEPENDENCIES_INSTALLING", "DATABASE_STARTING", "BUILDING",
                "APPLICATION_STARTING", "TESTING", "COLLECTING_RESULTS", "COMPLETED", "CLEANED_UP"]
BUILD_RESULT = {
    "verification": "VERIFIED_RUN", "status": "completed",
    "application": {"build": "passed", "startup": "passed", "health_check": "passed"},
    "tests": {"total": 2, "passed": 2, "failed": 0, "errors": 0},
    "security": {"total": 1, "passed": 1, "failed": 0}, "functional": {"total": 1, "passed": 1, "failed": 0},
    "cases": [], "stages": {"source": {"status": "ready", "files": 12, "patch": {"applied": False}},
                            "build": {"status": "passed", "command": "npm run build"},
                            "startup": {"status": "passed", "command": "npm run start", "health": {"path": "/"}}},
    "isolation": {"build_runner": {"verdict": "isolated", "probes": [{}] * 34}},
}

@pytest.fixture()
def routes_home(tmp_path, monkeypatch):
    home = tmp_path / "routes-home"
    monkeypatch.setenv("ROUTES_HOME", str(home))
    monkeypatch.setenv("GATEWAY_DEV_ALLOW_HOSTS", "")
    monkeypatch.setenv("ROUTES_COMPOSE_FILE", str(Path(__file__).resolve().parents[3] / "docker-compose.yml"))
    return home


@pytest.fixture()
def engine(monkeypatch, routes_home):
    fake = FakeEngine()
    from routes_cli import service
    from routes_cli.context import Context

    monkeypatch.setattr(Context, "engine_client", lambda self: fake.client())
    monkeypatch.setattr(service, "DISCOVERY_DEADLINE", 30)
    original = service.AssessmentRunner.__init__

    def fast_init(self, *a, **kw):
        kw.setdefault("poll_seconds", 0.02)
        original(self, *a, **kw)

    monkeypatch.setattr(service.AssessmentRunner, "__init__", fast_init)
    monkeypatch.setattr("routes_core.buildrun.POLL_SECONDS", 0.02)
    return fake


@pytest.fixture()
def fixture_project(tmp_path) -> Path:
    root = tmp_path / "my-app"
    (root / "app/api/search").mkdir(parents=True)
    (root / "node_modules/x").mkdir(parents=True)
    (root / "app/api/search/route.ts").write_text("export async function GET(req) { return 1 }\n")
    (root / "package.json").write_text('{"dependencies": {"next": "15.0.0", "pg": "8.0.0"}}')
    (root / "node_modules/x/index.js").write_text("ignored")
    return root
