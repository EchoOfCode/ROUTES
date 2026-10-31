import json
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

import httpx
import pytest

from routes_shared.contracts import DiscoveryResult, SourceResult
from routes_core import mapping, runner, sources, status
from routes_core.engine import EngineClient, EngineRejected, EngineUnavailable


# ------------------------------------------------------------------ runner
def test_summarise_marks_stage_done_only_after_a_later_stage_started():
    events = [{"stage": "validating", "message": "a"},
              {"stage": "discovering_pages", "message": "1 of 25", "data": {"pages_done": 1, "page_limit": 25}},
              {"stage": "discovering_pages", "message": "2 of 25", "data": {"pages_done": 2, "page_limit": 25}}]
    p = runner.summarise(events)
    assert p.current_stage == "discovering_pages"
    assert p.completed_stages == ("validating",)
    assert p.data == {"pages_done": 2, "page_limit": 25}
    assert runner.summarise([]).current_stage is None


class FakeRuns:
    def __init__(self, states):
        self.states = list(states)
        self.cancelled = 0

    def get(self, run_id):
        return self.states.pop(0) if len(self.states) > 1 else self.states[0]

    def cancel(self, run_id):
        self.cancelled += 1


def test_poll_run_reports_states_and_returns_terminal():
    client = FakeRuns([{"status": "running", "events": []}, None, {"status": "completed", "result": {}}])
    seen = []
    out = runner.poll_run(client, {"id": "r"}, deadline_seconds=60, on_state=seen.append, sleep=lambda s: None)
    assert out["status"] == "completed" and len(seen) == 2


def test_poll_run_waits_for_sandbox_cleanup():
    client = FakeRuns([{"status": "completed", "finished_at": None}, {"status": "completed", "finished_at": 12.0}])
    seen = []
    out = runner.poll_run(client, {"id": "r"}, deadline_seconds=60, on_state=seen.append, sleep=lambda s: None)
    assert out["finished_at"] == 12.0 and runner.is_cleaning_up(seen[0]) and not runner.is_cleaning_up(out)


def test_poll_run_cancels_once_and_waits_for_manager():
    client = FakeRuns([{"status": "running"}] * 3 + [{"status": "cancelled"}])
    out = runner.poll_run(client, {"id": "r"}, deadline_seconds=60, should_cancel=lambda: True, sleep=lambda s: None)
    assert out["status"] == "cancelled" and client.cancelled == 1


def test_poll_run_deadline():
    t = iter(range(0, 1000, 10))
    client = FakeRuns([{"status": "running", "events": [{"stage": "x", "message": ""}]}])
    out = runner.poll_run(client, {"id": "r"}, deadline_seconds=25, sleep=lambda s: None, clock=lambda: next(t))
    assert out["status"] == "timeout" and client.cancelled == 1 and out["events"]


# ------------------------------------------------------------------ status
@dataclass
class Step:
    kind: str
    status: str
    error: str | None = None


def test_final_status_is_honest():
    assert status.compute_final_status([Step("discovery", "completed")], cancel_requested=False) == ("completed", None)
    s, err = status.compute_final_status([Step("discovery", "completed"), Step("source", "failed", "boom")],
                                         cancel_requested=False)
    assert s == "partially_completed" and "Source: boom" in err
    assert status.compute_final_status([Step("discovery", "failed")], cancel_requested=False)[0] == "failed"
    assert status.compute_final_status([], cancel_requested=False)[0] == "failed"
    assert status.compute_final_status([Step("discovery", "completed")], cancel_requested=True)[0] == "cancelled"


@dataclass
class Ep:
    origin: str
    path: str
    details: dict | None = field(default_factory=dict)


def test_correlate_and_normalise():
    eps = [Ep("source_route", "/api/products/[id]", {"file": "app/api/products/[id]/route.ts", "line": 3}),
           Ep("js_reference", "/api/products/42"), Ep("form", "/contact")]
    assert status.correlate(eps) == 1
    assert eps[1].details["source_file"] == "app/api/products/[id]/route.ts"
    assert "source_file" not in eps[2].details


@dataclass
class A:
    status: str


def test_retention_never_removes_active():
    rows = [A("completed")] * 5 + [A("running"), A("failed"), A("completed")]
    victims = status.retention_victims(rows, 5)
    assert len(victims) == 2 and all(v.status != "running" for v in victims)


# ------------------------------------------------------------------ mapping
def test_discovery_records_dedupe_and_redact():
    result = DiscoveryResult.model_validate({
        "target_url": "https://example.com/", "hostname": "example.com",
        "pages": [{"url": "https://example.com/"}, {"url": "https://example.com/"}, {"url": "https://example.com/x", "error": "404"}],
        "forms": [{"page_url": "https://example.com/", "action": "https://example.com/login", "method": "POST",
                   "fields": [{"name": "password", "type": "password"}]}],
        "endpoints": [{"method": "POST", "url": "https://example.com/login", "path": "/login", "origin": "form",
                       "page_url": "https://example.com/", "evidence": "token=ghp_" + "a" * 36}],
        "technologies": [{"name": "Next.js", "category": "framework", "evidence": ["x-powered-by"]}],
    })
    r = mapping.discovery_records(result, {"requests": 3})
    assert len(r.pages) == 2 and r.summary["pages_failed"] == 1
    assert r.endpoints[0]["details"]["fields"][0]["name"] == "password"
    assert "ghp_" + "a" * 36 not in json.dumps(r.endpoints)
    assert r.technologies[0]["source"] == "website"


def test_source_records_fingerprints_and_redaction():
    finding = {"type": "Hardcoded Secret", "severity": "high", "confidence": "high", "title": "t", "file": "a.js",
               "line": 1, "rule_id": "routes.secrets.aws-access-key", "plain_description": "p",
               "evidence_summary": "key AKIAQWERTYUIOPASDFGH", "recommendation": "r"}
    result = SourceResult.model_validate({
        "source_kind": "zip", "support_status": "supported",
        "profile": {"framework": "Next.js", "framework_version": "15.0.0", "database_libraries": ["pg"]},
        "routes": [{"path": "/api/search", "methods": ["GET"], "file": "app/api/search/route.ts", "line": 3, "router": "app"}],
        "findings": [finding, finding],
    })
    r = mapping.source_records(result)
    assert len(r.findings) == 1 and len(r.findings[0]["fingerprint"]) == 32
    assert "AKIAQWERTYUIOPASDFGH" not in json.dumps(r.findings)
    assert {t["name"] for t in r.technologies} == {"Next.js", "pg"}
    assert r.endpoints[0]["origin"] == "source_route" and r.endpoints[0]["details"]["file"] == "app/api/search/route.ts"


# ------------------------------------------------------------------ sources
def test_classify(tmp_path):
    gh = sources.classify("https://github.com/acme/app/tree/main")
    assert (gh.kind, gh.owner, gh.repo, gh.ref) == ("github", "acme", "app", "main")
    assert sources.classify(str(tmp_path)).kind == "directory"
    z = tmp_path / "a.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("x.js", "1")
    assert sources.classify(str(z)).kind == "zip"
    (tmp_path / "notzip.zip").write_bytes(b"MZ....")
    for bad in ("https://gitlab.com/a/b", str(tmp_path / "missing"), str(tmp_path / "notzip.zip"), ""):
        with pytest.raises(sources.SourceError):
            sources.classify(bad)


def test_pack_directory_excludes_and_never_modifies(tmp_path):
    proj = tmp_path / "proj"
    (proj / "app/api").mkdir(parents=True)
    (proj / "node_modules/pkg").mkdir(parents=True)
    (proj / ".git").mkdir()
    (proj / "app/api/route.ts").write_text("export const GET = 1")
    (proj / "node_modules/pkg/index.js").write_text("x")
    (proj / ".git/config").write_text("[remote]")
    (proj / "logo.png").write_bytes(b"\x89PNG")
    before = {p: p.stat().st_mtime_ns for p in proj.rglob("*")}
    archive, report = sources.pack_directory(proj, tmp_path / "cache")
    with zipfile.ZipFile(archive) as zf:
        assert zf.namelist() == ["app/api/route.ts"]
    assert report.files == 1 and report.skipped_excluded >= 3
    assert {p: p.stat().st_mtime_ns for p in proj.rglob("*")} == before
    assert archive.parent == tmp_path / "cache"


def test_pack_directory_empty_folder_leaves_no_archive(tmp_path):
    (tmp_path / "empty").mkdir()
    with pytest.raises(sources.SourceError):
        sources.pack_directory(tmp_path / "empty", tmp_path / "cache")
    assert list((tmp_path / "cache").iterdir()) == []


# ------------------------------------------------------------------ engine
def _engine(handler):
    return EngineClient("http://engine", "t" * 32, transport=httpx.MockTransport(handler))


def test_engine_client_errors_and_auth():
    def handler(request: httpx.Request):
        assert request.headers["authorization"] == "Bearer " + "t" * 32
        if request.url.path == "/runs":
            body = json.loads(request.content)
            if body.get("target_url") == "http://169.254.169.254":
                return httpx.Response(422, json={"detail": "blocked address"})
            return httpx.Response(201, json={"id": "r1", "status": "pending"})
        if request.url.path == "/runs/gone":
            return httpx.Response(404)
        return httpx.Response(500)

    c = _engine(handler)
    assert c.start({"kind": "discovery", "target_url": "https://example.com"})["id"] == "r1"
    with pytest.raises(EngineRejected, match="blocked"):
        c.start({"kind": "discovery", "target_url": "http://169.254.169.254"})
    assert c.get("gone")["status"] == "failed"
    with pytest.raises(EngineUnavailable):
        c.health()


def test_engine_upload_streams_file(tmp_path):
    received = {}

    def handler(request: httpx.Request):
        received["body"] = request.read()
        return httpx.Response(201, json={"upload_id": "u", "size": len(received["body"]), "sha256": "x"})

    z = tmp_path / "a.zip"
    z.write_bytes(b"PK\x03\x04hello")
    assert _engine(handler).upload_zip(z)["upload_id"] == "u"
    assert received["body"] == b"PK\x03\x04hello"
