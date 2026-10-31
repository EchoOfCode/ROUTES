from datetime import timedelta

import pytest

from routes_core.mapping import DiscoveryRecords, SourceRecords
from routes_storage import repo
from routes_storage.config import Config, engine_settings, generate_engine_env, read_env_file
from routes_storage.db import Database
from routes_storage.models import utcnow
from routes_storage.paths import home


@pytest.fixture()
def db(tmp_path, monkeypatch):
    monkeypatch.setenv("ROUTES_HOME", str(tmp_path / "rh"))
    h = home()
    h.ensure()
    database = Database(h.db)
    s = database.session()
    yield s
    s.close()
    database.close()


def _finish(db, a, statuses):
    for s in a.steps:
        s.status = statuses.get(s.kind, "completed")
    db.commit()
    return repo.finalize(db, a)


def test_one_active_assessment_per_project(db):
    p = repo.create_project(db, name="My Shop", website_url="https://shop.example", hostname="shop.example",
                            authorised=True)
    assert p.name == "my-shop" and p.authorised_at is not None
    repo.start_assessment(db, p, target_url=p.website_url, source_kind=None, source_label=None, steps=["discovery"])
    with pytest.raises(repo.StorageError, match="already in progress"):
        repo.start_assessment(db, p, target_url=p.website_url, source_kind=None, source_label=None, steps=["discovery"])
    with pytest.raises(repo.StorageError):
        repo.create_project(db, name="my shop")


def test_final_status_and_retention_keep_five(db):
    p = repo.create_project(db, name="app")
    ids = []
    for i in range(7):
        a = repo.start_assessment(db, p, target_url=None, source_kind="zip", source_label="a.zip",
                                  steps=["discovery", "source"])
        a.created_at = utcnow() + timedelta(seconds=i)
        db.commit()
        final = _finish(db, a, {"source": "failed"} if i == 6 else {})
        ids.append(a.id)
    assert final.status == "partially_completed" and "Source" in final.error
    kept = [a.id for a in repo.history(db, p)]
    assert kept == list(reversed(ids[2:])) and len(kept) == 5
    assert repo.find_project(db, "app") is not None  # project never removed by retention


def test_results_are_stored_and_findings_numbered_by_severity(db):
    p = repo.create_project(db, name="x")
    p.match_status = "confirmed"
    db.commit()
    a = repo.start_assessment(db, p, target_url="https://x.example", source_kind="zip", source_label="x.zip",
                              steps=["discovery", "source"])
    repo.save_discovery(db, a, DiscoveryRecords(
        pages=[{"url": "https://x.example/", "status_code": 200, "title": "Home", "content_type": "text/html",
                "depth": 0, "rendered": False, "is_login": False, "is_registration": False, "links_count": 1,
                "forms_count": 0, "scripts_count": 0, "error": None}],
        endpoints=[{"method": "GET", "url": "https://x.example/api/items/3", "path": "/api/items/3",
                    "origin": "js_reference", "parameters": [], "details": {}, "evidence": "fetch", "page_url": None}],
        technologies=[], summary={"pages_total": 1}, manifest_detected=True, manifest_data={"detected": True}))
    base = {"status": "potential", "confidence": "high", "title": "t", "endpoint": None, "method": None,
            "rule_id": "r", "plain_description": "p", "evidence_summary": "e", "technical_details": {},
            "recommendation": "fix"}
    repo.save_source(db, a, SourceRecords(
        analysis={"source_kind": "zip", "support_status": "supported", "support_reason": "", "framework": "Next.js",
                  "runtime": "Node.js", "profile": {}, "routes": [], "db_interactions": [], "input_sources": [],
                  "config_refs": [], "env_var_names": [], "match_evidence": [], "warnings": []},
        findings=[{**base, "type": "Weak", "severity": "low", "file": "b.js", "line": 1, "fingerprint": "f1"},
                  {**base, "type": "SQL Injection", "severity": "high", "file": "a.ts", "line": 6, "fingerprint": "f2"}],
        technologies=[{"name": "pg", "category": "database_library", "version": None, "confidence": "high",
                       "source": "repository", "evidence": []}],
        endpoints=[{"method": "GET", "url": "/api/items/[id]", "path": "/api/items/[id]", "origin": "source_route",
                    "parameters": [], "details": {"file": "app/api/items/[id]/route.ts", "line": 2}, "evidence": "",
                    "page_url": None}],
        summary={"source_support": "supported"}))
    final = _finish(db, a, {})
    assert final.status == "completed" and final.summary["correlated_endpoints"] == 1
    found = repo.findings_for(db, a)
    assert [(f.seq, f.type) for f in found] == [(1, "SQL Injection"), (2, "Weak")]
    assert repo.findings_for(db, a, severity="low")[0].seq == 2
    assert repo.latest_finished(db, p).id == a.id
    assert repo.get_assessment(db, a.id[:8]).id == a.id


def test_reconcile_fails_abandoned_runs(db):
    p = repo.create_project(db, name="y")
    a = repo.start_assessment(db, p, target_url=None, source_kind="zip", source_label="y.zip", steps=["source"])
    a.heartbeat_at = utcnow() - timedelta(minutes=10)
    db.commit()
    assert repo.reconcile(db) == 1
    db.refresh(a)
    assert a.status == "failed" and "Interrupted" in a.error


def test_config_round_trip_and_engine_env(tmp_path, monkeypatch):
    monkeypatch.setenv("ROUTES_HOME", str(tmp_path / "rh"))
    h = home()
    h.ensure()
    generate_engine_env(h.engine_env)
    env = read_env_file(h.engine_env)
    assert len(env["SANDBOX_MANAGER_TOKEN"]) >= 32 and env["GATEWAY_DEV_ALLOW_HOSTS"] == ""
    before = h.engine_env.read_text()
    generate_engine_env(h.engine_env)  # never overwrites
    assert h.engine_env.read_text() == before
    cfg = Config()
    cfg.engine.env_file = str(h.engine_env)
    cfg.ui.reduced_motion = True
    cfg.current_project = "shop"
    cfg.save(h)
    loaded = Config.load(h)
    assert loaded.ui.reduced_motion and loaded.current_project == "shop"
    es = engine_settings(loaded)
    assert es.token == env["SANDBOX_MANAGER_TOKEN"] and es.url == "http://127.0.0.1:8190"
    assert "TOKEN" not in h.config.read_text()
