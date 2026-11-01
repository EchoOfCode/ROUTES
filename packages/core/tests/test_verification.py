"""routes_core.verification against a scripted engine client (simulated
engine responses: these test the mapping, not a sandbox)."""

from pathlib import Path

from routes_core.sources import SourceSpec
from routes_core.verification import failure_summary, parse_build_run, reanalyse, verify_build

PLAN = {"version": 1, "tests": [{"id": "sqli-01-quote", "name": "quote", "category": "security",
                                 "request": {"method": "GET", "path": "/api/products", "query": {"q": "'"}},
                                 "expect": {"status_not": [500]}}]}
SRC = SourceSpec("github", "github.com/acme/shop", owner="acme", repo="shop", ref="a" * 40)


def state(verification="TESTS_FAILED", cases=None, **extra):
    return {"id": "run-1", "status": "completed", "finished_at": 1.0, "created_at": 0.5,
            "cleanup": {"status": "complete", "errors": []},
            "result": {"verification": verification, "error": extra.get("error"), "failed_stage": extra.get("stage"),
                       "application": {"build": "passed", "startup": "passed"},
                       "stages": {"source": {"commit": "a" * 40, "patch": {"applied": extra.get("applied", False)}},
                                  "database": {"status": "ready"}},
                       "cases": cases if cases is not None else [
                           {"id": "sqli-01-quote", "name": "quote", "category": "security", "status": "failed",
                            "http_status": 500, "reasons": ["status 500 is not allowed"],
                            "response_excerpt": 'password = "hunter2hunter2"'}],
                       "isolation": {"test_runner": [{"host": "1.1.1.1", "port": 443, "ok": True}]},
                       "duration_seconds": 42.0}}


class Engine:
    def __init__(self, final):
        self.final, self.started = final, []

    def start(self, spec):
        self.started.append(spec)
        return {"id": "run-1", "status": "queued"}

    def get(self, run_id):
        return self.final

    def cancel(self, run_id):
        pass

    def upload_zip(self, path):
        return {"upload_id": "00000000-0000-0000-0000-000000000001"}


def test_build_run_evidence_is_parsed_and_sanitised():
    v = parse_build_run(state())
    assert (v.verification, v.build, v.startup, v.database, v.commit) == ("TESTS_FAILED", "passed", "passed",
                                                                           "ready", "a" * 40)
    assert not v.passed and not v.infrastructure_failure and v.cleanup["status"] == "complete"
    assert "hunter2hunter2" not in v.cases[0].excerpt
    assert "[security] quote: failed" in failure_summary(v)


def test_only_a_clean_verified_run_passes():
    ok = parse_build_run(state("VERIFIED_RUN", cases=[{"id": "x", "name": "x", "category": "security",
                                                       "status": "passed"}]))
    assert ok.passed
    errored = parse_build_run(state("VERIFIED_RUN", cases=[{"id": "x", "name": "x", "category": "security",
                                                            "status": "error"}]))
    assert not errored.passed
    empty = parse_build_run(state("VERIFIED_RUN", cases=[]))
    assert not empty.passed
    leaked = state("VERIFIED_RUN", cases=[{"id": "x", "name": "x", "category": "security", "status": "passed"}])
    leaked["result"]["isolation"]["test_runner"] = [{"host": "1.1.1.1", "port": 443, "ok": False}]
    assert not parse_build_run(leaked).passed
    assert parse_build_run(state("INCONCLUSIVE")).infrastructure_failure


def test_verify_build_submits_a_pinned_build_run_with_the_patch(tmp_path):
    engine = Engine(state(applied=True))
    v = verify_build(engine, source=SRC, plan=PLAN, patch=None, cache_dir=tmp_path, poll_seconds=0)
    spec = engine.started[0]
    assert spec["kind"] == "build_run" and spec["ref"] == "a" * 40 and spec["patch"] is None
    assert v.run_id == "run-1"


def test_reanalyse_requires_the_patch_to_be_confirmed(tmp_path):
    done = {"id": "r", "status": "completed", "finished_at": 1.0,
            "result": {"findings": [{"fingerprint": "f1"}, {"fingerprint": "f2"}], "patch_applied": True,
                       "source_commit": "a" * 40}}
    engine = Engine(done)
    r = reanalyse(engine, source=SRC, patch="--- a/x\n+++ b/x\n@@ -1 +1 @@\n-a\n+b\n", cache_dir=tmp_path,
                  poll_seconds=0)
    assert r.fingerprints == ["f1", "f2"] and engine.started[0]["kind"] == "source"
    assert engine.started[0]["patch"].startswith("--- a/x")
    done["result"]["patch_applied"] = False
    r = reanalyse(Engine(done), source=SRC, patch="x", cache_dir=tmp_path, poll_seconds=0)
    assert r.fingerprints is None and "patch" in r.error
    failed = reanalyse(Engine({"id": "r", "status": "failed", "finished_at": 1.0, "error": "boom"}), source=SRC,
                       patch=None, cache_dir=tmp_path, poll_seconds=0)
    assert failed.fingerprints is None


def test_reanalyse_refuses_sources_it_cannot_reconstruct(tmp_path):
    r = reanalyse(Engine({}), source=SourceSpec("directory", "x", path=Path(".")), patch=None, cache_dir=tmp_path)
    assert r.status == "unsupported" and r.fingerprints is None
