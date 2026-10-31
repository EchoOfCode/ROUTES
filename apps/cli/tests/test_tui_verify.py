"""/verify in the interactive interface: confirmation, live phases, cancel, token handling, results."""

from __future__ import annotations

import json

from routes_cli.renderers.buildrun import progress
from routes_cli.renderers.theme import ASCII
from routes_cli.tui.commands import complete, parse
from routes_cli.tui.modals import ConfirmModal, TokenModal
from tests.conftest import TOKEN
from tests.test_tui import make_app, type_text, wait_for

PLAN = {"tests": [{"id": "home", "name": "Home loads", "category": "health", "request": {"path": "/"},
                   "expect": {"status": [200]}}]}


def write_plan(tmp_path):
    path = tmp_path / "plan.json"
    path.write_text(json.dumps(PLAN))
    return path


def test_verify_parsing_and_completion(tmp_path, monkeypatch):
    cmd = parse('/verify ./app --tests plan.json --patch fix.diff --approve sharp,esbuild --private')
    assert cmd.name == "verify" and cmd.args == ["./app"] and "--private" in cmd.flags
    assert cmd.options == {"--tests": "plan.json", "--patch": "fix.diff", "--approve": "sharp,esbuild"}
    assert complete("/ver") == "/verify"
    assert complete("/verify ./app --te") == "/verify ./app --tests"
    (tmp_path / "plans").mkdir()
    monkeypatch.chdir(tmp_path)
    assert complete("/verify ./app --tests pla").startswith("/verify ./app --tests plans")


def test_progress_shows_only_phases_the_engine_entered():
    state = {"id": "r1", "phase_history": [{"phase": p} for p in ("CREATED", "SOURCE_READY", "DEPENDENCIES_INSTALLING",
                                                                   "BUILDING")], "events": []}
    from rich.console import Console

    from routes_cli.renderers.theme import THEME

    con = Console(width=100, record=True, color_system=None, theme=THEME)
    con.print(progress(state, ASCII, animate=False))
    text = " ".join(con.export_text().split())
    assert "+ Source snapshot ready" in text and "+ Installing dependencies" in text
    assert "- Disposable database" in text and "not required" in text   # skipped by the engine, not guessed
    assert "o Application start" in text and "Test plan" in text           # not reached yet: pending
    assert "Environment removed" not in text


async def test_verify_flow_confirmation_live_phases_and_result(engine, tmp_path, fixture_project, routes_home):
    plan = write_plan(tmp_path)
    app = make_app()
    async with app.run_test(size=(110, 44)) as pilot:
        await type_text(pilot, f'/verify "{fixture_project}" --tests "{plan}"')
        await pilot.press("enter")
        assert await wait_for(pilot, lambda: isinstance(app.screen, ConfirmModal))
        assert engine.specs == []                               # nothing starts before confirmation
        await pilot.press("tab", "enter")                       # "Build and run"
        assert await wait_for(pilot, lambda: app.view_name == "verified", 15)
        spec = engine.specs[0]
        assert spec["kind"] == "build_run" and spec["source"] == "zip" and spec["requested_by"] == "routes-tui"
        assert app.running is None
    saved = list((routes_home / "reports" / "build-runs").glob("*.json"))
    assert len(saved) == 1 and json.loads(saved[0].read_text())["result"]["verification"] == "VERIFIED_RUN"


async def test_declining_verify_starts_nothing(engine, tmp_path, fixture_project):
    plan = write_plan(tmp_path)
    app = make_app()
    async with app.run_test(size=(100, 34)) as pilot:
        await type_text(pilot, f'/verify "{fixture_project}" --tests "{plan}"')
        await pilot.press("enter")
        assert await wait_for(pilot, lambda: isinstance(app.screen, ConfirmModal))
        await pilot.press("enter")                              # focus starts on "Cancel"
        await pilot.pause(0.2)
        assert engine.specs == [] and app.running is None


async def test_invalid_plan_is_refused_before_anything_starts(engine, tmp_path, fixture_project):
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"tests": [{"id": "x", "name": "x", "request": {"path": "http://169.254.169.254/"},
                                          "expect": {}}]}))
    app = make_app()
    async with app.run_test(size=(100, 34)) as pilot:
        await type_text(pilot, f'/verify "{fixture_project}" --tests "{bad}"')
        await pilot.press("enter")
        await pilot.pause(0.3)
        assert not isinstance(app.screen, ConfirmModal) and engine.specs == []


async def test_ctrl_c_cancels_a_running_verify(engine, tmp_path, fixture_project):
    engine.hold.clear()                                         # stop before the run completes
    plan = write_plan(tmp_path)
    app = make_app()
    async with app.run_test(size=(100, 40)) as pilot:
        await type_text(pilot, f'/verify "{fixture_project}" --tests "{plan}"')
        await pilot.press("enter")
        assert await wait_for(pilot, lambda: isinstance(app.screen, ConfirmModal))
        await pilot.press("tab", "enter")
        assert await wait_for(pilot, lambda: app.running is not None and app.run_kind == "verify")
        assert await wait_for(pilot, lambda: engine.runs and engine.runs["run1"]["step"] >= 3)
        await pilot.press("ctrl+c")
        assert await wait_for(pilot, lambda: isinstance(app.screen, ConfirmModal))
        assert "build-and-run" in str(app.screen.title_text).lower()
        await pilot.press("tab", "enter")                       # "Cancel run"
        assert await wait_for(pilot, lambda: app.view_name == "verified", 15)
        assert engine.cancelled == ["run1"] and app.running is None


async def test_private_repository_token_is_hidden_and_never_stored(engine, tmp_path, routes_home):
    plan = write_plan(tmp_path)
    app = make_app()
    async with app.run_test(size=(100, 40)) as pilot:
        await type_text(pilot, f'/verify https://github.com/acme/app --tests "{plan}" --private')
        await pilot.press("enter")
        assert await wait_for(pilot, lambda: isinstance(app.screen, ConfirmModal))
        await pilot.press("tab", "enter")
        assert await wait_for(pilot, lambda: isinstance(app.screen, TokenModal))
        assert app.screen.query_one("#token").password is True
        await type_text(pilot, TOKEN)
        await pilot.press("enter")
        assert await wait_for(pilot, lambda: app.view_name == "verified", 15)
        assert engine.credentials == {"h0": TOKEN}
        assert TOKEN not in json.dumps(engine.specs) and engine.specs[0]["credential_handle"] == "h0"
    for path in routes_home.rglob("*"):
        if path.is_file():
            assert TOKEN.encode() not in path.read_bytes()


def test_failed_database_stage_shows_the_psql_error():
    from routes_cli.renderers.buildrun import failure_detail

    stages = {"database": {"schema": [{"file": "database/schema.sql", "status": "failed",
                                       "output": "psql:database/schema.sql:31: ERROR:  syntax error at or near \":\""}]}}
    text = failure_detail("database", stages)
    assert "schema.sql" in text and "syntax error" in text
    assert failure_detail("build", {"build": {"log_tail": "a\nb\nType error: x"}}).strip().endswith("Type error: x")


async def test_auto_plan_without_an_analysis_explains_what_to_run(engine, fixture_project):
    app = make_app()
    async with app.run_test(size=(100, 34)) as pilot:
        await type_text(pilot, f'/verify "{fixture_project}" --tests auto')
        await pilot.press("enter")
        await pilot.pause(0.3)
        assert not isinstance(app.screen, ConfirmModal) and engine.specs == []


def test_testplan_command_requires_an_analysis_first(routes_home, tmp_path):
    from tests.test_commands import invoke

    app_dir = tmp_path / "app"
    app_dir.mkdir()
    r = invoke("testplan", str(app_dir), "-o", str(tmp_path / "p.json"))
    assert r.exit_code == 1 and "routes analyze" in " ".join(r.output.split()) and not (tmp_path / "p.json").exists()
