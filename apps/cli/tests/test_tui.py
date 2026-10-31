"""Interactive interface tests with Textual's pilot (headless)."""

from __future__ import annotations

import pytest

from routes_cli.context import Context
from routes_cli.tui.app import RoutesApp
from routes_cli.tui.commands import CommandError, complete, parse, tokenize
from routes_cli.tui.modals import ConfirmModal, MatchModal, TokenModal
from tests.conftest import TOKEN


# ------------------------------------------------------------------ parser
def test_parser_and_tokenizer():
    assert tokenize(r'/analyze "C:\My Projects\shop" --url https://x.test') == \
        ["/analyze", r"C:\My Projects\shop", "--url", "https://x.test"]
    cmd = parse("/scan https://x.test --source ./app --private")
    assert cmd.name == "scan" and cmd.args == ["https://x.test"] and cmd.options == {"--source": "./app"}
    assert "--private" in cmd.flags
    assert parse("scan https://x.test").name == "scan"          # slash optional
    assert parse("analyse ./x").name == "analyze"               # alias
    with pytest.raises(CommandError, match="Did you mean /scan"):
        parse("/scna x")
    with pytest.raises(CommandError, match="never accepted"):
        parse("/analyze https://github.com/a/b --token abc")
    with pytest.raises(CommandError, match="Unknown option"):
        parse("/scan x --rm -rf")
    for hostile in ("/scan x; rm -rf /", "/doctor && calc", "!ls", "$(whoami)"):
        try:
            cmd = parse(hostile)
        except CommandError:
            continue
        assert cmd.name in ("scan", "doctor")  # parsed as plain arguments, never executed by a shell


def test_completion(tmp_path, monkeypatch):
    assert complete("/sc") == "/scan"
    assert complete("/scan https://x --so") == "/scan https://x --source"
    assert complete("/engine u") == "/engine up"
    assert complete("/report h") == "/report html"
    assert complete("/project use sh", projects=["shop", "blog"]) == "/project use shop"
    (tmp_path / "myproject").mkdir()
    monkeypatch.chdir(tmp_path)
    assert complete("/analyze myp").startswith("/analyze myproject")


# --------------------------------------------------------------------- app
def make_app(**kw) -> RoutesApp:
    return RoutesApp(ctx=Context.load(), check_environment=kw.pop("check_environment", False), **kw)


async def type_text(pilot, text: str) -> None:
    for ch in text:
        await pilot.press("space" if ch == " " else ch)


async def wait_for(pilot, cond, timeout=10.0):
    loops = int(timeout / 0.05)
    for _ in range(loops):
        if cond():
            return True
        await pilot.pause(0.05)
    return cond()


async def test_startup_home_menu_and_prompt(engine):
    app = make_app(check_environment=True)
    async with app.run_test(size=(110, 36)) as pilot:
        await pilot.pause(0.3)
        assert app.view_name == "home"
        assert app.query_one("#menu").index == 0 and app.focused is app.query_one("#menu")
        assert await wait_for(pilot, lambda: all(v is not None for v in app.query_one("#readiness").items.values()))
        assert app.query_one("#readiness").items["Engine"][0] == "ok"
        await pilot.press("down", "down", "down", "enter")  # "View latest findings"
        await pilot.pause(0.2)
        assert app.view_name == "results"
        await pilot.press("escape")
        await type_text(pilot, "/hel")
        await pilot.press("tab")
        assert app.prompt.value == "/help"
        await pilot.press("enter")
        await pilot.pause(0.1)
        assert app.view_name == "help"


async def test_typing_from_menu_keeps_first_character(engine):
    app = make_app()
    async with app.run_test(size=(100, 30)) as pilot:
        await pilot.pause(0.2)
        await type_text(pilot, "/hist")
        assert app.prompt.value == "/hist"


async def test_history_navigation_persists(engine, routes_home):
    app = make_app()
    async with app.run_test(size=(100, 30)) as pilot:
        for line in ("/help", "/projects"):
            await type_text(pilot, line)
            await pilot.press("enter")
        await pilot.press("escape", "up")
        assert app.prompt.value == "/projects"
        await pilot.press("up")
        assert app.prompt.value == "/help"
        await pilot.press("down", "down")
        assert app.prompt.value == ""
    assert (routes_home / "history").read_text().splitlines()[-2:] == ["/help", "/projects"]


async def test_scan_flow_with_permission_live_progress_and_results(engine):
    app = make_app()
    async with app.run_test(size=(110, 40)) as pilot:
        await type_text(pilot, "/scan http://shop.test")
        await pilot.press("enter")
        assert await wait_for(pilot, lambda: isinstance(app.screen, ConfirmModal))
        await pilot.press("tab", "enter")                   # "I confirm"
        assert await wait_for(pilot, lambda: app.view_name == "results", 15)
        assert engine.specs == [{"kind": "discovery", "target_url": "http://shop.test/"}]
        model = app.model
        assert model.finished.status == "completed"
        assert model.steps["discovery"].data == {"pages_done": 3, "page_limit": 25}


async def test_declining_permission_starts_nothing(engine):
    app = make_app()
    async with app.run_test(size=(100, 30)) as pilot:
        await type_text(pilot, "/scan http://shop.test")
        await pilot.press("enter")
        assert await wait_for(pilot, lambda: isinstance(app.screen, ConfirmModal))
        await pilot.press("enter")                           # focus starts on "Cancel"
        await pilot.pause(0.2)
        assert engine.specs == [] and app.running is None


async def test_private_repo_token_modal_is_hidden_and_not_in_history(engine, routes_home):
    app = make_app()
    async with app.run_test(size=(100, 30)) as pilot:
        await type_text(pilot, "/analyze https://github.com/acme/app --private")
        await pilot.press("enter")
        assert await wait_for(pilot, lambda: isinstance(app.screen, TokenModal))
        field = app.screen.query_one("#token")
        assert field.password is True
        await type_text(pilot, TOKEN)
        await pilot.press("enter")
        assert await wait_for(pilot, lambda: app.view_name == "results", 15)
        assert engine.credentials == {"h0": TOKEN}
    assert TOKEN not in (routes_home / "history").read_text()
    for path in routes_home.rglob("*"):
        if path.is_file():
            assert TOKEN.encode() not in path.read_bytes()


async def test_ctrl_c_cancels_running_assessment(engine, fixture_project):
    engine.hold.clear()                                       # keep the run "running"
    app = make_app()
    async with app.run_test(size=(100, 34)) as pilot:
        await type_text(pilot, f'/analyze "{fixture_project}"')
        await pilot.press("enter")
        assert await wait_for(pilot, lambda: app.running is not None and app.model.steps.get("source")
                              and app.model.steps["source"].status == "running")
        await pilot.press("ctrl+c")
        assert await wait_for(pilot, lambda: isinstance(app.screen, ConfirmModal))
        await pilot.press("tab", "enter")                     # "Cancel assessment"
        assert await wait_for(pilot, lambda: app.view_name == "results", 15)
        assert engine.cancelled                                # the engine was asked to stop the sandbox
        assert app.model.finished.status == "cancelled"


async def test_double_ctrl_c_exits_when_idle(engine):
    app = make_app()
    async with app.run_test(size=(100, 30)) as pilot:
        await pilot.press("ctrl+c")
        assert app.is_running
        await pilot.press("ctrl+c")
        await pilot.pause(0.1)
    assert app.return_code in (0, None)


async def test_reduced_motion_disables_animation(engine, routes_home):
    app = RoutesApp(ctx=Context.load(no_animation=True), check_environment=False)
    async with app.run_test(size=(100, 30)) as pilot:
        await pilot.pause(0.1)
        assert app.animation_level == "none" and app.motion is False
        assert app.query_one("#logo").reveal is False


async def test_engine_offline_is_shown(engine):
    engine.available = False
    app = make_app(check_environment=True)
    async with app.run_test(size=(100, 30)) as pilot:
        assert await wait_for(pilot, lambda: app.query_one("#readiness").items["Engine"] is not None)
        state, detail = app.query_one("#readiness").items["Engine"]
        assert state == "err" and "/engine up" in detail


async def test_match_question_when_website_and_source(engine, fixture_project):
    app = make_app()
    async with app.run_test(size=(110, 40)) as pilot:
        await type_text(pilot, f'/scan http://shop.test --source "{fixture_project}"')
        await pilot.press("enter")
        assert await wait_for(pilot, lambda: isinstance(app.screen, ConfirmModal))
        await pilot.press("tab", "enter")
        assert await wait_for(pilot, lambda: isinstance(app.screen, MatchModal))
        await pilot.press("tab", "tab", "enter")              # "Yes"
        assert await wait_for(pilot, lambda: app.view_name == "results", 15)
        assert {s["kind"] for s in engine.specs} == {"discovery", "source"}
        assert len(app._findings) == 2
