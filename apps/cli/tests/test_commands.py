"""Direct-command tests (Typer) against an isolated home and the fake engine."""

from __future__ import annotations

import json
import zipfile

import pytest
from typer.testing import CliRunner

from routes_cli.main import app
from tests.conftest import SECRET_VALUE, TOKEN

runner = CliRunner()


def invoke(*args, input=None):
    return runner.invoke(app, list(args), input=input, catch_exceptions=False)


def test_version_and_help_without_tty(routes_home):
    assert invoke("--version").output.strip() == "routes 0.2.0"
    out = invoke().output  # not a TTY: prints help instead of opening the interface
    assert "Usage" in out and "scan" in out and "analyze" in out


def test_init_creates_home(routes_home):
    out = invoke("init").output
    assert "Initialised" in out
    assert (routes_home / "routes.db").exists() and (routes_home / "config.toml").exists()
    for d in ("reports", "cache", "logs"):
        assert (routes_home / d).is_dir()


def test_scan_requires_permission_non_interactively(engine):
    r = invoke("scan", "https://shop.test")
    assert r.exit_code == 1 and "--authorised" in r.output
    assert engine.specs == []


@pytest.mark.parametrize("url", ["http://169.254.169.254/", "http://127.0.0.1/", "http://10.0.0.5/",
                                 "ftp://shop.test/", "http://user:pw@shop.test/", "http://shop.test:22/"])
def test_scan_rejects_unsafe_targets_before_contacting_engine(engine, url):
    r = invoke("scan", url, "--authorised")
    assert r.exit_code == 1
    assert engine.specs == []


def test_scan_end_to_end(engine):
    r = invoke("scan", "http://shop.test", "--authorised")
    assert r.exit_code == 0, r.output
    assert engine.specs == [{"kind": "discovery", "target_url": "http://shop.test/"}]
    assert "Target validation" in r.output and "Completed" in r.output
    assert "2 inspected, 1 failed" in r.output and "found /.well-known/routes.json" in r.output
    hist = json.loads(invoke("history", "--json").stdout)
    assert hist[0]["status"] == "completed" and hist[0]["target_url"] == "http://shop.test/"


def test_analyze_directory_packs_uploads_and_cleans_up(engine, fixture_project, routes_home):
    before = {p: p.read_bytes() for p in fixture_project.rglob("*") if p.is_file()}
    r = invoke("analyze", str(fixture_project))
    assert r.exit_code == 0, r.output
    spec = engine.specs[0]
    assert spec["kind"] == "source" and spec["source"] == "zip" and spec["upload_id"]
    upload = engine.uploads[0]
    assert {p: p.read_bytes() for p in fixture_project.rglob("*") if p.is_file()} == before  # untouched
    assert list((routes_home / "cache").iterdir()) == []                                        # packed zip deleted
    assert "SQL Injection" in r.output and "Hardcoded Secret" in r.output
    assert "Data-flow analysis" in r.output
    assert upload["size"] > 0


def test_analyze_zip_and_bad_zip(engine, tmp_path):
    z = tmp_path / "app.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("app/api/search/route.ts", "export const GET = 1")
    assert invoke("analyze", str(z)).exit_code == 0
    bad = tmp_path / "bad.zip"
    bad.write_bytes(b"MZ not a zip")
    r = invoke("analyze", str(bad))
    assert r.exit_code == 1 and "not a valid ZIP" in r.output


def test_private_repo_token_never_on_argv_or_disk(engine, routes_home, monkeypatch):
    r = invoke("analyze", "https://github.com/acme/app", "--private")
    assert r.exit_code == 1 and "interactive terminal" in r.output   # no TTY, no token prompt, nothing started
    assert engine.specs == []
    r = runner.invoke(app, ["analyze", "https://github.com/acme/app", "--token", TOKEN])
    assert r.exit_code != 0 and engine.specs == []                    # no such option
    # Interactive path: token entered through the hidden prompt.
    import routes_cli.main as main_mod

    monkeypatch.setattr(main_mod, "interactive", lambda: True)
    monkeypatch.setattr(main_mod.getpass, "getpass", lambda prompt="": TOKEN)
    r = invoke("analyze", "https://github.com/acme/app", "--private")
    assert r.exit_code == 0, r.output
    assert engine.credentials == {"h0": TOKEN}
    assert engine.specs[0]["credential_handle"] == "h0" and TOKEN not in json.dumps(engine.specs)
    for path in routes_home.rglob("*"):
        if path.is_file():
            assert TOKEN.encode() not in path.read_bytes(), path


def test_findings_list_detail_json_and_redaction(engine, fixture_project, routes_home):
    invoke("analyze", str(fixture_project))
    out = invoke("findings").output
    assert "01" in out and "SQL Injection" in out and "POTENTIAL" in out
    detail = invoke("findings", "--id", "01").output
    for heading in ("What is wrong", "Why it matters", "Where", "What ROUTES detected", "Suggested fix",
                    "Limitations of this result"):
        assert heading in detail
    assert "app/api/search/route.ts" in detail
    data = json.loads(invoke("findings", "--json").stdout)
    assert {f["type"] for f in data} == {"SQL Injection", "Hardcoded Secret"}
    for path in routes_home.rglob("*.db*"):
        assert SECRET_VALUE.encode() not in path.read_bytes()
    assert SECRET_VALUE not in json.dumps(data)


@pytest.mark.parametrize("fmt,name", [("markdown", "report.md"), ("html", "report.html"), ("json", "findings.json")])
def test_reports(engine, fixture_project, routes_home, fmt, name):
    invoke("analyze", str(fixture_project))
    r = invoke("report", "--format", fmt)
    assert r.exit_code == 0 and name in r.output
    path = next(routes_home.joinpath("reports").rglob(name))
    text = path.read_text(encoding="utf-8")
    assert "SQL Injection" in text and SECRET_VALUE not in text
    if fmt == "html":
        assert "<script" not in text.lower() and "Content-Security-Policy" in text
    if fmt == "json":
        assert json.loads(text)["findings"][0]["id"] == "01"


def test_html_report_escapes_untrusted_values(engine, fixture_project, routes_home, monkeypatch):
    from tests import conftest

    evil = dict(conftest.SOURCE_RESULT)
    evil["findings"] = [dict(conftest.SOURCE_RESULT["findings"][0], title="<img src=x onerror=alert(1)>")]
    monkeypatch.setattr(conftest, "SOURCE_RESULT", evil)
    invoke("analyze", str(fixture_project))
    invoke("report", "--format", "html")
    text = next(routes_home.joinpath("reports").rglob("report.html")).read_text(encoding="utf-8")
    assert "<img src=x" not in text and "&lt;img src=x" in text


def test_retention_keeps_five_and_removes_old_reports(engine, fixture_project, routes_home):
    for i in range(6):
        assert invoke("analyze", str(fixture_project)).exit_code == 0
        invoke("report", "--format", "json")
    hist = json.loads(invoke("history", "--json").stdout)
    assert len(hist) == 5
    reports_dirs = [d for d in routes_home.joinpath("reports").rglob("*") if d.is_dir() and d.parent.parent.name == "reports"]
    assert len(reports_dirs) == 5


def test_engine_unavailable_is_reported_honestly(engine, fixture_project):
    engine.available = False
    r = invoke("analyze", str(fixture_project))
    assert r.exit_code == 1
    assert "routes engine up" in r.output and "Failed" in r.output


def test_failed_step_gives_partial_status(engine, fixture_project):
    engine.fail_source = "The archive did not contain any analysable files."
    r = invoke("scan", "http://shop.test", "--source", str(fixture_project), "--authorised")
    assert r.exit_code == 3 and "Partially completed" in r.output
    assert "analysable files" in r.output


def test_projects_add_use_show(engine, fixture_project):
    r = invoke("project", "add", str(fixture_project), "--name", "My App", "--url", "https://shop.test")
    assert r.exit_code == 0 and "my-app" in r.output
    assert "my-app" in invoke("projects").output
    assert invoke("project", "use", "my-app").exit_code == 0
    show = invoke("project", "show").output
    assert "https://shop.test" in show and "directory" in show
    r = invoke("analyze", str(fixture_project), "--project", "my-app")
    assert r.exit_code == 0
    assert json.loads(invoke("history", "--json", "--project", "my-app").stdout)[0]["project"] == "my-app"


def test_doctor_reports_each_dependency(engine, monkeypatch):
    from routes_cli import doctor

    monkeypatch.setattr(doctor, "run_quiet", lambda cmd, timeout=20: (0, "29.0.0" if "version" in cmd else "2026-01-01T00:00:00"))
    monkeypatch.setattr(doctor, "docker_available", lambda: True)
    monkeypatch.setattr(doctor, "_probe_image", lambda image, code: {"semgrep": "1.0", "tree-sitter": "0.25",
                                                                     "tree-sitter-javascript": "0.25",
                                                                     "tree-sitter-typescript": "0.23",
                                                                     "playwright": "1.5", "chromium": True})
    r = invoke("doctor", "--json")
    names = {c["name"]: c["status"] for c in json.loads(r.stdout)}
    for n in ("Python runtime", "ROUTES installation", "SQLite database", "Docker daemon", "Sandbox Manager",
              "Docker API proxy", "Network gateway", "Semgrep", "Tree-sitter", "Playwright", "Chromium"):
        assert names[n] == "PASS", (n, names)
    engine.available = False
    names = {c["name"]: c["status"] for c in json.loads(invoke("doctor", "--json").stdout)}
    assert names["Sandbox Manager"] == "FAIL"
