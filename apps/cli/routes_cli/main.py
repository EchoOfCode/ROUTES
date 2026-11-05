"""`routes` entry point: the interactive interface, or direct commands."""

from __future__ import annotations

import getpass
import json
import sys
import threading
import time
from pathlib import Path
from typing import Optional

import typer
from rich.live import Live
from rich.markup import escape
from rich.text import Text

from routes_storage import repo
from routes_storage.models import Project, as_utc

from routes_cli import __version__, actions, doctor as doctor_mod, engine_ctl, reports
from routes_cli.context import Context, initialise
from routes_cli.renderers import results as R
from routes_cli.renderers.progress import ProgressModel
from routes_cli.renderers.theme import glyphs, make_console, severity_text
from routes_cli.service import AssessmentRunner, PlanError, StepUpdate, set_match
from routes_cli.stages import STEP_TITLES, label

app = typer.Typer(add_completion=False, no_args_is_help=False, rich_markup_mode=None,
                  help="ROUTES: local-first application security assessment.\n\nRun `routes` with no arguments "
                       "to open the interactive interface.")
engine_app = typer.Typer(help="Start, stop and check the local sandbox engine.", no_args_is_help=True)
project_app = typer.Typer(help="Register and select projects.", no_args_is_help=True)
app.add_typer(engine_app, name="engine")
app.add_typer(project_app, name="project")


class State:
    no_animation = False


def interactive() -> bool:
    return sys.stdin.isatty() and sys.stdout.isatty()


def _ctx() -> Context:
    ctx = Context.load(no_animation=State.no_animation)
    if ctx.init_report is not None:
        make_console(plain=not sys.stdout.isatty(), stderr=True).print(
            f"[muted]First run: created {ctx.home.root}[/]")
    return ctx


def _console(ctx: Context | None = None, *, force_plain: bool = False):
    plain = force_plain or not sys.stdout.isatty() or State.no_animation
    return make_console(plain=plain)


def _fail(message: str, code: int = 1) -> None:
    make_console(plain=not sys.stderr.isatty(), stderr=True).print(f"[err]Error:[/] {escape(message)}")
    raise typer.Exit(code)


def _version(value: bool) -> None:
    if value:
        print(f"routes {__version__}")
        raise typer.Exit()


@app.callback(invoke_without_command=True)
def main(ctx: typer.Context,
         version: bool = typer.Option(False, "--version", callback=_version, is_eager=True,
                                      help="Show the version and exit."),
         no_animation: bool = typer.Option(False, "--no-animation", help="Disable animation and live rendering.")):
    State.no_animation = no_animation
    if ctx.invoked_subcommand is not None:
        return
    if not interactive():
        print(ctx.get_help())
        raise typer.Exit()
    from routes_cli.tui.app import RoutesApp

    RoutesApp(no_animation=no_animation).run()


# ------------------------------------------------------------------- setup
@app.command()
def init():
    """Create ~/.routes (database, configuration, engine credentials)."""
    report = initialise()
    con = _console()
    con.print(f"[ok]Initialised[/] {report.home}")
    con.print(f"  database     {report.home / 'routes.db'}")
    con.print(f"  config       {report.home / 'config.toml'}")
    con.print(f"  engine       {report.compose_file or '[err]not found[/]'}")
    con.print(f"  credentials  {report.env_file}  [muted]({report.env_source})[/]")
    for note in report.notes:
        con.print(f"  [muted]{escape(note)}[/]")
    con.print("\nNext: [accent]routes engine up[/] then [accent]routes doctor[/]")


@engine_app.command("up")
def engine_up(no_build: bool = typer.Option(False, "--no-build", help="Use existing images."),
              sample_site: bool = typer.Option(False, "--with-sample-site", hidden=True)):
    """Build and start the sandbox engine (Sandbox Manager, Docker proxy, network gateway)."""
    ctx = _ctx()
    es = ctx.engine
    target = engine_ctl.ComposeTarget(es.compose_file, es.env_file)
    con = _console()
    try:
        cmd = engine_ctl.up_command(target, build=not no_build, sample_site=sample_site)
    except engine_ctl.EngineControlError as exc:
        _fail(str(exc))
    con.print("[accent]Starting the ROUTES engine[/] [muted](the first build downloads and builds several images)[/]")
    last = [""]

    def line(text: str) -> None:
        if text.strip():
            last[0] = text
            con.print(f"  [muted]{escape(text[:140])}[/]")

    try:
        rc = engine_ctl.stream(cmd, line)
    except engine_ctl.EngineControlError as exc:
        _fail(str(exc))
    if rc != 0:
        _fail(f"docker compose exited with status {rc}. {last[0]}")
    con.print(f"[ok]{glyphs(con).done} Engine running[/] at {es.url}")


@engine_app.command("stop")
def engine_stop():
    """Stop the engine services (images and data are kept)."""
    ctx = _ctx()
    es = ctx.engine
    try:
        rc = engine_ctl.stream(engine_ctl.stop_command(engine_ctl.ComposeTarget(es.compose_file, es.env_file)),
                               lambda t: None)
    except engine_ctl.EngineControlError as exc:
        _fail(str(exc))
    if rc != 0:
        _fail(f"docker compose exited with status {rc}.")
    _console().print("Engine stopped.")


@engine_app.command("status")
def engine_status():
    """Show whether the engine is reachable."""
    ctx = _ctx()
    from routes_core.engine import EngineUnavailable

    con = _console()
    try:
        with ctx.engine_client() as c:
            h = c.health()
    except EngineUnavailable as exc:
        con.print(f"[err]Engine unavailable:[/] {escape(str(exc))}\nStart it with [accent]routes engine up[/].")
        raise typer.Exit(1)
    g = glyphs(con)
    con.print(f"[ok]{g.done}[/] Sandbox Manager  {ctx.engine.url}")
    con.print(f"{'[ok]' + g.done if h.get('docker') else '[err]' + g.failed}[/] Docker API proxy")
    con.print(f"{'[ok]' + g.done if h.get('gateway') else '[err]' + g.failed}[/] Network gateway")
    con.print(f"[muted]{h.get('active_runs', 0)} active sandbox run(s)[/]")


@app.command()
def doctor(quick: bool = typer.Option(False, "--quick", help="Skip reading tool versions from the sandbox images."),
           as_json: bool = typer.Option(False, "--json", help="Machine-readable output.")):
    """Check Python, Docker, the engine, SQLite and the analysis tools."""
    ctx = _ctx()
    con = _console()
    if as_json:
        checks = doctor_mod.run_checks(ctx, probe_images=not quick)
        print(json.dumps([c.__dict__ for c in checks], indent=2))
        raise typer.Exit(1 if any(c.status == doctor_mod.FAIL for c in checks) else 0)
    if sys.stdout.isatty() and not State.no_animation:
        with con.status("[accent]Checking the ROUTES environment[/]", spinner="dots"):
            checks = doctor_mod.run_checks(ctx, probe_images=not quick)
    else:
        checks = doctor_mod.run_checks(ctx, probe_images=not quick)
    from routes_cli.renderers.doctor import doctor_view

    con.print(doctor_view(checks, glyphs(con)))
    raise typer.Exit(1 if any(c.status == doctor_mod.FAIL for c in checks) else 0)


# -------------------------------------------------------------- assessments
def _confirm(prompt: str) -> bool:
    return typer.confirm(prompt, default=False)


def _prepare_interactively(ctx: Context, req: actions.Request, authorised: bool) -> actions.Prepared:
    con = _console()
    try:
        prepared = actions.prepare(ctx, req)
    except PlanError as exc:
        _fail(str(exc))
    if prepared.needs_authorisation:
        if not authorised:
            if not interactive():
                _fail("Confirm permission with --authorised when running non-interactively.")
            con.print(f"\n[heading]Website:[/] {escape(prepared.plan.target_url)}")
            con.print("[muted]ROUTES will crawl up to 25 public pages on this exact hostname. It never submits "
                      "forms, logs in or sends attacks.[/]")
            if not _confirm(actions.AUTHORISATION_STATEMENT):
                _fail("Permission not confirmed. Nothing was started.", 2)
        actions.confirm_authorisation(ctx, prepared)
    if prepared.needs_token:
        if not interactive():
            _fail("Private repositories need an interactive terminal so the token can be entered hidden.")
        con.print("[muted]Enter a fine-grained GitHub token with Contents: Read-only for this repository. It is "
                  "used once and never stored.[/]")
        try:
            actions.attach_token(prepared, getpass.getpass("GitHub token (hidden): "))
        except PlanError as exc:
            _fail(str(exc))
    if prepared.ask_match and interactive():
        q = actions.MATCH_QUESTION.format(host=prepared.hostname)
        answer = typer.prompt(f"{q} [yes/no/unsure]", default="unsure").strip().lower()
        decision = {"y": "confirmed", "yes": "confirmed", "n": "rejected", "no": "rejected"}.get(answer, "pending")
        set_match(ctx, prepared.project.id, decision)
    return prepared


def _run_assessment(ctx: Context, prepared: actions.Prepared) -> str:
    con = _console()
    g = glyphs(con)
    live_mode = con.is_terminal and not State.no_animation
    model = ProgressModel()
    cancel = threading.Event()
    done = threading.Event()
    outcome: dict = {}
    printed: dict[str, set] = {}

    def on_update(u) -> None:
        notes = model.apply(u)
        if not live_mode:
            _plain_progress(con, model, u, printed)
        for sev, msg in notes:
            if not live_mode:
                con.print(f"  [{'warn' if sev == 'warning' else 'err' if sev == 'error' else 'info'}]{escape(msg)}[/]")

    def work():
        try:
            outcome["result"] = AssessmentRunner(ctx, prepared.plan, on_update, cancel).run()
        except BaseException as exc:  # noqa: BLE001
            outcome["error"] = exc
        finally:
            done.set()

    thread = threading.Thread(target=work, name="routes-assessment", daemon=True)
    thread.start()
    interrupts = 0
    live = Live(console=con, refresh_per_second=12, transient=False) if live_mode else None
    try:
        if live:
            live.start()
        frame = 0
        while not done.is_set():
            try:
                if live:
                    live.update(model.render(g, frame, animate=True))
                    frame += 1
                done.wait(1 / 12 if live else 0.5)
            except KeyboardInterrupt:
                interrupts += 1
                if interrupts == 1:
                    cancel.set()
                    msg = "Cancelling: waiting for the sandbox to stop and be removed (Ctrl+C again to leave now)."
                    (live.console if live else con).print(f"[warn]{msg}[/]")
                else:
                    raise
        if live:
            live.update(model.render(g, frame, animate=False))
    finally:
        if live:
            live.stop()
    if "error" in outcome:
        exc = outcome["error"]
        if isinstance(exc, PlanError):
            _fail(str(exc))
        raise exc
    result = outcome["result"]
    a = actions.latest(ctx, assessment=result.assessment_id)
    con.print()
    con.print(R.assessment_summary(a, g))
    if a.findings:
        con.print()
        con.print(R.findings_table(a.findings, g))
        con.print(f"\n[muted]Details:[/] routes findings --id {a.findings[0].seq:02d}   "
                  f"[muted]Report:[/] routes report --format html")
    elif a.source_result is not None:
        con.print()
        con.print(R.findings_table([], g))
    if a.findings:
        _offer_remediation(ctx, a)
    return result.status


def _plain_progress(con, model: ProgressModel, u, printed: dict[str, set]) -> None:
    g = glyphs(con)
    if not isinstance(u, StepUpdate):
        return
    seen = printed.setdefault(u.kind, set())
    title = STEP_TITLES.get(u.kind, u.kind)
    for stage in u.completed:
        if stage not in seen:
            seen.add(stage)
            con.print(f"[{title}] {g.done} {label(stage)}")
    key = f"current:{u.stage}"
    if u.status == "running" and u.stage and key not in seen:
        seen.add(key)
        con.print(f"[{title}] {g.running} {label(u.stage)}")
    s = model.steps.get(u.kind)
    pages = s.data.get("pages_done") if s else None
    if pages is not None and f"pages:{pages}" not in seen and pages and pages % 5 == 0:
        seen.add(f"pages:{pages}")
        con.print(f"[{title}]   {pages} of up to {s.data.get('page_limit')} pages inspected")
    if u.status in ("completed", "failed", "cancelled") and f"end" not in seen:
        seen.add("end")
        mark = {"completed": g.done, "failed": g.failed, "cancelled": g.cancelled}[u.status]
        con.print(f"[{title}] {mark} {u.status}" + (f": {u.error}" if u.error and u.status != "completed" else ""))


def _exit_for(status: str) -> None:
    raise typer.Exit(0 if status == "completed" else 3 if status == "partially_completed" else 1)


@app.command()
def scan(url: str = typer.Argument(..., help="Website to assess, e.g. https://example.com"),
         source: Optional[str] = typer.Option(None, "--source", "-s", help="Also analyse this GitHub URL, folder or .zip"),
         ref: Optional[str] = typer.Option(None, "--ref", help="Branch, tag or commit for a GitHub source"),
         private: bool = typer.Option(False, "--private", help="The GitHub repository is private (token prompted)"),
         project: Optional[str] = typer.Option(None, "--project", "-p", help="Record under this project"),
         authorised: bool = typer.Option(False, "--authorised", "-y",
                                         help="Confirm you own the site or have permission to assess it")):
    """Discover a website's pages, endpoints and technologies (optionally with its source)."""
    ctx = _ctx()
    prepared = _prepare_interactively(ctx, actions.Request(url=url, source=source, ref=ref, private=private,
                                                           project=project), authorised)
    _exit_for(_run_assessment(ctx, prepared))


@app.command()
def analyze(source: str = typer.Argument(..., help="GitHub repository URL, local folder or .zip file"),
            url: Optional[str] = typer.Option(None, "--url", "-u", help="Also discover this website"),
            ref: Optional[str] = typer.Option(None, "--ref", help="Branch, tag or commit for a GitHub source"),
            private: bool = typer.Option(False, "--private", help="The GitHub repository is private (token prompted)"),
            project: Optional[str] = typer.Option(None, "--project", "-p", help="Record under this project"),
            authorised: bool = typer.Option(False, "--authorised", "-y",
                                            help="With --url: confirm permission to assess the website")):
    """Analyse source code statically (repository code is never run)."""
    ctx = _ctx()
    prepared = _prepare_interactively(ctx, actions.Request(url=url, source=source, ref=ref, private=private,
                                                           project=project), authorised)
    _exit_for(_run_assessment(ctx, prepared))


# ------------------------------------------------------------- build & run
def _print_generated(con, generated, path) -> None:
    counts: dict[str, int] = {}
    for t in generated.plan["tests"]:
        counts[t["category"]] = counts.get(t["category"], 0) + 1
    summary = ", ".join(f"{n} {cat}" for cat, n in sorted(counts.items()))
    con.print(f"[heading]Generated test plan[/] [muted]({summary}; {generated.flows_covered} finding(s) "
              f"covered, {generated.flows_skipped} skipped)[/]" + (f"\n  written to [path]{escape(str(path))}[/]"
                                                                  if path else ""))
    for note in generated.notes:
        con.print(f"  [muted]- {escape(note)}[/]")


@app.command()
def testplan(source: Optional[str] = typer.Argument(None, help="GitHub URL, folder or .zip that was analysed "
                                                                "(default: current project)"),
             assessment: Optional[str] = typer.Option(None, "--assessment", "-a", help="Assessment ID (prefix)"),
             project: Optional[str] = typer.Option(None, "--project", "-p"),
             ref: Optional[str] = typer.Option(None, "--ref"),
             output: str = typer.Option("routes-testplan.json", "--output", "-o", help="Where to write the plan")):
    """Generate a build-and-run test plan from the latest source analysis.

    Uses the routes and findings of `routes analyze` (SQL injection, XSS, access
    control, security headers, CORS). Review
    and edit the file, then run `routes verify <source> --tests <file>`.
    """
    from pathlib import Path

    from routes_core.sources import SourceError, classify

    ctx = _ctx()
    try:
        spec = classify(source, ref=ref) if source else None
        a = actions.source_analysis(ctx, source=spec, assessment=assessment, project=project)
        generated = actions.generate_test_plan(a)
    except (SourceError, PlanError) as exc:
        _fail(str(exc))
    path = Path(output)
    path.write_text(json.dumps(generated.plan, indent=2) + "\n", "utf-8")
    con = _console()
    con.print(f"[muted]From assessment {a.id[:8]} of {escape(a.project.display_name)}[/]")
    _print_generated(con, generated, path.resolve())


def _execute_build_and_run(ctx: Context, source: str, tests: str = "auto", patch: Optional[str] = None,
                           ref: Optional[str] = None, private: bool = False,
                           approve_script: list[str] | tuple = (), as_json: bool = False,
                           output: Optional[str] = None) -> tuple[int, dict]:
    from pathlib import Path

    from routes_core.buildrun import EXIT_CODES, BuildRunInvalid, BuildRunRequest, submit, verification_of
    from routes_core.buildrun import wait as wait_run
    from routes_core.engine import EngineRejected, EngineUnavailable
    from routes_core.sources import SourceError, classify
    from routes_cli.renderers import buildrun as BR

    notice = make_console(plain=as_json or not sys.stderr.isatty() or State.no_animation, stderr=True)
    try:
        spec = classify(source, ref=ref)
        if tests.strip().lower() == "auto":
            generated = actions.generate_test_plan(actions.source_analysis(ctx, source=spec))
            plan_data = generated.plan
            _print_generated(notice, generated, None)
        else:
            plan_data = json.loads(Path(tests).read_text("utf-8"))
        patch_text = Path(patch).read_bytes().decode("utf-8") if patch else None  # keep CRLF lines intact
    except (SourceError, PlanError) as exc:
        _fail(str(exc))
    except (OSError, ValueError) as exc:
        _fail(f"Could not read the test plan or patch: {exc}")
    req = BuildRunRequest(source=spec, test_plan=plan_data, patch=patch_text, approved_scripts=list(approve_script))
    if private:
        if not spec.is_github:
            _fail("--private applies to GitHub repositories only.")
        if not interactive():
            _fail("Private repositories need an interactive terminal so the token can be entered hidden.")
        req.token = getpass.getpass("GitHub token (hidden, Contents: Read-only): ").strip() or None
    con = make_console(plain=as_json or not sys.stderr.isatty() or State.no_animation, stderr=True)
    g = glyphs(con)
    client = ctx.engine_client()
    seen_phases: list[str] = []
    last_msg = [""]

    final_phases = ("COLLECTING_RESULTS", "COMPLETED", "FAILED", "CANCELLED", "CLEANED_UP")

    def on_state(state: dict) -> None:
        history = [p["phase"] for p in state.get("phase_history") or []]
        new = history[len(seen_phases):]
        work = [ph for ph in new if ph not in final_phases]
        closing = [ph for ph in new if ph in final_phases]
        for ph in work:
            seen_phases.append(ph)
            con.print(BR.phase_line(ph, g, current=True))
        events = state.get("events") or []
        if events and events[-1].get("message") and events[-1]["message"] != last_msg[0]:
            last_msg[0] = events[-1]["message"]
            con.print(f"      [muted]{escape(last_msg[0][:140])}[/]")
        for ph in closing:
            seen_phases.append(ph)
            con.print(BR.phase_line(ph, g, current=ph not in ("COMPLETED", "FAILED", "CANCELLED", "CLEANED_UP")))

    try:
        try:
            run = submit(client, req, cache_dir=ctx.home.cache, on_local=lambda m: con.print(f"  [muted]{escape(m)}[/]"))
        except (BuildRunInvalid, SourceError) as exc:
            _fail(str(exc))
        except EngineRejected as exc:
            _fail(f"The engine rejected the request: {exc}")
        except EngineUnavailable:
            _fail("The ROUTES engine is not reachable. Start it with `routes engine up` (Docker must be running).")
        con.print(f"[heading]Build-and-run[/] [muted]run {run['id']} (Ctrl+C cancels and removes the environment)[/]")
        cancel = threading.Event()
        try:
            final = wait_run(client, run, on_state=on_state, should_cancel=cancel.is_set)
        except KeyboardInterrupt:
            con.print("[warn]Cancelling; waiting for the sandbox to be removed...[/]")
            cancel.set()
            final = wait_run(client, run, on_state=on_state, should_cancel=cancel.is_set, deadline_seconds=120)
    finally:
        req.token = None
        client.close()
    if output:
        Path(output).write_text(json.dumps(final, indent=2), "utf-8")
    if as_json:
        print(json.dumps(final, indent=2))
    else:
        out = _console()
        out.print()
        out.print(BR.render(final, glyphs(out)))
    return EXIT_CODES.get(verification_of(final), 1), final


@app.command()
def verify(source: str = typer.Argument(..., help="GitHub repository URL, local folder or .zip file"),
           tests: str = typer.Option(..., "--tests", "-t",
                                     help="Test plan (JSON) to run, or 'auto' to generate one from the latest "
                                          "`routes analyze` of this source"),
           patch: Optional[str] = typer.Option(None, "--patch", help="Candidate patch (unified diff) to apply to a "
                                                                     "temporary copy"),
           ref: Optional[str] = typer.Option(None, "--ref", help="Branch, tag or commit for a GitHub source"),
           private: bool = typer.Option(False, "--private", help="The GitHub repository is private (token prompted)"),
           approve_script: list[str] = typer.Option([], "--approve-script",
                                                    help="Allow this dependency's install scripts (repeatable; "
                                                         "'<root>' for the project's own)"),
           as_json: bool = typer.Option(False, "--json", help="Print the structured result as JSON"),
           output: Optional[str] = typer.Option(None, "--output", "-o", help="Also write the JSON result to this file")):
    """Build, run and test an application in a disposable sandbox.

    The source is never modified: any patch is applied to a temporary copy
    inside the sandbox. Exit codes: 0 verified run, 3 tests failed,
    4 dynamic verification unsupported, 1 build failure or inconclusive.
    """
    ctx = _ctx()
    code, final = _execute_build_and_run(ctx, source, tests=tests, patch=patch, ref=ref, private=private,
                                         approve_script=approve_script, as_json=as_json, output=output)
    raise typer.Exit(code)


# ------------------------------------------------------------------ results
@app.command()
def findings(id: Optional[str] = typer.Option(None, "--id", help="Show one finding in detail, e.g. 01"),
             severity: Optional[str] = typer.Option(None, "--severity", help="critical, high, medium, low or info"),
             assessment: Optional[str] = typer.Option(None, "--assessment", "-a", help="Assessment ID (prefix)"),
             project: Optional[str] = typer.Option(None, "--project", "-p"),
             as_json: bool = typer.Option(False, "--json")):
    """Show the findings of the latest assessment."""
    ctx = _ctx()
    con = _console()
    g = glyphs(con)
    try:
        a = actions.latest(ctx, assessment=assessment, project=project)
    except PlanError as exc:
        _fail(str(exc))
    if a is None:
        con.print(R.empty("No finished assessments yet. Run `routes scan <url>` or `routes analyze <source>`."))
        return
    items = [f for f in a.findings if not severity or f.severity == severity.lower()]
    if id:
        match = next((f for f in a.findings if id.lstrip("0") == str(f.seq) or id == f"{f.seq:02d}"), None)
        if match is None:
            _fail(f"No finding {id} in assessment {a.id[:8]}.")
        if as_json:
            print(json.dumps(next(x for x in reports.report_data(a)["findings"] if x["id"] == f"{match.seq:02d}"),
                             indent=2))
            return
        con.print(R.finding_detail(match, g))
        return
    if as_json:
        data = reports.report_data(a)["findings"]
        print(json.dumps([x for x in data if not severity or x["severity"] == severity.lower()], indent=2))
        return
    con.print(f"[heading]SECURITY FINDINGS[/]  [muted]{escape(a.project.display_name)} · assessment {a.id[:8]} · "
              f"{R.local_time(a.finished_at)}[/]\n")
    if a.source_result is None and not a.findings:
        con.print(R.empty("This assessment did not include source analysis, so there are no code findings. "
                          "Run `routes analyze <source>`."))
        return
    con.print(R.findings_table(items, g))
    if items:
        con.print(f"\n[muted]Use[/] routes findings --id {items[0].seq:02d} [muted]for details.[/]")


# ------------------------------------------------------------- remediation
def _pick_findings(con, a) -> list | None:
    """Interactive choice: all code findings, or some of them by number."""
    from routes_core.testplan import vuln_class
    from routes_cli.remediation import RemediationError, actionable, select

    code = actionable(a)
    g = glyphs(con)
    con.print("\n[heading]Findings that can be remediated[/]")
    groups: dict[str, list] = {}
    for f in code:
        groups.setdefault(vuln_class({"type": f.type, "rule_id": f.rule_id}), []).append(f)
    for klass, items in groups.items():
        con.print(f"  [label]{escape(klass)}[/]")
        for f in items:
            loc = f"{f.file}:{f.line}" if f.line else f.file
            con.print(f"    [accent]{f.seq:02d}[/]  {severity_text(f.severity, g)}  {escape(f.title)}  "
                      f"[muted]{escape(loc or '')}[/]")
    while True:
        try:
            raw = typer.prompt("Remediate which? (Enter = all, e.g. 01,03, 0 = cancel)", default="all",
                               show_default=False).strip()
        except (typer.Abort, EOFError):
            return None
        if raw in ("0", "q"):
            return None
        if raw.lower() in ("", "all", "a"):
            return code
        try:
            return select(a, [raw])
        except RemediationError as exc:
            con.print(f"[err]{escape(str(exc))}[/]")


def _run_remediation(ctx: Context, a, targets: list, *, source: Optional[str] = None, attempts: int = 3,
                     output: Optional[str] = None, as_json: bool = False, yes: bool = False) -> int:
    """Drive the staged workflow with a live pipeline view. Returns an exit code."""
    from routes_cli import remediation as rem
    from routes_cli.renderers import remediation as RV

    con = _console(force_plain=as_json)
    err = make_console(plain=as_json or not sys.stderr.isatty() or State.no_animation, stderr=True)
    g = glyphs(con)
    try:
        prepared = rem.prepare(ctx, a, targets, source=source, max_attempts=attempts)
    except rem.RemediationError as exc:
        _fail(str(exc))
    if not yes:
        if not interactive():
            _fail("Remediation sends redacted code to the configured model providers and runs the application in "
                  "the sandbox. Confirm with --yes when there is no terminal.")
        err.print(f"\n[heading]AI remediation[/]  [muted]{len(targets)} finding(s) · {escape(prepared.source.label)}[/]")
        err.print("  [muted]For each finding: Model A plans the fix, ROUTES builds the tests, the original is run in "
                  "the sandbox (baseline),\n  then up to "
                  f"{attempts} attempts of Model B patch → validate → build & test → rescan, with the failure fed "
                  "back each time.\n  The code region sent to the models is redacted first. Your files are not "
                  "changed.[/]")
        if not typer.confirm("Start?", default=True):
            prepared.close()
            raise typer.Exit(2)

    live_mode = con.is_terminal and not State.no_animation and not as_json
    cancel = threading.Event()
    done = threading.Event()
    outcome: dict = {}

    class PlainListener(rem.Listener):
        def log(self, line: str) -> None:
            if not as_json:
                err.print(escape(line))

    listener = rem.Listener() if live_mode else PlainListener()
    wf = prepared.workflow(listener=listener, should_cancel=cancel.is_set)

    def work():
        try:
            outcome["run"] = wf.execute()
        except BaseException as exc:  # noqa: BLE001
            outcome["error"] = exc
        finally:
            done.set()

    thread = threading.Thread(target=work, name="routes-remediation", daemon=True)
    thread.start()
    live = Live(console=con, refresh_per_second=12, transient=False) if live_mode else None
    interrupts = 0
    try:
        if live:
            live.start()
        frame = 0
        while not done.is_set():
            try:
                if live:
                    live.update(RV.render(wf.run, g, frame, animate=True))
                    frame += 1
                done.wait(1 / 12 if live else 0.5)
            except KeyboardInterrupt:
                interrupts += 1
                if interrupts == 1:
                    cancel.set()
                    (live.console if live else err).print(
                        "[warn]Cancelling: waiting for the sandbox to stop and be removed (Ctrl+C again to leave "
                        "now).[/]")
                else:
                    raise
        if live:
            live.update(RV.render(wf.run, g, frame, animate=False, show_all=True))
    finally:
        if live:
            live.stop()
        prepared.close()
    if "error" in outcome:
        raise outcome["error"]
    run = outcome["run"]
    saved = rem.save(ctx, run, output=output)
    if as_json:
        print(json.dumps({**run.to_dict(), "saved": {"folder": str(saved.folder), "report": str(saved.report),
                                                      "combined_patch": str(saved.combined) if saved.combined else None}},
                         indent=2, default=str))
    else:
        con.print()
        con.print(RV.summary(run, g, saved))
        if output and saved.combined:
            con.print(f"[muted]Also written to[/] [path]{escape(str(Path(output).resolve()))}[/]")
        if interactive():
            _after_remediation(ctx, a, prepared.source, saved)
        elif saved.combined:
            con.print(f"\n[muted]Apply it with[/] git apply {escape(str(saved.combined))}")
    return {"verified_fixed": 0, "partially_remediated": 3, "human_review": 3, "inconclusive": 3,
            "cancelled": 2}.get(run.verdict, 1)


def _after_remediation(ctx: Context, a, source, saved) -> None:
    from routes_cli import remediation as rem

    con = _console()
    options = []
    if saved.combined and source.spec.kind == "directory":
        options.append(("apply", f"Apply the patch to {source.spec.label}"))
    options.append(("report", "Write the assessment report (HTML)"))
    options.append(("exit", "Done"))
    con.print("\n[heading]Next[/]")
    for i, (_, text) in enumerate(options, 1):
        con.print(f"  [accent]{i}[/]  {escape(text)}")
    try:
        raw = typer.prompt("Choose", default=str(len(options)), show_default=False).strip()
        key = options[int(raw) - 1][0]
    except (typer.Abort, EOFError, ValueError, IndexError):
        return
    if key == "apply":
        if not typer.confirm(f"Modify files in {source.spec.label}?", default=False):
            return
        try:
            files = rem.apply_patch(source.spec.path, saved.combined.read_bytes().decode("utf-8"))
        except Exception as exc:  # noqa: BLE001 - PatchRejected or OSError: nothing was written
            con.print(f"[err]Not applied:[/] {escape(str(exc))} (no file was changed)")
            return
        con.print(f"[ok]{glyphs(con).done} Applied[/] to {', '.join(escape(f) for f in files)}. Run "
                  "`routes analyze` again to confirm.")
    elif key == "report":
        path = reports.write_report(ctx.home, a, "html")
        con.print(f"[ok]Report written to[/] [path]{escape(str(path.resolve()))}[/]")


def _offer_remediation(ctx: Context, a) -> None:
    """After an analysis: continue straight into the remediation workflow."""
    from routes_cli.remediation import actionable

    if not actionable(a) or not interactive():
        return
    con = _console()
    try:
        go = typer.confirm(f"\nRemediate {'these findings' if len(actionable(a)) > 1 else 'this finding'} with "
                           "the AI correction loop now?", default=False)
    except (typer.Abort, EOFError):
        return
    if not go:
        con.print("[muted]Later:[/] routes remediate")
        return
    targets = _pick_findings(con, a)
    if targets:
        _run_remediation(ctx, a, targets, yes=True)


@app.command()
def remediate(ids: Optional[list[str]] = typer.Argument(None, help="Finding numbers, e.g. 01 03 (default: choose "
                                                                     "interactively, or all with --all)"),
              id: Optional[str] = typer.Option(None, "--id", "-f", help="Finding sequence number (e.g. 02) to remediate"),
              all_findings: bool = typer.Option(False, "--all", help="Every code finding of the assessment"),
              attempts: int = typer.Option(3, "--attempts", "-n", help="Patch attempts per finding (1-10)"),
              source: Optional[str] = typer.Option(None, "--source", "-s",
                                                   help="Folder, .zip or GitHub URL of the code (default: the "
                                                        "assessment's source)"),
              assessment: Optional[str] = typer.Option(None, "--assessment", "-a", help="Assessment ID (prefix)"),
              project: Optional[str] = typer.Option(None, "--project", "-p"),
              output: Optional[str] = typer.Option(None, "--output", "-o",
                                                   help="Also write the combined patch to this file"),
              yes: bool = typer.Option(False, "--yes", "-y", help="Do not ask for confirmation"),
              as_json: bool = typer.Option(False, "--json", help="Print the full run record as JSON")):
    """Fix findings with the verified AI correction loop.

    Per finding: context → Model A plan → testbench → baseline on the original
    (sandbox) → up to N attempts of Model B patch → validate → build & test →
    rescan, with each failure fed back → evidence-based verdict. Your files
    are never modified unless you choose to apply the patch.
    Exit codes: 0 all verified fixed, 3 not all verified, 2 cancelled, 1 error.
    """
    from routes_cli.remediation import RemediationError, select

    ctx = _ctx()
    try:
        a = actions.latest(ctx, assessment=assessment, project=project)
    except PlanError as exc:
        _fail(str(exc))
    if a is None or not a.findings:
        _fail("No findings to remediate. Run `routes analyze <source>` first.")
    try:
        target_ids = list(ids or [])
        if id and id not in target_ids:
            target_ids.append(id)
        if target_ids or all_findings:
            targets = select(a, target_ids if target_ids and not all_findings else None)
        elif interactive() and not as_json:
            targets = _pick_findings(_console(), a)
            if not targets:
                raise typer.Exit(2)
        else:
            _fail("Give finding numbers, --id <number>, or --all.")
    except RemediationError as exc:
        _fail(str(exc))
    raise typer.Exit(_run_remediation(ctx, a, targets, source=source, attempts=attempts, output=output,
                                      as_json=as_json, yes=yes))


@app.command()
def history(project: Optional[str] = typer.Option(None, "--project", "-p"),
            as_json: bool = typer.Option(False, "--json")):
    """Show previous assessments (the five most recent are kept per project)."""
    ctx = _ctx()
    con = _console()
    with ctx.session() as db:
        p = repo.find_project(db, project) if project else None
        if project and p is None:
            _fail(f"No project named '{project}'.")
        items = repo.history(db, p)
        for a in items:
            _ = (a.project, list(a.findings))
        if as_json:
            print(json.dumps([{"id": a.id, "project": a.project.name, "status": a.status, "target_url": a.target_url,
                               "source": a.source_label, "findings": len(a.findings),
                               "created_at": as_utc(a.created_at).isoformat()} for a in items], indent=2))
            return
        con.print(R.history_table(items, glyphs(con)))


@app.command()
def report(format: str = typer.Option(None, "--format", "-f", help="markdown, html or json"),
           assessment: Optional[str] = typer.Option(None, "--assessment", "-a"),
           project: Optional[str] = typer.Option(None, "--project", "-p")):
    """Write a report of the latest assessment to ~/.routes/reports/."""
    ctx = _ctx()
    fmt = (format or ctx.config.report_format).lower()
    if fmt == "md":
        fmt = "markdown"
    if fmt not in reports.FORMATS:
        _fail("Report format must be markdown, html or json.")
    try:
        a = actions.latest(ctx, assessment=assessment, project=project)
    except PlanError as exc:
        _fail(str(exc))
    if a is None:
        _fail("No finished assessments to report on.")
    path = reports.write_report(ctx.home, a, fmt)
    _console().print(f"[ok]Report written[/] {path}")


# ----------------------------------------------------------------- projects
@app.command()
def projects(as_json: bool = typer.Option(False, "--json")):
    """List projects."""
    ctx = _ctx()
    con = _console()
    with ctx.session() as db:
        items = repo.list_projects(db)
        for p in items:
            _ = list(p.assessments)
        if as_json:
            print(json.dumps([{"name": p.name, "registered": p.registered, "website_url": p.website_url,
                               "source": p.source_location, "assessments": len(p.assessments)} for p in items], indent=2))
            return
        con.print(R.projects_table(items, ctx.config.current_project, glyphs(con)))


@project_app.command("add")
def project_add(source: Optional[str] = typer.Argument(None, help="GitHub URL, local folder or .zip"),
                name: str = typer.Option(..., "--name", "-n", help="Project name"),
                url: Optional[str] = typer.Option(None, "--url", "-u", help="Website of the project"),
                ref: Optional[str] = typer.Option(None, "--ref"),
                private: bool = typer.Option(False, "--private", help="Private GitHub repository")):
    """Register a project so it can be re-assessed with `routes scan --project` or `routes analyze --project`."""
    from routes_core.sources import SourceError, classify

    from routes_cli.service import validate_target

    ctx = _ctx()
    spec = None
    hostname = norm_url = None
    try:
        if source:
            spec = classify(source, ref=ref)
        if url:
            norm_url, hostname = validate_target(ctx, url)
    except (SourceError, PlanError, ValueError) as exc:
        _fail(str(exc))
    if spec is None and norm_url is None:
        _fail("Give a source and/or --url.")
    from routes_cli.service import _source_location

    with ctx.session() as db:
        try:
            p = repo.create_project(db, name=name, display_name=name, website_url=norm_url, hostname=hostname,
                                    source_kind=spec.kind if spec else None, source_location=_source_location(spec),
                                    source_ref=spec.ref if spec else None, source_private=private and bool(spec and spec.is_github))
        except repo.StorageError as exc:
            _fail(str(exc))
    ctx.config.current_project = p.name
    ctx.save_config()
    _console().print(f"[ok]Project added[/] {p.name} [muted](now the current project)[/]")


@project_app.command("use")
def project_use(name: str = typer.Argument(...)):
    """Make a project the current one."""
    ctx = _ctx()
    with ctx.session() as db:
        p = repo.find_project(db, name)
        if p is None:
            _fail(f"No project named '{name}'.")
    ctx.config.current_project = p.name
    ctx.save_config()
    _console().print(f"Current project: [accent]{p.name}[/]")


@project_app.command("show")
def project_show(name: Optional[str] = typer.Argument(None)):
    """Show a project and its assessment history."""
    ctx = _ctx()
    ref = name or ctx.config.current_project
    if not ref:
        _fail("No current project. Use `routes project use <name>` or give a name.")
    con = _console()
    with ctx.session() as db:
        p = repo.find_project(db, ref)
        if p is None:
            _fail(f"No project named '{ref}'.")
        for a in p.assessments:
            _ = (a.project, list(a.findings))
        con.print(R.project_detail(p, glyphs(con)))


@project_app.command("remove")
def project_remove(name: str = typer.Argument(...), yes: bool = typer.Option(False, "--yes")):
    """Delete a project, its assessments and reports."""
    import shutil

    ctx = _ctx()
    with ctx.session() as db:
        p = repo.find_project(db, name)
        if p is None:
            _fail(f"No project named '{name}'.")
        if not yes and not (interactive() and _confirm(f"Delete {p.name} and its {len(p.assessments)} assessment(s)?")):
            _fail("Nothing deleted.", 2)
        pid = p.id
        try:
            repo.delete_project(db, p)
        except repo.StorageError as exc:
            _fail(str(exc))
    shutil.rmtree(ctx.home.reports / pid, ignore_errors=True)
    if ctx.config.current_project == name:
        ctx.config.current_project = ""
        ctx.save_config()
    _console().print(f"Deleted {name}.")


def run() -> None:
    """Console-script entry point."""
    for stream in (sys.stdout, sys.stderr):
        # Pipes and files on Windows default to the ANSI code page; write UTF-8 instead.
        if not stream.isatty() and hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8")
            except (ValueError, OSError):
                pass
    # --no-animation is global but accepted anywhere (routes scan URL --no-animation).
    args = sys.argv[1:]
    if "--no-animation" in args[1:]:
        args = ["--no-animation"] + [a for a in args if a != "--no-animation"]
    try:
        app(args=args, prog_name="routes")
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        sys.exit(130)


if __name__ == "__main__":
    run()
