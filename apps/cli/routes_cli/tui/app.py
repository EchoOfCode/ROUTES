"""The interactive ROUTES application (`routes` with no arguments)."""

from __future__ import annotations

import asyncio
import threading
import time
from pathlib import Path

from rich.markup import escape
from rich.text import Text
from textual import on, work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Vertical, VerticalScroll
from textual.widgets import DataTable, Input, Static

from routes_core.engine import EngineUnavailable
from routes_storage import repo

from routes_cli import __version__, actions, doctor as doctor_mod, engine_ctl, reports
from routes_cli.context import Context
from routes_cli.renderers import results as R
from routes_cli.renderers.doctor import doctor_view
from routes_cli.renderers.progress import ProgressModel
import os

from routes_cli.renderers.theme import ASCII, THEME, UNICODE
from routes_cli.service import AssessmentFinished, AssessmentRunner, PlanError, set_match
from routes_cli.tui.commands import COMMANDS, Command, CommandError, parse
from routes_cli.tui.modals import ConfirmModal, MatchModal, TokenModal
from routes_cli.tui.widgets import (AssessmentPanel, BuildRunPanel, Logo, Menu, PromptInput, Readiness,
                                   RemediationPanel, fade_in)

MENU = [
    ("scan", "Scan a website", "/scan "),
    ("analyze", "Analyse a repository or folder", "/analyze "),
    ("findings", "View latest findings", "/findings"),
    ("remediate", "Fix findings with the verified AI loop", "/remediate "),
    ("history", "View assessment history", "/history"),
    ("projects", "Projects", "/projects"),
    ("doctor", "Check ROUTES installation", "/doctor"),
]

HINTS = {
    "home": "↑↓ menu · type a command · Tab completes · ↑ history · /help · Ctrl+C twice to exit",
    "running": "Assessment running · Ctrl+C cancels it (the sandbox is stopped and removed)",
    "verifying": "Build-and-run in progress · Ctrl+C cancels it (all three containers and networks are removed)",
    "verified": "/verify again · /home · Esc back to prompt",
    "remediating": "AI remediation running · Ctrl+C cancels it (the current sandbox is stopped and removed)",
    "remediated": "/findings · /remediate <id> · /report html · /home",
    "results": "↑↓ select a finding · Enter shows details · /remediate [id] fixes it · /report html · Esc prompt",
    "default": "Type a command · Tab completes · ↑ history · /help · /home",
}


class RoutesApp(App):
    CSS_PATH = "theme.tcss"
    TITLE = "ROUTES"
    ENABLE_COMMAND_PALETTE = False
    BINDINGS = [
        Binding("ctrl+c", "interrupt", "Cancel / exit", priority=True, show=False),
        Binding("ctrl+l", "clear", "Clear", show=False),
        Binding("escape", "focus_prompt", "Prompt", show=False),
        Binding("f1", "help", "Help", show=False),
    ]

    def __init__(self, *, no_animation: bool = False, ctx: Context | None = None, check_environment: bool = True):
        super().__init__()
        self.ctx = ctx or Context.load(no_animation=no_animation)
        self.motion = not self.ctx.no_animation
        if not self.motion:
            self.animation_level = "none"
        # Textual draws Unicode itself; ROUTES_ASCII=1 forces plain symbols for limited fonts.
        self.g = ASCII if os.environ.get("ROUTES_ASCII") == "1" else UNICODE
        self.check_environment = check_environment
        self.running: threading.Event | None = None      # cancel event of the running assessment
        self.model: ProgressModel | None = None
        self.last_interrupt = 0.0
        self.view_name = "home"
        self.run_kind = "assessment"                      # what Ctrl+C would cancel: "assessment" | "verify"
        self._findings: list = []
        self.console.push_theme(THEME)

    # ----------------------------------------------------------------- layout
    def compose(self) -> ComposeResult:
        yield Static(self._topbar_text(), id="topbar")
        yield VerticalScroll(id="body")
        with Vertical(id="prompt-area"):
            yield PromptInput(self.ctx.home.history, self._project_names, id="prompt")
            yield Static(HINTS["home"], id="hint")

    def _topbar_text(self) -> Text:
        project = self.ctx.config.current_project
        return Text.from_markup(f"[b #36c2b4]ROUTES[/]  [#5c6068]{__version__}[/]"
                                + (f"   [#8a8f98]project[/] {escape(project)}" if project else ""))

    def on_mount(self) -> None:
        self.show_home()
        if self.ctx.init_report is not None:
            self.notify(f"First run: created {self.ctx.home.root}", title="ROUTES initialised")

    def _project_names(self) -> list[str]:
        try:
            with self.ctx.session() as db:
                return [p.name for p in repo.list_projects(db)]
        except Exception:  # noqa: BLE001
            return []

    @property
    def body(self) -> VerticalScroll:
        return self.query_one("#body", VerticalScroll)

    @property
    def prompt(self) -> PromptInput:
        return self.query_one("#prompt", PromptInput)

    def set_view(self, name: str, *widgets, hint: str | None = None) -> None:
        self.view_name = name
        body = self.body
        body.remove_children()
        container = Vertical(*widgets, classes="view")
        body.mount(container)
        body.scroll_home(animate=False)
        fade_in(container, enabled=self.motion)
        self.query_one("#hint", Static).update(hint or HINTS.get(name, HINTS["default"]))
        self.query_one("#topbar", Static).update(self._topbar_text())

    def show_text(self, name: str, renderable, *, title: str | None = None) -> None:
        widgets = []
        if title:
            widgets.append(Static(title, classes="section-title"))
        widgets.append(Static(renderable))
        self.set_view(name, *widgets)

    # ------------------------------------------------------------------- home
    def show_home(self) -> None:
        ascii_only = self.g is ASCII
        menu = Menu([(key, label) for key, label, _ in MENU], pointer=self.g.arrow, id="menu")
        readiness = Readiness(self.g, animate=self.motion, id="readiness")
        tagline = Static(Text.from_markup("[#e6e6e3]Application security assessment[/]\n"
                                          "[#8a8f98]Local-first · your code never leaves this machine except to the "
                                          "local sandbox engine[/]"), id="tagline")
        self.set_view("home", Logo(ascii_only=ascii_only, animate=self.motion, id="logo"), tagline, readiness,
                      Static("What would you like to do?", classes="section-title"), menu)
        self.call_after_refresh(menu.focus)
        if self.check_environment:
            self.check_readiness(readiness)

    @work(thread=True, exclusive=True, group="readiness")
    def check_readiness(self, widget: Readiness) -> None:
        try:
            with self.ctx.session() as db:
                n = len(repo.history(db, None, limit=1000))
            self.call_from_thread(widget.set, "Database", True, f"{n} assessment{'s' if n != 1 else ''}")
        except Exception as exc:  # noqa: BLE001
            self.call_from_thread(widget.set, "Database", False, type(exc).__name__)
        rc, out = engine_ctl.run_quiet(["docker", "version", "--format", "{{.Server.Version}}"], timeout=10)
        self.call_from_thread(widget.set, "Docker", rc == 0, out[:20] if rc == 0 else "not running")
        try:
            with self.ctx.engine_client() as c:
                h = c.health()
            ok = bool(h.get("docker") and h.get("gateway"))
            self.call_from_thread(widget.set, "Engine", ok if ok else None, "ready" if ok else "degraded · /doctor")
        except EngineUnavailable:
            self.call_from_thread(widget.set, "Engine", False, "offline · /engine up")

    @on(Menu.Chosen, "#menu")
    def menu_selected(self, event: Menu.Chosen) -> None:
        entry = next(m for m in MENU if m[0] == event.key)
        if entry[2].endswith(" "):
            self.prompt.value = entry[2]
            self.prompt.cursor_position = len(entry[2])
            self.prompt.focus()
            hint = {"verify": "Enter a GitHub URL, folder or .zip, then --tests <plan.json> [--patch <fix.diff>]",
                    "remediate": "Enter finding numbers (e.g. 01 03), or just Enter for every code finding of the "
                                 "latest assessment · /findings lists them"}.get(
                event.key, "Enter a website URL (scan) or a GitHub URL, folder or .zip (analyse), then press Enter")
            self.query_one("#hint", Static).update(hint)
        else:
            self.execute(entry[2])

    def on_key(self, event) -> None:
        # Typing anywhere goes to the prompt.
        if self.focused is not self.prompt and event.is_printable and event.character \
                and not isinstance(self.screen, (ConfirmModal, TokenModal, MatchModal)) and event.character != " ":
            self.prompt.focus()
            self.prompt.insert_text_at_cursor(event.character)
            event.stop()

    # ---------------------------------------------------------------- prompt
    @on(Input.Submitted, "#prompt")
    def prompt_submitted(self, event: Input.Submitted) -> None:
        line = event.value.strip()
        self.prompt.value = ""
        if not line:
            return
        self.prompt.remember(line)
        self.execute(line)

    def execute(self, line: str) -> None:
        try:
            cmd = parse(line)
        except CommandError as exc:
            if str(exc):
                self.notify(str(exc), severity="warning")
            return
        handler = getattr(self, f"cmd_{cmd.name}", None)
        if handler is None:
            self.notify(f"/{cmd.name} is not available here.", severity="warning")
            return
        handler(cmd)

    def action_focus_prompt(self) -> None:
        self.prompt.focus()

    def action_clear(self) -> None:
        self.cmd_clear(Command("clear"))

    def action_help(self) -> None:
        self.cmd_help(Command("help"))

    def action_interrupt(self) -> None:
        if self.running is not None and not self.running.is_set():
            self.confirm_cancel()
            return
        if isinstance(self.screen, (ConfirmModal, TokenModal, MatchModal)):
            self.screen.dismiss(None if isinstance(self.screen, TokenModal) else False)
            return
        if self.prompt.value:
            self.prompt.value = ""
            return
        now = time.monotonic()
        if now - self.last_interrupt < 2.0:
            self.exit()
            return
        self.last_interrupt = now
        self.notify("Press Ctrl+C again to exit ROUTES.", timeout=2)

    @work
    async def confirm_cancel(self) -> None:
        if self.run_kind == "remediate":
            modal = ConfirmModal(
                "Cancel the remediation?",
                "ROUTES will stop the current sandbox run, remove its containers and networks, and record the "
                "remaining findings as cancelled. Patches already verified are kept.",
                yes="Cancel remediation", no="Keep running")
        elif self.run_kind == "verify":
            modal = ConfirmModal(
                "Cancel the build-and-run?",
                "ROUTES will stop the application, database and test runner, remove their containers and networks, "
                "and delete the staged source. The result will be reported as cancelled (inconclusive).",
                yes="Cancel run", no="Keep running")
        else:
            modal = ConfirmModal(
                "Cancel the running assessment?",
                "ROUTES will stop the sandbox, remove its container and network, and record the assessment as "
                "cancelled. Results gathered so far are not kept.", yes="Cancel assessment", no="Keep running")
        ok = await self.push_screen_wait(modal)
        if ok and self.running is not None:
            self.running.set()
            self.notify("Cancelling: waiting for the engine to stop and remove the sandbox.")
            self.query_one("#hint", Static).update("Cancelling…")

    # -------------------------------------------------------------- commands
    def cmd_help(self, cmd: Command) -> None:
        t = R.table("Command", "What it does")
        for spec in COMMANDS:
            t.add_row(f"[accent]{escape(spec.usage)}[/]", spec.summary)
        keys = R.table("Key", "Action")
        for k, v in (("Enter", "Run the command"), ("↑ / ↓", "Command history (in the prompt)"),
                     ("Tab", "Complete commands, options, project names and paths"),
                     ("Esc", "Back to the prompt"), ("Ctrl+L", "Clear the screen"),
                     ("Ctrl+C", "Cancel a running assessment · press twice to exit")):
            keys.add_row(k, v)
        self.set_view("help", Static("Commands", classes="section-title"), Static(t),
                      Static("Keys", classes="section-title"), Static(keys),
                      Static(Text("Website scans read up to 25 public pages on the exact hostname, using GET "
                                  "requests only. Source analysis is static: repository code is never run. "
                                  "/verify is the exception: it builds and runs the application inside a "
                                  "disposable, network-isolated sandbox (docs/BUILD_RUN.md).",
                                  style="#8a8f98")))

    def cmd_clear(self, cmd: Command) -> None:
        self.set_view("default", Static(""))

    def cmd_home(self, cmd: Command) -> None:
        self.show_home()

    def cmd_exit(self, cmd: Command) -> None:
        if self.running is not None and not self.running.is_set():
            self.notify("An assessment is running. Cancel it first (Ctrl+C).", severity="warning")
            return
        self.exit()

    def cmd_scan(self, cmd: Command) -> None:
        if not cmd.args:
            self.notify("Usage: /scan <website-url> [--source <repo|folder|zip>]", severity="warning")
            return
        req = actions.Request(url=cmd.args[0], source=cmd.options.get("--source"), ref=cmd.options.get("--ref"),
                              private="--private" in cmd.flags, project=cmd.options.get("--project"))
        self.start_assessment(req)

    def cmd_analyze(self, cmd: Command) -> None:
        if not cmd.args:
            self.notify("Usage: /analyze <github-url|folder|zip> [--url <website>]", severity="warning")
            return
        req = actions.Request(url=cmd.options.get("--url"), source=cmd.args[0], ref=cmd.options.get("--ref"),
                              private="--private" in cmd.flags, project=cmd.options.get("--project"))
        self.start_assessment(req)

    # ------------------------------------------------------------ remediation
    def cmd_remediate(self, cmd: Command) -> None:
        self.start_remediation(cmd)

    @work(exclusive=True, group="assessment")
    async def start_remediation(self, cmd: Command) -> None:
        from routes_cli import remediation as rem

        if self.running is not None and not self.running.is_set():
            self.notify("Something is already running. Wait for it or cancel it (Ctrl+C).", severity="warning")
            return
        try:
            a = actions.latest(self.ctx, assessment=cmd.options.get("--assessment"))
            if a is None or not a.findings:
                raise rem.RemediationError("No findings to remediate. Run /analyze first.")
            targets = rem.select(a, None if "--all" in cmd.flags else (cmd.args or None))
            attempts = int(cmd.options.get("--attempts", rem.DEFAULT_MAX_ATTEMPTS))
            prepared = await asyncio.to_thread(rem.prepare, self.ctx, a, targets, source=cmd.options.get("--source"),
                                               max_attempts=attempts)
        except ValueError as exc:   # RemediationError, or a non-numeric --attempts
            self.notify(str(exc), severity="error", title="Cannot start remediation")
            return
        listing = "\n".join(f"  #{f.seq:02d} {escape(f.title)} ({escape(f.file or '')}:{f.line})" for f in targets[:8])
        if len(targets) > 8:
            listing += f"\n  … and {len(targets) - 8} more"
        body = (f"[b]{len(targets)} finding(s)[/b] in {escape(prepared.source.label)}\n{listing}\n\n"
                "For each finding: Model A plans the fix, ROUTES generates the tests and runs the ORIGINAL in the "
                f"sandbox (baseline), then up to {attempts} attempts of Model B patch → validate → build & test → "
                "rescan, feeding every failure back. The code region sent to the models is redacted first. The "
                "application's own code runs inside the sandbox. Your files are not changed.")
        ok = await self.push_screen_wait(ConfirmModal("Start the AI remediation loop?", body, yes="Start",
                                                      no="Cancel"))
        if not ok:
            prepared.close()
            self.notify("Not started.")
            return
        self.running = threading.Event()
        self.run_kind = "remediate"
        panel = RemediationPanel(self.g, animate=self.motion, id="remediation")
        head = Static(Text.from_markup("[b #e6e6e3]ROUTES[/] [#5c6068]/[/] [#8a8f98]AI REMEDIATION[/]"),
                      id="assessment-head")
        self.set_view("remediating", head, panel)
        self.prompt.focus()
        self._remediation_worker(prepared, self.running, panel, cmd.options.get("--output"), a.id)

    @work(thread=True, exclusive=True, group="runner")
    def _remediation_worker(self, prepared, cancel: threading.Event, panel, output, assessment_id) -> None:
        from routes_cli import remediation as rem

        app = self

        class UiListener(rem.Listener):
            def changed(self, run) -> None:
                app.call_from_thread(panel.set_run, run)

        run = saved = None
        try:
            wf = prepared.workflow(listener=UiListener(), should_cancel=cancel.is_set)
            self.call_from_thread(panel.set_run, wf.run)
            run = wf.execute()
            saved = rem.save(self.ctx, run, output=output)
        except EngineUnavailable:
            self.call_from_thread(self.notify, "The ROUTES engine is not reachable. Run /engine up.", severity="error")
        except Exception as exc:  # noqa: BLE001
            self.call_from_thread(self.notify, f"The remediation stopped unexpectedly ({type(exc).__name__}: "
                                               f"{str(exc)[:120]}).", severity="error")
        finally:
            prepared.close()
        self.call_from_thread(self._remediation_finished, run, saved, panel)

    def _remediation_finished(self, run, saved, panel) -> None:
        from routes_cli.renderers import remediation as RV

        self.running = None
        self.run_kind = "assessment"
        if run is None:
            self.query_one("#hint", Static).update(HINTS["default"])
            return
        sev = {"verified_fixed": "information", "partially_remediated": "warning", "cancelled": "warning"}.get(
            run.verdict, "error" if run.verdict == "failed" else "warning")
        self.notify(f"Remediation finished: {run.verdict.replace('_', ' ')}", severity=sev, timeout=8)
        title = Text.from_markup(f"[b #e6e6e3]AI remediation[/]  [#5c6068]run {escape(run.id)}[/]")
        widgets = [Static(title, classes="section-title"), Static(RV.summary(run, self.g, saved)),
                   Static("Pipeline", classes="section-title"), Static(RV.render(run, self.g, animate=False,
                                                                                 show_all=True))]
        hint = HINTS["remediated"]
        if saved is not None and saved.combined:
            hint = f"git apply {saved.combined} · /findings · /report html · /home"
        self.set_view("remediated", *widgets, hint=hint)

    # ------------------------------------------------------------ build & run
    def cmd_verify(self, cmd: Command) -> None:
        if not cmd.args or "--tests" not in cmd.options:
            self.notify("Usage: /verify <github-url|folder|zip> --tests <plan.json> [--patch <fix.diff>]",
                        severity="warning")
            return
        self.start_verify(cmd)

    @work(exclusive=True, group="assessment")
    async def start_verify(self, cmd: Command) -> None:
        import json as _json

        from routes_core.buildrun import BuildRunInvalid, BuildRunRequest
        from routes_core.sources import SourceError, classify

        if self.running is not None and not self.running.is_set():
            self.notify("Something is already running. Wait for it or cancel it (Ctrl+C).", severity="warning")
            return
        try:
            spec = classify(cmd.args[0], ref=cmd.options.get("--ref"))
            generated = None
            if cmd.options["--tests"].strip().lower() == "auto":
                generated = actions.generate_test_plan(actions.source_analysis(self.ctx, source=spec))
                plan = generated.plan
            else:
                plan = _json.loads(Path(cmd.options["--tests"]).expanduser().read_text("utf-8"))
            patch = Path(cmd.options["--patch"]).expanduser().read_text("utf-8") if "--patch" in cmd.options else None
            approved = [x.strip() for x in cmd.options.get("--approve", "").split(",") if x.strip()]
            req = BuildRunRequest(source=spec, test_plan=plan, patch=patch, approved_scripts=approved,
                                  requested_by="routes-tui")
            req.validate()
        except (SourceError, PlanError) as exc:
            self.notify(str(exc), severity="error", title="Cannot start")
            return
        except (OSError, ValueError) as exc:
            msg = str(exc) if isinstance(exc, BuildRunInvalid) else f"Could not read the test plan or patch: {exc}"
            self.notify(msg, severity="error", title="Cannot start")
            return
        body = (f"[b]{escape(spec.label)}[/b]\n\nROUTES will install its dependencies (npm registry only, install "
                "scripts off), build and start it inside disposable containers with no network access after "
                "installation, then run your test plan against it. The repository's own code runs inside the "
                "sandbox, so only use projects you own or trust. Your files are never modified"
                + (", and the patch is applied to a temporary copy only." if patch else "."))
        if generated is not None:
            body += (f"\n\n[b]Generated test plan:[/b] {len(plan['tests'])} tests from your latest analysis "
                     f"({generated.flows_covered} SQL injection flow(s) covered, {generated.flows_skipped} skipped). "
                     "Use [b]routes testplan[/b] to save and review it.")
        ok = await self.push_screen_wait(ConfirmModal("Run this application in a sandbox?", body,
                                                      yes="Build and run", no="Cancel"))
        if not ok:
            self.notify("Not started.")
            return
        if "--private" in cmd.flags:
            if not spec.is_github:
                self.notify("--private applies to GitHub repositories only.", severity="warning")
                return
            token = await self.push_screen_wait(TokenModal(spec.label))
            if not token:
                self.notify("Not started: no token was entered.")
                return
            req.token, token = token.strip(), None
        self.run_verify(req)

    def run_verify(self, req) -> None:
        self.running = threading.Event()
        self.run_kind = "verify"
        panel = BuildRunPanel(self.g, animate=self.motion, source=req.source.label, id="buildrun")
        head = Static(Text.from_markup("[b #e6e6e3]ROUTES[/] [#5c6068]/[/] [#8a8f98]BUILD & RUN[/]"),
                      id="assessment-head")
        self.set_view("verifying", head, panel)
        self.prompt.focus()
        self._verify_worker(req, self.running, panel)

    @work(thread=True, exclusive=True, group="runner")
    def _verify_worker(self, req, cancel: threading.Event, panel) -> None:
        from routes_core.buildrun import BuildRunInvalid, submit, wait
        from routes_core.engine import EngineRejected
        from routes_core.sources import SourceError

        client = self.ctx.engine_client()
        final = None
        try:
            run = submit(client, req, cache_dir=self.ctx.home.cache,
                         on_local=lambda m: self.call_from_thread(panel.add_local, m))
            self.call_from_thread(panel.set_state, run)
            final = wait(client, run, on_state=lambda st: self.call_from_thread(panel.set_state, st),
                         should_cancel=cancel.is_set)
        except (BuildRunInvalid, SourceError) as exc:
            self.call_from_thread(self.notify, str(exc), severity="error", title="Cannot start")
        except EngineRejected as exc:
            self.call_from_thread(self.notify, f"The engine rejected the request: {exc}", severity="error")
        except EngineUnavailable:
            self.call_from_thread(self.notify, "The ROUTES engine is not reachable. Run /engine up (Docker must be "
                                               "running).", severity="error")
        except Exception as exc:  # noqa: BLE001
            self.call_from_thread(self.notify, f"The build-and-run stopped unexpectedly ({type(exc).__name__}).",
                                  severity="error")
        finally:
            req.token = None
            client.close()
        self.call_from_thread(self._verify_finished, final, panel)

    def _verify_finished(self, final, panel) -> None:
        import json as _json

        from routes_cli.renderers import buildrun as BR

        self.running = None
        self.run_kind = "assessment"
        panel.finish()
        if final is None:
            self.query_one("#hint", Static).update(HINTS["default"])
            return
        verdict = (final.get("result") or {}).get("verification", "INCONCLUSIVE")
        saved = None
        try:
            out_dir = self.ctx.home.reports / "build-runs"
            out_dir.mkdir(parents=True, exist_ok=True)
            saved = out_dir / f"{time.strftime('%Y%m%d-%H%M%S')}-{final.get('id', 'run')}.json"
            saved.write_text(_json.dumps(final, indent=2), "utf-8")
        except OSError:
            saved = None
        sev = {"VERIFIED_RUN": "information", "TESTS_FAILED": "warning",
               "DYNAMIC_VERIFICATION_UNSUPPORTED": "warning"}.get(verdict, "error")
        self.notify(f"Build-and-run finished: {verdict}", severity=sev, timeout=8)
        title = Text.from_markup(f"[b #e6e6e3]Build & run[/]  [#5c6068]run {escape(str(final.get('id', '')))}[/]")
        widgets = [Static(title, classes="section-title"), Static(BR.render(final, self.g))]
        if saved is not None:
            widgets.append(Static(Text(f"Full result saved to {saved}", style="#5c6068")))
        self.set_view("verified", *widgets)

    @work(exclusive=True, group="assessment")
    async def start_assessment(self, req: actions.Request) -> None:
        if self.running is not None and not self.running.is_set():
            self.notify("An assessment is already running.", severity="warning")
            return
        try:
            prepared = actions.prepare(self.ctx, req)
        except PlanError as exc:
            self.notify(str(exc), severity="error", title="Cannot start")
            return
        if prepared.needs_authorisation:
            ok = await self.push_screen_wait(ConfirmModal(
                "Permission to assess this website",
                f"[b]{escape(prepared.plan.target_url)}[/b]\n\nROUTES will read up to 25 public pages on this exact "
                "hostname with GET requests. It never submits forms, signs in or sends attacks.\n\n"
                f"[b]{escape(actions.AUTHORISATION_STATEMENT)}[/b]", yes="I confirm", no="Cancel"))
            if not ok:
                self.notify("Not started: permission was not confirmed.")
                return
            actions.confirm_authorisation(self.ctx, prepared)
        if prepared.needs_token:
            token = await self.push_screen_wait(TokenModal(prepared.source.label))
            if not token:
                self.notify("Not started: no token was entered.")
                return
            try:
                actions.attach_token(prepared, token)
            except PlanError as exc:
                self.notify(str(exc), severity="error")
                return
            finally:
                token = None
        if prepared.ask_match:
            decision = await self.push_screen_wait(MatchModal(actions.MATCH_QUESTION.format(host=prepared.hostname)))
            set_match(self.ctx, prepared.project.id, decision or "pending")
        self.run_assessment(prepared)

    def run_assessment(self, prepared: actions.Prepared) -> None:
        self.model = ProgressModel()
        self.running = threading.Event()
        self.run_kind = "assessment"
        panel = AssessmentPanel(self.model, self.g, animate=self.motion, id="progress")
        self.set_view("running", Static(Text.from_markup("[b #e6e6e3]ROUTES[/] [#5c6068]/[/] [#8a8f98]ASSESSMENT[/]"),
                                        id="assessment-head"), panel)
        self.prompt.focus()
        self._assessment_worker(prepared, self.model, self.running, panel)

    @work(thread=True, exclusive=True, group="runner")
    def _assessment_worker(self, prepared, model: ProgressModel, cancel: threading.Event, panel) -> None:
        def on_update(u) -> None:
            self.call_from_thread(self._apply_update, model, panel, u)

        try:
            AssessmentRunner(self.ctx, prepared.plan, on_update, cancel).run()
        except PlanError as exc:
            self.call_from_thread(self.notify, str(exc), severity="error", title="Cannot start")
            self.call_from_thread(self._finished, None)
        except Exception as exc:  # noqa: BLE001
            self.call_from_thread(self.notify, f"The assessment stopped unexpectedly ({type(exc).__name__}).",
                                  severity="error")
            self.call_from_thread(self._finished, None)

    def _apply_update(self, model: ProgressModel, panel, u) -> None:
        for sev, message in model.apply(u):
            self.notify(message, severity=sev, timeout=6)
        panel.redraw()
        if isinstance(u, AssessmentFinished):
            self.set_timer(0.6 if self.motion else 0.0, lambda: self._finished(u))

    def _finished(self, u: AssessmentFinished | None) -> None:
        self.running = None
        if u is None:
            self.query_one("#hint", Static).update(HINTS["default"])
            return
        sev = {"completed": "information", "partially_completed": "warning"}.get(u.status, "error")
        self.notify(f"Assessment {u.status.replace('_', ' ')} · {u.findings} finding{'s' if u.findings != 1 else ''}",
                    severity=sev)
        self.show_results(u.assessment_id)

    # --------------------------------------------------------------- results
    def show_results(self, assessment_id: str | None = None, *, detail: str | None = None,
                     severity: str | None = None) -> None:
        try:
            a = actions.latest(self.ctx, assessment=assessment_id)
        except PlanError as exc:
            self.notify(str(exc), severity="error")
            return
        if a is None:
            self.show_text("results", R.empty("No finished assessments yet. Try /scan <url> or /analyze <path>."))
            return
        items = [f for f in a.findings if not severity or f.severity == severity]
        self._findings = items
        widgets = [Static(Text.from_markup(f"[b #e6e6e3]{escape(a.project.display_name)}[/]  [#5c6068]assessment "
                                           f"{a.id[:8]}[/]"), classes="section-title"),
                   Static(R.assessment_summary(a, self.g))]
        if a.source_result is not None or a.findings:
            widgets.append(Static("Security findings", classes="section-title"))
            if items:
                table = DataTable(id="findings-table", cursor_type="row", zebra_stripes=False)
                table.add_columns("ID", "Vulnerability", "Severity", "Status", "Location")
                for f in items:
                    where = f"{f.file}:{f.line}" if f.file else (f.endpoint or "-")
                    table.add_row(f"{f.seq:02d}", f.type, Text.from_markup(R.severity_text(f.severity, self.g),
                                                                             style=""),
                                  f.status.upper(), where, key=str(f.seq))
                widgets += [table, Static("", id="detail")]
            else:
                widgets.append(Static(R.findings_table([], self.g)))
        elif any(s.kind == "discovery" for s in a.steps):
            web = [e for e in a.endpoints if e.origin != "source_route"]
            widgets += [Static("Technologies", classes="section-title"), Static(R.technologies_table(a.technologies, self.g)),
                        Static("Endpoints", classes="section-title"), Static(R.endpoints_table(web, self.g, limit=25))]
        self.set_view("results", *widgets)
        if items:
            target = next((f for f in items if detail and (detail.lstrip("0") == str(f.seq))), items[0])
            detail_widget = widgets[-1]

            def select() -> None:
                table.move_cursor(row=items.index(target))
                detail_widget.update(R.finding_detail(target, self.g))
                table.focus()

            self.call_after_refresh(select)

    @on(DataTable.RowHighlighted, "#findings-table")
    def finding_highlighted(self, event: DataTable.RowHighlighted) -> None:
        seq = event.row_key.value if event.row_key else None
        f = next((x for x in self._findings if str(x.seq) == seq), None)
        if f is not None:
            self._show_detail(f)

    def _show_detail(self, f) -> None:
        for widget in self.query("#detail"):
            widget.update(R.finding_detail(f, self.g))

    def cmd_findings(self, cmd: Command) -> None:
        sev = cmd.options.get("--severity")
        self.show_results(detail=cmd.args[0] if cmd.args else None, severity=sev.lower() if sev else None)

    def cmd_history(self, cmd: Command) -> None:
        with self.ctx.session() as db:
            p = repo.find_project(db, cmd.args[0]) if cmd.args else None
            if cmd.args and p is None:
                self.notify(f"No project named '{cmd.args[0]}'.", severity="warning")
                return
            items = repo.history(db, p)
            for a in items:
                _ = (a.project, list(a.findings))
            self.show_text("history", R.history_table(items, self.g), title="Assessment history")

    def cmd_projects(self, cmd: Command) -> None:
        with self.ctx.session() as db:
            items = repo.list_projects(db)
            for p in items:
                _ = list(p.assessments)
            self.show_text("projects", R.projects_table(items, self.ctx.config.current_project, self.g),
                           title="Projects")

    def cmd_project(self, cmd: Command) -> None:
        sub = cmd.args[0] if cmd.args else "show"
        if sub == "use" and len(cmd.args) == 2:
            with self.ctx.session() as db:
                p = repo.find_project(db, cmd.args[1])
            if p is None:
                self.notify(f"No project named '{cmd.args[1]}'.", severity="warning")
                return
            self.ctx.config.current_project = p.name
            self.ctx.save_config()
            self.query_one("#topbar", Static).update(self._topbar_text())
            self.notify(f"Current project: {p.name}")
        elif sub == "show":
            ref = cmd.args[1] if len(cmd.args) > 1 else self.ctx.config.current_project
            if not ref:
                self.notify("No current project. Use /project use <name>.", severity="warning")
                return
            with self.ctx.session() as db:
                p = repo.find_project(db, ref)
                if p is None:
                    self.notify(f"No project named '{ref}'.", severity="warning")
                    return
                for a in p.assessments:
                    _ = (a.project, list(a.findings))
                self.show_text("projects", R.project_detail(p, self.g))
        elif sub == "add" and "--name" in cmd.options:
            self._project_add(cmd)
        else:
            self.notify("Usage: /project add <source> --name <name> [--url <site>] | use <name> | show [name]",
                        severity="warning")

    def _project_add(self, cmd: Command) -> None:
        from routes_core.sources import SourceError, classify

        from routes_cli.service import _source_location, validate_target

        spec = url = host = None
        try:
            if len(cmd.args) > 1:
                spec = classify(cmd.args[1], ref=cmd.options.get("--ref"))
            if "--url" in cmd.options:
                url, host = validate_target(self.ctx, cmd.options["--url"])
            if spec is None and url is None:
                raise PlanError("Give a source and/or --url.")
            with self.ctx.session() as db:
                p = repo.create_project(db, name=cmd.options["--name"], display_name=cmd.options["--name"],
                                        website_url=url, hostname=host, source_kind=spec.kind if spec else None,
                                        source_location=_source_location(spec), source_ref=spec.ref if spec else None,
                                        source_private="--private" in cmd.flags and bool(spec and spec.is_github))
        except (SourceError, PlanError, ValueError, repo.StorageError) as exc:
            self.notify(str(exc), severity="error")
            return
        self.ctx.config.current_project = p.name
        self.ctx.save_config()
        self.notify(f"Project {p.name} added and selected.")
        self.cmd_projects(Command("projects"))

    def cmd_report(self, cmd: Command) -> None:
        fmt = (cmd.args[0] if cmd.args else self.ctx.config.report_format).lower()
        fmt = "markdown" if fmt == "md" else fmt
        if fmt not in reports.FORMATS:
            self.notify("Report format must be markdown, html or json.", severity="warning")
            return
        a = actions.latest(self.ctx)
        if a is None:
            self.notify("No finished assessments to report on.", severity="warning")
            return
        path = reports.write_report(self.ctx.home, a, fmt)
        self.notify(str(path), title=f"{fmt.upper()} report written", timeout=8)

    def cmd_doctor(self, cmd: Command) -> None:
        panel = Static(Text.from_markup("[#36c2b4]Checking the ROUTES environment…[/]"), id="doctor")
        self.set_view("doctor", panel)
        self._doctor_worker(panel)

    @work(thread=True, exclusive=True, group="doctor")
    def _doctor_worker(self, panel: Static) -> None:
        stop = threading.Event()
        frames = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏" if self.g.done == "✓" else "|/-\\"

        def spin():
            i = 0
            while not stop.wait(0.1):
                i += 1
                if self.motion:
                    self.call_from_thread(panel.update, Text.from_markup(
                        f"[#36c2b4]{frames[i % len(frames)]}[/] Checking Docker, the engine, SQLite and the "
                        "analysis tools…"))

        t = threading.Thread(target=spin, daemon=True)
        t.start()
        try:
            checks = doctor_mod.run_checks(self.ctx)
        finally:
            stop.set()
        self.call_from_thread(panel.update, doctor_view(checks, self.g))

    def cmd_engine(self, cmd: Command) -> None:
        sub = cmd.args[0] if cmd.args else "status"
        if sub not in ("up", "status", "stop"):
            self.notify("Usage: /engine up | status | stop", severity="warning")
            return
        if sub == "status":
            try:
                with self.ctx.engine_client() as c:
                    h = c.health()
                self.notify(f"Engine ready · Docker proxy {'ok' if h.get('docker') else 'unreachable'} · "
                            f"gateway {'ok' if h.get('gateway') else 'unreachable'}")
            except EngineUnavailable as exc:
                self.notify(str(exc), severity="error")
            return
        if self.running is not None:
            self.notify("Wait for the running assessment to finish.", severity="warning")
            return
        log = Static("", id="engine-log")
        title = "Starting the engine" if sub == "up" else "Stopping the engine"
        self.set_view("engine", Static(title, classes="section-title"), log)
        self._engine_worker(sub, log)

    @work(thread=True, exclusive=True, group="engine")
    def _engine_worker(self, sub: str, log: Static) -> None:
        es = self.ctx.engine
        target = engine_ctl.ComposeTarget(es.compose_file, es.env_file)
        lines: list[str] = []
        try:
            cmd = engine_ctl.up_command(target) if sub == "up" else engine_ctl.stop_command(target)

            def on_line(text: str) -> None:
                if text.strip():
                    lines.append(text.strip()[:140])
                    shown = "\n".join(escape(x) for x in lines[-14:])
                    self.call_from_thread(log.update, Text.from_markup(f"[#8a8f98]{shown}[/]"))

            rc = engine_ctl.stream(cmd, on_line)
        except engine_ctl.EngineControlError as exc:
            self.call_from_thread(self.notify, str(exc), severity="error")
            return
        if rc == 0:
            self.call_from_thread(self.notify, "Engine running." if sub == "up" else "Engine stopped.")
        else:
            self.call_from_thread(self.notify, f"docker compose exited with status {rc}.", severity="error")
