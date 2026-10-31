"""Assessment orchestration for the CLI.

The same path as the web stack's workers, without Redis or PostgreSQL:
start sandbox runs on the engine, poll them, validate the results against the
shared contracts, map them with ``routes_core.mapping`` and store them in
SQLite. Progress is reported through callbacks so the direct commands (Rich)
and the interactive interface (Textual) render the same real events.
"""

from __future__ import annotations

import queue
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from pydantic import ValidationError

from routes_core.engine import EngineClient, EngineRejected, EngineUnavailable
from routes_core.mapping import discovery_records, network_summary, source_records
from routes_core.runner import is_cleaning_up, poll_run, summarise
from routes_core.sources import SourceError, SourceSpec, pack_directory
from routes_shared.contracts import DiscoveryResult, SourceResult
from routes_shared.netpolicy import UrlPolicyError, parse_target_url
from routes_storage import repo
from routes_storage.models import Assessment, Project, utcnow

from routes_cli.context import Context

DISCOVERY_DEADLINE = 840
SOURCE_DEADLINE = 1100
ENGINE_DOWN = "The ROUTES engine is not reachable. Start it with `routes engine up` (Docker must be running)."


# ----------------------------------------------------------------- updates
@dataclass(frozen=True)
class StepUpdate:
    kind: str                      # discovery | source
    status: str                    # queued | running | completed | failed | cancelled
    stage: str | None = None       # current stage (sandbox or local)
    completed: tuple[str, ...] = ()
    message: str = ""
    data: dict = field(default_factory=dict)
    cleaning_up: bool = False
    error: str | None = None


@dataclass(frozen=True)
class AssessmentStarted:
    assessment_id: str
    project_name: str
    target_url: str | None
    source_label: str | None
    steps: tuple[str, ...]
    local_stages: tuple[str, ...]


@dataclass(frozen=True)
class ResultsProcessing:
    assessment_id: str


@dataclass(frozen=True)
class AssessmentFinished:
    assessment_id: str
    status: str
    error: str | None
    findings: int
    removed_by_retention: tuple[str, ...] = ()


Update = StepUpdate | AssessmentStarted | ResultsProcessing | AssessmentFinished


class PlanError(ValueError):
    """User-facing problem with what was asked (bad URL, no permission, busy project)."""


@dataclass
class Plan:
    project_id: str
    target_url: str | None
    source: SourceSpec | None
    token: str | None = None       # memory only; handed to the engine, then dropped

    def steps(self) -> list[str]:
        return (["discovery"] if self.target_url else []) + (["source"] if self.source else [])


# ---------------------------------------------------------------- planning
def validate_target(ctx: Context, url: str) -> tuple[str, str]:
    """Return (normalised URL, hostname) or raise PlanError. The engine checks again."""
    try:
        target = parse_target_url(url, dev_allow_hosts=ctx.dev_allow_hosts())
    except UrlPolicyError as exc:
        raise PlanError(str(exc)) from exc
    return target.url, target.hostname


def resolve_project(ctx: Context, *, project_ref: str | None, url: str | None, hostname: str | None,
                    source: SourceSpec | None, authorised: bool) -> Project:
    """Use the named/current project, reuse one for the same target, or create a one-off project."""
    with ctx.session() as db:
        project = None
        if project_ref:
            project = repo.find_project(db, project_ref)
            if project is None:
                raise PlanError(f"No project named '{project_ref}'. See `routes projects`.")
        if project is None:
            location = _source_location(source)
            project = repo.project_for_target(db, hostname=hostname, source_location=location)
        if project is None:
            base = hostname or (source.repo if source and source.repo else Path(source.label).stem if source else "assessment")
            project = repo.create_project(db, name=repo.unique_name(db, base), display_name=hostname or source.label,
                                          website_url=url, hostname=hostname,
                                          source_kind=source.kind if source else None,
                                          source_location=_source_location(source),
                                          source_ref=source.ref if source else None, registered=False)
        if url and hostname:
            if project.hostname and project.hostname != hostname:
                raise PlanError(f"Project '{project.name}' is for {project.hostname}, not {hostname}.")
            project.website_url, project.hostname = url, hostname
            if authorised:
                project.authorised_at = utcnow()
        if source is not None:
            project.source_kind, project.source_location = source.kind, _source_location(source)
            project.source_ref = source.ref
        db.commit()
        if repo.active_assessment(db, project.id) is not None:
            repo.reconcile(db)
            if repo.active_assessment(db, project.id) is not None:
                raise PlanError(f"An assessment for '{project.name}' is already running.")
        return project


def _source_location(source: SourceSpec | None) -> str | None:
    if source is None:
        return None
    if source.is_github:
        return f"https://github.com/{source.owner}/{source.repo}"
    return str(source.path)


def set_match(ctx: Context, project_id: str, decision: str) -> None:
    with ctx.session() as db:
        p = db.get(Project, project_id)
        p.match_status = decision
        db.commit()


# ----------------------------------------------------------------- running
class AssessmentRunner:
    def __init__(self, ctx: Context, plan: Plan, on_update: Callable[[Update], None],
                 cancel: threading.Event | None = None, *, client_factory: Callable[[], EngineClient] | None = None,
                 poll_seconds: float = 1.5):
        self.ctx = ctx
        self.plan = plan
        self.emit = on_update
        self.cancel = cancel or threading.Event()
        self.client_factory = client_factory or ctx.engine_client
        self.poll_seconds = poll_seconds
        self._last: dict[str, StepUpdate] = {}

    def run(self) -> AssessmentFinished:
        plan = self.plan
        with self.ctx.session() as db:
            project = db.get(Project, plan.project_id)
            try:
                a = repo.start_assessment(db, project, target_url=plan.target_url,
                                          source_kind=plan.source.kind if plan.source else None,
                                          source_label=plan.source.label if plan.source else None,
                                          steps=plan.steps())
            except repo.StorageError as exc:
                raise PlanError(str(exc)) from exc
            local = ("packing", "uploading") if plan.source and plan.source.kind == "directory" else \
                    ("uploading",) if plan.source and plan.source.kind == "zip" else ()
            self.emit(AssessmentStarted(a.id, project.name, plan.target_url,
                                        plan.source.label if plan.source else None, tuple(plan.steps()), local))
            try:
                return self._run(db, a)
            except BaseException:
                db.rollback()
                a = db.get(Assessment, a.id)
                for s in a.steps:
                    if s.status in ("queued", "running"):
                        s.status, s.error, s.finished_at = "failed", "Interrupted.", utcnow()
                a.cancel_requested = a.cancel_requested or self.cancel.is_set()
                db.commit()
                repo.finalize(db, a)
                raise

    # -------------------------------------------------------------- internals
    def _run(self, db, a: Assessment) -> AssessmentFinished:
        plan = self.plan
        client = self.client_factory()
        runs: dict[str, dict] = {}
        try:
            repo.heartbeat(db, a, status="discovering" if plan.target_url else "analysing")
            if plan.target_url:
                self._start(db, a, client, runs, "discovery", {"kind": "discovery", "target_url": plan.target_url})
            if plan.source:
                spec = self._prepare_source(db, a, client)
                if spec is not None:
                    self._start(db, a, client, runs, "source", spec)
        finally:
            plan.token = None
            client.close()
        finals = self._supervise(db, a, runs)
        for kind, state in finals.items():
            self._store(db, a, kind, state)
        self.emit(ResultsProcessing(a.id))
        a.cancel_requested = self.cancel.is_set()
        db.commit()
        repo.finalize(db, a)
        removed = repo_retention_ids(self.ctx, a)
        count = len(repo.findings_for(db, a))
        result = AssessmentFinished(a.id, a.status, a.error, count, tuple(removed or ()))
        self.emit(result)
        return result

    def _fail(self, db, a, kind: str, error: str, status: str = "failed") -> None:
        s = repo.step(a, kind)
        s.status, s.error, s.finished_at = status, error[:1000], utcnow()
        db.commit()
        self.emit(StepUpdate(kind, status, s.stage, tuple(s.stages_completed or []), "", {}, error=error))

    def _local_stage(self, db, a, stage: str, message: str, done: list[str]) -> None:
        s = repo.step(a, "source")
        s.status, s.stage, s.message, s.stages_completed = "running", stage, message, list(done)
        s.started_at = s.started_at or utcnow()
        repo.heartbeat(db, a)
        self.emit(StepUpdate("source", "running", stage, tuple(done), message))

    def _prepare_source(self, db, a, client: EngineClient) -> dict | None:
        src = self.plan.source
        spec: dict = {"kind": "source", "target_url": self.plan.target_url}
        packed: Path | None = None
        done: list[str] = []
        try:
            if src.kind == "github":
                spec.update(source="github", owner=src.owner, repo=src.repo, ref=src.ref)
                if self.plan.token:
                    spec["credential_handle"] = client.put_credential(self.plan.token, f"github:{src.owner}/{src.repo}")
                    self.plan.token = None
                return spec
            path = src.path
            if src.kind == "directory":
                self._local_stage(db, a, "packing", f"Packing {src.label} (your files are only read)", done)
                packed, report = pack_directory(src.path, self.ctx.home.cache)
                done.append("packing")
                path = packed
                repo.step(a, "source").details = {"packed_files": report.files,
                                                  "skipped_excluded": report.skipped_excluded,
                                                  "skipped_links": report.skipped_links}
            self._local_stage(db, a, "uploading", f"Uploading {path.stat().st_size // 1024} KB", done)
            uploaded = client.upload_zip(path)
            spec.update(source="zip", upload_id=uploaded["upload_id"])
            return spec
        except SourceError as exc:
            self._fail(db, a, "source", str(exc))
        except EngineRejected as exc:
            self._fail(db, a, "source", f"The source could not be analysed: {exc}")
        except EngineUnavailable:
            self._fail(db, a, "source", ENGINE_DOWN)
        finally:
            if packed is not None:
                packed.unlink(missing_ok=True)
        return None

    def _start(self, db, a, client: EngineClient, runs: dict, kind: str, spec: dict) -> None:
        if self.cancel.is_set():
            self._fail(db, a, kind, "Cancelled.", "cancelled")
            return
        try:
            run = client.start(spec)
        except EngineRejected as exc:
            what = "The website URL was rejected" if kind == "discovery" else "The source could not be analysed"
            self._fail(db, a, kind, f"{what}: {exc}")
            return
        except EngineUnavailable:
            self._fail(db, a, kind, ENGINE_DOWN)
            return
        s = repo.step(a, kind)
        s.status, s.started_at = "running", s.started_at or utcnow()
        s.details = {**(s.details or {}), "run_id": run["id"]}
        if s.stage in ("packing", "uploading"):
            s.stages_completed = list(dict.fromkeys([*(s.stages_completed or []), s.stage]))
        s.stage = "starting"
        db.commit()
        runs[kind] = run
        self.emit(StepUpdate(kind, "running", "starting", tuple(s.stages_completed or []), "Starting sandbox"))

    def _supervise(self, db, a, runs: dict[str, dict]) -> dict[str, dict]:
        updates: queue.Queue = queue.Queue()
        finals: dict[str, dict] = {}
        threads = []
        for kind, run in runs.items():
            deadline = DISCOVERY_DEADLINE if kind == "discovery" else SOURCE_DEADLINE

            def target(kind=kind, run=run, deadline=deadline):
                client = self.client_factory()
                try:
                    finals[kind] = poll_run(client, run, deadline_seconds=deadline,
                                            on_state=lambda st: updates.put((kind, st)),
                                            should_cancel=self.cancel.is_set, poll_seconds=self.poll_seconds)
                except Exception as exc:  # noqa: BLE001
                    finals[kind] = {"status": "failed", "error": f"Lost contact with the engine ({type(exc).__name__})."}
                finally:
                    client.close()
                    updates.put((kind, None))

            t = threading.Thread(target=target, name=f"routes-{kind}", daemon=True)
            threads.append(t)
            t.start()
        pending = len(threads)
        while pending:
            try:
                kind, state = updates.get(timeout=5)
            except queue.Empty:
                repo.heartbeat(db, a)
                continue
            if state is None:
                pending -= 1
                continue
            self._mirror(db, a, kind, state)
        return finals

    def _mirror(self, db, a, kind: str, state: dict) -> None:
        s = repo.step(a, kind)
        local_done = [x for x in (s.stages_completed or []) if x in ("packing", "uploading")]
        progress = summarise(state.get("events") or [])
        if progress.current_stage:
            s.stage = progress.current_stage[:64]
            s.message = progress.message[:500]
            s.stages_completed = local_done + list(progress.completed_stages)
        repo.heartbeat(db, a)
        update = StepUpdate(kind, "running", s.stage, tuple(s.stages_completed or []), s.message or "",
                            dict(progress.data), cleaning_up=is_cleaning_up(state))
        if self._last.get(kind) != update:   # only report real changes
            self._last[kind] = update
            self.emit(update)

    def _store(self, db, a, kind: str, state: dict) -> None:
        s = repo.step(a, kind)
        net = network_summary(state)
        if state.get("status") == "cancelled" or self.cancel.is_set():
            s.details = {**(s.details or {}), "network": net}
            return self._fail(db, a, kind, "Cancelled.", "cancelled")
        if state.get("status") != "completed":
            result = state.get("result") or {}
            error = result.get("error") or state.get("error") or (
                "Website discovery did not complete." if kind == "discovery" else "Source analysis did not complete.")
            if kind == "discovery" and result.get("manifest"):
                a.manifest_detected = bool(result["manifest"].get("detected"))
            s.details = {**(s.details or {}), "network": net}
            return self._fail(db, a, kind, error)
        try:
            if kind == "discovery":
                records = discovery_records(DiscoveryResult.model_validate(state["result"]), net)
                repo.save_discovery(db, a, records)
                details = {"network": net, "requests_made": state["result"].get("requests_made")}
            else:
                result = SourceResult.model_validate(state["result"])
                repo.save_source(db, a, source_records(result))
                details = {"support_status": result.support_status, "findings": len(result.findings),
                           "semgrep_failed": bool(state["result"].get("semgrep_failed"))}
        except (ValidationError, KeyError, TypeError):
            return self._fail(db, a, kind, "The sandbox returned malformed results.")
        s.status, s.error, s.finished_at, s.stage, s.message = "completed", None, utcnow(), "done", None
        all_seen = list(dict.fromkeys([*(s.stages_completed or []), *[e["stage"] for e in state.get("events") or []]]))
        s.stages_completed = all_seen
        s.details = {**(s.details or {}), **details}
        db.commit()
        self.emit(StepUpdate(kind, "completed", None, tuple(all_seen), "", {}))


def repo_retention_ids(ctx: Context, a: Assessment) -> list[str]:
    """Remove report folders of assessments deleted by retention."""
    import shutil

    with ctx.session() as db:
        alive = {x.id for x in repo.history(db, None, limit=10_000)}
    project_dir = ctx.home.reports / a.project_id
    removed = []
    if project_dir.is_dir():
        for d in project_dir.iterdir():
            if d.is_dir() and d.name not in alive:
                shutil.rmtree(d, ignore_errors=True)
                removed.append(d.name)
    return removed
