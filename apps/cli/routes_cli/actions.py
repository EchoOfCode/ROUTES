"""Operations shared by the direct commands and the interactive interface."""

from __future__ import annotations

from dataclasses import dataclass

from routes_core.sources import SourceError, SourceSpec, classify
from routes_shared.github import validate_github_token
from routes_storage import repo
from routes_storage.models import Assessment, Project

from routes_cli.context import Context
from routes_cli.service import Plan, PlanError, resolve_project, validate_target

AUTHORISATION_STATEMENT = "I own this website or have permission to assess it."
MATCH_QUESTION = "Does this repository contain the source code for {host}?"


@dataclass
class Request:
    url: str | None = None
    source: str | None = None
    ref: str | None = None
    private: bool = False
    project: str | None = None


@dataclass
class Prepared:
    plan: Plan
    project: Project
    hostname: str | None
    source: SourceSpec | None
    needs_authorisation: bool
    needs_token: bool
    ask_match: bool


def prepare(ctx: Context, req: Request) -> Prepared:
    """Validate a scan/analyze request without starting anything."""
    url = hostname = None
    project_ref = req.project or None
    if not req.url and not req.source and project_ref is None and ctx.config.current_project:
        project_ref = ctx.config.current_project
    if req.url:
        url, hostname = validate_target(ctx, req.url)
    source = None
    if req.source:
        try:
            source = classify(req.source, ref=req.ref)
        except (SourceError, ValueError) as exc:
            raise PlanError(str(exc)) from exc
        if req.private and not source.is_github:
            raise PlanError("--private applies to GitHub repositories only.")
    if url is None and source is None:
        if project_ref is None:
            raise PlanError("Give a website URL or a source to analyse.")
        with ctx.session() as db:
            p = repo.find_project(db, project_ref)
            if p is None:
                raise PlanError(f"No project named '{project_ref}'.")
            if p.website_url:
                url, hostname = validate_target(ctx, p.website_url)
            if p.source_kind:
                source = classify(p.source_location, ref=p.source_ref)
                req.private = req.private or p.source_private
    project = resolve_project(ctx, project_ref=project_ref, url=url, hostname=hostname, source=source,
                              authorised=False)
    needs_auth = url is not None
    ask_match = url is not None and source is not None and project.match_status == "pending"
    plan = Plan(project_id=project.id, target_url=url, source=source)
    return Prepared(plan, project, hostname, source, needs_auth, bool(source and source.is_github and req.private),
                    ask_match)


def confirm_authorisation(ctx: Context, prepared: Prepared) -> None:
    from routes_storage.models import utcnow

    with ctx.session() as db:
        p = db.get(Project, prepared.project.id)
        p.authorised_at = utcnow()
        db.commit()


def attach_token(prepared: Prepared, token: str) -> None:
    try:
        prepared.plan.token = validate_github_token(token)
    except ValueError as exc:
        raise PlanError(str(exc)) from exc
    if not prepared.plan.token:
        raise PlanError("A token is required for a private repository.")


def latest(ctx: Context, *, assessment: str | None = None, project: str | None = None) -> Assessment | None:
    with ctx.session() as db:
        if assessment:
            a = repo.get_assessment(db, assessment)
            if a is None:
                raise PlanError(f"No assessment '{assessment}'. See `routes history`.")
            return _loaded(db, a)
        p = None
        ref = project or ctx.config.current_project or None
        if ref:
            p = repo.find_project(db, ref)
            if p is None and project:
                raise PlanError(f"No project named '{project}'.")
        a = repo.latest_finished(db, p)
        return _loaded(db, a) if a else None


def _loaded(db, a: Assessment) -> Assessment:
    # Touch relationships so they are available after the session closes.
    _ = (a.project, list(a.steps), list(a.findings), list(a.pages), list(a.endpoints), list(a.technologies),
         a.source_result)
    return a
