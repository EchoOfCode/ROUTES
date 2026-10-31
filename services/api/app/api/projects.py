import socket
import uuid

from fastapi import APIRouter, Depends, File, Response, UploadFile
from sqlalchemy import select
from sqlalchemy.orm import Session

from routes_shared.netpolicy import UrlPolicyError, all_addresses_allowed, parse_target_url

from app.core.config import get_settings
from app.core.db import get_db
from app.core.deps import get_current_user
from app.core.errors import ApiError
from app.models import Assessment, Project, ProjectIntegration, User
from app.schemas.assessments import AssessmentOut, StartAssessmentRequest
from app.schemas.projects import (
    AUTHORISATION_STATEMENT,
    GithubConnectRequest,
    IntegrationOut,
    MatchDecision,
    ProjectCreate,
    ProjectOut,
    ProjectUpdate,
)
from app.services import assessments as assessment_service
from app.services import lifecycle, sandbox_client
from app.services.projects import owned_project, serialize_assessments, serialize_projects
from app.services.uploads import discard_upload, stage_zip

router = APIRouter(prefix="/projects", tags=["projects"])


def _validate_target(raw: str):
    settings = get_settings()
    try:
        target = parse_target_url(raw, dev_allow_hosts=settings.dev_hosts)
    except UrlPolicyError as exc:
        raise ApiError(422, "validation_error", str(exc), {"website_url": str(exc)}) from exc
    if target.hostname in settings.dev_hosts:
        return target
    # Early feedback only; the network gateway re-resolves and enforces this
    # on every connection, so DNS changes after this point cannot bypass it.
    try:
        infos = socket.getaddrinfo(target.hostname, target.port, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, UnicodeError):
        return target  # Unresolvable sites fail gracefully during discovery.
    addresses = sorted({i[4][0] for i in infos})
    if not all_addresses_allowed(addresses):
        msg = "This hostname resolves to a private or internal address and cannot be assessed."
        raise ApiError(422, "validation_error", msg, {"website_url": msg})
    return target


@router.get("", response_model=list[ProjectOut])
def list_projects(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    projects = db.scalars(
        select(Project).where(Project.owner_id == user.id).order_by(Project.created_at.desc())
    ).all()
    return serialize_projects(db, list(projects))


@router.post("", status_code=201)
def create_project(body: ProjectCreate, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    target = _validate_target(body.website_url)
    project = Project(
        owner_id=user.id,
        name=(body.name or "").strip() or target.hostname,
        website_url=target.url,
        hostname=target.hostname,
        authorised_at=lifecycle.now(),
        authorisation_statement=AUTHORISATION_STATEMENT,
    )
    db.add(project)
    db.commit()
    # Discovery starts automatically once the developer has confirmed authorisation.
    assessment, _ = assessment_service.start_assessment(db, project, include_source=False, token=None)
    db.refresh(project)
    return {
        "project": serialize_projects(db, [project])[0],
        "assessment_id": str(assessment.id),
    }


@router.get("/{project_id}", response_model=ProjectOut)
def get_project(project_id: uuid.UUID, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return serialize_projects(db, [owned_project(db, user, project_id)])[0]


@router.patch("/{project_id}", response_model=ProjectOut)
def update_project(
    project_id: uuid.UUID, body: ProjectUpdate, user: User = Depends(get_current_user), db: Session = Depends(get_db)
):
    project = owned_project(db, user, project_id)
    project.name = body.name.strip()
    db.commit()
    return serialize_projects(db, [project])[0]


@router.delete("/{project_id}", status_code=204)
def delete_project(
    project_id: uuid.UUID, response: Response, user: User = Depends(get_current_user), db: Session = Depends(get_db)
):
    project = owned_project(db, user, project_id)
    if lifecycle.active_assessment(db, project.id) is not None:
        raise ApiError(409, "assessment_active", "Cancel the running assessment before deleting this project.")
    db.delete(project)
    db.commit()
    response.status_code = 204
    return response


# ------------------------------------------------------------ assessments


@router.get("/{project_id}/assessments", response_model=list[AssessmentOut])
def list_project_assessments(
    project_id: uuid.UUID, user: User = Depends(get_current_user), db: Session = Depends(get_db)
):
    project = owned_project(db, user, project_id)
    rows = db.scalars(
        select(Assessment).where(Assessment.project_id == project.id).order_by(Assessment.created_at.desc()).limit(
            get_settings().assessment_history_limit + 1
        )
    ).all()
    return serialize_assessments(db, list(rows))


@router.post("/{project_id}/assessments", status_code=201)
def start_assessment(
    project_id: uuid.UUID,
    body: StartAssessmentRequest,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    project = owned_project(db, user, project_id)
    assessment, notes = assessment_service.start_assessment(
        db, project, include_source=body.include_source, token=body.token
    )
    return {"assessment_id": str(assessment.id), "notes": notes}


# ----------------------------------------------------------- integrations


def _replace_integration(db: Session, project: Project, integration: ProjectIntegration) -> ProjectIntegration:
    active = lifecycle.active_assessment(db, project.id)
    if active is not None and any(j.kind == "source" and j.status in ("queued", "running") for j in active.jobs):
        raise ApiError(409, "source_active", "Wait for the current source analysis to finish before changing the source.")
    for existing in list(project.integrations):
        db.delete(existing)
    db.flush()
    integration.project_id = project.id
    db.add(integration)
    db.commit()
    db.refresh(project)
    return integration


@router.post("/{project_id}/integrations/github", status_code=201)
def connect_github(
    project_id: uuid.UUID, body: GithubConnectRequest, user: User = Depends(get_current_user), db: Session = Depends(get_db)
):
    project = owned_project(db, user, project_id)
    try:
        owner, repo, ref = body.parsed()
    except ValueError as exc:
        raise ApiError(422, "validation_error", str(exc), {"repo_url": str(exc)}) from exc
    private = body.visibility == "private"
    if private and not body.token:
        raise ApiError(422, "validation_error", "A fine-grained access token is required for private repositories.",
                       {"token": "Required for private repositories."})
    handle = sandbox_client.store_ephemeral_credential(body.token, owner, repo) if private else None
    try:
        integration = _replace_integration(
            db, project,
            ProjectIntegration(kind="github_private" if private else "github_public", repo_owner=owner,
                               repo_name=repo, repo_ref=ref, match_status="pending", match_evidence=[]),
        )
        assessment = assessment_service.run_source_for(db, project, integration, upload_id=None, credential_handle=handle)
    except Exception:
        if handle:
            sandbox_client.discard_credential(handle)
        raise
    return {"integration": IntegrationOut.model_validate(integration), "assessment_id": str(assessment.id)}


@router.post("/{project_id}/integrations/zip", status_code=201)
async def upload_zip(
    project_id: uuid.UUID,
    file: UploadFile = File(...),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    project = owned_project(db, user, project_id)
    upload_id, filename, size, sha = await stage_zip(file)
    try:
        integration = _replace_integration(
            db, project,
            ProjectIntegration(kind="zip", upload_filename=filename, upload_size=size, upload_sha256=sha,
                               match_status="pending", match_evidence=[]),
        )
        assessment = assessment_service.run_source_for(db, project, integration, upload_id=upload_id, credential_handle=None)
    except Exception:
        discard_upload(upload_id)
        raise
    return {"integration": IntegrationOut.model_validate(integration), "assessment_id": str(assessment.id)}


@router.post("/{project_id}/integrations/match", response_model=IntegrationOut)
def decide_match(
    project_id: uuid.UUID, body: MatchDecision, user: User = Depends(get_current_user), db: Session = Depends(get_db)
):
    project = owned_project(db, user, project_id)
    if not project.integrations:
        raise ApiError(404, "not_found", "No source is connected to this project.")
    integration = project.integrations[0]
    integration.match_status = "confirmed" if body.matches else "rejected"
    integration.match_decided_at = lifecycle.now()
    db.commit()
    return integration


@router.delete("/{project_id}/integrations", status_code=204)
def disconnect(project_id: uuid.UUID, response: Response, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    project = owned_project(db, user, project_id)
    active = lifecycle.active_assessment(db, project.id)
    if active is not None and any(j.kind == "source" and j.status in ("queued", "running") for j in active.jobs):
        raise ApiError(409, "source_active", "Wait for the current source analysis to finish.")
    for existing in list(project.integrations):
        db.delete(existing)
    db.commit()
    response.status_code = 204
    return response
