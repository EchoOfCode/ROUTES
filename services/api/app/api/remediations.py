"""Remediation endpoints.

Everything is scoped under an assessment the caller owns (``owned_assessment``
checks ``projects.owner_id``), and every run, artifact and record is looked up
*through* that assessment, so one user can never read or change another
user's remediation data, even with a guessed id.

Restricted to SQL injection findings with a persisted code snapshot: the
gate's known-bad-fix library and the fixed exploit-payload list are still
SQLi-only, so offering remediation elsewhere would be dishonest about what is
actually checked.
"""

import uuid

from fastapi import APIRouter, Depends, Query, Response
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.core.deps import get_current_user
from app.core.errors import ApiError, not_found
from app.models import (
    AiModelInvocation,
    Remediation,
    RemediationArtifact,
    RemediationAuditEvent,
    RemediationBatchFile,
    RemediationContext,
    RemediationFinding,
    RemediationPatchAttempt,
    RemediationPatchBatch,
    RemediationPlan,
    RemediationReanalysisFinding,
    RemediationReanalysisRun,
    RemediationTestCase,
    RemediationTestResult,
    RemediationTestSuite,
    RemediationVerificationRun,
    SecurityFinding,
    User,
)
from app.schemas.remediations import (
    AuditEventOut,
    AuditPage,
    ContextOut,
    InvocationOut,
    PatchAttemptOut,
    PatchBatchOut,
    PlanOut,
    ReanalysisFindingOut,
    ReanalysisOut,
    RemediationCreate,
    RemediationFindingOut,
    RemediationIterationOut,
    RemediationOut,
    RemediationPage,
    RemediationSummaryOut,
    TestCaseOut,
    TestResultOut,
    TestSuiteOut,
    VerificationRunOut,
)
from app.services import artifacts, outbox
from app.services import remediation_store as store
from app.services.projects import owned_assessment

router = APIRouter(prefix="/assessments", tags=["remediations"])

SUPPORTED_RULE_PREFIXES = store.SUPPORTED_RULE_PREFIXES


def _owned_finding(db: Session, user: User, assessment_id: uuid.UUID, finding_id: uuid.UUID) -> SecurityFinding:
    a = owned_assessment(db, user, assessment_id)
    f = db.scalar(
        select(SecurityFinding).where(SecurityFinding.id == finding_id, SecurityFinding.assessment_id == a.id)
    )
    if f is None:
        raise not_found("Finding")
    return f


def _owned_run(db: Session, user: User, assessment_id: uuid.UUID, remediation_id: uuid.UUID) -> Remediation:
    a = owned_assessment(db, user, assessment_id)
    run = db.scalar(select(Remediation).where(Remediation.id == remediation_id, Remediation.assessment_id == a.id))
    if run is None:
        raise not_found("Remediation")
    return run


def _out(db: Session, run: Remediation) -> RemediationOut:
    """The full run view. Candidate code is read from the artifact store for
    runs recorded after migration 0008 (one query, no per-row lookups)."""
    attempts = {a.legacy_iteration_id: a for a in db.scalars(
        select(RemediationPatchAttempt).where(RemediationPatchAttempt.remediation_id == run.id)).all()
        if a.legacy_iteration_id}
    art_ids = [a.candidate_artifact_id for a in attempts.values() if a.candidate_artifact_id]
    arts = {a.id: a for a in db.scalars(select(RemediationArtifact).where(RemediationArtifact.id.in_(art_ids)))} \
        if art_ids else {}
    iterations = []
    for it in run.iterations:
        out = RemediationIterationOut.model_validate(it)
        if out.candidate_code is None and it.id in attempts:
            out.candidate_code = artifacts.read_text(arts.get(attempts[it.id].candidate_artifact_id))
        iterations.append(out)
    findings = db.scalars(select(RemediationFinding).where(RemediationFinding.remediation_id == run.id)
                          .order_by(RemediationFinding.is_primary.desc(), RemediationFinding.created_at)).all()
    data = {c: getattr(run, c) for c in RemediationOut.model_fields if c not in ("iterations", "findings")}
    return RemediationOut(**data, iterations=iterations,
                          findings=[RemediationFindingOut.model_validate(f) for f in findings])


def _create(db: Session, user: User, assessment, findings, idempotency_key=None) -> tuple[Remediation, bool]:
    try:
        run, created = store.create_run(db, user=user, assessment=assessment, findings=findings,
                                        idempotency_key=idempotency_key)
    except store.RemediationError as exc:
        raise ApiError(exc.status, exc.code, exc.message) from None
    if created:
        outbox.relay_safely(db)
    return run, created


# ----------------------------------------------------------- start / cancel
@router.post("/{assessment_id}/findings/{finding_id}/remediate", response_model=RemediationOut, status_code=201)
def start_remediation(
    assessment_id: uuid.UUID, finding_id: uuid.UUID, user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Start (or return the active) remediation of one finding."""
    finding = _owned_finding(db, user, assessment_id, finding_id)
    a = owned_assessment(db, user, assessment_id)
    run, _ = _create(db, user, a, [finding])
    return _out(db, run)


@router.post("/{assessment_id}/remediations", response_model=RemediationOut, status_code=201)
def start_remediation_run(
    assessment_id: uuid.UUID, body: RemediationCreate, response: Response, user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Start one run for several findings of this assessment. Findings in
    the same file must go into separate runs (their patches would overlap)."""
    a = owned_assessment(db, user, assessment_id)
    found = {f.id: f for f in db.scalars(select(SecurityFinding).where(
        SecurityFinding.assessment_id == a.id, SecurityFinding.id.in_(body.finding_ids))).all()}
    if len(found) != len(set(body.finding_ids)):
        raise not_found("Finding")
    run, created = _create(db, user, a, [found[i] for i in body.finding_ids if i in found], body.idempotency_key)
    if not created:
        response.status_code = 200
    return _out(db, run)


@router.get("/{assessment_id}/findings/{finding_id}/remediations/{remediation_id}", response_model=RemediationOut)
def get_remediation(
    assessment_id: uuid.UUID, finding_id: uuid.UUID, remediation_id: uuid.UUID,
    user: User = Depends(get_current_user), db: Session = Depends(get_db),
):
    finding = _owned_finding(db, user, assessment_id, finding_id)
    run = _owned_run(db, user, assessment_id, remediation_id)
    targeted = db.scalar(select(RemediationFinding.id).where(RemediationFinding.remediation_id == run.id,
                                                             RemediationFinding.finding_id == finding.id))
    if targeted is None:
        raise not_found("Remediation")
    return _out(db, run)


@router.post("/{assessment_id}/findings/{finding_id}/remediations/{remediation_id}/cancel",
             response_model=RemediationOut)
def cancel_remediation(
    assessment_id: uuid.UUID, finding_id: uuid.UUID, remediation_id: uuid.UUID,
    user: User = Depends(get_current_user), db: Session = Depends(get_db),
):
    _owned_finding(db, user, assessment_id, finding_id)
    return _cancel(db, user, _owned_run(db, user, assessment_id, remediation_id))


@router.post("/{assessment_id}/remediations/{remediation_id}/cancel", response_model=RemediationOut)
def cancel_remediation_run(assessment_id: uuid.UUID, remediation_id: uuid.UUID,
                           user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return _cancel(db, user, _owned_run(db, user, assessment_id, remediation_id))


def _cancel(db: Session, user: User, run: Remediation) -> RemediationOut:
    from app.services import queueing

    if run.status in ("pending", "running"):
        queueing.cancel_job("remediate", run.id)  # no-op once a worker picked it up
    run = store.request_cancel(db, run, user)
    db.expire_all()
    return _out(db, db.get(Remediation, run.id))


# ------------------------------------------------------------------ reads
@router.get("/{assessment_id}/remediations", response_model=RemediationPage)
def list_remediations(assessment_id: uuid.UUID, limit: int = Query(20, ge=1, le=100), offset: int = Query(0, ge=0),
                      user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    a = owned_assessment(db, user, assessment_id)
    total = db.scalar(select(func.count()).select_from(Remediation).where(Remediation.assessment_id == a.id))
    rows = db.scalars(select(Remediation).where(Remediation.assessment_id == a.id)
                      .order_by(Remediation.created_at.desc()).limit(limit).offset(offset)).all()
    return RemediationPage(items=[RemediationSummaryOut.model_validate(r) for r in rows], total=total or 0,
                           limit=limit, offset=offset)


@router.get("/{assessment_id}/remediations/{remediation_id}", response_model=RemediationOut)
def get_remediation_run(assessment_id: uuid.UUID, remediation_id: uuid.UUID,
                        user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return _out(db, _owned_run(db, user, assessment_id, remediation_id))


@router.get("/{assessment_id}/remediations/{remediation_id}/plans", response_model=list[PlanOut])
def list_plans(assessment_id: uuid.UUID, remediation_id: uuid.UUID, user: User = Depends(get_current_user),
               db: Session = Depends(get_db)):
    run = _owned_run(db, user, assessment_id, remediation_id)
    return db.scalars(select(RemediationPlan).where(RemediationPlan.remediation_id == run.id)
                      .order_by(RemediationPlan.version)).all()


@router.get("/{assessment_id}/remediations/{remediation_id}/contexts", response_model=list[ContextOut])
def list_contexts(assessment_id: uuid.UUID, remediation_id: uuid.UUID, user: User = Depends(get_current_user),
                  db: Session = Depends(get_db)):
    run = _owned_run(db, user, assessment_id, remediation_id)
    return db.scalars(select(RemediationContext).where(RemediationContext.remediation_id == run.id)
                      .order_by(RemediationContext.created_at)).all()


@router.get("/{assessment_id}/remediations/{remediation_id}/testbench", response_model=list[TestSuiteOut])
def list_test_suites(assessment_id: uuid.UUID, remediation_id: uuid.UUID, user: User = Depends(get_current_user),
                     db: Session = Depends(get_db)):
    run = _owned_run(db, user, assessment_id, remediation_id)
    suites = db.scalars(select(RemediationTestSuite).where(RemediationTestSuite.remediation_id == run.id)
                        .order_by(RemediationTestSuite.version)).all()
    cases = db.scalars(select(RemediationTestCase).where(RemediationTestCase.suite_id.in_([s.id for s in suites]))
                       .order_by(RemediationTestCase.created_at)).all() if suites else []
    by_suite: dict = {}
    for c in cases:
        by_suite.setdefault(c.suite_id, []).append(TestCaseOut.model_validate(c))
    return [TestSuiteOut.model_validate(s).model_copy(update={"cases": by_suite.get(s.id, [])}) for s in suites]


@router.get("/{assessment_id}/remediations/{remediation_id}/batches", response_model=list[PatchBatchOut])
def list_batches(assessment_id: uuid.UUID, remediation_id: uuid.UUID, user: User = Depends(get_current_user),
                 db: Session = Depends(get_db)):
    run = _owned_run(db, user, assessment_id, remediation_id)
    batches = db.scalars(select(RemediationPatchBatch).where(RemediationPatchBatch.remediation_id == run.id)
                         .order_by(RemediationPatchBatch.sequence)).all()
    files: dict = {}
    for bf in db.scalars(select(RemediationBatchFile).where(RemediationBatchFile.remediation_id == run.id)).all():
        files.setdefault(bf.batch_id, []).append(bf.file_path)
    return [PatchBatchOut(**{k: getattr(b, k) for k in PatchBatchOut.model_fields if k != "files"},
                          files=sorted(files.get(b.id, []))) for b in batches]


@router.get("/{assessment_id}/remediations/{remediation_id}/attempts", response_model=list[PatchAttemptOut])
def list_attempts(assessment_id: uuid.UUID, remediation_id: uuid.UUID, user: User = Depends(get_current_user),
                  db: Session = Depends(get_db)):
    run = _owned_run(db, user, assessment_id, remediation_id)
    return db.scalars(select(RemediationPatchAttempt).where(RemediationPatchAttempt.remediation_id == run.id)
                      .order_by(RemediationPatchAttempt.created_at)).all()


@router.get("/{assessment_id}/remediations/{remediation_id}/invocations", response_model=list[InvocationOut])
def list_invocations(assessment_id: uuid.UUID, remediation_id: uuid.UUID, user: User = Depends(get_current_user),
                     db: Session = Depends(get_db)):
    run = _owned_run(db, user, assessment_id, remediation_id)
    return db.scalars(select(AiModelInvocation).where(AiModelInvocation.remediation_id == run.id)
                      .order_by(AiModelInvocation.sequence)).all()


@router.get("/{assessment_id}/remediations/{remediation_id}/verifications", response_model=list[VerificationRunOut])
def list_verifications(assessment_id: uuid.UUID, remediation_id: uuid.UUID, user: User = Depends(get_current_user),
                       db: Session = Depends(get_db)):
    run = _owned_run(db, user, assessment_id, remediation_id)
    runs = db.scalars(select(RemediationVerificationRun).where(RemediationVerificationRun.remediation_id == run.id)
                      .order_by(RemediationVerificationRun.started_at)).all()
    results = db.scalars(select(RemediationTestResult).where(
        RemediationTestResult.verification_run_id.in_([r.id for r in runs]))).all() if runs else []
    by_run: dict = {}
    for r in results:
        by_run.setdefault(r.verification_run_id, []).append(TestResultOut.model_validate(r))
    return [VerificationRunOut.model_validate(r).model_copy(update={"results": by_run.get(r.id, [])}) for r in runs]


@router.get("/{assessment_id}/remediations/{remediation_id}/reanalysis", response_model=list[ReanalysisOut])
def list_reanalysis(assessment_id: uuid.UUID, remediation_id: uuid.UUID, user: User = Depends(get_current_user),
                    db: Session = Depends(get_db)):
    run = _owned_run(db, user, assessment_id, remediation_id)
    rows = db.scalars(select(RemediationReanalysisRun).where(RemediationReanalysisRun.remediation_id == run.id)
                      .order_by(RemediationReanalysisRun.started_at)).all()
    diffs = db.scalars(select(RemediationReanalysisFinding).where(
        RemediationReanalysisFinding.reanalysis_id.in_([r.id for r in rows]))).all() if rows else []
    by_run: dict = {}
    for d in diffs:
        by_run.setdefault(d.reanalysis_id, []).append(ReanalysisFindingOut.model_validate(d))
    return [ReanalysisOut.model_validate(r).model_copy(update={"findings": by_run.get(r.id, [])}) for r in rows]


@router.get("/{assessment_id}/remediations/{remediation_id}/audit", response_model=AuditPage)
def list_audit(assessment_id: uuid.UUID, remediation_id: uuid.UUID, after_seq: int = Query(0, ge=0),
               limit: int = Query(100, ge=1, le=500), user: User = Depends(get_current_user),
               db: Session = Depends(get_db)):
    run = _owned_run(db, user, assessment_id, remediation_id)
    rows = db.scalars(select(RemediationAuditEvent).where(RemediationAuditEvent.remediation_id == run.id,
                                                          RemediationAuditEvent.seq > after_seq)
                      .order_by(RemediationAuditEvent.seq).limit(limit + 1)).all()
    more = len(rows) > limit
    rows = rows[:limit]
    return AuditPage(items=[AuditEventOut.model_validate(r) for r in rows],
                     next_after_seq=rows[-1].seq if more else None)


@router.get("/{assessment_id}/remediations/{remediation_id}/report")
def remediation_report(assessment_id: uuid.UUID, remediation_id: uuid.UUID, user: User = Depends(get_current_user),
                       db: Session = Depends(get_db)) -> dict:
    return store.report(db, _owned_run(db, user, assessment_id, remediation_id))


@router.get("/{assessment_id}/remediations/{remediation_id}/artifacts/{artifact_id}")
def download_artifact(assessment_id: uuid.UUID, remediation_id: uuid.UUID, artifact_id: uuid.UUID,
                      user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> Response:
    """Artifacts are served only to the run's owner. Content is redacted
    source code: still confidential, never cached."""
    run = _owned_run(db, user, assessment_id, remediation_id)
    art = store.artifact_for_run(db, run, artifact_id)
    if art is None:
        raise not_found("Artifact")
    try:
        data = artifacts.read(art)
    except artifacts.ArtifactMissing as exc:
        raise ApiError(410, "artifact_unavailable", str(exc)) from None
    media = art.media_type if art.media_type in ("text/plain", "application/json", "text/x-diff") else "text/plain"
    return Response(content=data, media_type=f"{media}; charset=utf-8", headers={
        "Content-Disposition": f'attachment; filename="{art.kind}-{art.sha256[:12]}.txt"',
        "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"})
