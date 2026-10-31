import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.schemas.projects import validate_github_token


class JobOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    kind: str
    status: str
    stage: str | None
    message: str | None
    stages_completed: list
    error: str | None
    started_at: datetime | None
    finished_at: datetime | None


class AssessmentCounts(BaseModel):
    pages: int = 0
    endpoints: int = 0
    forms: int = 0
    technologies: int = 0
    findings: int = 0


class AssessmentOut(BaseModel):
    id: uuid.UUID
    project_id: uuid.UUID
    project_name: str
    status: str
    target_url: str
    source_kind: str | None
    source_label: str | None
    manifest_detected: bool
    manifest_data: dict | None
    discovery_summary: dict
    error: str | None
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    jobs: list[JobOut]
    counts: AssessmentCounts
    severity_counts: dict[str, int]


class StartAssessmentRequest(BaseModel):
    include_source: bool = True
    # Required again for private repositories: tokens are never retained.
    token: str | None = Field(default=None, max_length=400)

    @field_validator("token")
    @classmethod
    def _token(cls, v: str | None) -> str | None:
        return validate_github_token(v)


class PageOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    url: str
    status_code: int | None
    title: str | None
    content_type: str | None
    depth: int
    rendered: bool
    is_login: bool
    is_registration: bool
    links_count: int
    forms_count: int
    scripts_count: int
    error: str | None


class EndpointOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    method: str
    url: str
    path: str
    origin: str
    parameters: list
    details: dict
    evidence: str
    page_url: str | None


class TechnologyOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    category: str
    version: str | None
    confidence: str
    source: str
    evidence: list


class SourceResultOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    source_kind: str
    support_status: str
    support_reason: str
    framework: str
    runtime: str
    profile: dict
    routes: list
    db_interactions: list
    input_sources: list
    config_refs: list
    env_var_names: list
    match_evidence: list
    warnings: list


class SnapshotOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    file: str
    start_line: int
    end_line: int
    code: str


class FindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    assessment_id: uuid.UUID
    type: str
    status: str
    severity: str
    confidence: str
    title: str
    file: str | None
    line: int | None
    end_line: int | None
    endpoint: str | None
    method: str | None
    rule_id: str
    plain_description: str
    evidence_summary: str
    technical_details: dict
    recommendation: str
    fingerprint: str
    snapshot: SnapshotOut | None
    created_at: datetime


class FindingWithContext(FindingOut):
    project_id: uuid.UUID
    project_name: str


class Overview(BaseModel):
    projects: int
    assessments: int
    active_assessments: int
    open_findings: int
    severity_counts: dict[str, int]
    recent_assessments: list[AssessmentOut]
    recent_findings: list[FindingWithContext]
