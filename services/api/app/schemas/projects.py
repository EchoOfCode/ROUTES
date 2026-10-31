import re
import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

AUTHORISATION_STATEMENT = "I confirm that I own this website or have permission to assess it."

_GITHUB_URL_RE = re.compile(
    r"^(?:https?://)?(?:www\.)?github\.com/(?P<owner>[A-Za-z0-9](?:[A-Za-z0-9-]{0,38}))/"
    r"(?P<repo>[A-Za-z0-9._-]{1,100}?)(?:\.git)?/?(?:tree/(?P<ref>[A-Za-z0-9._/-]{1,255}))?/?$"
)
_REF_RE = re.compile(r"^[A-Za-z0-9._/-]{1,255}$")


def validate_github_token(v: str | None) -> str | None:
    if v is None or v.strip() == "":
        return None
    v = v.strip()
    if not re.fullmatch(r"[A-Za-z0-9_]{20,400}", v):
        raise ValueError("The access token format is not recognised.")
    return v


class ProjectCreate(BaseModel):
    website_url: str = Field(max_length=2048)
    name: str | None = Field(default=None, max_length=120)
    authorised: bool

    @field_validator("authorised")
    @classmethod
    def _must_confirm(cls, v: bool) -> bool:
        if v is not True:
            raise ValueError("Confirm that you own this website or have permission to assess it.")
        return v


class ProjectUpdate(BaseModel):
    name: str = Field(min_length=1, max_length=120)


class IntegrationOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    kind: str
    repo_owner: str | None
    repo_name: str | None
    repo_ref: str | None
    upload_filename: str | None
    upload_size: int | None
    match_status: str
    match_evidence: list
    match_decided_at: datetime | None
    created_at: datetime


class AssessmentBrief(BaseModel):
    id: uuid.UUID
    status: str
    created_at: datetime
    finished_at: datetime | None
    findings_count: int


class ProjectOut(BaseModel):
    id: uuid.UUID
    name: str
    website_url: str
    hostname: str
    authorised_at: datetime
    authorisation_statement: str
    created_at: datetime
    integration: IntegrationOut | None
    latest_assessment: AssessmentBrief | None
    framework: str | None


class GithubConnectRequest(BaseModel):
    repo_url: str = Field(max_length=500)
    ref: str | None = Field(default=None, max_length=255)
    visibility: Literal["public", "private"] = "public"
    # Only accepted on this request, never stored or echoed back.
    token: str | None = Field(default=None, max_length=400)

    @field_validator("ref")
    @classmethod
    def _ref(cls, v: str | None) -> str | None:
        if v is None or v.strip() == "":
            return None
        v = v.strip()
        if not _REF_RE.match(v) or ".." in v:
            raise ValueError("The branch, tag or commit name is not valid.")
        return v

    @field_validator("token")
    @classmethod
    def _token(cls, v: str | None) -> str | None:
        return validate_github_token(v)

    def parsed(self) -> tuple[str, str, str | None]:
        m = _GITHUB_URL_RE.match(self.repo_url.strip())
        if not m:
            raise ValueError("Enter a GitHub repository URL such as https://github.com/owner/repository.")
        return m.group("owner"), m.group("repo"), self.ref or m.group("ref")


class MatchDecision(BaseModel):
    matches: bool
