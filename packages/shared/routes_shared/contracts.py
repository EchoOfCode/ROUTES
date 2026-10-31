"""Data contracts exchanged between sandboxes, the Sandbox Manager and workers.

Sandbox output is untrusted: workers re-validate it with these models (strict
lengths and list caps) before persisting anything.
"""

from __future__ import annotations

from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field

Str200 = Annotated[str, Field(max_length=200)]
Str500 = Annotated[str, Field(max_length=500)]
Url = Annotated[str, Field(max_length=2048)]

# Line protocol: every line a sandbox prints that starts with this prefix is a
# JSON event. Anything else is treated as diagnostic output and discarded.
EVENT_PREFIX = "ROUTES_EVENT "


class _Model(BaseModel):
    model_config = ConfigDict(extra="ignore")


class StageEvent(_Model):
    type: Literal["stage"] = "stage"
    stage: Str200
    message: Str500 = ""


# ---------------------------------------------------------------- discovery


class ManifestInfo(_Model):
    checked: bool = False
    detected: bool = False
    valid: bool = False
    status_code: int | None = None
    data: dict[str, Any] | None = None
    error: Str500 | None = None


class RobotsInfo(_Model):
    found: bool = False
    disallow_rules: int = 0
    sitemaps: list[Url] = Field(default_factory=list, max_length=20)
    blocked_urls: list[Url] = Field(default_factory=list, max_length=200)


class PageResult(_Model):
    url: Url
    status_code: int | None = None
    title: Str500 | None = None
    content_type: Str200 | None = None
    depth: int = 0
    rendered: bool = False
    is_login: bool = False
    is_registration: bool = False
    links_count: int = 0
    forms_count: int = 0
    scripts_count: int = 0
    error: Str500 | None = None


class FormField(_Model):
    name: Str200 | None = None
    type: Str200 = "text"
    required: bool = False


class FormResult(_Model):
    page_url: Url
    action: Url
    method: Str200 = "GET"
    fields: list[FormField] = Field(default_factory=list, max_length=200)


class EndpointResult(_Model):
    method: Str200 = "GET"
    url: Url
    path: Url
    origin: Str200
    parameters: list[Str200] = Field(default_factory=list, max_length=200)
    evidence: Str500 = ""
    page_url: Url | None = None


class TechnologyResult(_Model):
    name: Str200
    category: Str200
    version: Str200 | None = None
    confidence: Literal["high", "medium", "low"] = "medium"
    evidence: list[Str500] = Field(default_factory=list, max_length=20)


class StackSummary(_Model):
    framework: Str200 = "Unknown"
    language: Str200 = "Unknown"
    runtime: Str200 = "Unknown"
    database: Str200 = "Unknown"
    confidence: Literal["high", "medium", "low"] = "low"


class OpenApiSpec(_Model):
    url: Url
    title: Str500 | None = None
    version: Str200 | None = None
    paths_count: int = 0


class DiscoveryResult(_Model):
    target_url: Url
    hostname: Str500
    manifest: ManifestInfo = Field(default_factory=ManifestInfo)
    robots: RobotsInfo = Field(default_factory=RobotsInfo)
    sitemap_urls: int = 0
    pages: list[PageResult] = Field(default_factory=list, max_length=500)
    forms: list[FormResult] = Field(default_factory=list, max_length=500)
    endpoints: list[EndpointResult] = Field(default_factory=list, max_length=2000)
    scripts: list[Url] = Field(default_factory=list, max_length=500)
    external_hosts: list[Str500] = Field(default_factory=list, max_length=500)
    technologies: list[TechnologyResult] = Field(default_factory=list, max_length=200)
    stack: StackSummary = Field(default_factory=StackSummary)
    openapi: list[OpenApiSpec] = Field(default_factory=list, max_length=20)
    page_limit: int = 25
    page_limit_reached: bool = False
    reachable: bool = True
    error: Str500 | None = None


# ------------------------------------------------------------------- source


class Dependency(_Model):
    name: Str200
    version: Str200 | None = None
    dev: bool = False


class SourceProfile(_Model):
    languages: dict[str, int] = Field(default_factory=dict)
    framework: Str200 = "Unknown"
    framework_version: Str200 | None = None
    runtime: Str200 = "Unknown"
    package_manager: Str200 | None = None
    lockfiles: list[Str200] = Field(default_factory=list, max_length=20)
    typescript: bool = False
    router: Str200 | None = None
    dependencies: list[Dependency] = Field(default_factory=list, max_length=2000)
    database_libraries: list[Str200] = Field(default_factory=list, max_length=50)
    total_files: int = 0
    analysed_files: int = 0
    top_level_dirs: list[Str200] = Field(default_factory=list, max_length=100)


class SourceRoute(_Model):
    path: Url
    methods: list[Str200] = Field(default_factory=list, max_length=10)
    file: Url
    line: int | None = None
    router: Str200
    handler: Str200 | None = None


class DbInteraction(_Model):
    file: Url
    line: int
    call: Str500
    client: Str200
    query_construction: Str200  # parameterised | interpolated | concatenated | constant | dynamic
    uses_user_input: bool = False
    endpoint: Url | None = None
    method: Str200 | None = None


class InputSource(_Model):
    file: Url
    line: int
    kind: Str200
    name: Str200 | None = None


class ConfigReference(_Model):
    file: Url
    line: int | None = None
    kind: Str200
    name: Str500


class MatchEvidence(_Model):
    kind: Str200
    detail: Str500
    file: Url | None = None
    matches_target: bool = False


class SnapshotOut(_Model):
    """The data-flow slice for this finding - plain code, no LLM involved
    in producing it (built at scan time, VulnClass.build_snapshot)."""

    file: Url
    start_line: int
    end_line: int
    code: Annotated[str, Field(max_length=2000)]


class Finding(_Model):
    type: Str200
    status: Literal["potential", "confirmed", "inconclusive"] = "potential"
    severity: Literal["critical", "high", "medium", "low", "info"]
    confidence: Literal["high", "medium", "low"]
    title: Str500
    file: Url | None = None
    line: int | None = None
    end_line: int | None = None
    endpoint: Url | None = None
    method: Str200 | None = None
    rule_id: Str200
    plain_description: Annotated[str, Field(max_length=2000)]
    evidence_summary: Annotated[str, Field(max_length=2000)]
    technical_details: dict[str, Any] = Field(default_factory=dict)
    recommendation: Annotated[str, Field(max_length=2000)]
    fingerprint: Annotated[str, Field(max_length=64)] | None = None
    snapshot: SnapshotOut | None = None


class SourceResult(_Model):
    source_kind: Str200
    support_status: Literal["supported", "partial", "unsupported"]
    support_reason: Str500 = ""
    profile: SourceProfile = Field(default_factory=SourceProfile)
    routes: list[SourceRoute] = Field(default_factory=list, max_length=2000)
    db_interactions: list[DbInteraction] = Field(default_factory=list, max_length=2000)
    input_sources: list[InputSource] = Field(default_factory=list, max_length=2000)
    config_refs: list[ConfigReference] = Field(default_factory=list, max_length=2000)
    env_var_names: list[Str200] = Field(default_factory=list, max_length=500)
    findings: list[Finding] = Field(default_factory=list, max_length=1000)
    match_evidence: list[MatchEvidence] = Field(default_factory=list, max_length=100)
    warnings: list[Str500] = Field(default_factory=list, max_length=100)
