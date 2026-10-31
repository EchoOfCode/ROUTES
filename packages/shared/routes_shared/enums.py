from enum import StrEnum


class AssessmentStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    DISCOVERING = "discovering"
    ANALYSING = "analysing"
    COMPLETED = "completed"
    PARTIALLY_COMPLETED = "partially_completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


ACTIVE_ASSESSMENT_STATUSES: frozenset[str] = frozenset(
    {
        AssessmentStatus.QUEUED,
        AssessmentStatus.RUNNING,
        AssessmentStatus.DISCOVERING,
        AssessmentStatus.ANALYSING,
    }
)

TERMINAL_ASSESSMENT_STATUSES: frozenset[str] = frozenset(
    {
        AssessmentStatus.COMPLETED,
        AssessmentStatus.PARTIALLY_COMPLETED,
        AssessmentStatus.FAILED,
        AssessmentStatus.CANCELLED,
    }
)


class JobKind(StrEnum):
    DISCOVERY = "discovery"
    SOURCE = "source"
    RESULTS = "results"


class JobStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    SKIPPED = "skipped"


TERMINAL_JOB_STATUSES: frozenset[str] = frozenset(
    {JobStatus.COMPLETED, JobStatus.FAILED, JobStatus.CANCELLED, JobStatus.SKIPPED}
)


class IntegrationKind(StrEnum):
    GITHUB_PUBLIC = "github_public"
    GITHUB_PRIVATE = "github_private"
    ZIP = "zip"


class MatchStatus(StrEnum):
    PENDING = "pending"
    CONFIRMED = "confirmed"
    REJECTED = "rejected"


class FindingStatus(StrEnum):
    POTENTIAL = "potential"
    CONFIRMED = "confirmed"
    INCONCLUSIVE = "inconclusive"


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Confidence(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class SupportStatus(StrEnum):
    SUPPORTED = "supported"
    PARTIAL = "partial"
    UNSUPPORTED = "unsupported"


class EndpointOrigin(StrEnum):
    FORM = "form"
    LINK_QUERY = "link_query"
    JS_REFERENCE = "js_reference"
    OPENAPI = "openapi"
    SOURCE_ROUTE = "source_route"


# Progress stages emitted by sandboxes (and shown in the UI, in this order).
DISCOVERY_STAGES: tuple[str, ...] = (
    "validating",
    "checking_integration",
    "discovering_pages",
    "inspecting_javascript",
    "identifying_endpoints",
    "detecting_technologies",
)

SOURCE_STAGES: tuple[str, ...] = (
    "retrieving_source",
    "extracting",
    "profiling",
    "analysing_structure",
    "running_static_rules",
    "tracing_data_flow",
)
