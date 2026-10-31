"""Human labels for the stages the sandboxes actually report, in emission order."""

from __future__ import annotations

DISCOVERY_STAGES: list[tuple[str, str]] = [
    ("validating", "Target validation"),
    ("checking_integration", "ROUTES integration check"),
    ("discovering_pages", "Website discovery"),
    ("inspecting_javascript", "JavaScript inspection"),
    ("identifying_endpoints", "Endpoint extraction"),
    ("detecting_technologies", "Technology identification"),
]

# Steps performed by the CLI itself before the source sandbox starts.
LOCAL_SOURCE_STAGES: list[tuple[str, str]] = [
    ("packing", "Packing local folder"),
    ("uploading", "Uploading archive to the engine"),
]

SOURCE_STAGES: list[tuple[str, str]] = [
    ("retrieving_source", "Source retrieval"),
    ("extracting", "Safe archive extraction"),
    ("profiling", "Repository profiling"),
    ("running_static_rules", "Static rules (Semgrep)"),
    ("analysing_structure", "Route parsing (Tree-sitter)"),
    ("tracing_data_flow", "Data-flow analysis"),
]

LABELS = {k: v for k, v in DISCOVERY_STAGES + LOCAL_SOURCE_STAGES + SOURCE_STAGES}
LABELS.update({"starting": "Starting sandbox", "cleanup": "Removing sandbox", "results": "Results processing"})

STEP_TITLES = {"discovery": "Website discovery", "source": "Source analysis"}


def stages_for(kind: str, *, local: list[str] | None = None) -> list[tuple[str, str]]:
    if kind == "discovery":
        return list(DISCOVERY_STAGES)
    pre = [s for s in LOCAL_SOURCE_STAGES if s[0] in (local or [])]
    return pre + list(SOURCE_STAGES)


def label(stage: str | None) -> str:
    if not stage:
        return ""
    return LABELS.get(stage, stage.replace("_", " ").capitalize())
