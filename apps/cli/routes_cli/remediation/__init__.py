"""AI remediation for the CLI: the staged, sandbox-verified correction loop.

    prepared = prepare(ctx, assessment, ids=["03"], source=None)
    run = prepared.workflow(listener=..., should_cancel=...).execute()
    paths = save(ctx, run)
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from routes_cli.remediation.llm import ChatClient, LLMSetupError, load_models
from routes_cli.remediation.source import (
    RemediationSource,
    RemediationSourceError,
    resolve,
)
from routes_cli.remediation.workflow import (
    DEFAULT_MAX_ATTEMPTS,
    FindingRun,
    Listener,
    RemediationRun,
    Services,
    Workflow,
)

__all__ = ["DEFAULT_MAX_ATTEMPTS", "FindingRun", "Listener", "Prepared", "RemediationError", "RemediationRun",
           "actionable", "apply_patch", "prepare", "save", "select"]


class RemediationError(ValueError):
    """The remediation cannot start."""


def actionable(assessment) -> list:
    """Findings that point at code (a line, or a whole file such as next.config): the ones a patch can address."""
    return [f for f in assessment.findings if f.file]


def select(assessment, ids: list[str] | None) -> list:
    code = actionable(assessment)
    if not ids:
        return code
    out = []
    for raw in ids:
        for part in raw.split(","):
            part = part.strip().lstrip("#")
            if not part:
                continue
            f = next((x for x in assessment.findings if part.lstrip("0") == str(x.seq)), None)
            if f is None:
                raise RemediationError(f"No finding {part} in assessment {assessment.id[:8]}.")
            if not f.file:
                raise RemediationError(f"Finding #{f.seq:02d} does not point at a file, so it cannot be "
                                       "patched.")
            if f not in out:
                out.append(f)
    return out


@dataclass
class Prepared:
    assessment: object
    findings: list
    source: RemediationSource
    services: Services
    max_attempts: int

    def workflow(self, *, listener: Listener | None = None, should_cancel=None) -> Workflow:
        return Workflow(self.services, self.assessment, self.findings, max_attempts=self.max_attempts,
                        listener=listener, should_cancel=should_cancel)

    def close(self) -> None:
        self.services.model_a.close()
        self.services.model_b.close()
        self.source.close()


def prepare(ctx, assessment, findings: list, *, source: str | None = None,
            max_attempts: int = DEFAULT_MAX_ATTEMPTS, check_engine: bool = True,
            model_transport=None, engine_factory=None) -> Prepared:
    """Validate everything that can be checked before any model or sandbox call."""
    if not findings:
        raise RemediationError("No code findings to remediate. Run `routes analyze <source>` first.")
    if not 1 <= max_attempts <= 10:
        raise RemediationError("--attempts must be between 1 and 10.")
    try:
        src = resolve(assessment, override=source, cache_dir=ctx.home.cache)
        a_cfg, b_cfg = load_models(ctx.home.root)
    except (RemediationSourceError, LLMSetupError) as exc:
        raise RemediationError(str(exc)) from exc
    engine = engine_factory or ctx.engine_client
    if check_engine:
        from routes_core.engine import EngineUnavailable

        try:
            c = engine()
            try:
                c.health()
            finally:
                c.close()
        except EngineUnavailable as exc:
            raise RemediationError("The ROUTES engine is not reachable; every candidate is built, tested and "
                                   "rescanned in it. Start it with `routes engine up`.") from exc
    services = Services(engine=engine, model_a=ChatClient(a_cfg, transport=model_transport),
                        model_b=ChatClient(b_cfg, transport=model_transport), source=src,
                        cache_dir=ctx.home.cache)
    return Prepared(assessment, findings, src, services, max_attempts)


@dataclass
class Saved:
    folder: Path
    report: Path
    combined: Path | None
    patches: dict[int, Path]


def save(ctx, run: RemediationRun, *, output: str | None = None) -> Saved:
    """Write the run record and every accepted patch under ~/.routes/reports/remediations/<run>/."""
    folder = ctx.home.reports / "remediations" / run.id
    folder.mkdir(parents=True, exist_ok=True)
    patches: dict[int, Path] = {}
    for fr in run.findings:
        if fr.accepted_patch:
            p = folder / f"finding-{fr.seq:02d}.diff"
            p.write_text(fr.accepted_patch, "utf-8", newline="\n")
            patches[fr.seq] = p
    combined = None
    if run.combined_patch:
        combined = folder / "combined.diff"
        combined.write_text(run.combined_patch, "utf-8", newline="\n")
        if output:
            Path(output).write_text(run.combined_patch, "utf-8", newline="\n")
    report = folder / "run.json"
    report.write_text(json.dumps(run.to_dict(), indent=2, default=str), "utf-8")
    return Saved(folder, report, combined, patches)


def apply_patch(source_folder: Path, patch: str) -> list[str]:
    """Apply a verified patch to the developer's folder: strict, all-or-nothing."""
    from routes_shared.patching import apply_unified_diff

    return apply_unified_diff(Path(source_folder), patch)
