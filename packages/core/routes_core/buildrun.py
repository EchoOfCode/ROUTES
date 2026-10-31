"""Client-side API for build-and-run verification (engine run kind ``build_run``).

This is the interface the future Remediation Engine uses: give it the original
source (GitHub repository, ZIP or folder), an optional candidate patch and a
test plan; it returns the engine's structured evidence. The patch is applied
by the build runner to a temporary copy inside the sandbox. The developer's
files are only read, and nothing here decides whether a patch is secure.

    request = BuildRunRequest(source=classify("./my-app"), test_plan=plan, patch=diff_text)
    run = submit(client, request, cache_dir=home.cache)
    final = wait(client, run, on_state=print)
    final["result"]["verification"]   # VERIFIED_RUN | TESTS_FAILED | BUILD_FAILED | ...
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from pydantic import ValidationError

from routes_core.engine import EngineClient
from routes_core.runner import poll_run
from routes_core.sources import SourceError, SourceSpec, pack_directory
from routes_shared.buildrun import BuildRunOptions, PatchRejected, Phase, TestPlan, validate_patch

POLL_SECONDS = 2.0
DEFAULT_DEADLINE = 2700          # client-side safety net above the engine's own lifetime limit
EXIT_CODES = {"VERIFIED_RUN": 0, "TESTS_FAILED": 3, "DYNAMIC_VERIFICATION_UNSUPPORTED": 4}


class BuildRunInvalid(ValueError):
    """The request is invalid before anything was sent to the engine."""


@dataclass
class BuildRunRequest:
    source: SourceSpec
    test_plan: dict
    patch: str | None = None
    approved_scripts: list[str] = field(default_factory=list)
    timeouts: dict[str, int] = field(default_factory=dict)
    requested_by: str = "routes-cli"
    token: str | None = None      # private GitHub only; memory only, handed to the engine once

    def validate(self) -> tuple[TestPlan, BuildRunOptions]:
        try:
            plan = TestPlan.model_validate(self.test_plan)
            options = BuildRunOptions(approved_scripts=self.approved_scripts, timeouts=self.timeouts)
        except ValidationError as exc:
            first = exc.errors()[0]
            where = ".".join(str(p) for p in first.get("loc", ()))
            raise BuildRunInvalid(f"Invalid test plan or options ({where}): {first.get('msg')}") from exc
        if self.patch is not None:
            try:
                validate_patch(self.patch)
            except PatchRejected as exc:
                raise BuildRunInvalid(f"The patch was rejected: {exc}") from exc
        return plan, options


def submit(client: EngineClient, request: BuildRunRequest, *, cache_dir: Path,
           on_local: Callable[[str], None] | None = None) -> dict:
    """Upload or reference the source, then start the run. Returns the initial run state."""
    plan, options = request.validate()
    src = request.source
    spec: dict = {"kind": "build_run", "test_plan": plan.model_dump(by_alias=True), "patch": request.patch,
                  "options": options.model_dump(), "requested_by": request.requested_by}
    note = on_local or (lambda _m: None)
    if src.is_github:
        spec.update(source="github", owner=src.owner, repo=src.repo, ref=src.ref)
        if request.token:
            spec["credential_handle"] = client.put_credential(request.token, f"github:{src.owner}/{src.repo}")
            request.token = None
        return client.start(spec)
    packed: Path | None = None
    try:
        path = src.path
        if src.kind == "directory":
            note(f"Packing {src.label} for building (your files are only read)")
            packed, _report = pack_directory(src.path, cache_dir, for_build=True)
            path = packed
        elif src.kind != "zip":
            raise SourceError("Unsupported source.")
        note(f"Uploading source snapshot ({path.stat().st_size // 1024} KB)")
        spec.update(source="zip", upload_id=client.upload_zip(path)["upload_id"])
    finally:
        if packed is not None:
            packed.unlink(missing_ok=True)
    return client.start(spec)


def wait(client: EngineClient, run: dict, *, on_state: Callable[[dict], None] | None = None,
         should_cancel: Callable[[], bool] | None = None, deadline_seconds: float = DEFAULT_DEADLINE,
         poll_seconds: float | None = None) -> dict:
    return poll_run(client, run, deadline_seconds=deadline_seconds, on_state=on_state, should_cancel=should_cancel,
                    poll_seconds=POLL_SECONDS if poll_seconds is None else poll_seconds)


def verification_of(state: dict) -> str:
    result = state.get("result") or {}
    return result.get("verification") or "INCONCLUSIVE"


PHASE_LABELS = {
    Phase.CREATED.value: "Environment created",
    Phase.SOURCE_READY.value: "Source snapshot ready",
    Phase.DEPENDENCIES_INSTALLING.value: "Installing dependencies (registry only, scripts off)",
    Phase.DATABASE_STARTING.value: "Disposable database",
    Phase.BUILDING.value: "Production build (no network)",
    Phase.APPLICATION_STARTING.value: "Application start + health check",
    Phase.TESTING.value: "Test plan",
    Phase.COLLECTING_RESULTS.value: "Collecting results",
    Phase.COMPLETED.value: "Completed",
    Phase.FAILED.value: "Failed",
    Phase.CANCELLED.value: "Cancelled",
    Phase.CLEANED_UP.value: "Environment removed",
}
