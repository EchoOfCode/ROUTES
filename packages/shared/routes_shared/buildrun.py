"""Contracts for build-and-run sandboxes (kind ``build_run``).

A build-run receives an approved source snapshot, optionally applies a
candidate patch to a temporary copy, installs dependencies from the lockfile,
provisions a disposable PostgreSQL database, builds and starts the application
and runs an independently supplied, declarative test plan against it.

Everything here is pure validation shared by the Sandbox Manager, the build
runner, the test runner and the CLI. Nothing in this module decides whether a
patch is secure; it only describes what was executed and what was observed.
"""

from __future__ import annotations

import re
from enum import StrEnum
from pathlib import PurePosixPath
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

MAX_PATCH_BYTES = 1024 * 1024
MAX_PATCH_FILES = 200
MAX_SEED_BYTES = 256 * 1024
MAX_TESTS = 200
MAX_TEST_BODY = 64 * 1024
APP_PORT = 3000


class Phase(StrEnum):
    """Run states. Each is entered only when that work actually begins."""

    CREATED = "CREATED"
    SOURCE_READY = "SOURCE_READY"
    DEPENDENCIES_INSTALLING = "DEPENDENCIES_INSTALLING"
    DATABASE_STARTING = "DATABASE_STARTING"
    BUILDING = "BUILDING"
    APPLICATION_STARTING = "APPLICATION_STARTING"
    TESTING = "TESTING"
    COLLECTING_RESULTS = "COLLECTING_RESULTS"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    CLEANED_UP = "CLEANED_UP"


# Build-runner event stage -> phase. The runner emits these as it starts each step.
STAGE_PHASES: dict[str, Phase] = {
    "source_ready": Phase.SOURCE_READY,
    "dependencies_installing": Phase.DEPENDENCIES_INSTALLING,
    "database_starting": Phase.DATABASE_STARTING,
    "building": Phase.BUILDING,
    "application_starting": Phase.APPLICATION_STARTING,
}
# Handshake stages between the build runner and the Sandbox Manager.
STAGE_AWAITING_ISOLATION = "awaiting_isolation"   # dependencies installed; cut egress now
STAGE_ISOLATED = "isolated"                       # runner confirmed egress is gone
STAGE_APPLICATION_READY = "application_ready"     # app answers its health check; start tests


class Verification(StrEnum):
    """Overall outcome of a build-run. Only VERIFIED_RUN means every stage ran
    and every test passed; it says nothing about security by itself."""

    VERIFIED_RUN = "VERIFIED_RUN"                     # built, started, all tests passed
    TESTS_FAILED = "TESTS_FAILED"                     # ran, but at least one test failed
    BUILD_FAILED = "BUILD_FAILED"                     # install/build/start/database step failed
    DYNAMIC_VERIFICATION_UNSUPPORTED = "DYNAMIC_VERIFICATION_UNSUPPORTED"
    INCONCLUSIVE = "INCONCLUSIVE"                     # e.g. timeout, cancelled, infrastructure error


# ------------------------------------------------------------------- patches
class PatchRejected(ValueError):
    pass


_GIT_HEADER = re.compile(r"^diff --git a/(?P<a>\S+) b/(?P<b>\S+)$")
_HUNK = re.compile(r"^@@ -\d+(?:,(?P<old>\d+))? \+\d+(?:,(?P<new>\d+))? @@")


def _safe_rel(path: str) -> bool:
    if not path or "\x00" in path or "\\" in path or path.startswith("/") or (len(path) > 1 and path[1] == ":"):
        return False
    parts = PurePosixPath(path).parts
    return bool(parts) and not any(p in ("..", ".git") for p in parts) and len(parts) <= 40


def _header_path(line: str) -> str:
    path = line[4:].split("	", 1)[0].strip()
    if path.startswith('"'):
        raise PatchRejected("Quoted (escaped) file names are not supported in patches.")
    if path == "/dev/null":
        return path
    return path[2:] if path.startswith(("a/", "b/")) else path


def validate_patch(text: str) -> list[str]:
    """Return the files a unified diff touches, or raise PatchRejected.

    Refused: oversized or binary patches, symbolic links and submodules,
    absolute paths, ``..`` traversal and changes inside ``.git``. Hunk bodies
    are skipped by line count, so changed lines that happen to start with
    ``---`` are never mistaken for file headers. The patch is applied later to
    a temporary copy of the source only.
    """
    if not isinstance(text, str) or not text.strip():
        raise PatchRejected("The patch is empty.")
    if len(text.encode("utf-8", "replace")) > MAX_PATCH_BYTES:
        raise PatchRejected("The patch is larger than 1 MB.")
    if "\x00" in text or "GIT binary patch" in text:
        raise PatchRejected("Binary patches are not supported.")
    files: list[str] = []
    old = new = 0

    def add(path: str) -> None:
        if path == "/dev/null":
            return
        if not _safe_rel(path):
            raise PatchRejected("The patch contains an unsafe path.")
        if path not in files:
            files.append(path)

    for line in text.splitlines():
        if old > 0 or new > 0:                       # inside a hunk
            if line.startswith("\\"):                 # "\ No newline at end of file"
                continue
            tag = line[:1]
            if tag in (" ", ""):
                old, new = old - 1, new - 1
            elif tag == "-":
                old -= 1
            elif tag == "+":
                new -= 1
            else:
                raise PatchRejected("The patch is malformed (hunk line counts do not match).")
            if old < 0 or new < 0:
                raise PatchRejected("The patch is malformed (hunk line counts do not match).")
            continue
        if m := _HUNK.match(line):
            old = int(m.group("old") if m.group("old") is not None else 1)
            new = int(m.group("new") if m.group("new") is not None else 1)
        elif line.startswith(("new file mode", "deleted file mode", "old mode", "new mode")):
            if line.rsplit(" ", 1)[-1] not in ("100644", "100755"):
                raise PatchRejected("The patch may only contain regular files (no symbolic links or submodules).")
        elif line.startswith(("rename from ", "rename to ", "copy from ", "copy to ")):
            add(line.split(" ", 2)[2])
        elif line.startswith("Binary files "):
            raise PatchRejected("Binary patches are not supported.")
        elif m := _GIT_HEADER.match(line):
            add(m.group("a"))
            add(m.group("b"))
        elif line.startswith(("--- ", "+++ ")):
            add(_header_path(line))
    if old > 0 or new > 0:
        raise PatchRejected("The patch is truncated.")
    if not files:
        raise PatchRejected("The patch does not change any file.")
    if len(files) > MAX_PATCH_FILES:
        raise PatchRejected(f"The patch changes more than {MAX_PATCH_FILES} files.")
    return files


# ----------------------------------------------------------------- test plan
class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")
    __test__ = False      # "Test*" models are not pytest test classes


def _app_path(v: str) -> str:
    """Tests address the application under test only: a path, never a URL."""
    if not v.startswith("/") or v.startswith("//") or "\\" in v or any(c in v for c in "\r\n\t\x00 #"):
        raise ValueError("must be an absolute path on the application, e.g. /api/products")
    return v


class TestRequest(_Strict):
    method: Literal["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"] = "GET"
    path: str = Field(max_length=2048)
    query: dict[str, str] = Field(default_factory=dict)
    headers: dict[str, str] = Field(default_factory=dict)
    json_body: dict | list | str | int | float | bool | None = Field(default=None, alias="json")
    body: str | None = Field(default=None, max_length=MAX_TEST_BODY)
    timeout_seconds: float = Field(default=15, gt=0, le=120)

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    _path = field_validator("path")(lambda cls, v: _app_path(v))

    @field_validator("headers")
    @classmethod
    def _headers(cls, v: dict[str, str]) -> dict[str, str]:
        if len(v) > 30:
            raise ValueError("too many headers")
        for k, val in v.items():
            if not re.fullmatch(r"[A-Za-z0-9-]{1,64}", k) or k.lower() in ("host", "content-length", "transfer-encoding"):
                raise ValueError(f"header {k!r} is not permitted")
            if any(c in val for c in "\r\n\x00") or len(val) > 4096:
                raise ValueError(f"header {k!r} has an invalid value")
        return v

    @model_validator(mode="after")
    def _one_body(self):
        if self.json_body is not None and self.body is not None:
            raise ValueError("give either json or body, not both")
        return self


class TestExpect(_Strict):
    status: list[int] | None = None                 # any of these
    status_not: list[int] = Field(default_factory=list)
    body_contains: list[str] = Field(default_factory=list, max_length=50)
    body_not_contains: list[str] = Field(default_factory=list, max_length=50)
    json_equals: dict[str, object] = Field(default_factory=dict)   # top-level key -> value
    max_ms: int | None = Field(default=None, gt=0, le=120_000)
    # Response headers (names are case-insensitive): each must be present / must not have any of these values.
    headers_present: list[str] = Field(default_factory=list, max_length=30)
    header_not: dict[str, list[str]] = Field(default_factory=dict)

    @field_validator("headers_present")
    @classmethod
    def _present_names(cls, v: list[str]) -> list[str]:
        for name in v:
            if not re.fullmatch(r"[A-Za-z0-9-]{1,64}", name):
                raise ValueError(f"invalid header name {name!r}")
        return [n.lower() for n in v]

    @field_validator("header_not")
    @classmethod
    def _not_values(cls, v: dict[str, list[str]]) -> dict[str, list[str]]:
        if len(v) > 30:
            raise ValueError("too many header expectations")
        for name, values in v.items():
            if not re.fullmatch(r"[A-Za-z0-9-]{1,64}", name) or len(values) > 20:
                raise ValueError(f"invalid header expectation {name!r}")
        return {k.lower(): [str(x) for x in vals] for k, vals in v.items()}


class TestCase(_Strict):
    id: str = Field(pattern=r"^[A-Za-z0-9._-]{1,64}$")
    name: str = Field(max_length=200)
    category: Literal["security", "functional", "edge", "health"] = "functional"
    request: TestRequest
    expect: TestExpect


class HealthCheck(_Strict):
    path: str = Field(default="/", max_length=2048)
    expect_status: list[int] = Field(default_factory=lambda: list(range(200, 400)))
    _path = field_validator("path")(lambda cls, v: _app_path(v))


class DatabasePlan(_Strict):
    # Synthetic data supplied by ROUTES (trusted), applied after the repository schema.
    seed_sql: str | None = Field(default=None, max_length=MAX_SEED_BYTES)


class TestPlan(_Strict):
    version: Literal[1] = 1
    health: HealthCheck = Field(default_factory=HealthCheck)
    database: DatabasePlan = Field(default_factory=DatabasePlan)
    tests: list[TestCase] = Field(default_factory=list, max_length=MAX_TESTS)

    @field_validator("tests")
    @classmethod
    def _unique(cls, v: list[TestCase]) -> list[TestCase]:
        ids = [t.id for t in v]
        if len(ids) != len(set(ids)):
            raise ValueError("test ids must be unique")
        return v


# ------------------------------------------------------------ run options
TIMEOUT_KEYS = ("install", "database", "build", "startup", "tests", "total")


class BuildRunOptions(_Strict):
    """Caller-adjustable settings. Timeouts may only be *lowered* below the
    engine's configured maximums; the manager enforces that."""

    timeouts: dict[str, int] = Field(default_factory=dict)
    # Dependencies whose install scripts the developer explicitly approved.
    # "<root>" approves the project's own install/postinstall scripts.
    approved_scripts: list[str] = Field(default_factory=list, max_length=100)

    @field_validator("timeouts")
    @classmethod
    def _timeouts(cls, v: dict[str, int]) -> dict[str, int]:
        for k, val in v.items():
            if k not in TIMEOUT_KEYS or not isinstance(val, int) or not (5 <= val <= 7200):
                raise ValueError(f"invalid timeout {k!r}")
        return v

    @field_validator("approved_scripts")
    @classmethod
    def _names(cls, v: list[str]) -> list[str]:
        for name in v:
            if name != "<root>" and not re.fullmatch(r"(@[a-z0-9._~-]+/)?[a-z0-9._~-]{1,214}", name):
                raise ValueError(f"invalid package name {name!r}")
        return v
