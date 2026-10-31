"""Sandbox Manager API (bearer-token protected).

Reachable from the backend network (web stack) and, for the ROUTES CLI, from
127.0.0.1 on the host through the dedicated ``cli`` network.
"""

from __future__ import annotations

import hmac
import logging
import os
import re
import time
import uuid
from contextlib import asynccontextmanager
from typing import Literal

from fastapi import Depends, FastAPI, HTTPException, Request
from pydantic import BaseModel, Field, field_validator

from routes_shared.netpolicy import UrlPolicyError, parse_target_url
from routes_shared.uploads import MAX_UPLOAD_BYTES, UploadRejected, ZipStager, discard_upload

from manager.config import Settings
from manager.credentials import CredentialStore
from manager.docker_api import DockerAPI
from manager.gateway_client import GatewayClient
from manager.runs import RunManager

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
log = logging.getLogger("routes.sandbox")

_NAME = re.compile(r"^[A-Za-z0-9._-]{1,100}$")
_REF = re.compile(r"^[A-Za-z0-9._/-]{1,255}$")
UNCLAIMED_UPLOAD_TTL = 1800  # seconds an upload may wait for its run
MAX_PENDING_UPLOADS = 8


def dev_hosts() -> frozenset[str]:
    return frozenset(h.strip().lower() for h in os.environ.get("GATEWAY_DEV_ALLOW_HOSTS", "").split(",") if h.strip())


class DiscoveryRun(BaseModel):
    kind: Literal["discovery"]
    target_url: str = Field(max_length=2048)


class SourceRun(BaseModel):
    kind: Literal["source"]
    source: Literal["github", "zip"]
    target_url: str | None = Field(default=None, max_length=2048)
    upload_id: str | None = None
    owner: str | None = None
    repo: str | None = None
    ref: str | None = None
    credential_handle: str | None = Field(default=None, max_length=100)

    @field_validator("upload_id")
    @classmethod
    def _uuid(cls, v):
        if v is not None:
            uuid.UUID(v)
        return v

    @field_validator("owner", "repo")
    @classmethod
    def _name(cls, v):
        if v is not None and not _NAME.match(v):
            raise ValueError("invalid repository name")
        return v

    @field_validator("ref")
    @classmethod
    def _ref(cls, v):
        if v is not None and (not _REF.match(v) or ".." in v):
            raise ValueError("invalid ref")
        return v


class CredentialIn(BaseModel):
    secret: str = Field(min_length=10, max_length=400)
    scope: str = Field(max_length=220)


def build_app(settings: Settings | None = None, *, docker: DockerAPI | None = None,
              gateway: GatewayClient | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    if len(settings.token) < 24:
        raise SystemExit("SANDBOX_MANAGER_TOKEN must be set (24+ characters)")
    credentials = CredentialStore()
    docker = docker or DockerAPI(settings.docker_url)
    gateway = gateway or GatewayClient(settings.gateway_url, settings.gateway_token)
    runs = RunManager(settings, docker, gateway, credentials)

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        removed = await runs.cleanup_orphans()
        log.info("startup cleanup removed %d orphaned sandbox object(s)", removed)
        yield
        for run in runs.runs.values():
            run.cancel.set()

    app = FastAPI(title="ROUTES Sandbox Manager", docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
    app.state.runs = runs
    app.state.credentials = credentials
    pending_uploads: dict[str, float] = {}  # upload_id -> staged at (removed when a run claims it)

    def prune_uploads() -> None:
        cutoff = time.time() - UNCLAIMED_UPLOAD_TTL
        for upload_id in [u for u, t in pending_uploads.items() if t < cutoff]:
            pending_uploads.pop(upload_id, None)
            discard_upload(settings.uploads_dir, upload_id)

    def require_token(request: Request) -> None:
        header = request.headers.get("authorization", "")
        if not hmac.compare_digest(header, f"Bearer {settings.token}"):
            raise HTTPException(status_code=403, detail="forbidden")

    @app.get("/health")
    async def health():
        return {"status": "ok", "docker": await _safe(docker.ping), "gateway": await gateway.health(),
                "active_runs": sum(1 for r in runs.runs.values() if r.status in ("pending", "running"))}

    @app.post("/credentials", status_code=201, dependencies=[Depends(require_token)])
    async def put_credential(body: CredentialIn):
        try:
            return {"handle": credentials.put(body.secret, body.scope)}
        except OverflowError as exc:
            raise HTTPException(status_code=429, detail="too many pending credentials") from exc

    @app.delete("/credentials/{handle}", status_code=204, dependencies=[Depends(require_token)])
    async def delete_credential(handle: str):
        credentials.discard(handle)

    @app.post("/uploads", status_code=201, dependencies=[Depends(require_token)])
    async def upload(request: Request):
        """Stage a ZIP for one source run. The body is the raw archive (<= 100 MB).
        It is never opened here; the analyzer sandbox validates and extracts it."""
        prune_uploads()
        if len(pending_uploads) >= MAX_PENDING_UPLOADS:
            raise HTTPException(status_code=429, detail="too many pending uploads")
        declared = request.headers.get("content-length")
        if declared and declared.isdigit() and int(declared) > MAX_UPLOAD_BYTES:
            raise HTTPException(status_code=413, detail="ZIP uploads are limited to 100 MB.")
        try:
            with ZipStager(settings.uploads_dir) as stager:
                async for chunk in request.stream():
                    stager.write(chunk)
        except UploadRejected as exc:
            raise HTTPException(status_code=exc.status, detail=exc.message) from exc
        pending_uploads[stager.upload_id] = time.time()
        return {"upload_id": stager.upload_id, "size": stager.size, "sha256": stager.sha256}

    @app.post("/runs", status_code=201, dependencies=[Depends(require_token)])
    async def create_run(body: dict):
        kind = body.get("kind")
        try:
            if kind == "discovery":
                spec = DiscoveryRun.model_validate(body)
                target = parse_target_url(spec.target_url, dev_allow_hosts=dev_hosts())
                run = runs.start("discovery", {"target_url": target.url, "target_host": target.hostname,
                                               "target_port": target.port})
            elif kind == "source":
                spec = SourceRun.model_validate(body)
                if spec.source == "zip" and not spec.upload_id:
                    raise ValueError("upload_id required")
                if spec.source == "github" and not (spec.owner and spec.repo):
                    raise ValueError("owner and repo required")
                host = ""
                if spec.target_url:
                    host = parse_target_url(spec.target_url, dev_allow_hosts=dev_hosts()).hostname
                if spec.upload_id:
                    pending_uploads.pop(spec.upload_id, None)  # the run now owns (and deletes) it
                run = runs.start("source", {**spec.model_dump(), "target_host": host})
            else:
                raise ValueError("unknown run kind")
        except (ValueError, UrlPolicyError) as exc:
            raise HTTPException(status_code=422, detail=str(exc)[:300]) from exc
        return run.public()

    @app.get("/runs/{run_id}", dependencies=[Depends(require_token)])
    async def get_run(run_id: str):
        run = runs.runs.get(run_id)
        if run is None:
            raise HTTPException(status_code=404, detail="run not found")
        return run.public()

    @app.delete("/runs/{run_id}", dependencies=[Depends(require_token)])
    async def cancel_run(run_id: str):
        run = runs.cancel(run_id)
        if run is None:
            raise HTTPException(status_code=404, detail="run not found")
        return run.public()

    return app


async def _safe(fn) -> bool:
    try:
        return bool(await fn())
    except Exception:  # noqa: BLE001
        return False


def create_app() -> FastAPI:  # uvicorn factory
    return build_app()
