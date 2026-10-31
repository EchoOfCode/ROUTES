"""Control API used only by the Sandbox Manager to open and close sessions.

Protected by a bearer token and by a peer-address check: only networks the
gateway was attached to at startup (the control network) may call it. The
per-run sandbox networks attached later are therefore excluded.
"""

from __future__ import annotations

import hmac
import ipaddress
import re
import time

from pydantic import BaseModel, Field, field_validator
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from routes_shared.netpolicy import normalise_hostname

from gateway.sessions import GithubImport, SessionStore

_NAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,100}$")


class GithubSpec(BaseModel):
    owner: str = Field(max_length=100)
    repo: str = Field(max_length=100)
    ref: str | None = Field(default=None, max_length=255)
    token: str | None = Field(default=None, max_length=400)

    @field_validator("owner", "repo")
    @classmethod
    def _name(cls, v: str) -> str:
        if not _NAME_RE.match(v):
            raise ValueError("invalid name")
        return v


class SessionRequest(BaseModel):
    mode: str = Field(pattern="^(web|github_import)$")
    allowed_host: str | None = Field(default=None, max_length=253)
    allowed_ports: list[int] = Field(default_factory=lambda: [80, 443], max_length=4)
    subnet: str = Field(max_length=64)
    ttl_seconds: int = Field(default=900, ge=30, le=3600)
    max_bytes: int = Field(default=256 * 1024 * 1024, ge=1024, le=512 * 1024 * 1024)
    github: GithubSpec | None = None

    @field_validator("allowed_ports")
    @classmethod
    def _ports(cls, v: list[int]) -> list[int]:
        if any(p not in (80, 443, 8080, 8443) for p in v):
            raise ValueError("port not permitted")
        return v


def build_control_app(store: SessionStore, *, token: str, allowed_peers: list) -> Starlette:
    def authorised(request: Request) -> bool:
        header = request.headers.get("authorization", "")
        if not token or not hmac.compare_digest(header, f"Bearer {token}"):
            return False
        try:
            peer = ipaddress.ip_address(request.client.host if request.client else "")
        except ValueError:
            return False
        return any(peer in net for net in allowed_peers)

    async def create(request: Request):
        if not authorised(request):
            return JSONResponse({"error": "forbidden"}, status_code=403)
        try:
            spec = SessionRequest.model_validate(await request.json())
            subnet = ipaddress.ip_network(spec.subnet, strict=False)
        except Exception as exc:  # noqa: BLE001
            return JSONResponse({"error": "invalid", "detail": str(exc)[:300]}, status_code=422)
        if subnet.num_addresses > 65536 or any(subnet.overlaps(n) for n in allowed_peers):
            return JSONResponse({"error": "invalid subnet"}, status_code=422)
        if spec.mode == "web":
            if not spec.allowed_host:
                return JSONResponse({"error": "allowed_host required"}, status_code=422)
            hosts = frozenset({normalise_hostname(spec.allowed_host)})
            github = None
        else:
            if spec.github is None:
                return JSONResponse({"error": "github spec required"}, status_code=422)
            hosts = frozenset()
            github = GithubImport(owner=spec.github.owner, repo=spec.github.repo, ref=spec.github.ref,
                                  token=spec.github.token)
        session = store.create(
            mode=spec.mode, allowed_hosts=hosts, allowed_ports=frozenset(spec.allowed_ports), subnet=subnet,
            expires_at=time.time() + spec.ttl_seconds, max_bytes=spec.max_bytes, github=github,
        )
        return JSONResponse({"id": session.id, "token": session.token}, status_code=201)

    async def close(request: Request):
        if not authorised(request):
            return JSONResponse({"error": "forbidden"}, status_code=403)
        session = store.close(request.path_params["sid"])
        if session is None:
            return JSONResponse({"error": "not found"}, status_code=404)
        return JSONResponse(session.summary())

    async def health(request: Request):
        store.sweep()
        return JSONResponse({"status": "ok", "sessions": len(store)})

    return Starlette(routes=[
        Route("/sessions", create, methods=["POST"]),
        Route("/sessions/{sid}", close, methods=["DELETE"]),
        Route("/health", health, methods=["GET"]),
    ])
