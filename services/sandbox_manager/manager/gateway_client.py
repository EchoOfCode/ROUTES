"""Client for the network gateway control API."""

from __future__ import annotations

import httpx


class GatewayClient:
    def __init__(self, base_url: str, token: str, *, transport: httpx.AsyncBaseTransport | None = None):
        self._client = httpx.AsyncClient(base_url=base_url, headers={"Authorization": f"Bearer {token}"},
                                         timeout=10.0, transport=transport)

    async def close_client(self) -> None:
        await self._client.aclose()

    async def _open(self, body: dict) -> dict:
        r = await self._client.post("/sessions", json=body)
        if r.status_code != 201:
            raise RuntimeError(f"gateway refused session ({r.status_code})")
        return r.json()

    async def open_web(self, host: str, port: int, subnet: str, *, ttl: int) -> dict:
        ports = sorted({80, 443, port})
        return await self._open({"mode": "web", "allowed_host": host, "allowed_ports": ports, "subnet": subnet,
                                 "ttl_seconds": min(ttl, 3600)})

    async def open_github(self, owner: str, repo: str, ref: str | None, token: str | None, subnet: str, *, ttl: int) -> dict:
        return await self._open({"mode": "github_import", "subnet": subnet, "allowed_ports": [443],
                                 "ttl_seconds": min(ttl, 3600),
                                 "github": {"owner": owner, "repo": repo, "ref": ref, "token": token}})

    async def open_packages(self, subnet: str, *, ttl: int, max_bytes: int, github: dict | None = None) -> dict:
        """Registry-only HTTPS egress for dependency installation (hosts fixed by the gateway),
        optionally with one repository import."""
        body = {"mode": "packages", "subnet": subnet, "allowed_ports": [443], "ttl_seconds": min(ttl, 3600),
                "max_bytes": max_bytes}
        if github:
            body["github"] = github
        return await self._open(body)

    async def close(self, session_id: str) -> dict | None:
        r = await self._client.delete(f"/sessions/{session_id}")
        return r.json() if r.status_code == 200 else None

    async def health(self) -> bool:
        try:
            r = await self._client.get("/health")
        except httpx.HTTPError:
            return False
        return r.status_code == 200
