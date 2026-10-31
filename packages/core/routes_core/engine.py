"""Client for the Sandbox Manager API (the ROUTES sandbox engine).

Used by the RQ workers (inside Compose) and by the CLI (on the host, through
127.0.0.1). Every call is authenticated with the manager's bearer token.
"""

from __future__ import annotations

import os
from pathlib import Path

import httpx

DEFAULT_URL = "http://sandbox-manager:8100"


class EngineUnavailable(Exception):
    """The Sandbox Manager could not be reached or refused for an infrastructure reason."""


class EngineRejected(ValueError):
    """The Sandbox Manager rejected the request as invalid (for example a blocked URL)."""


class EngineClient:
    def __init__(self, base_url: str | None = None, token: str | None = None, *,
                 timeout: float = 20.0, transport: httpx.BaseTransport | None = None):
        self.base_url = (base_url or os.environ.get("SANDBOX_MANAGER_URL") or DEFAULT_URL).rstrip("/")
        token = token if token is not None else os.environ.get("SANDBOX_MANAGER_TOKEN", "")
        self.client = httpx.Client(base_url=self.base_url, headers={"Authorization": f"Bearer {token}"},
                                   timeout=httpx.Timeout(timeout, connect=5.0), transport=transport, trust_env=False)

    # ----------------------------------------------------------------- runs
    def start(self, spec: dict) -> dict:
        try:
            r = self.client.post("/runs", json=spec)
        except httpx.HTTPError as exc:
            raise EngineUnavailable("The Sandbox Manager is unavailable.") from exc
        if r.status_code == 422:
            raise EngineRejected(_detail(r, "The sandbox request was rejected."))
        if r.status_code != 201:
            raise EngineUnavailable(f"The Sandbox Manager refused the run ({r.status_code}).")
        return r.json()

    def get(self, run_id: str) -> dict | None:
        """Current run state, or None if the manager could not be reached this time."""
        try:
            r = self.client.get(f"/runs/{run_id}")
        except httpx.HTTPError:
            return None
        if r.status_code == 404:
            return {"status": "failed", "error": "The sandbox run was lost (the Sandbox Manager restarted)."}
        return r.json() if r.status_code == 200 else None

    def cancel(self, run_id: str) -> None:
        try:
            self.client.delete(f"/runs/{run_id}")
        except httpx.HTTPError:
            pass

    # ------------------------------------------------------- credentials
    def put_credential(self, secret: str, scope: str) -> str:
        """Hand a token to the manager's in-memory store; returns an opaque single-use handle."""
        try:
            r = self.client.post("/credentials", json={"secret": secret, "scope": scope})
        except httpx.HTTPError as exc:
            raise EngineUnavailable("The Sandbox Manager is unavailable.") from exc
        if r.status_code == 422:
            raise EngineRejected("The access token format was not accepted.")
        if r.status_code != 201:
            raise EngineUnavailable(f"The Sandbox Manager refused the credential ({r.status_code}).")
        return r.json()["handle"]

    def discard_credential(self, handle: str) -> None:
        try:
            self.client.delete(f"/credentials/{handle}")
        except httpx.HTTPError:
            pass

    # ----------------------------------------------------------- uploads
    def upload_zip(self, path: Path) -> dict:
        """Stream a ZIP (<= 100 MB) to the manager; returns {upload_id, size, sha256}."""
        path = Path(path)

        def chunks():
            with path.open("rb") as fh:
                while chunk := fh.read(1024 * 1024):
                    yield chunk

        try:
            r = self.client.post("/uploads", content=chunks(), timeout=httpx.Timeout(300.0, connect=5.0),
                                 headers={"Content-Type": "application/zip",
                                          "Content-Length": str(path.stat().st_size)})
        except httpx.HTTPError as exc:
            raise EngineUnavailable("The Sandbox Manager is unavailable.") from exc
        if r.status_code in (400, 413):
            raise EngineRejected(_detail(r, "The archive was rejected."))
        if r.status_code != 201:
            raise EngineUnavailable(f"The Sandbox Manager refused the upload ({r.status_code}).")
        return r.json()

    # ------------------------------------------------------------ health
    def health(self) -> dict:
        try:
            r = self.client.get("/health", timeout=5.0)
        except httpx.HTTPError as exc:
            raise EngineUnavailable(f"The Sandbox Manager is not reachable at {self.base_url}.") from exc
        if r.status_code != 200:
            raise EngineUnavailable(f"The Sandbox Manager health check failed ({r.status_code}).")
        return r.json()

    def close(self) -> None:
        self.client.close()

    def __enter__(self) -> "EngineClient":
        return self

    def __exit__(self, *exc) -> None:
        self.close()


def _detail(r: httpx.Response, default: str) -> str:
    try:
        detail = r.json().get("detail")
    except ValueError:
        return default
    return str(detail)[:300] if detail else default
