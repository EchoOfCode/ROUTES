"""Client for the internal Sandbox Manager service."""

import httpx

from app.core.config import get_settings
from app.core.errors import ApiError


def _client() -> httpx.Client:
    s = get_settings()
    return httpx.Client(
        base_url=s.sandbox_manager_url,
        headers={"Authorization": f"Bearer {s.sandbox_manager_token}"},
        timeout=httpx.Timeout(15.0, connect=5.0),
    )


def store_ephemeral_credential(token: str, owner: str, repo: str) -> str:
    """Hand a GitHub token to the Sandbox Manager's in-memory store.

    Returns an opaque single-use handle. The token itself never touches
    PostgreSQL, Redis or logs.
    """
    try:
        with _client() as c:
            r = c.post("/credentials", json={"secret": token, "scope": f"github:{owner}/{repo}"})
    except httpx.HTTPError as exc:
        raise ApiError(503, "sandbox_unavailable", "The sandbox service is unavailable. Try again shortly.") from exc
    if r.status_code != 201:
        raise ApiError(503, "sandbox_unavailable", "The access token could not be prepared for use.")
    return r.json()["handle"]


def discard_credential(handle: str) -> None:
    try:
        with _client() as c:
            c.delete(f"/credentials/{handle}")
    except httpx.HTTPError:
        pass  # TTL expiry in the manager is the backstop.
