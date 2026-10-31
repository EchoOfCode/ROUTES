"""Download a repository tarball through the gateway's narrow import path.

The sandbox never sees the developer's token: the gateway attaches it when
calling GitHub. The sandbox only holds a single-use gateway session token.
"""

from __future__ import annotations

from pathlib import Path

import httpx

MAX_BYTES = 100 * 1024 * 1024


class ImportFailed(Exception):
    pass


def download(import_url: str, session_token: str, dest: Path) -> int:
    headers = {"Proxy-Authorization": f"Bearer {session_token}"}
    size = 0
    try:
        with httpx.Client(timeout=httpx.Timeout(120.0, connect=10.0), trust_env=False) as client:
            with client.stream("GET", import_url, headers=headers) as r:
                if r.status_code != 200:
                    body = r.read()[:500].decode("utf-8", "replace").strip()
                    raise ImportFailed(body or f"Repository import failed (HTTP {r.status_code}).")
                with dest.open("wb") as fh:
                    for chunk in r.iter_bytes():
                        size += len(chunk)
                        if size > MAX_BYTES:
                            raise ImportFailed("The repository archive is larger than 100 MB.")
                        fh.write(chunk)
    except httpx.RemoteProtocolError as exc:
        raise ImportFailed("The repository download was interrupted or exceeded the size limit.") from exc
    except httpx.HTTPError as exc:
        raise ImportFailed(f"The repository could not be downloaded ({type(exc).__name__}).") from exc
    if size == 0:
        raise ImportFailed("The repository archive was empty.")
    return size
