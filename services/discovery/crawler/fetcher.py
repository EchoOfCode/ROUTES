"""HTTP fetching with manual, scope-checked redirect handling.

All traffic goes through the ROUTES gateway (configured as the client proxy);
the gateway re-validates every hop, so the in-scope check here is about
crawl correctness while the gateway provides the security boundary.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

import httpx

from discovery.crawler.urls import dedupe_key, in_scope, normalise

USER_AGENT = "ROUTES-Discovery/0.1 (authorised application assessment)"
MAX_REDIRECTS = 5


@dataclass
class FetchResult:
    url: str
    final_url: str
    status: int | None = None
    headers: dict[str, str] = field(default_factory=dict)
    set_cookies: list[str] = field(default_factory=list)
    body: bytes = b""
    error: str | None = None
    truncated: bool = False
    external_redirect: str | None = None
    redirects: list[str] = field(default_factory=list)
    redirect_to_known: bool = False

    @property
    def content_type(self) -> str:
        return self.headers.get("content-type", "").split(";")[0].strip().lower()

    @property
    def ok(self) -> bool:
        return self.error is None and self.status is not None and 200 <= self.status < 300

    def text(self) -> str:
        return self.body.decode("utf-8", "replace")


def friendly_error(exc: Exception, response: httpx.Response | None = None) -> str:
    if response is not None:
        reason = response.headers.get("x-routes-gateway-reason")
        if reason:
            return f"Blocked by the ROUTES network gateway ({reason})."
    if isinstance(exc, httpx.ConnectTimeout):
        return "Connection timed out."
    if isinstance(exc, httpx.ReadTimeout):
        return "The server took too long to respond."
    if isinstance(exc, httpx.ProxyError):
        return "The ROUTES network gateway refused or could not complete the connection."
    if isinstance(exc, httpx.ConnectError):
        text = str(exc).lower()
        if "certificate" in text or "ssl" in text:
            return "The TLS certificate could not be verified."
        return "Could not connect to the website."
    return f"Request failed ({type(exc).__name__})."


class Fetcher:
    def __init__(self, hostname: str, *, proxy: str | None, timeout: float = 15.0, client: httpx.AsyncClient | None = None):
        self.hostname = hostname
        self.client = client or httpx.AsyncClient(
            proxy=proxy,
            timeout=httpx.Timeout(timeout, connect=10.0),
            follow_redirects=False,
            headers={"User-Agent": USER_AGENT, "Accept": "text/html,application/xhtml+xml,*/*;q=0.8"},
            http2=False,
            trust_env=False,
        )
        self.requests_made = 0
        self._lock = asyncio.Semaphore(3)

    async def close(self) -> None:
        await self.client.aclose()

    async def get(self, url: str, *, max_bytes: int, accept: str | None = None,
                  known: set[str] | None = None) -> FetchResult:
        """``known`` holds dedupe keys already inspected: a redirect to one of
        them stops without re-fetching the page."""
        result = FetchResult(url=url, final_url=url)
        current = url
        async with self._lock:
            for _ in range(MAX_REDIRECTS + 1):
                if not in_scope(current, self.hostname):
                    result.external_redirect = current
                    result.error = "Redirected outside the assessed hostname; not followed."
                    return result
                self.requests_made += 1
                headers = {"Accept": accept} if accept else None
                try:
                    async with self.client.stream("GET", current, headers=headers) as response:
                        if response.is_redirect:
                            location = response.headers.get("location", "")
                            nxt = normalise(location, current)
                            if not nxt:
                                result.status = response.status_code
                                result.error = "Redirect with an invalid location."
                                return result
                            result.redirects.append(nxt)
                            if known is not None and dedupe_key(nxt) in known:
                                result.status = response.status_code
                                result.final_url = nxt
                                result.redirect_to_known = True
                                return result
                            current = nxt
                            continue
                        result.final_url = current
                        result.status = response.status_code
                        result.headers = {k.lower(): v for k, v in response.headers.items()}
                        result.set_cookies = response.headers.get_list("set-cookie")
                        if response.headers.get("x-routes-gateway-reason"):
                            result.error = friendly_error(Exception(), response)
                            return result
                        body = bytearray()
                        async for chunk in response.aiter_bytes():
                            body += chunk
                            if len(body) > max_bytes:
                                result.truncated = True
                                body = body[:max_bytes]
                                break
                        result.body = bytes(body)
                        return result
                except httpx.HTTPError as exc:
                    result.error = friendly_error(exc)
                    return result
            result.error = "Too many redirects."
            return result
