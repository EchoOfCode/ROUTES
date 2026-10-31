"""Optional JavaScript rendering with Playwright/Chromium.

Only used for pages that look like client-rendered shells. The browser is
routed through the gateway, and every non-GET or out-of-scope request the
page attempts is aborted before it leaves the sandbox.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from discovery.crawler.fetcher import USER_AGENT
from discovery.crawler.urls import in_scope

log = logging.getLogger("routes.discovery.browser")


@dataclass
class Rendered:
    url: str
    html: str = ""
    api_requests: list[tuple[str, str]] = field(default_factory=list)  # (method, url)
    blocked_requests: int = 0
    external_hosts: set[str] = field(default_factory=set)
    error: str | None = None


class Renderer:
    def __init__(self, hostname: str, proxy_url: str | None, *, timeout_seconds: int = 20):
        self.hostname = hostname
        self.proxy_url = proxy_url
        self.timeout_ms = timeout_seconds * 1000
        self._pw = None
        self._browser = None

    async def start(self) -> None:
        from playwright.async_api import async_playwright

        self._pw = await async_playwright().start()
        proxy = None
        if self.proxy_url:
            parts = urlsplit(self.proxy_url)
            proxy = {"server": f"http://{parts.hostname}:{parts.port}", "username": parts.username or "",
                     "password": parts.password or ""}
        # The container (non-root, no capabilities, seccomp) is the sandbox
        # boundary; Chromium's own namespace sandbox needs privileges we drop.
        self._browser = await self._pw.chromium.launch(
            headless=True, proxy=proxy,
            args=["--no-sandbox", "--disable-gpu", "--disable-extensions", "--no-first-run",
                  "--disable-background-networking", "--disable-sync", "--disable-default-apps",
                  "--disable-component-update", "--metrics-recording-only", "--mute-audio"],
        )

    async def close(self) -> None:
        try:
            if self._browser:
                await self._browser.close()
        finally:
            if self._pw:
                await self._pw.stop()

    async def render(self, url: str) -> Rendered:
        out = Rendered(url=url)
        if self._browser is None:
            out.error = "Browser not available."
            return out
        context = await self._browser.new_context(user_agent=USER_AGENT, accept_downloads=False,
                                                  service_workers="block", ignore_https_errors=False,
                                                  java_script_enabled=True)
        try:
            async def guard(route):
                req = route.request
                if req.method not in ("GET", "HEAD") or not in_scope(req.url, self.hostname):
                    out.blocked_requests += 1
                    host = urlsplit(req.url).hostname
                    if host and not in_scope(req.url, self.hostname):
                        out.external_hosts.add(host)
                    await route.abort()
                    return
                await route.continue_()

            await context.route("**/*", guard)
            page = await context.new_page()
            page.on("dialog", lambda d: d.dismiss())
            page.on("popup", lambda p: p.close())

            def on_request(req):
                if req.resource_type in ("xhr", "fetch") and in_scope(req.url, self.hostname):
                    out.api_requests.append((req.method, req.url))

            page.on("request", on_request)
            try:
                await page.goto(url, wait_until="networkidle", timeout=self.timeout_ms)
            except Exception as exc:  # noqa: BLE001 - partial render is still useful
                out.error = f"Rendering incomplete ({type(exc).__name__})."
            out.html = (await page.content())[:2_000_000]
        except Exception as exc:  # noqa: BLE001
            out.error = f"Rendering failed ({type(exc).__name__})."
        finally:
            await context.close()
        return out
