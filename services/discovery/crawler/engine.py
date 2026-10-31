"""Hybrid crawler: HTTP-first breadth-first discovery, browser only when needed."""

from __future__ import annotations

import asyncio
import time
from collections import deque
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from discovery.crawler.extract import extract
from discovery.crawler.fetcher import Fetcher, FetchResult
from discovery.crawler.policy_files import MANIFEST_PATH, Robots, parse_sitemap, validate_manifest
from discovery.crawler.urls import (
    dedupe_key,
    in_scope,
    looks_like_asset,
    looks_destructive,
    normalise,
    path_of,
    query_params,
)
from discovery.endpoint_detection.javascript import find_endpoints
from discovery.endpoint_detection.openapi import CANDIDATE_PATHS, parse_spec
from discovery.events import emit
from discovery.technology_detection.detect import Detector

HTML_MAX = 3 * 1024 * 1024
JS_MAX = 4 * 1024 * 1024
MAX_JS_FILES = 30
MAX_RENDERS = 8
MAX_DEPTH = 6


@dataclass
class Config:
    target_url: str
    max_pages: int = 25
    proxy_url: str | None = None
    enable_browser: bool = True
    time_budget_seconds: int = 480


@dataclass
class State:
    pages: list[dict] = field(default_factory=list)
    forms: list[dict] = field(default_factory=list)
    endpoints: dict[tuple[str, str, str], dict] = field(default_factory=dict)
    scripts: list[str] = field(default_factory=list)
    external_hosts: set[str] = field(default_factory=set)
    openapi: list[dict] = field(default_factory=list)


class Crawler:
    def __init__(self, config: Config, *, fetcher: Fetcher | None = None, renderer=None):
        self.config = config
        self.target = normalise(config.target_url) or config.target_url
        self.hostname = urlsplit(self.target).hostname or ""
        self.origin = f"{urlsplit(self.target).scheme}://{urlsplit(self.target).netloc}"
        self.fetcher = fetcher or Fetcher(self.hostname, proxy=config.proxy_url)
        self.renderer = renderer
        self.detector = Detector()
        self.state = State()
        self.deadline = time.monotonic() + config.time_budget_seconds
        self.renders = 0

    # ---------------------------------------------------------------- helpers
    def _endpoint(self, method: str, url: str, origin: str, evidence: str, page_url: str | None,
                  parameters: list[str] | None = None, details: dict | None = None) -> None:
        key = (method, dedupe_key(url).split("?")[0], origin)
        existing = self.state.endpoints.get(key)
        params = sorted(set(parameters or []) | set(query_params(url)))
        if existing:
            existing["parameters"] = sorted(set(existing["parameters"]) | set(params))[:100]
            return
        if len(self.state.endpoints) >= 1500:
            return
        self.state.endpoints[key] = {
            "method": method, "url": url[:2048], "path": path_of(url)[:2048], "origin": origin,
            "parameters": params[:100], "evidence": evidence[:500], "page_url": page_url, "details": details or {},
        }

    def _out_of_time(self) -> bool:
        return time.monotonic() > self.deadline

    # ------------------------------------------------------------------- run
    async def run(self) -> dict:
        result: dict = {"target_url": self.target, "hostname": self.hostname, "page_limit": self.config.max_pages}
        try:
            emit("validating", f"Checking {self.origin}")
            root = await self.fetcher.get(self.target, max_bytes=HTML_MAX)
            if root.error and root.status is None and not root.external_redirect:
                return {**result, "fatal": True, "reachable": False,
                        "error": f"The website could not be reached: {root.error}"}

            emit("checking_integration", "Looking for /.well-known/routes.json")
            manifest_res = await self.fetcher.get(self.origin + MANIFEST_PATH, max_bytes=16 * 1024 + 1,
                                                  accept="application/json")
            manifest = validate_manifest(manifest_res.status, manifest_res.body, manifest_res.content_type)
            if manifest_res.error and manifest_res.status is None:
                manifest["error"] = manifest_res.error
            if manifest_res.truncated:
                manifest.update(valid=False, error="Manifest exceeds 16 KB.")

            robots_res = await self.fetcher.get(self.origin + "/robots.txt", max_bytes=512 * 1024, accept="text/plain")
            robots = Robots(robots_res.text() if robots_res.ok and "html" not in robots_res.content_type else None)
            sitemap_urls = await self._sitemaps(robots)

            emit("discovering_pages", "Crawling public pages")
            await self._crawl(root, sitemap_urls, robots)

            emit("inspecting_javascript", f"Inspecting {min(len(self.state.scripts), MAX_JS_FILES)} script files")
            await self._inspect_scripts()

            emit("identifying_endpoints", "Checking for public API specifications")
            await self._openapi(robots)

            emit("detecting_technologies", "Summarising technology evidence")
            pages_ok = [p for p in self.state.pages if not p.get("error")]
            result.update({
                "reachable": True,
                "manifest": manifest,
                "robots": {"found": robots.found, "disallow_rules": robots.disallow_rules,
                           "sitemaps": robots.sitemaps[:20], "blocked_urls": self._robots_blocked[:200]},
                "sitemap_urls": len(sitemap_urls),
                "pages": self.state.pages,
                "forms": self.state.forms[:500],
                "endpoints": list(self.state.endpoints.values()),
                "scripts": self.state.scripts[:500],
                "external_hosts": sorted(self.state.external_hosts)[:500],
                "technologies": self.detector.results(),
                "stack": self.detector.summary(),
                "openapi": self.state.openapi,
                "page_limit_reached": self._limit_reached,
                "requests_made": self.fetcher.requests_made,
            })
            if not pages_ok:
                result.update(fatal=True, error="No pages could be inspected. " + (self.state.pages[0].get("error") or "")
                              if self.state.pages else "No pages could be inspected.")
            return result
        finally:
            await self.fetcher.close()
            if self.renderer is not None:
                try:
                    await self.renderer.close()
                except Exception:  # noqa: BLE001
                    pass

    async def _sitemaps(self, robots: Robots) -> list[str]:
        candidates = [normalise(s, self.origin) for s in robots.sitemaps] or [self.origin + "/sitemap.xml"]
        candidates = [c for c in candidates if c and in_scope(c, self.hostname)][:3]
        pages: list[str] = []
        fetched = 0
        while candidates and fetched < 5 and len(pages) < 500:
            url = candidates.pop(0)
            fetched += 1
            res = await self.fetcher.get(url, max_bytes=5 * 1024 * 1024, accept="application/xml,text/xml")
            if not res.ok:
                continue
            found, nested = parse_sitemap(res.body, self.hostname, url)
            pages.extend(found)
            candidates.extend(nested[:3])
        return list(dict.fromkeys(pages))[:500]

    async def _crawl(self, root: FetchResult, sitemap_urls: list[str], robots: Robots) -> None:
        self._robots_blocked: list[str] = []
        self._limit_reached = False
        seen: set[str] = set()
        crawled: set[str] = set()
        queue: deque[tuple[str, int, FetchResult | None]] = deque()
        queue.append((self.target, 0, root))
        seen.add(dedupe_key(self.target))
        for url in sitemap_urls:
            k = dedupe_key(url)
            if k not in seen:
                seen.add(k)
                queue.append((url, 1, None))

        while queue and not self._out_of_time():
            if len(self.state.pages) >= self.config.max_pages:
                self._limit_reached = True
                break
            url, depth, prefetched = queue.popleft()
            if url != self.target and not robots.allowed(url):
                self._robots_blocked.append(url)
                continue
            res = prefetched or await self.fetcher.get(url, max_bytes=HTML_MAX, known=crawled)
            if res.redirect_to_known:
                continue
            for hop in res.redirects:
                seen.add(dedupe_key(hop))
            page = {"url": url, "status_code": res.status, "title": None, "content_type": res.content_type or None,
                    "depth": depth, "rendered": False, "is_login": False, "is_registration": False,
                    "links_count": 0, "forms_count": 0, "scripts_count": 0, "error": res.error}
            if res.external_redirect:
                self.state.external_hosts.add(urlsplit(res.external_redirect).hostname or "")
            if res.headers:
                self.detector.headers(res.headers, res.set_cookies, url)
            if res.error or res.status is None:
                self.state.pages.append(page)
                continue
            if res.status >= 400:
                page["error"] = f"HTTP {res.status}"
                self.state.pages.append(page)
                continue
            if "html" not in res.content_type:
                page["error"] = f"Not an HTML page ({res.content_type or 'unknown type'})."
                self.state.pages.append(page)
                continue
            if res.final_url != url and dedupe_key(res.final_url) != dedupe_key(url):
                if dedupe_key(res.final_url) in crawled:
                    continue  # redirect to a page we already inspected
                page["url"] = res.final_url
            crawled.add(dedupe_key(res.final_url))
            html = res.text()
            ex = extract(html, res.final_url)
            if ex.js_shell and self.renderer is not None and self.renders < MAX_RENDERS and not self._out_of_time():
                emit("discovering_pages", f"Rendering JavaScript for {path_of(url)[:80]}")
                rendered = await self._render(res.final_url)
                if rendered is not None and rendered.html:
                    html = rendered.html
                    ex = extract(html, res.final_url)
                    page["rendered"] = True
                    for method, api_url in rendered.api_requests:
                        self._endpoint(method, api_url, "js_reference", "Requested by the page while rendering", url)
                    self.state.external_hosts |= rendered.external_hosts
            self.detector.html(html, url, ex.meta_generator)
            page.update(title=ex.title, is_login=ex.is_login, is_registration=ex.is_registration,
                        links_count=len(ex.links), forms_count=len(ex.forms), scripts_count=len(ex.scripts))
            self.state.pages.append(page)
            emit("discovering_pages", f"{len(self.state.pages)} of up to {self.config.max_pages} pages inspected")

            for form in ex.forms:
                if not in_scope(form.action, self.hostname):
                    self.state.external_hosts.add(urlsplit(form.action).hostname or "")
                self.state.forms.append({"page_url": url, "action": form.action, "method": form.method,
                                         "fields": form.fields})
                names = [f["name"] for f in form.fields if f.get("name")]
                self._endpoint(form.method if form.method != "DIALOG" else "GET", form.action, "form",
                               f"Form on {path_of(url)}", url, names,
                               details={"fields": form.fields[:100], "page_url": url})
            for script in ex.scripts:
                if in_scope(script, self.hostname):
                    if script not in self.state.scripts:
                        self.state.scripts.append(script)
                else:
                    self.state.external_hosts.add(urlsplit(script).hostname or "")
                self.detector.script_url(script)
            for i, inline in enumerate(ex.inline_scripts[:20]):
                eps, external = find_endpoints(inline, res.final_url, self.hostname, f"inline script on {path_of(url)}")
                for ep in eps:
                    self._endpoint(ep.method, ep.url, "js_reference", ep.evidence, url)
                self.state.external_hosts |= external
            for link in ex.links:
                if not in_scope(link, self.hostname):
                    self.state.external_hosts.add(urlsplit(link).hostname or "")
                    continue
                if urlsplit(link).query:
                    self._endpoint("GET", link, "link_query", f"Link with query parameters on {path_of(url)}", url)
                if looks_like_asset(link) or looks_destructive(link) or depth + 1 > MAX_DEPTH:
                    continue
                k = dedupe_key(link)
                if k in seen:
                    continue
                seen.add(k)
                queue.append((link, depth + 1, None))

        if queue and len(self.state.pages) >= self.config.max_pages:
            self._limit_reached = True
        self.state.external_hosts.discard("")

    async def _render(self, url: str):
        self.renders += 1
        try:
            if getattr(self.renderer, "_browser", True) is None:
                await self.renderer.start()
            return await asyncio.wait_for(self.renderer.render(url), 40)
        except Exception:  # noqa: BLE001 - fall back to the HTTP response
            return None

    async def _inspect_scripts(self) -> None:
        for script in self.state.scripts[:MAX_JS_FILES]:
            if self._out_of_time():
                break
            res = await self.fetcher.get(script, max_bytes=JS_MAX, accept="*/*")
            if not res.ok:
                continue
            js = res.text()
            self.detector.bundle(js, script)
            eps, external = find_endpoints(js, script, self.hostname, f"script {path_of(script)[-80:]}")
            for ep in eps:
                self._endpoint(ep.method, ep.url, "js_reference", ep.evidence, None)
            self.state.external_hosts |= external

    async def _openapi(self, robots: Robots) -> None:
        for path in CANDIDATE_PATHS:
            if self._out_of_time():
                break
            url = self.origin + path
            if not robots.allowed(url):
                continue
            res = await self.fetcher.get(url, max_bytes=5 * 1024 * 1024, accept="application/json")
            if not res.ok or "html" in res.content_type:
                continue
            parsed = parse_spec(res.body, url, self.origin)
            if parsed is None:
                continue
            meta, endpoints = parsed
            self.state.openapi.append(meta)
            self.detector.openapi(url)
            for ep in endpoints:
                if in_scope(ep["url"], self.hostname):
                    self._endpoint(ep["method"], ep["url"], "openapi", f"Declared in {path}", None, ep["parameters"],
                                   details={"summary": ep["summary"]})
            if len(self.state.openapi) >= 3:
                break
