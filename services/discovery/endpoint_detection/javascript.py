"""Find API endpoint references inside JavaScript (bundles and inline)."""

from __future__ import annotations

import re
from dataclasses import dataclass

from discovery.crawler.urls import in_scope, normalise

# fetch("/api/x", {method: "POST"}) / fetch(`/api/x`)
_FETCH = re.compile(r"""\bfetch\(\s*(['"`])(?P<url>[^'"`\s]{1,300})\1(?P<rest>[^)]{0,200})""")
# axios.get("/api/x") / axios.post('/api/x') / $.ajax / http.get
_AXIOS = re.compile(r"""\b(?:axios|api|http|client|\$http|request)\.(?P<m>get|post|put|patch|delete)\(\s*(['"`])(?P<url>[^'"`\s]{1,300})\2""", re.I)
# xhr.open("GET", "/api/x")
_XHR = re.compile(r"""\.open\(\s*(['"])(?P<m>GET|POST|PUT|PATCH|DELETE)\1\s*,\s*(['"`])(?P<url>[^'"`\s]{1,300})\3""", re.I)
# Bare string literals that look like API paths.
_PATH = re.compile(r"""(['"`])(?P<url>/(?:api|graphql|v\d+|rest|rpc|trpc|_api)(?:/[A-Za-z0-9_\-.:{}$\[\]]*)*/?)(?:\?[^'"`\s]*)?\1""")
_ABS = re.compile(r"""(['"`])(?P<url>https?://[A-Za-z0-9.\-]+(?::\d+)?/(?:api|graphql|v\d+|rest)(?:/[A-Za-z0-9_\-.:{}$]*)*)\1""")
_METHOD_IN_OPTS = re.compile(r"""method\s*:\s*['"`](GET|POST|PUT|PATCH|DELETE)['"`]""", re.I)


@dataclass(frozen=True)
class JsEndpoint:
    method: str
    url: str
    evidence: str


def _clean(url: str) -> str | None:
    # Template literals: keep the static prefix (`/api/users/${id}` -> /api/users/).
    if "${" in url:
        url = url.split("${", 1)[0]
    if len(url) <= 1 or not (url.startswith(("/", "http://", "https://"))):
        return None
    return url


def find_endpoints(js: str, base_url: str, hostname: str, source: str) -> tuple[list[JsEndpoint], set[str]]:
    """Return (in-scope endpoints, external hosts referenced)."""
    found: dict[tuple[str, str], JsEndpoint] = {}
    external: set[str] = set()

    def add(method: str, raw: str, kind: str) -> None:
        cleaned = _clean(raw)
        if not cleaned:
            return
        url = normalise(cleaned, base_url)
        if not url:
            return
        if not in_scope(url, hostname):
            host = url.split("/")[2]
            external.add(host)
            return
        key = (method, url)
        if key not in found and len(found) < 300:
            found[key] = JsEndpoint(method=method, url=url, evidence=f"{kind} in {source}"[:300])

    for m in _FETCH.finditer(js):
        mm = _METHOD_IN_OPTS.search(m.group("rest") or "")
        add(mm.group(1).upper() if mm else "GET", m.group("url"), "fetch() call")
    for m in _AXIOS.finditer(js):
        add(m.group("m").upper(), m.group("url"), "HTTP client call")
    for m in _XHR.finditer(js):
        add(m.group("m").upper(), m.group("url"), "XMLHttpRequest")
    known_urls = {u for (_, u) in found}
    for regex in (_PATH, _ABS):
        for m in regex.finditer(js):
            url = normalise(m.group("url"), base_url)
            if url and url not in known_urls:
                add("GET", m.group("url"), "API path string")
                known_urls.add(url)
    return list(found.values()), external
