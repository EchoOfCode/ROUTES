from __future__ import annotations

from urllib.parse import parse_qsl, urljoin, urlsplit, urlunsplit

from routes_shared.netpolicy import normalise_hostname

DEFAULT_PORTS = {"http": 80, "https": 443}
SKIP_SCHEMES = ("mailto:", "tel:", "javascript:", "data:", "blob:", "ftp:", "file:", "sms:")
# Static assets that are not HTML pages.
ASSET_EXTENSIONS = (
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico", ".css", ".js", ".mjs", ".map", ".woff", ".woff2",
    ".ttf", ".eot", ".otf", ".pdf", ".zip", ".gz", ".mp4", ".mp3", ".webm", ".avi", ".mov", ".xml", ".json",
    ".txt", ".csv", ".xls", ".xlsx", ".doc", ".docx", ".ppt", ".pptx", ".dmg", ".exe", ".apk", ".avif",
)
# Never follow links that look like state-changing actions.
DESTRUCTIVE_HINTS = ("logout", "log-out", "signout", "sign-out", "delete", "remove", "unsubscribe", "destroy")


def normalise(url: str, base: str | None = None) -> str | None:
    """Absolute, fragment-free, canonical URL or None if not crawlable."""
    raw = (url or "").strip()
    if not raw or raw.lower().startswith(SKIP_SCHEMES) or raw.startswith("#"):
        return None
    try:
        absolute = urljoin(base, raw) if base else raw
        parts = urlsplit(absolute)
        scheme = parts.scheme.lower()
        if scheme not in DEFAULT_PORTS or not parts.hostname:
            return None
        host = normalise_hostname(parts.hostname)
        port = parts.port
    except ValueError:
        return None
    if parts.username or parts.password:
        return None
    netloc = host if port in (None, DEFAULT_PORTS[scheme]) else f"{host}:{port}"
    path = parts.path or "/"
    return urlunsplit((scheme, netloc, path, parts.query, ""))


def in_scope(url: str, hostname: str) -> bool:
    try:
        host = urlsplit(url).hostname
        return host is not None and normalise_hostname(host) == hostname
    except ValueError:
        return False


def query_params(url: str) -> list[str]:
    return sorted({k for k, _ in parse_qsl(urlsplit(url).query, keep_blank_values=True)})[:50]


def path_of(url: str) -> str:
    p = urlsplit(url)
    return p.path or "/"


def looks_like_asset(url: str) -> bool:
    return path_of(url).lower().endswith(ASSET_EXTENSIONS)


def looks_destructive(url: str) -> bool:
    lowered = url.lower()
    return any(h in lowered for h in DESTRUCTIVE_HINTS)


def dedupe_key(url: str) -> str:
    """Two URLs differing only by query-parameter order or trailing slash crawl once."""
    p = urlsplit(url)
    query = "&".join(sorted(p.query.split("&"))) if p.query else ""
    path = p.path.rstrip("/") or "/"
    return urlunsplit((p.scheme, p.netloc, path, query, ""))
