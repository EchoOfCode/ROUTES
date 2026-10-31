"""robots.txt, sitemap.xml and the ROUTES integration manifest."""

from __future__ import annotations

import json
from urllib.robotparser import RobotFileParser

from defusedxml import ElementTree as SafeET

from discovery.crawler.urls import in_scope, normalise

MANIFEST_PATH = "/.well-known/routes.json"
MANIFEST_MAX_BYTES = 16 * 1024
KNOWN_ASSESSMENTS = {"sqli"}


class Robots:
    def __init__(self, text: str | None, agent: str = "ROUTES-Discovery"):
        self.found = text is not None
        self.agent = agent
        self.parser = RobotFileParser()
        self.parser.parse((text or "").splitlines())
        lines = [ln.split("#", 1)[0].strip() for ln in (text or "").splitlines()]
        self.disallow_rules = sum(1 for ln in lines if ln.lower().startswith("disallow:") and ln[9:].strip())
        self.sitemaps = [ln.split(":", 1)[1].strip() for ln in lines if ln.lower().startswith("sitemap:")][:20]

    def allowed(self, url: str) -> bool:
        if not self.found:
            return True
        return self.parser.can_fetch(self.agent, url)


def parse_sitemap(xml: bytes, hostname: str, base: str) -> tuple[list[str], list[str]]:
    """Return (page urls, nested sitemap urls), both restricted to the hostname."""
    try:
        root = SafeET.fromstring(xml)
    except Exception:  # noqa: BLE001 - malformed or hostile XML is simply ignored
        return [], []
    pages, nested = [], []
    for el in root.iter():
        tag = el.tag.rsplit("}", 1)[-1]
        if tag != "loc" or not el.text:
            continue
        url = normalise(el.text.strip(), base)
        if not url or not in_scope(url, hostname):
            continue
        if root.tag.rsplit("}", 1)[-1] == "sitemapindex":
            nested.append(url)
        else:
            pages.append(url)
        if len(pages) + len(nested) >= 1000:
            break
    return pages, nested


def validate_manifest(status: int | None, body: bytes, content_type: str) -> dict:
    """Treat the manifest as untrusted metadata: strict schema, only known keys kept."""
    info = {"checked": True, "detected": False, "valid": False, "status_code": status, "data": None, "error": None}
    if status is None:
        info["error"] = "Could not be retrieved."
        return info
    if status == 404 or status == 410:
        return info
    if status != 200:
        info["error"] = f"Unexpected HTTP status {status}."
        return info
    if len(body) > MANIFEST_MAX_BYTES:
        info["error"] = "Manifest exceeds 16 KB."
        return info
    try:
        data = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        info["error"] = "Manifest is not valid JSON."
        return info
    if not isinstance(data, dict):
        info["error"] = "Manifest must be a JSON object."
        return info
    info["detected"] = True
    problems = []
    if data.get("routes_enabled") is not True:
        problems.append("routes_enabled must be true")
    if data.get("integration") != "routes":
        problems.append('integration must be "routes"')
    assessments = data.get("supported_assessments")
    if not isinstance(assessments, list) or not all(isinstance(a, str) for a in assessments):
        problems.append("supported_assessments must be a list of strings")
        assessments = []
    version = data.get("version")
    if not isinstance(version, str) or len(version) > 20:
        problems.append("version must be a short string")
        version = None
    info["data"] = {
        "routes_enabled": data.get("routes_enabled") is True,
        "integration": data.get("integration") if data.get("integration") == "routes" else None,
        "supported_assessments": [a[:20] for a in assessments if a[:20] in KNOWN_ASSESSMENTS][:10],
        "unrecognised_assessments": [a[:20] for a in assessments if a[:20] not in KNOWN_ASSESSMENTS][:10],
        "version": version,
    }
    info["valid"] = not problems
    if problems:
        info["error"] = "; ".join(problems)
    if "json" not in content_type and content_type:
        info["error"] = ((info["error"] + "; ") if info["error"] else "") + f"served as {content_type[:60]}"
    return info
