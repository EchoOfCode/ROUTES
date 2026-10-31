"""Turn validated sandbox results into storage-neutral records.

Both stores (the web stack's PostgreSQL and the CLI's SQLite) persist exactly
these records, so redaction and shaping happen in one place.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from routes_shared.contracts import DiscoveryResult, SourceResult
from routes_shared.redaction import redact_structure, redact_text


@dataclass
class DiscoveryRecords:
    pages: list[dict]
    endpoints: list[dict]
    technologies: list[dict]
    summary: dict
    manifest_detected: bool
    manifest_data: dict | None


@dataclass
class SourceRecords:
    analysis: dict
    findings: list[dict]
    technologies: list[dict]
    endpoints: list[dict]
    summary: dict
    match_evidence: list = field(default_factory=list)


def network_summary(state: dict) -> dict:
    summary = state.get("network_summary") or {}
    return {k: summary.get(k) for k in ("requests", "allowed", "denied", "denied_reasons", "destinations")}


def discovery_records(result: DiscoveryResult, network: dict) -> DiscoveryRecords:
    pages, seen = [], set()
    for p in result.pages[:result.page_limit + 5]:
        if p.url in seen:
            continue
        seen.add(p.url)
        pages.append(p.model_dump())
    endpoints = []
    for e in result.endpoints:
        details: dict = {}
        if e.origin == "form":
            form = next((f for f in result.forms if f.action == e.url and f.page_url == e.page_url), None)
            if form is not None:
                details = {"fields": [f.model_dump() for f in form.fields]}
        endpoints.append({"method": e.method[:16], "url": e.url, "path": e.path, "origin": e.origin,
                          "parameters": list(e.parameters), "details": details,
                          "evidence": redact_text(e.evidence, max_length=500), "page_url": e.page_url})
    technologies = [{"name": t.name, "category": t.category, "version": t.version, "confidence": t.confidence,
                     "source": "website", "evidence": list(t.evidence)} for t in result.technologies]
    pages_ok = sum(1 for p in result.pages if not p.error)
    summary = {
        "stack": result.stack.model_dump(),
        "pages_total": len(result.pages),
        "pages_inspected": pages_ok,
        "pages_failed": len(result.pages) - pages_ok,
        "page_limit": result.page_limit,
        "page_limit_reached": result.page_limit_reached,
        "rendered_pages": sum(1 for p in result.pages if p.rendered),
        "login_pages": [p.url for p in result.pages if p.is_login][:10],
        "registration_pages": [p.url for p in result.pages if p.is_registration][:10],
        "robots": result.robots.model_dump(),
        "sitemap_urls": result.sitemap_urls,
        "scripts": result.scripts[:200],
        "scripts_count": len(result.scripts),
        "external_hosts": result.external_hosts[:200],
        "openapi": [o.model_dump() for o in result.openapi],
        "forms_count": len(result.forms),
        "network": network,
    }
    return DiscoveryRecords(pages, endpoints, technologies, summary, result.manifest.detected,
                            result.manifest.model_dump() if result.manifest.checked else None)


def source_records(result: SourceResult) -> SourceRecords:
    clean = redact_structure(result.model_dump(), max_length=2000)  # defence in depth
    profile = clean["profile"]
    analysis = {
        "source_kind": result.source_kind, "support_status": result.support_status,
        "support_reason": clean["support_reason"], "framework": profile["framework"], "runtime": profile["runtime"],
        "profile": profile, "routes": clean["routes"], "db_interactions": clean["db_interactions"],
        "input_sources": clean["input_sources"], "config_refs": clean["config_refs"],
        "env_var_names": clean["env_var_names"], "match_evidence": clean["match_evidence"],
        "warnings": clean["warnings"],
    }
    findings, seen = [], set()
    for f in finding_records(clean):
        if f["fingerprint"] in seen:
            continue
        seen.add(f["fingerprint"])
        findings.append(f)
    technologies = []
    if profile["framework"] != "Unknown":
        evidence = [f"package.json dependency {profile['framework']} {profile.get('framework_version') or ''}".strip()]
        technologies.append({"name": profile["framework"], "category": "framework",
                             "version": profile.get("framework_version"), "confidence": "high",
                             "source": "repository", "evidence": evidence})
    for lib in profile.get("database_libraries", [])[:20]:
        technologies.append({"name": lib, "category": "database_library", "version": None, "confidence": "high",
                             "source": "repository", "evidence": ["Declared in package.json"]})
    endpoints = []
    for r in clean["routes"][:500]:
        for method in r["methods"] or ["ANY"]:
            endpoints.append({"method": method[:16], "url": r["path"], "path": r["path"], "origin": "source_route",
                              "parameters": [], "details": {"file": r["file"], "line": r["line"], "router": r["router"]},
                              "evidence": f"Route handler in {r['file']}"[:500], "page_url": None})
    summary = {"source_framework": profile["framework"], "source_support": result.support_status}
    return SourceRecords(analysis, findings, technologies, endpoints, summary, clean["match_evidence"])


def finding_records(clean: dict) -> list[dict]:
    out = []
    for f in clean["findings"]:
        out.append({
            "type": f["type"], "status": f["status"], "severity": f["severity"], "confidence": f["confidence"],
            "title": f["title"], "file": f["file"], "line": f["line"], "end_line": f.get("end_line"),
            "endpoint": f["endpoint"], "method": (f["method"] or None) and f["method"][:16], "rule_id": f["rule_id"],
            "plain_description": f["plain_description"],
            "evidence_summary": redact_text(f["evidence_summary"], max_length=2000),
            "technical_details": f["technical_details"], "recommendation": f["recommendation"],
            "fingerprint": f.get("fingerprint") or _fingerprint(f),
            "snapshot": f.get("snapshot"),
        })
    return out


def _fingerprint(f: dict) -> str:
    """Safety net: both finding producers (SQLi, Semgrep) always set a
    fingerprint themselves, so this should not normally run."""
    from routes_shared.fingerprint import fingerprint

    snippet = (f.get("technical_details") or {}).get("snippet") or f.get("evidence_summary") or ""
    return fingerprint(f["rule_id"], f["file"], snippet)


def fingerprint(f: dict) -> str:
    return _fingerprint(f)
