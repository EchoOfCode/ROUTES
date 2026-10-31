"""Detect publicly served OpenAPI / Swagger documents (GET only)."""

from __future__ import annotations

import json

from discovery.crawler.urls import normalise

CANDIDATE_PATHS = (
    "/openapi.json",
    "/swagger.json",
    "/api/openapi.json",
    "/api/swagger.json",
    "/v3/api-docs",
    "/api-docs",
    "/swagger/v1/swagger.json",
    "/api/docs/openapi.json",
)
HTTP_METHODS = ("get", "post", "put", "patch", "delete", "head", "options")


def parse_spec(body: bytes, spec_url: str, origin: str) -> tuple[dict, list[dict]] | None:
    try:
        doc = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return None
    if not isinstance(doc, dict) or not ("openapi" in doc or "swagger" in doc) or not isinstance(doc.get("paths"), dict):
        return None
    info = doc.get("info") if isinstance(doc.get("info"), dict) else {}
    base_path = doc.get("basePath") if isinstance(doc.get("basePath"), str) else ""
    servers = doc.get("servers") if isinstance(doc.get("servers"), list) else []
    server_path = ""
    if servers and isinstance(servers[0], dict) and isinstance(servers[0].get("url"), str):
        su = servers[0]["url"]
        server_path = su if su.startswith("/") else ""
    prefix = (server_path or base_path or "").rstrip("/")
    endpoints = []
    for path, ops in list(doc["paths"].items())[:500]:
        if not isinstance(path, str) or not isinstance(ops, dict):
            continue
        shared = ops.get("parameters") if isinstance(ops.get("parameters"), list) else []
        for method in HTTP_METHODS:
            op = ops.get(method)
            if not isinstance(op, dict):
                continue
            params = [p.get("name") for p in (shared + (op.get("parameters") or [])) if isinstance(p, dict) and p.get("name")]
            if isinstance(op.get("requestBody"), dict):
                params.append("(request body)")
            url = normalise(prefix + path, origin)
            if url:
                endpoints.append({"method": method.upper(), "url": url, "parameters": [str(p)[:100] for p in params][:50],
                                  "summary": str(op.get("summary") or "")[:200]})
    meta = {"url": spec_url, "title": str(info.get("title") or "")[:300] or None,
            "version": str(info.get("version") or "")[:50] or None, "paths_count": len(doc["paths"])}
    return meta, endpoints
