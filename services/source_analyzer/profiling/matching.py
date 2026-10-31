"""Evidence for "does this repository belong to the submitted website?".

Only references to the submitted hostname are reported as matches; other
discovered URLs are listed as context without being treated as evidence.
The developer always makes the final decision.
"""

from __future__ import annotations

import json
import re

from source_analyzer.profiling.profile import Profile

URL_RE = re.compile(r"https?://([A-Za-z0-9.-]+\.[A-Za-z]{2,})(?::\d+)?[^\s\"'<>)]*")
CANDIDATE_FILES = ("README.md", "README", "readme.md", "README.txt", "package.json", "vercel.json", "netlify.toml",
                   "CNAME", "next.config.js", "next.config.mjs", "next.config.ts", "app.json", "fly.toml",
                   "render.yaml", ".env.example", "public/CNAME", "public/robots.txt", "public/sitemap.xml")


def _host_matches(host: str, target: str) -> bool:
    host, target = host.lower().rstrip("."), target.lower().rstrip(".")
    bare = target[4:] if target.startswith("www.") else target
    return host in (target, bare, f"www.{bare}")


def collect(profile: Profile, target_host: str) -> list[dict]:
    evidence: list[dict] = []
    files = {f.rel: f for f in profile.files}
    seen: set[tuple[str, str]] = set()

    def add(kind: str, detail: str, file: str | None, matches: bool) -> None:
        key = (kind, detail)
        if key not in seen and len(evidence) < 60:
            seen.add(key)
            evidence.append({"kind": kind, "detail": detail[:300], "file": file, "matches_target": matches})

    pkg = profile.package_json or {}
    if isinstance(pkg.get("name"), str):
        name = pkg["name"]
        matches = bool(target_host) and name.lower().replace("@", "").split("/")[-1] in target_host.lower()
        add("package_name", f'package.json name is "{name[:100]}"', "package.json", matches)
    homepage = pkg.get("homepage")
    if isinstance(homepage, str):
        m = URL_RE.search(homepage)
        add("homepage", f"package.json homepage is {homepage[:200]}", "package.json",
            bool(m and target_host and _host_matches(m.group(1), target_host)))
    repo = pkg.get("repository")
    if isinstance(repo, (str, dict)):
        url = repo if isinstance(repo, str) else repo.get("url", "")
        add("repository", f"package.json repository is {str(url)[:200]}", "package.json", False)

    for rel in CANDIDATE_FILES:
        f = files.get(rel)
        if f is None or f.size > 512 * 1024:
            continue
        content = f.read()
        if rel.endswith("CNAME"):
            host = content.strip().splitlines()[0] if content.strip() else ""
            if host:
                add("cname", f"{rel} points to {host[:200]}", rel, bool(target_host) and _host_matches(host, target_host))
            continue
        if rel == "vercel.json":
            try:
                data = json.loads(content)
                for alias in (data.get("alias") or [])[:10] if isinstance(data, dict) else []:
                    add("deployment", f"vercel.json alias {str(alias)[:200]}", rel,
                        bool(target_host) and _host_matches(str(alias), target_host))
            except ValueError:
                pass
        for m in URL_RE.finditer(content):
            host = m.group(1)
            if target_host and _host_matches(host, target_host):
                add("website_reference", f"{rel} references {m.group(0)[:200]}", rel, True)

    # Hostname references anywhere in application source (first few only).
    if target_host:
        needle = target_host.lower()
        for f in profile.js_files()[:3000]:
            if f.size > 256 * 1024:
                continue
            try:
                content = f.read()
            except OSError:
                continue
            if needle in content.lower():
                add("source_reference", f"{f.rel} mentions {target_host}", f.rel, True)
                if sum(1 for e in evidence if e["kind"] == "source_reference") >= 5:
                    break
    if profile.framework != "Unknown":
        add("framework", f"Repository uses {profile.framework}", None, False)
    return evidence
