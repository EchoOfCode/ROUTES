#!/usr/bin/env python3
"""End-to-end check of the ROUTES CLI against the real local engine.

Prerequisites (from the repository root, with the CLI installed in a venv):
    GATEWAY_DEV_ALLOW_HOSTS=sample-site routes engine up --with-sample-site

Usage:
    GATEWAY_DEV_ALLOW_HOSTS=sample-site python scripts/cli_e2e.py [--skip-github] [--skip-retention]

Uses a temporary ROUTES_HOME, so your own ~/.routes is not touched. It runs
the real `routes` commands (website discovery, ZIP / folder / GitHub source
analysis, findings, reports, history, retention) and then verifies sandbox
cleanup and the restricted Docker API.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import time
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "services" / "source_analyzer" / "tests" / "fixtures" / "nextjs-pg"
SITE = "http://sample-site:8080"
PUBLIC_REPO = "https://github.com/octocat/Hello-World"

failures = 0


def step(msg: str) -> None:
    print(f"\n== {msg}", flush=True)


def check(cond: bool, msg: str) -> None:
    global failures
    print(("  PASS  " if cond else "  FAIL  ") + msg, flush=True)
    if not cond:
        failures += 1


def routes(*args: str, env: dict, timeout: int = 1200) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, "-m", "routes_cli", *args], capture_output=True, text=True,
                          encoding="utf-8", errors="replace", env=env, timeout=timeout, cwd=ROOT, stdin=subprocess.DEVNULL)


def docker(*args: str) -> str:
    return subprocess.run(["docker", *args], capture_output=True, text=True, cwd=ROOT).stdout


def tree_hash(root: Path) -> str:
    h = hashlib.sha256()
    for p in sorted(root.rglob("*")):
        if p.is_file():
            h.update(p.relative_to(root).as_posix().encode())
            h.update(p.read_bytes())
    return h.hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--skip-github", action="store_true", help="Skip the public GitHub import (needs internet)")
    ap.add_argument("--skip-retention", action="store_true")
    opts = ap.parse_args()

    home = Path(tempfile.mkdtemp(prefix="routes-e2e-"))
    env = {**os.environ, "ROUTES_HOME": str(home), "PYTHONIOENCODING": "utf-8"}
    db_path = home / "routes.db"

    def q(sql: str, *params):
        with sqlite3.connect(db_path) as conn:
            return conn.execute(sql, params).fetchall()

    step("Initialise and check the environment")
    r = routes("init", env=env)
    check(r.returncode == 0 and db_path.exists(), "routes init created the local database")
    r = routes("doctor", "--json", env=env, timeout=300)
    checks = {c["name"]: c["status"] for c in json.loads(r.stdout)}
    for name in ("Docker daemon", "Sandbox Manager", "Docker API proxy", "Network gateway", "SQLite database",
                 "Semgrep", "Tree-sitter", "Playwright", "Chromium"):
        check(checks.get(name) == "PASS", f"doctor: {name} {checks.get(name)}")

    step("Website discovery (sample site)")
    r = routes("scan", SITE, "--authorised", "--no-animation", env=env)
    check(r.returncode == 0, f"scan completed (exit {r.returncode})")
    (aid, status, summary, manifest) = q("select id, status, summary, manifest_detected from assessments "
                                         "order by created_at desc limit 1")[0]
    summary = json.loads(summary)
    check(status == "completed", "assessment status completed")
    check(bool(manifest), "ROUTES manifest detected")
    check(summary.get("page_limit_reached") is True and summary.get("pages_total", 0) <= 25, "25-page limit enforced")
    hosts = {u.split("/")[2] for (u,) in q("select url from pages where assessment_id=?", aid)}
    check(hosts == {"sample-site:8080"}, f"only the exact host was crawled ({hosts})")
    origins = {o for (o,) in q("select distinct origin from endpoints where assessment_id=?", aid)}
    check({"form", "js_reference", "link_query", "openapi"} <= origins, f"endpoint origins {sorted(origins)}")
    techs = {n for (n,) in q("select name from technologies where assessment_id=?", aid)}
    check("Next.js" in techs, "Next.js detected from the website")
    check(summary.get("stack", {}).get("database") in (None, "Unknown"), "database not guessed")

    step("Unsafe targets are refused")
    before_count = q("select count(*) from assessments")[0][0]
    r = routes("scan", "http://169.254.169.254/latest/meta-data", "--authorised", env=env)
    check(r.returncode == 1 and q("select count(*) from assessments")[0][0] == before_count,
          f"cloud metadata address refused by the CLI ({(r.stdout + r.stderr).strip()[-90:]})")
    sys.path.insert(0, str(ROOT / "apps" / "cli"))
    from routes_cli.context import Context  # noqa: E402
    from routes_core.engine import EngineRejected  # noqa: E402

    os.environ["ROUTES_HOME"] = str(home)
    try:
        with Context.load().engine_client() as c:
            c.start({"kind": "discovery", "target_url": "http://169.254.169.254/"})
        refused = False
    except EngineRejected:
        refused = True
    check(refused, "the engine itself also refuses the metadata address")

    step("Source analysis: ZIP archive")
    zpath = home / "fixture.zip"
    with zipfile.ZipFile(zpath, "w") as zf:
        for p in FIXTURE.rglob("*"):
            if p.is_file():
                zf.write(p, p.relative_to(FIXTURE).as_posix())
    r = routes("analyze", str(zpath), "--no-animation", env=env)
    check(r.returncode == 0, f"ZIP analysis completed (exit {r.returncode})")
    aid = q("select id from assessments order by created_at desc limit 1")[0][0]
    rows = q("select type, status, file, line, evidence_summary from findings where assessment_id=?", aid)
    check(("SQL Injection", "potential", "app/api/search/route.ts", 6) in [r_[:4] for r_ in rows],
          "SQL injection at app/api/search/route.ts:6")
    safe_routes = {"app/api/safe/route.ts", "app/api/sort/route.ts", "app/api/limit/route.ts",
                   "app/api/constant/route.ts"}
    flagged = {f for t, _, f, _, _ in rows if t == "SQL Injection"}
    check(not (safe_routes & flagged), f"parameterised / allow-listed / constant routes not flagged ({sorted(safe_routes & flagged)})")
    check(all(s != "confirmed" for _, s, _, _, _ in rows), "no finding claims confirmation")
    check("AKIAQWERTYUIOPASDFGH" not in db_path.read_bytes().decode("latin-1"), "secret value not stored")
    check(q("select support_status from source_results where assessment_id=?", aid)[0][0] == "supported",
          "Next.js + pg reported as supported")

    step("Source analysis: local folder (read only)")
    before = tree_hash(FIXTURE)
    r = routes("analyze", str(FIXTURE), "--no-animation", env=env)
    check(r.returncode == 0, f"folder analysis completed (exit {r.returncode})")
    check(tree_hash(FIXTURE) == before, "the project folder was not modified")
    check(not any((home / "cache").iterdir()), "temporary packed archive deleted")

    if not opts.skip_github:
        step("Source analysis: public GitHub repository")
        r = routes("analyze", PUBLIC_REPO, "--no-animation", env=env)
        check(r.returncode == 0, f"GitHub import and analysis completed (exit {r.returncode})")

    step("Findings, reports, history")
    r = routes("findings", "--json", "--assessment", aid, env=env)
    check(r.returncode == 0 and len(json.loads(r.stdout)) > 0, "findings --json")
    for fmt, name in (("markdown", "report.md"), ("html", "report.html"), ("json", "findings.json")):
        r = routes("report", "--format", fmt, "--assessment", aid, env=env)
        check(r.returncode == 0 and any(home.joinpath("reports").rglob(name)), f"{fmt} report written")

    if not opts.skip_retention:
        step("History keeps the five most recent assessments per project")
        for _ in range(6):
            routes("scan", SITE, "--authorised", "--no-animation", env=env)
        counts = q("select project_id, count(*) from assessments group by project_id")
        check(all(n <= 5 for _, n in counts), f"at most 5 per project ({[n for _, n in counts]})")

    step("Sandbox cleanup and isolation")
    time.sleep(2)
    check(docker("ps", "-a", "--filter", "label=routes.sandbox=true", "-q").strip() == "", "no sandbox containers remain")
    check("routes-sbx-" not in docker("network", "ls", "--format", "{{.Name}}"), "no sandbox networks remain")
    uploads = subprocess.run(["docker", "compose", "exec", "-T", "sandbox-manager", "ls", "-A", "/data/uploads"],
                             capture_output=True, text=True, cwd=ROOT).stdout.strip()
    check(uploads == "", "staged uploads deleted")
    probe = (
        "import json,urllib.request as u\n"
        "def call(m,p,b=None):\n"
        "  r=u.Request('http://docker-proxy:2375/v1.47'+p,data=json.dumps(b).encode() if b else None,method=m,"
        "headers={'Content-Type':'application/json'})\n"
        "  try: return u.urlopen(r,timeout=10).status\n"
        "  except u.HTTPError as e: return e.code\n"
        "print(call('POST','/containers/create?name=routes-sbx-e2e',{'Image':'routes/discovery:local','User':'0',"
        "'HostConfig':{'Privileged':True,'Binds':['/:/host']}}))\n"
        "print(call('GET','/info'))\n"
        "print(call('POST','/containers/routes-p1-gateway/exec',{'Cmd':['sh']}))\n"
    )
    out = subprocess.run(["docker", "compose", "exec", "-T", "sandbox-manager", "python", "-c", probe],
                         capture_output=True, text=True, cwd=ROOT).stdout.split()
    check(out == ["403", "403", "403"], f"docker-proxy refuses privileged create, /info and exec ({out})")
    published = docker("port", "routes-sandbox-manager-1")
    check(published.strip() and all(line.split("->")[-1].strip().startswith("127.0.0.1:")
                                     for line in published.strip().splitlines()),
          f"engine API published on 127.0.0.1 only ({published.strip()})")

    print(f"\n{'All checks passed.' if not failures else f'{failures} check(s) FAILED.'}  (home: {home})")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
