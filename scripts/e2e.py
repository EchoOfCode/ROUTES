#!/usr/bin/env python3
"""End-to-end acceptance check for a running ROUTES stack (stdlib only).

Prerequisites:
    GATEWAY_DEV_ALLOW_HOSTS=sample-site docker compose --profile testing up -d --build

Usage:
    python scripts/e2e.py [--api http://127.0.0.1:8000] [--skip-retention]

Exercises the Phase 1 acceptance workflow against the bundled sample site and
the vulnerable fixture repository, then checks restricted Docker operations
and that no sandbox containers or networks are left behind.
"""

from __future__ import annotations

import argparse
import http.cookiejar
import io
import json
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "services" / "source_analyzer" / "tests" / "fixtures" / "nextjs-pg"
ACTIVE = {"queued", "running", "discovering", "analysing"}


class Client:
    def __init__(self, base: str):
        self.base = base.rstrip("/")
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar))
        self.csrf = self.call("GET", "/auth/csrf")["csrf_token"]

    def call(self, method: str, path: str, body=None, *, raw: bytes | None = None, content_type: str | None = None,
             expect=(200, 201, 204)):
        data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
        req = urllib.request.Request(f"{self.base}/api/v1{path}", data=data, method=method)
        if body is not None:
            req.add_header("Content-Type", "application/json")
        if content_type:
            req.add_header("Content-Type", content_type)
        if method not in ("GET", "HEAD"):
            req.add_header("X-CSRF-Token", self.csrf)
        try:
            with self.opener.open(req, timeout=60) as r:
                status, text = r.status, r.read()
        except urllib.error.HTTPError as e:
            status, text = e.code, e.read()
        if status not in expect:
            raise AssertionError(f"{method} {path} -> {status}: {text[:400]!r}")
        return json.loads(text) if text else None


def step(msg: str) -> None:
    print(f"\n== {msg}", flush=True)


def check(cond: bool, msg: str) -> None:
    print(("  PASS  " if cond else "  FAIL  ") + msg, flush=True)
    if not cond:
        raise SystemExit(1)


def wait(c: Client, aid: str, timeout: int = 900) -> dict:
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        a = c.call("GET", f"/assessments/{aid}")
        stages = [(j["kind"], j["status"], j["stage"]) for j in a["jobs"]]
        if stages != last:
            print(f"  .. {a['status']:<20} {stages}", flush=True)
            last = stages
        if a["status"] not in ACTIVE:
            return a
        time.sleep(3)
    raise SystemExit(f"assessment {aid} did not finish in {timeout}s")


def fixture_zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for f in FIXTURE.rglob("*"):
            if f.is_file():
                zf.write(f, f"acme-shop/{f.relative_to(FIXTURE).as_posix()}")
    return buf.getvalue()


def multipart(filename: str, payload: bytes) -> tuple[bytes, str]:
    boundary = uuid.uuid4().hex
    body = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{filename}\"\r\n"
            f"Content-Type: application/zip\r\n\r\n").encode() + payload + f"\r\n--{boundary}--\r\n".encode()
    return body, f"multipart/form-data; boundary={boundary}"


def docker(*args: str) -> str:
    return subprocess.run(["docker", *args], capture_output=True, text=True, check=False).stdout


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--api", default="http://127.0.0.1:8000")
    ap.add_argument("--skip-retention", action="store_true")
    args = ap.parse_args()

    step("Register and log in")
    c = Client(args.api)
    email = f"e2e-{uuid.uuid4().hex[:8]}@example.com"
    c.call("POST", "/auth/register", {"email": email, "password": "e2e correct horse battery"})
    c2 = Client(args.api)
    c2.call("POST", "/auth/login", {"email": email, "password": "e2e correct horse battery"})
    check(c2.call("GET", "/auth/me")["email"] == email, "login works with a fresh session")
    intruder = Client(args.api)
    intruder.call("POST", "/auth/register", {"email": f"x-{uuid.uuid4().hex[:8]}@example.com", "password": "another long password"})

    step("Create project (URL-first, authorisation required)")
    c.call("POST", "/projects", {"website_url": "http://sample-site:8080/", "authorised": False}, expect=(422,))
    check(True, "project creation refused without authorisation")
    c.call("POST", "/projects", {"website_url": "http://169.254.169.254/", "authorised": True}, expect=(422,))
    check(True, "cloud metadata address refused")
    created = c.call("POST", "/projects", {"website_url": "http://sample-site:8080/", "authorised": True, "name": "Sample shop"})
    pid, aid = created["project"]["id"], created["assessment_id"]
    intruder.call("GET", f"/projects/{pid}", expect=(404,)); check(True, "other users cannot see the project")

    step("Connect source (ZIP) while discovery runs")
    body, ctype = multipart("acme-shop.zip", fixture_zip())
    up = c.call("POST", f"/projects/{pid}/integrations/zip", raw=body, content_type=ctype)
    check(up["assessment_id"] == aid, "source analysis attached to the running assessment")

    step("Wait for background workers")
    a = wait(c, aid)
    check(a["status"] == "completed", f"assessment completed (status={a['status']}, error={a['error']})")
    check(a["manifest_detected"] is True, "ROUTES integration manifest detected")
    pages = c.call("GET", f"/assessments/{aid}/pages")
    check(0 < len(pages) <= 25, f"{len(pages)} pages recorded (limit 25)")
    check(a["discovery_summary"].get("page_limit_reached") is True, "25-page limit reached on the sample site")
    check(all("sample-site" in p["url"] for p in pages), "only the submitted hostname was crawled")
    endpoints = c.call("GET", f"/assessments/{aid}/endpoints")
    origins = {e["origin"] for e in endpoints}
    check({"form", "js_reference", "openapi", "source_route"} <= origins, f"endpoint origins found: {sorted(origins)}")
    techs = {t["name"] for t in c.call("GET", f"/assessments/{aid}/technologies")}
    check("Next.js" in techs, "Next.js identified with evidence")
    check(a["discovery_summary"]["stack"]["database"] == "Unknown", "database not fabricated from the framework")

    step("Source analysis results")
    source = c.call("GET", f"/assessments/{aid}/source")
    check(source["support_status"] == "supported", "fixture recognised as supported (Next.js + pg)")
    findings = c.call("GET", f"/assessments/{aid}/findings")
    sqli = [f for f in findings if f["type"] == "SQL Injection" and f["status"] == "potential"]
    check(any(f["file"] == "app/api/search/route.ts" and f["line"] == 6 for f in sqli), "SQLi found at app/api/search/route.ts:6")
    check(not any(f["file"] == "app/api/safe/route.ts" for f in findings), "parameterised queries not flagged")
    check(all(f["status"] != "confirmed" for f in findings), "no finding claims dynamic confirmation")
    check("AKIAQWERTYUIOPASDFGH" not in json.dumps(findings) + json.dumps(source), "secret values redacted")
    intruder.call("GET", f"/assessments/{aid}/findings", expect=(404,)); check(True, "findings protected from other users")

    step("Repository matching requires developer confirmation")
    project = c.call("GET", f"/projects/{pid}")
    check(project["integration"]["match_status"] == "pending", "match awaiting confirmation")
    c.call("POST", f"/projects/{pid}/integrations/match", {"matches": True})

    step("Temporary data cleanup")
    time.sleep(3)
    check(docker("ps", "-a", "--filter", "label=routes.sandbox=true", "-q").strip() == "", "no sandbox containers remain")
    check("routes-sbx-" not in docker("network", "ls", "--format", "{{.Name}}"), "no sandbox networks remain")
    uploads = subprocess.run(["docker", "compose", "exec", "-T", "api", "ls", "-A", "/data/uploads"],
                             capture_output=True, text=True, cwd=ROOT).stdout.strip()
    check(uploads == "", "uploaded archive deleted after analysis")

    step("Restricted Docker API")
    probe = (
        "import json,urllib.request as u\n"
        "def call(m,p,b=None):\n"
        "  r=u.Request('http://docker-proxy:2375/v1.47'+p,data=json.dumps(b).encode() if b else None,method=m,headers={'Content-Type':'application/json'})\n"
        "  try: return u.urlopen(r,timeout=10).status\n"
        "  except u.HTTPError as e: return e.code\n"
        "print(call('POST','/containers/create?name=routes-sbx-e2e',{'Image':'routes/discovery:local','User':'0','HostConfig':{'Privileged':True,'Binds':['/:/host']}}))\n"
        "print(call('GET','/info'))\n"
        "print(call('POST','/containers/routes-p1-gateway/exec',{'Cmd':['sh']}))\n"
    )
    out = subprocess.run(["docker", "compose", "exec", "-T", "sandbox-manager", "python", "-c", probe],
                         capture_output=True, text=True, cwd=ROOT).stdout.split()
    check(out == ["403", "403", "403"], f"privileged create, /info and exec all refused by docker-proxy ({out})")

    if not args.skip_retention:
        step("Assessment history keeps the five most recent")
        for i in range(5):
            started = c.call("POST", f"/projects/{pid}/assessments", {"include_source": False})
            wait(c, started["assessment_id"])
        history = c.call("GET", f"/projects/{pid}/assessments")
        check(len(history) == 5, f"{len(history)} assessments retained")
        check(aid not in {h["id"] for h in history}, "oldest assessment removed")
        check(c.call("GET", f"/projects/{pid}")["integration"] is not None, "project configuration retained")

    print("\nAll end-to-end checks passed.")


if __name__ == "__main__":
    try:
        main()
    except AssertionError as exc:
        print(f"  FAIL  {exc}")
        sys.exit(1)
