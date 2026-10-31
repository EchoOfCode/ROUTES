"""Test runner sandbox entrypoint (trusted, fixed code).

Executes a declarative ROUTES test plan (/input/testplan.json) against the
application under test, and nothing else: every request goes to the single
base URL given by the Sandbox Manager, and the container sits on a private
network shared only with that application. Results are evidence; this code
does not judge whether a patch is secure.
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

import httpx
from pydantic import ValidationError

from routes_shared.buildrun import TestCase, TestPlan
from routes_shared.events import emit
from routes_shared.redaction import redact_structure, redact_text

RESULT_PREFIX = "ROUTES_RESULT "
PLAN = Path(os.environ.get("ROUTES_INPUT_DIR", "/input")) / "testplan.json"
MAX_BODY_READ = 1024 * 1024
EXCERPT = 300


def evaluate(case: TestCase, status: int | None, body: str, elapsed_ms: int, error: str | None) -> tuple[str, list[str]]:
    if error is not None:
        return "error", [error]
    exp = case.expect
    reasons = []
    if exp.status is not None and status not in exp.status:
        reasons.append(f"status {status} not in {exp.status}")
    if status in exp.status_not:
        reasons.append(f"status {status} is not allowed")
    for text in exp.body_contains:
        if text not in body:
            reasons.append(f"response does not contain {text!r}")
    for text in exp.body_not_contains:
        if text in body:
            reasons.append(f"response contains {text!r}")
    if exp.json_equals:
        try:
            data = json.loads(body)
        except ValueError:
            data = None
        if not isinstance(data, dict):
            reasons.append("response is not a JSON object")
        else:
            for key, value in exp.json_equals.items():
                if data.get(key) != value:
                    reasons.append(f"JSON {key!r} is {data.get(key)!r}, expected {value!r}")
    if exp.max_ms is not None and elapsed_ms > exp.max_ms:
        reasons.append(f"took {elapsed_ms} ms (limit {exp.max_ms} ms)")
    return ("passed" if not reasons else "failed"), reasons


def execute(client: httpx.Client, base: str, case: TestCase) -> dict:
    req = case.request
    started = time.monotonic()
    status, body, error = None, "", None
    try:
        with client.stream(req.method, base + req.path, params=req.query or None, headers=req.headers or None,
                           json=req.json_body if req.json_body is not None else None,
                           content=req.body.encode() if req.body is not None else None,
                           timeout=req.timeout_seconds) as r:
            status = r.status_code
            chunks, size = [], 0
            for chunk in r.iter_bytes():
                chunks.append(chunk)
                size += len(chunk)
                if size > MAX_BODY_READ:
                    break
            body = b"".join(chunks)[:MAX_BODY_READ].decode("utf-8", "replace")
    except httpx.TimeoutException:
        error = f"no response within {req.timeout_seconds}s"
    except httpx.HTTPError as exc:
        error = f"request failed ({type(exc).__name__})"
    elapsed = int((time.monotonic() - started) * 1000)
    outcome, reasons = evaluate(case, status, body, elapsed, error)
    return {"id": case.id, "name": case.name, "category": case.category, "method": req.method, "path": req.path,
            "status": outcome, "http_status": status, "duration_ms": elapsed, "reasons": reasons[:10],
            "response_excerpt": redact_text(body[:EXCERPT], max_length=EXCERPT) if outcome != "passed" else ""}


def peers_unreachable() -> list[dict]:
    """Evidence that this runner can reach only the application under test."""
    import socket

    out = []
    for item in filter(None, os.environ.get("ROUTES_FORBIDDEN_PEERS", "").split(",")):
        host, _, port = item.rpartition(":")
        try:
            s = socket.create_connection((host, int(port)), timeout=1.5)
            s.close()
            observed = "connected"
        except socket.gaierror:
            observed = "dns_failed"
        except OSError as exc:
            observed = type(exc).__name__
        out.append({"host": host, "port": int(port), "observed": observed, "ok": observed != "connected"})
    return out


def main() -> int:
    base = os.environ.get("ROUTES_APP_URL", "").rstrip("/")
    result: dict
    try:
        plan = TestPlan.model_validate_json(PLAN.read_text("utf-8"))
    except (OSError, ValidationError, ValueError) as exc:
        result = {"fatal": True, "error": f"The test plan is missing or invalid ({type(exc).__name__})."}
        sys.stdout.write(RESULT_PREFIX + json.dumps(result) + "\n")
        return 0
    total = len(plan.tests)
    emit("testing", f"Running {total} test(s)", tests_total=total, tests_done=0, tests_failed=0)
    cases = []
    with httpx.Client(trust_env=False, follow_redirects=False) as client:
        reachable = False
        for _ in range(30):
            try:
                client.get(base + plan.health.path, timeout=3)
                reachable = True
                break
            except httpx.HTTPError:
                time.sleep(1)
        if not reachable:
            result = {"fatal": True, "error": "The test runner could not reach the application under test."}
            sys.stdout.write(RESULT_PREFIX + json.dumps(result) + "\n")
            return 0
        failed = 0
        for i, case in enumerate(plan.tests, start=1):
            outcome = execute(client, base, case)
            failed += outcome["status"] != "passed"
            cases.append(outcome)
            emit("testing", f"{i}/{total}: {case.id} {outcome['status']}", tests_total=total, tests_done=i,
                 tests_failed=failed)
    by_category: dict[str, dict] = {}
    for c in cases:
        bucket = by_category.setdefault(c["category"], {"total": 0, "passed": 0, "failed": 0})
        bucket["total"] += 1
        bucket["passed" if c["status"] == "passed" else "failed"] += 1
    passed = sum(c["status"] == "passed" for c in cases)
    result = {"tests": {"total": total, "passed": passed, "failed": total - passed,
                        "errors": sum(c["status"] == "error" for c in cases)},
              "by_category": by_category, "cases": cases, "isolation": peers_unreachable()}
    sys.stdout.write(RESULT_PREFIX + json.dumps(redact_structure(result, max_length=2000), separators=(",", ":")) + "\n")
    sys.stdout.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
