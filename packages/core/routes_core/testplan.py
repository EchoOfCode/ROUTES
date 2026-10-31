"""Generate a build-and-run test plan from a stored source analysis.

Input is what ``routes analyze`` already recorded: the route handlers found in
the code and the SQL injection flows (which request input reaches which
query). Output is an ordinary ``routes_shared.buildrun.TestPlan`` that the
developer can review and edit before running it.

What the generated tests check (all against the sandboxed copy only):

* health: the server answers at ``/`` (any non-5xx status);
* smoke: every GET route without dynamic segments answers without a 5xx;
* security, per traced SQL injection flow, using only that flow's input:
  - a lone quote must not cause a server error or leak a PostgreSQL error message
    (error-based signal);
  - a stacked ``pg_sleep(3)`` must not delay the response (time-based signal,
    which also catches injection whose errors are hidden).

Payloads are non-destructive: no writes, drops or data changes. They pass on a
correctly parameterised implementation, so the same plan verifies a fix. A
passing plan is evidence about these specific inputs, not proof that an
application is free of SQL injection.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import quote

from routes_shared.buildrun import TestPlan

SLEEP_SECONDS = 3
SLEEP_LIMIT_MS = 2500
SERVER_ERRORS = [500, 502, 503, 504]
# PostgreSQL error text that should never reach a client.
DB_ERROR_MARKERS = ["syntax error at or near", "unterminated quoted string", "invalid input syntax for",
                    "current transaction is aborted", "error: column", "error: relation"]
STRING_SLEEP = f"'; SELECT pg_sleep({SLEEP_SECONDS}); --"
NUMBER_SLEEP = f"1; SELECT pg_sleep({SLEEP_SECONDS}); --"
DYNAMIC_SEGMENT = re.compile(r"\[\[?\.{0,3}([A-Za-z0-9_]+)\]?\]|:([A-Za-z0-9_]+)|\{([A-Za-z0-9_]+)\}")
HEADER_NAME = re.compile(r"^[A-Za-z0-9-]{1,64}$")
FIELD_NAME = re.compile(r"^[A-Za-z_$][A-Za-z0-9_$.-]{0,99}$")
MAX_SMOKE = 40
MAX_SECURITY = 60


@dataclass
class GeneratedPlan:
    plan: dict
    notes: list[str] = field(default_factory=list)
    flows_covered: int = 0
    flows_skipped: int = 0


def _id(prefix: str, n: int, suffix: str) -> str:
    return f"{prefix}-{n:02d}-{suffix}"[:64]


def _fill_path(path: str, value: str = "1", target: str | None = None) -> str:
    """Replace dynamic segments with a harmless value, or the payload for ``target``."""
    def repl(m: re.Match) -> str:
        name = next(g for g in m.groups() if g)
        return quote(value if (target is None or name == target) else "1", safe="")
    return DYNAMIC_SEGMENT.sub(repl, path)


def _is_dynamic(path: str) -> bool:
    return bool(DYNAMIC_SEGMENT.search(path))


def _numeric_hint(name: str) -> bool:
    lowered = name.lower()
    return lowered == "id" or lowered.endswith(("id", "_id", "number", "count", "page", "limit", "offset"))


def _request(method: str, path: str, kind: str, name: str, payload: str) -> dict | None:
    """Place ``payload`` in the input the data-flow analysis traced. None if it cannot be placed."""
    kind = (kind or "").lower()
    if "query" in kind:
        return {"method": method, "path": _fill_path(path), "query": {name: payload}}
    if "route" in kind:
        if not _is_dynamic(path):
            return None
        filled = _fill_path(path, payload, target=name)
        return {"method": method, "path": filled} if filled != _fill_path(path) else None
    if "body" in kind:
        body_method = method if method not in ("GET", "HEAD") else "POST"
        return {"method": body_method, "path": _fill_path(path), "json": {name: payload},
                "headers": {"Content-Type": "application/json"}}
    if "header" in kind and HEADER_NAME.match(name):
        return {"method": method, "path": _fill_path(path), "headers": {name: payload}}
    return None


def generate(routes: list[dict], findings: list[dict], *, health_path: str = "/") -> GeneratedPlan:
    notes: list[str] = []
    tests: list[dict] = []
    covered = skipped = 0

    # ------------------------------------------------------------- security
    flows = [f for f in findings if f.get("type") == "SQL Injection"]
    for n, f in enumerate(flows, start=1):
        if len(tests) >= MAX_SECURITY:
            notes.append(f"Only the first {MAX_SECURITY} security tests were generated.")
            break
        where = f"{f.get('file')}:{f.get('line')}"
        if f.get("status") != "potential":
            notes.append(f"Skipped {where}: the finding is inconclusive (no traced request input to test).")
            skipped += 1
            continue
        details = f.get("technical_details") or {}
        source = details.get("source") or {}
        kind, name = source.get("kind") or "", (source.get("name") or "").strip()
        endpoint, method = f.get("endpoint"), (f.get("method") or "GET").upper()
        if method == "ANY":
            method = "GET"
        if not endpoint or not endpoint.startswith("/"):
            notes.append(f"Skipped {where}: no HTTP route is known for this flow.")
            skipped += 1
            continue
        if not name or not FIELD_NAME.match(name) or name in ("request", "req", "body", "query", "params"):
            notes.append(f"Skipped {where} ({method} {endpoint}): the exact input name could not be determined "
                         f"from the code ({kind or 'unknown source'}). Add a test by hand.")
            skipped += 1
            continue
        label = f"{method} {endpoint} {kind} \"{name}\""
        quote_req = _request(method, endpoint, kind, name, "'")
        if quote_req is None:
            notes.append(f"Skipped {where}: input kind '{kind}' cannot be placed in a request automatically.")
            skipped += 1
            continue
        covered += 1
        tests.append({"id": _id("sqli", n, "quote"), "category": "security",
                      "name": f"SQL injection ({where}): a quote in {label} causes no server or database error",
                      "request": quote_req,
                      "expect": {"status_not": SERVER_ERRORS, "body_not_contains": DB_ERROR_MARKERS}})
        sleeps = [("sleep", STRING_SLEEP)]
        if _numeric_hint(name) or "route" in kind.lower():
            sleeps.append(("sleep-num", NUMBER_SLEEP))
        for suffix, payload in sleeps:
            req = _request(method, endpoint, kind, name, payload)
            if req is None:
                continue
            req["timeout_seconds"] = 20
            tests.append({"id": _id("sqli", n, suffix), "category": "security",
                          "name": f"SQL injection ({where}): stacked pg_sleep({SLEEP_SECONDS}) in {label} "
                                  f"does not delay the response",
                          "request": req, "expect": {"max_ms": SLEEP_LIMIT_MS, "status_not": [502, 503, 504]}})

    # ---------------------------------------------------------------- smoke
    seen: set[str] = set()
    smoke = 0
    for r in routes:
        path = r.get("path") or ""
        methods = [m.upper() for m in (r.get("methods") or ["GET"])]
        if not path.startswith("/") or _is_dynamic(path) or path in seen or not ({"GET", "ANY"} & set(methods)):
            continue
        if smoke >= MAX_SMOKE:
            notes.append(f"Only the first {MAX_SMOKE} routes got smoke tests.")
            break
        seen.add(path)
        smoke += 1
        tests.append({"id": _id("smoke", smoke, re.sub(r"[^A-Za-z0-9]+", "-", path).strip("-")[:40] or "root"),
                      "category": "functional", "name": f"GET {path} answers without a server error",
                      "request": {"method": "GET", "path": path}, "expect": {"status_not": SERVER_ERRORS}})
    dynamic = sum(1 for r in routes if _is_dynamic(r.get("path") or ""))
    if dynamic:
        notes.append(f"{dynamic} route(s) with dynamic segments ([id], ...) have no smoke test; their valid values "
                     "depend on your data.")
    write_only = sum(1 for r in routes if not ({"GET", "ANY"} & {m.upper() for m in (r.get("methods") or ["GET"])}))
    if write_only:
        notes.append(f"{write_only} route(s) accept only POST/PUT/PATCH/DELETE; no functional test was generated "
                     "for them (request bodies are application-specific).")

    tests.append({"id": "health-root", "category": "health", "name": f"The application answers at {health_path}",
                  "request": {"method": "GET", "path": health_path}, "expect": {"status_not": SERVER_ERRORS}})
    plan = {"version": 1, "health": {"path": health_path, "expect_status": list(range(200, 500))}, "tests": tests}
    TestPlan.model_validate(plan)   # never hand out a plan the engine would reject
    if not covered:
        notes.append("No SQL injection flow with a known request input was found, so the plan has no security tests. "
                     "It still checks that the application builds, starts and answers.")
    return GeneratedPlan(plan, notes, covered, skipped)
