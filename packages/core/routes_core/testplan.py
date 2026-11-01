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

* security, per reflected XSS finding: a unique script marker sent in the traced input must not come
  back unescaped in the response;
* security, per unauthenticated database route (broken access control): an anonymous request must be
  rejected (401/403/404, or a redirect to sign in);
* security, for missing security headers: the page must send every header the analysis found missing;
* security, for a wildcard CORS policy: a request from a foreign origin must not be granted access.

Findings whose effect cannot be observed with one HTTP request (DOM-only XSS, ownership checks that need
two signed-in users, cookie flags, TLS settings, weak crypto, secrets) get no runtime test; the
remediation loop then relies on the static rescan, and says so.

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

    # ---------------------------------------- XSS, access control, configuration
    for n, f in enumerate([f for f in findings if f.get("type") != "SQL Injection"], start=1):
        if len(tests) >= MAX_SECURITY:
            notes.append(f"Only the first {MAX_SECURITY} security tests were generated.")
            break
        built, why = _class_tests(f, n, routes, health_path)
        if built:
            covered += 1
            tests.extend(built)
        elif why:
            skipped += 1
            where = f.get("file") or f.get("rule_id")
            notes.append(f"No runtime test for {where}{':' + str(f['line']) if f.get('line') else ''}: {why}")

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
        notes.append("No finding could be turned into a runtime security test, so the plan has no security tests. "
                     "It still checks that the application builds, starts and answers.")
    return GeneratedPlan(plan, notes, covered, skipped)


# ------------------------------------------------------------ other classes
XSS_MARKERS = ["<script>routes_xss_probe()</script>", '"><svg onload=routes_xss_probe()>']
CORS_PROBE_ORIGIN = "https://routes-cors-probe.example"
AUTH_REJECTED = [401, 403, 404, 302, 303, 307, 308]
CLASS_LABELS = {"SQL Injection": "SQL injection", "Cross-Site Scripting": "XSS",
                "Broken Access Control": "Access control", "Insecure Configuration": "Misconfiguration"}
RUNTIME_CHECKS = {
    "routes.xss.reflected-response": "script markers in the traced input must come back escaped",
    "routes.a01.unprotected-db-route": "an anonymous request must be rejected",
    "routes.config.missing-security-headers": "the page must send the missing security headers",
    "routes.config.cors-wildcard": "a foreign origin must not be granted access",
}
NO_RUNTIME = {
    "routes.xss.dom-sink-tainted": "DOM-based XSS runs in the browser, not in one HTTP response",
    "routes.xss.dangerously-set-inner-html": "the markup is rendered in the browser, not observable in one "
                                             "HTTP response",
    "routes.a01.missing-ownership-check": "an ownership check needs two signed-in users",
    "routes.config.insecure-cookie": "the request that sets this cookie is application-specific",
}


def vuln_class(f: dict) -> str:
    """Short class label: SQL injection, XSS, Access control, Misconfiguration, or the finding type."""
    rule = f.get("rule_id") or ""
    if rule.startswith(("routes.config.", "routes.crypto.")):
        return "Misconfiguration"
    if rule.startswith("routes.sqli."):
        return "SQL injection"
    if rule.startswith("routes.xss."):
        return "XSS"
    if rule.startswith("routes.a01."):
        return "Access control"
    return CLASS_LABELS.get(f.get("type") or "", f.get("type") or "Other")


def _route_for_file(routes: list[dict], file: str | None) -> dict | None:
    return next((r for r in routes if file and r.get("file") == file and (r.get("path") or "").startswith("/")),
                None)


def _class_tests(f: dict, n: int, routes: list[dict], health_path: str) -> tuple[list[dict], str | None]:
    """Runtime security tests for one non-SQL-injection finding, or ([], why there are none)."""
    rule = f.get("rule_id") or ""
    if f.get("status") != "potential":
        return [], "the finding is inconclusive"
    details = f.get("technical_details") or {}
    where = f"{f.get('file')}:{f.get('line')}" if f.get("line") else (f.get("file") or rule)
    method = (f.get("method") or "GET").upper()
    method = "GET" if method == "ANY" else method
    endpoint = f.get("endpoint")

    if rule == "routes.xss.reflected-response":
        source = details.get("source") or {}
        kind, name = source.get("kind") or "", (source.get("name") or "").strip()
        if not endpoint or not endpoint.startswith("/"):
            return [], "no HTTP route is known for this flow"
        if not name or not FIELD_NAME.match(name):
            return [], f"the exact input name could not be determined ({kind or 'unknown source'})"
        out = []
        for i, marker in enumerate(XSS_MARKERS, start=1):
            req = _request(method, endpoint, kind, name, marker)
            if req is None:
                return [], f"input kind '{kind}' cannot be placed in a request automatically"
            out.append({"id": _id("xss", n, f"marker{i}"), "category": "security",
                        "name": f'XSS ({where}): markup in {method} {endpoint} {kind} "{name}" comes back escaped',
                        "request": req, "expect": {"status_not": SERVER_ERRORS, "body_not_contains": [marker]}})
        return out, None

    if rule == "routes.a01.unprotected-db-route":
        if not endpoint or not endpoint.startswith("/"):
            return [], "no HTTP route is known for this handler"
        req: dict = {"method": method, "path": _fill_path(endpoint)}
        if method in ("POST", "PUT", "PATCH"):
            req.update(json={}, headers={"Content-Type": "application/json"})
        return [{"id": _id("a01", n, "anonymous"), "category": "security",
                 "name": f"Access control ({where}): an anonymous {method} {endpoint} is rejected",
                 "request": req, "expect": {"status": AUTH_REJECTED}}], None

    if rule == "routes.config.missing-security-headers":
        missing = [h for h in details.get("missing_headers") or [] if isinstance(h, str)]
        if not missing:
            return [], "the missing headers are not recorded; re-run the analysis"
        return [{"id": _id("hdr", n, "security-headers"), "category": "security",
                 "name": f"Misconfiguration: {health_path} sends {', '.join(missing)}",
                 "request": {"method": "GET", "path": health_path},
                 "expect": {"headers_present": missing}}], None

    if rule == "routes.config.cors-wildcard":
        route = _route_for_file(routes, f.get("file"))
        path = _fill_path(route["path"]) if route else health_path
        return [{"id": _id("cors", n, "foreign-origin"), "category": "security",
                 "name": f"Misconfiguration ({where}): {path} does not grant access to a foreign origin",
                 "request": {"method": "GET", "path": path, "headers": {"Origin": CORS_PROBE_ORIGIN}},
                 "expect": {"header_not": {"access-control-allow-origin": ["*", CORS_PROBE_ORIGIN]}}}], None

    return [], NO_RUNTIME.get(rule, "this kind of finding cannot be observed with an HTTP request")


def runtime_check(f: dict, routes: list[dict] | None = None, health_path: str = "/") -> tuple[str | None, str]:
    """(what the runtime security test for `f` checks, or None; why there is none)."""
    if f.get("type") == "SQL Injection":
        gen = generate(routes or [], [f], health_path=health_path)
        if any(t["category"] == "security" for t in gen.plan["tests"]):
            return "quote and pg_sleep probes on the traced input", ""
        return None, "the SQL injection flow has no request input ROUTES can target"
    built, why = _class_tests(f, 1, routes or [], health_path)
    if built:
        return RUNTIME_CHECKS.get(f.get("rule_id") or "", "runtime probe"), ""
    return None, why or "no runtime test"
