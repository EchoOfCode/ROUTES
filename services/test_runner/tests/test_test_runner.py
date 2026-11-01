"""Test-runner unit tests against a local stand-in application."""

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import httpx
import pytest

from routes_shared.buildrun import TestCase
from test_runner.main import evaluate, execute


class App(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        body = {"/ok": (200, b'{"ok": true, "n": 3}'), "/boom": (500, b"query failed"),
                "/secret": (200, b"token=ghp_" + b"A" * 36)}.get(self.path.split("?")[0], (404, b"missing"))
        self.send_response(body[0])
        self.end_headers()
        self.wfile.write(body[1])

    def log_message(self, *a):
        pass


@pytest.fixture(scope="module")
def base():
    server = HTTPServer(("127.0.0.1", 0), App)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()


def case(path, **expect):
    return TestCase.model_validate({"id": "t", "name": "t", "category": "security", "request": {"path": path},
                                    "expect": expect})


def test_passing_and_failing_expectations(base):
    with httpx.Client(trust_env=False) as c:
        assert execute(c, base, case("/ok", status=[200], json_equals={"ok": True}))["status"] == "passed"
        failed = execute(c, base, case("/boom", status=[200], body_not_contains=["query failed"]))
        assert failed["status"] == "failed" and len(failed["reasons"]) == 2 and failed["http_status"] == 500


def test_unreachable_application_is_an_error_not_a_pass():
    with httpx.Client(trust_env=False) as c:
        r = execute(c, "http://127.0.0.1:9", case("/ok", status=[200]))
    assert r["status"] == "error"


def test_failure_excerpts_are_redacted(base):
    with httpx.Client(trust_env=False) as c:
        r = execute(c, base, case("/secret", status=[204]))
    assert r["status"] == "failed" and "A" * 20 not in r["response_excerpt"] and "[redacted]" in r["response_excerpt"]


def test_evaluate_json_and_timing():
    c = case("/x", json_equals={"a": 1}, max_ms=10)
    outcome, reasons = evaluate(c, 200, json.dumps({"a": 2}), 50, None)
    assert outcome == "failed" and any("expected 1" in r for r in reasons) and any("limit" in r for r in reasons)


def test_header_expectations():
    c = case("/x", headers_present=["Content-Security-Policy", "x-frame-options"],
             header_not={"Access-Control-Allow-Origin": ["*", "https://probe.example"]})
    ok = {"content-security-policy": "default-src 'self'", "X-Frame-Options": "DENY"}
    assert evaluate(c, 200, "", 5, None, ok) == ("passed", [])
    status, reasons = evaluate(c, 200, "", 5, None, {"Access-Control-Allow-Origin": " * "})
    assert status == "failed" and len(reasons) == 3
    assert "'content-security-policy' is missing" in reasons[0] and "'access-control-allow-origin' is '*'" in reasons[2]
