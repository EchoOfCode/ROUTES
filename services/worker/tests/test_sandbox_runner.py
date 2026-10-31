"""Unit tests for the SandboxRunner interface (S5): FakeSandboxRunner's
canned scenarios, and RealSandboxRunner's request shape + graceful handling
of sandbox_manager rejecting/erroring/timing out - against a fake HTTP
transport, no real network calls.
"""

import json

import httpx

from worker.sandbox import real as real_module
from worker.sandbox.fake import FakeSandboxRunner, canned_fail, canned_missing_stub, canned_pass, canned_timeout
from worker.sandbox.real import RealSandboxRunner
from worker.sandbox.runner import SandboxFile, SandboxRunRequest

REQUEST = SandboxRunRequest(
    run_id="run-1", finding_id="finding-1", round_no=1,
    files=[SandboxFile(path="app/api/search/route.ts", content="export async function GET() {}")],
    testbench=SandboxFile(path="app/api/search/route.test.ts", content="test('exploit', () => {})"),
)


# ----------------------------------------------------------------- Fake


def test_fake_runner_returns_the_canned_result_and_records_the_call():
    runner = FakeSandboxRunner(canned_pass())
    result = runner.run(REQUEST)
    assert result.status == "passed"
    assert runner.calls == [REQUEST]


def test_canned_pass_shape():
    result = canned_pass()
    assert result.status == "passed"
    assert all(t.passed for t in result.tests)
    assert {t.category for t in result.tests} == {"exploit", "benign"}


def test_canned_fail_shape():
    result = canned_fail()
    assert result.status == "failed"
    exploit_test = next(t for t in result.tests if t.category == "exploit")
    assert exploit_test.passed is False and exploit_test.message


def test_canned_timeout_shape():
    result = canned_timeout()
    assert result.status == "timeout"
    assert result.error_reason == "timeout"


def test_canned_missing_stub_shape():
    result = canned_missing_stub("pg")
    assert result.status == "error"
    assert result.error_reason == "missing_stub:pg"


# ----------------------------------------------------------------- Real


def _runner(handler, timeout_s=5) -> tuple[RealSandboxRunner, SandboxRunRequest]:
    runner = RealSandboxRunner(manager_url="http://fake-manager", manager_token="t",
                               transport=httpx.MockTransport(handler))
    request = SandboxRunRequest(**{**REQUEST.__dict__, "timeout_s": timeout_s})
    return runner, request


def test_real_runner_posts_the_expected_request_shape():
    posted = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/runs":
            posted.append(json.loads(request.content))
            return httpx.Response(422, json={"detail": "unsupported kind"})
        raise AssertionError("should not poll after a 422")

    runner, request = _runner(handler)
    runner.run(request)

    assert len(posted) == 1
    body = posted[0]
    assert body["run_id"] == "run-1" and body["finding_id"] == "finding-1" and body["round_no"] == 1
    assert body["files"] == [{"path": "app/api/search/route.ts", "content": "export async function GET() {}"}]
    assert body["testbench"] == {"path": "app/api/search/route.test.ts", "content": "test('exploit', () => {})"}
    assert body["limits"] == {"timeout_s": 5, "memory_mb": 256}


def test_real_runner_rejection_is_a_graceful_error_not_an_exception():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(422, json={"detail": "unsupported kind"})

    runner, request = _runner(handler)
    result = runner.run(request)

    assert result.status == "error"
    assert "sandbox_manager rejected the run" in result.error_reason


def test_real_runner_unreachable_is_a_graceful_error():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("boom")

    runner, request = _runner(handler)
    result = runner.run(request)

    assert result.status == "error"
    assert "unreachable" in result.error_reason


def test_real_runner_maps_a_completed_run_with_tests():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/runs":
            return httpx.Response(201, json={"id": "sbx-1", "status": "running"})
        return httpx.Response(200, json={
            "id": "sbx-1", "status": "completed",
            "result": {
                "tests": [{"name": "exploit rejected", "category": "exploit", "passed": True},
                          {"name": "benign ok", "category": "benign", "passed": True}],
                "stdout": "2 passed", "stderr": "", "duration_ms": 95,
            },
        })

    runner, request = _runner(handler)
    result = runner.run(request)

    assert result.status == "passed"
    assert len(result.tests) == 2
    assert result.duration_ms == 95


def test_real_runner_maps_a_completed_run_with_a_failing_test():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/runs":
            return httpx.Response(201, json={"id": "sbx-1", "status": "running"})
        return httpx.Response(200, json={
            "id": "sbx-1", "status": "completed",
            "result": {"tests": [{"name": "exploit rejected", "category": "exploit", "passed": False,
                                  "message": "exploit succeeded"}]},
        })

    runner, request = _runner(handler)
    result = runner.run(request)

    assert result.status == "failed"
    assert result.tests[0].passed is False


def test_real_runner_maps_infra_level_failure_to_error():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/runs":
            return httpx.Response(201, json={"id": "sbx-1", "status": "running"})
        return httpx.Response(200, json={"id": "sbx-1", "status": "failed", "error": "OOM killed", "result": {}})

    runner, request = _runner(handler)
    result = runner.run(request)

    assert result.status == "error"


def test_real_runner_maps_sandbox_manager_timeout():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/runs":
            return httpx.Response(201, json={"id": "sbx-1", "status": "running"})
        return httpx.Response(200, json={"id": "sbx-1", "status": "timeout"})

    runner, request = _runner(handler)
    result = runner.run(request)

    assert result.status == "timeout"


def test_real_runner_maps_sandbox_manager_cancellation_to_killed():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/runs":
            return httpx.Response(201, json={"id": "sbx-1", "status": "running"})
        return httpx.Response(200, json={"id": "sbx-1", "status": "cancelled"})

    runner, request = _runner(handler)
    result = runner.run(request)

    assert result.status == "killed"


def test_real_runner_gives_up_after_its_own_deadline(monkeypatch):
    monkeypatch.setattr(real_module, "POLL_SECONDS", 0)
    deleted = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/runs":
            return httpx.Response(201, json={"id": "sbx-1", "status": "running"})
        if request.method == "DELETE":
            deleted.append(request)
            return httpx.Response(204)
        return httpx.Response(200, json={"id": "sbx-1", "status": "running"})

    runner, request = _runner(handler, timeout_s=0)
    result = runner.run(request)

    assert result.status == "timeout"
    assert len(deleted) == 1
