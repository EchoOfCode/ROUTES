"""RealSandboxRunner: HTTP calls to the existing sandbox_manager, the same
service workers already talk to for discovery/source runs. sandbox_manager
itself is NOT modified by this file - it is owned by someone else, and as
of this writing it has no run `kind` that accepts a testbench verification
request. Until its owner adds one, every real run gets rejected by
sandbox_manager's own input validation (422) - handled here as a graceful
SandboxRunResult(status="error"), never an exception. Once a matching kind
exists, this becomes functional with no interface change.
"""

from __future__ import annotations

import time

import httpx

from worker.sandbox.runner import SandboxRunRequest, SandboxRunner, SandboxRunResult, TestResult

POLL_SECONDS = 2.0
RUN_KIND = "remediate_verify"  # not yet recognised by sandbox_manager; see module docstring


class RealSandboxRunner(SandboxRunner):
    def __init__(self, *, manager_url: str, manager_token: str, timeout: float = 20.0,
                 transport: httpx.BaseTransport | None = None) -> None:
        self._client = httpx.Client(
            base_url=manager_url, headers={"Authorization": f"Bearer {manager_token}"},
            timeout=httpx.Timeout(timeout, connect=5.0), transport=transport,
        )

    def close(self) -> None:
        self._client.close()

    def run(self, request: SandboxRunRequest) -> SandboxRunResult:
        spec = {
            "kind": RUN_KIND,
            "run_id": request.run_id,
            "finding_id": request.finding_id,
            "round_no": request.round_no,
            "files": [{"path": f.path, "content": f.content} for f in request.files],
            "testbench": {"path": request.testbench.path, "content": request.testbench.content},
            "limits": {"timeout_s": request.timeout_s, "memory_mb": request.memory_mb},
        }
        try:
            r = self._client.post("/runs", json=spec)
        except httpx.HTTPError as exc:
            return SandboxRunResult(status="error", error_reason=f"sandbox_manager unreachable: {exc}")
        if r.status_code == 422:
            return SandboxRunResult(status="error",
                                    error_reason=f"sandbox_manager rejected the run: {r.text[:300]}")
        if r.status_code != 201:
            return SandboxRunResult(status="error",
                                    error_reason=f"sandbox_manager refused the run ({r.status_code}): {r.text[:300]}")

        run_id = r.json()["id"]
        deadline = time.monotonic() + request.timeout_s
        while True:
            try:
                state = self._client.get(f"/runs/{run_id}").json()
            except httpx.HTTPError as exc:
                return SandboxRunResult(status="error", error_reason=f"sandbox_manager unreachable: {exc}")
            status = state.get("status")
            if status in ("completed", "failed", "cancelled", "timeout"):
                return self._to_result(state)
            if time.monotonic() > deadline:
                try:
                    self._client.delete(f"/runs/{run_id}")
                except httpx.HTTPError:
                    pass
                return SandboxRunResult(status="timeout", error_reason="timeout")
            time.sleep(POLL_SECONDS)

    @staticmethod
    def _to_result(state: dict) -> SandboxRunResult:
        status = state.get("status")
        if status == "timeout":
            return SandboxRunResult(status="timeout", error_reason="timeout")
        if status == "cancelled":
            return SandboxRunResult(status="killed", error_reason="cancelled")
        result = state.get("result") or {}
        tests = [
            TestResult(name=t.get("name", ""), category=t.get("category", ""), passed=bool(t.get("passed")),
                      message=t.get("message", ""))
            for t in (result.get("tests") or [])
        ]
        if status == "failed" and not tests:
            # sandbox_manager's own "failed" with no test breakdown means an
            # infrastructure-level problem (e.g. the testbench itself could
            # not run), not a test assertion failing.
            return SandboxRunResult(status="error", stderr=result.get("stderr", "") or state.get("error", "") or "",
                                    error_reason=result.get("error_reason") or state.get("error"))
        overall = "passed" if tests and all(t.passed for t in tests) else "failed"
        return SandboxRunResult(status=overall, tests=tests, stdout=result.get("stdout", ""),
                                stderr=result.get("stderr", ""), duration_ms=int(result.get("duration_ms", 0)),
                                error_reason=result.get("error_reason"))
