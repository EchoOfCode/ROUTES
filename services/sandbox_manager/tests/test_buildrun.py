"""Build-run orchestration tests with scripted Docker and gateway fakes.

The fake build runner advances only when the manager performs the real
handshake actions (egress removed, private networks attached, container
stopped), so these tests check ordering, not just the final state.
"""

import asyncio
import json
import uuid

import pytest
from fastapi.testclient import TestClient

from manager.app import build_app
from manager.buildrun import effective_timeouts
from manager.config import Settings
from manager.credentials import CredentialStore
from manager.docker_api import DockerError
from manager.runs import RESULT_PREFIX, RunManager

PLAN = {"health": {"path": "/api/health"}, "tests": [
    {"id": "sqli", "name": "injection blocked", "category": "security", "request": {"path": "/api/products", "query": {"q": "x' OR '1'='1"}},
     "expect": {"status": [200], "body_not_contains": ["Widget"]}},
    {"id": "search", "name": "search works", "category": "functional", "request": {"path": "/api/products", "query": {"q": "Wid"}},
     "expect": {"body_contains": ["Widget"]}},
]}


def ev(stage, message="", **data):
    payload = {"stage": stage, "message": message}
    if data:
        payload["data"] = data
    return "ROUTES_EVENT " + json.dumps(payload) + "\n"


def res(data):
    return (RESULT_PREFIX + json.dumps(data) + "\n").encode()


APP_OK = {"status": "completed", "stages": {"build": {"status": "passed"}, "startup": {"status": "passed"}},
          "project": {"framework": "Next.js"}, "isolation": {"verdict": "isolated", "probes": []}}
TESTS_OK = {"tests": {"total": 2, "passed": 2, "failed": 0, "errors": 0},
            "by_category": {"security": {"total": 1, "passed": 1, "failed": 0},
                            "functional": {"total": 1, "passed": 1, "failed": 0}},
            "cases": [], "isolation": [{"host": "db", "port": 5432, "observed": "dns_failed", "ok": True}]}


class ScriptedDocker:
    def __init__(self, *, app_result=APP_OK, test_result=TESTS_OK, needs_db=1, unsupported=False, hang=False,
                 fail_create=None):
        self.calls: list[tuple] = []
        self.containers: dict[str, dict] = {}
        self.networks: dict[str, dict] = {}
        self.app_result, self.test_result = app_result, test_result
        self.needs_db, self.unsupported, self.hang = needs_db, unsupported, hang
        self.fail_create = list(fail_create or [])
        self.app_stage = 0

    # networks
    async def create_network(self, name, run_id, *, egress=True):
        self.calls.append(("create_network", name, egress))
        self.networks[name] = {"IPAM": {"Config": [{"Subnet": "10.77.0.0/24"}]}, "Containers": {}, "egress": egress}

    async def connect(self, network, container):
        self.calls.append(("connect", network, container))
        self.networks[network]["Containers"][container] = {"Name": container, "IPv4Address": "10.77.0.2/24"}
        if network.endswith("-testnet"):
            self.app_stage = 2

    async def inspect_network(self, name):
        return self.networks[name]

    async def disconnect(self, network, container):
        self.calls.append(("disconnect", network, container))
        self.networks.get(network, {}).get("Containers", {}).pop(container, None)

    async def remove_network(self, name):
        self.calls.append(("remove_network", name))
        self.networks.pop(name, None)

    # containers
    async def create_container(self, name, spec):
        if self.fail_create:
            raise self.fail_create.pop(0)
        self.calls.append(("create_container", name))
        self.containers[name] = {"spec": spec, "running": False, "polls": 0}
        return name

    async def start(self, cid):
        self.calls.append(("start", cid))
        self.containers[cid]["running"] = True
        if cid.endswith("-app"):
            self.app_stage = 1

    async def stop(self, cid, timeout=15):
        self.calls.append(("stop", cid))
        if cid in self.containers:
            self.containers[cid]["running"] = False

    async def kill(self, cid):
        self.calls.append(("kill", cid))
        if cid in self.containers:
            self.containers[cid]["running"] = False

    async def inspect(self, cid):
        c = self.containers[cid]
        c["polls"] += 1
        if cid.endswith("-test") and c["polls"] >= 2:
            c["running"] = False
        if cid.endswith("-app") and self.unsupported and c["polls"] >= 1:
            c["running"] = False
        return {"State": {"Running": c["running"], "ExitCode": 0, "OOMKilled": False}}

    async def logs(self, cid, *, stdout, stderr, max_bytes):
        c = self.containers.get(cid)
        if c is None:
            raise DockerError(404, "gone")
        if cid.endswith("-app"):
            if stderr:
                text = ev("source_ready", files=12) + ev("dependencies_installing")
                if self.unsupported:
                    return text.encode()
                text += ev("awaiting_isolation", needs_database=self.needs_db)
                if self.app_stage >= 2 and not self.hang:
                    text += ev("isolated") + (ev("database_starting") if self.needs_db else "") + ev("building") + \
                            ev("application_starting") + ev("application_ready")
                return text.encode()
            if self.unsupported:
                return res({"status": "unsupported", "verification": "DYNAMIC_VERIFICATION_UNSUPPORTED",
                            "failed_stage": "profiling", "error": "No package-lock.json was found."})
            return res(self.app_result) if not c["running"] else b""
        if cid.endswith("-test"):
            if stderr:
                return ev("testing", tests_total=2, tests_done=2, tests_failed=0).encode()
            return res(self.test_result) if not c["running"] else b""
        return b""

    async def remove(self, cid):
        self.calls.append(("remove", cid))
        self.containers.pop(cid, None)

    async def list_containers(self):
        return []

    async def list_networks(self):
        return []


class FakeGateway:
    def __init__(self):
        self.opened, self.closed = [], []

    async def open_packages(self, subnet, *, ttl, max_bytes, github=None):
        self.opened.append({"subnet": subnet, "github": dict(github) if github else None, "max_bytes": max_bytes})
        return {"id": "pkg-session", "token": "session-token"}

    async def close(self, sid):
        self.closed.append(sid)
        return {"requests": 40, "allowed": 40, "denied": 0, "destinations": ["registry.npmjs.org:443"]}

    async def health(self):
        return True


def settings(tmp_path):
    return Settings(token="x" * 32, docker_url="", gateway_url="", gateway_token="", gateway_container="routes-p1-gateway",
                    upload_volume="routes_uploads", uploads_dir=str(tmp_path), max_concurrent_runs=2, max_crawl_pages=25)


def upload(tmp_path):
    uid = str(uuid.uuid4())
    (tmp_path / uid).mkdir()
    (tmp_path / uid / "source.zip").write_bytes(b"PK\x03\x04")
    return uid


def spec(tmp_path, **kw):
    base = {"source": "zip", "upload_id": upload(tmp_path), "patch": None, "test_plan": PLAN, "options": {},
            "requested_by": "cli:test"}
    base.update(kw)
    return base


async def _go(manager, s, timeout=20):
    run = manager.start("build_run", s)
    await asyncio.wait_for(run.task, timeout)
    return run


@pytest.fixture(autouse=True)
def fast(monkeypatch):
    monkeypatch.setattr("manager.buildrun.POLL_SECONDS", 0.01)


def names(calls, op):
    return [c[1] for c in calls if c[0] == op]


def test_happy_path_phases_isolation_order_and_cleanup(tmp_path):
    docker, gw = ScriptedDocker(), FakeGateway()
    m = RunManager(settings(tmp_path), docker, gw, CredentialStore())
    s = spec(tmp_path, patch="--- a/x.js\n+++ b/x.js\n@@ -1 +1 @@\n-a\n+b\n")
    run = asyncio.run(_go(m, s))
    r = run.result
    assert run.status == "completed" and r["verification"] == "VERIFIED_RUN"
    assert r["application"] == {"build": "passed", "startup": "passed", "health_check": "passed"}
    assert r["tests"]["passed"] == 2 and r["security"]["passed"] == 1 and r["functional"]["passed"] == 1
    phases = [p["phase"] for p in run.phase_history]
    assert phases == ["CREATED", "SOURCE_READY", "DEPENDENCIES_INSTALLING", "DATABASE_STARTING", "BUILDING",
                      "APPLICATION_STARTING", "TESTING", "COLLECTING_RESULTS", "COMPLETED", "CLEANED_UP"]
    assert run.owner == "cli:test" and any(a["action"] == "egress_session_closed" for a in run.audit)

    calls = docker.calls
    base = f"routes-sbx-{run.id}"
    # Only the package network may carry the gateway; private networks are created without egress.
    assert ("create_network", f"{base}-pkgnet", True) in calls
    assert ("create_network", f"{base}-dbnet", False) in calls and ("create_network", f"{base}-testnet", False) in calls
    assert not any(c[0] == "connect" and c[2] == "routes-p1-gateway" and not c[1].endswith("-pkgnet") for c in calls)
    # Egress is removed *before* the app joins any private network or the database starts.
    cut = calls.index(("disconnect", f"{base}-pkgnet", "routes-p1-gateway"))
    assert cut < calls.index(("connect", f"{base}-dbnet", f"{base}-app"))
    assert cut < calls.index(("create_container", f"{base}-db"))
    assert gw.closed == ["pkg-session"] and run.network_summary["destinations"] == ["registry.npmjs.org:443"]
    # Tests start only after the app is ready, the app is stopped (not killed) to collect its report.
    assert calls.index(("start", f"{base}-test")) > calls.index(("connect", f"{base}-testnet", f"{base}-app"))
    assert ("stop", f"{base}-app") in calls
    # Everything owned by the run is gone; nothing else was touched.
    assert docker.containers == {} and docker.networks == {}
    assert set(names(calls, "remove")) == {f"{base}-app", f"{base}-db", f"{base}-test"}
    assert list(tmp_path.iterdir()) == []


def test_container_specs_keep_sandbox_controls(tmp_path):
    docker = ScriptedDocker()
    m = RunManager(settings(tmp_path), docker, FakeGateway(), CredentialStore())
    seen = {}
    original = docker.create_container

    async def capture(name, s):
        seen[name.rsplit("-", 1)[-1]] = s
        return await original(name, s)

    docker.create_container = capture
    run = asyncio.run(_go(m, spec(tmp_path)))
    assert set(seen) == {"app", "db", "test"}
    for role, s in seen.items():
        host = s["HostConfig"]
        assert s["User"] == "10001:10001" and host["ReadonlyRootfs"] is True and host["CapDrop"] == ["ALL"]
        assert "PortBindings" not in host and "Binds" not in host and not s.get("ExposedPorts")
        assert s["Labels"]["routes.run"] == run.id and s["Labels"]["routes.sandbox"] == "true"
        execs = [p for p, o in host["Tmpfs"].items() if "noexec" not in o]
        assert execs == (["/work"] if role == "app" else [])
    assert seen["db"]["HostConfig"]["NetworkMode"].endswith("-dbnet")
    assert seen["test"]["HostConfig"]["NetworkMode"].endswith("-testnet")
    assert "ROUTES_PROXY_TOKEN" not in " ".join(seen["app"]["Env"])          # zip source: no import credential
    assert not any("ghp_" in e or "github_pat" in e for e in seen["app"]["Env"] + seen["test"]["Env"])


def test_failed_tests_are_reported_not_hidden(tmp_path):
    failing = {**TESTS_OK, "tests": {"total": 2, "passed": 1, "failed": 1, "errors": 0},
               "by_category": {"security": {"total": 1, "passed": 0, "failed": 1}}}
    m = RunManager(settings(tmp_path), ScriptedDocker(test_result=failing), FakeGateway(), CredentialStore())
    run = asyncio.run(_go(m, spec(tmp_path)))
    assert run.status == "completed" and run.result["verification"] == "TESTS_FAILED"
    assert run.result["security"] == {"total": 1, "passed": 0, "failed": 1}


def test_unsupported_project_stops_before_isolation_and_creates_nothing_else(tmp_path):
    docker = ScriptedDocker(unsupported=True)
    m = RunManager(settings(tmp_path), docker, FakeGateway(), CredentialStore())
    run = asyncio.run(_go(m, spec(tmp_path)))
    assert run.status == "failed" and run.result["verification"] == "DYNAMIC_VERIFICATION_UNSUPPORTED"
    assert run.result["application"]["build"] == "not_run"
    assert names(docker.calls, "create_container") == [f"routes-sbx-{run.id}-app"]
    assert run.phase_history[-2]["phase"] == "FAILED" and run.phase == "CLEANED_UP"
    assert docker.networks == {} and docker.containers == {}


def test_cancel_cleans_up_everything(tmp_path):
    docker = ScriptedDocker(hang=True)
    m = RunManager(settings(tmp_path), docker, FakeGateway(), CredentialStore())

    async def go():
        run = m.start("build_run", spec(tmp_path))
        await asyncio.sleep(0.3)
        m.cancel(run.id)
        await asyncio.wait_for(run.task, 10)
        return run

    run = asyncio.run(go())
    assert run.status == "cancelled" and run.result["verification"] == "INCONCLUSIVE"
    assert "CANCELLED" in [p["phase"] for p in run.phase_history] and run.phase == "CLEANED_UP"
    assert docker.containers == {} and docker.networks == {} and list(tmp_path.iterdir()) == []


def test_lifetime_timeout_is_inconclusive(tmp_path, monkeypatch):
    monkeypatch.setenv("BUILD_TOTAL_TIMEOUT_SECONDS", "1")
    docker = ScriptedDocker(hang=True)
    m = RunManager(settings(tmp_path), docker, FakeGateway(), CredentialStore())
    run = asyncio.run(_go(m, spec(tmp_path)))
    assert run.status == "timeout" and run.result["verification"] == "INCONCLUSIVE"
    assert docker.containers == {} and docker.networks == {}


def test_transient_docker_errors_are_retried_once_but_policy_denials_are_not(tmp_path, monkeypatch):
    monkeypatch.setattr("manager.buildrun.RETRY_DELAY", 0)
    docker = ScriptedDocker(fail_create=[DockerError(500, "daemon hiccup")])
    run = asyncio.run(_go(RunManager(settings(tmp_path), docker, FakeGateway(), CredentialStore()), spec(tmp_path)))
    assert run.result["verification"] == "VERIFIED_RUN" and any(a["action"] == "retry" for a in run.audit)

    docker = ScriptedDocker(fail_create=[DockerError(403, "ROUTES docker-proxy denied request: privileged_forbidden")])
    run = asyncio.run(_go(RunManager(settings(tmp_path), docker, FakeGateway(), CredentialStore()), spec(tmp_path)))
    assert run.status == "failed" and "privileged_forbidden" in run.error
    assert docker.networks == {}


async def _no_sleep(*_a, **_k):
    await asyncio.sleep(0)


def test_private_repository_token_reaches_only_the_gateway(tmp_path):
    creds = CredentialStore()
    handle = creds.put("github_pat_" + "Q" * 60, "github:acme/app")
    docker, gw = ScriptedDocker(), FakeGateway()
    seen = {}
    original = docker.create_container

    async def capture(name, s):
        seen[name] = s
        return await original(name, s)

    docker.create_container = capture
    s = {"source": "github", "owner": "acme", "repo": "app", "ref": "main", "credential_handle": handle,
         "patch": None, "test_plan": PLAN, "options": {}}
    asyncio.run(_go(RunManager(settings(tmp_path), docker, gw, creds), s))
    assert gw.opened[0]["github"]["token"].startswith("github_pat_")
    assert all("github_pat_" not in " ".join(c["Env"]) for c in seen.values())
    assert creds.take(handle, "github:acme/app") is None   # single use, discarded


def test_timeouts_can_only_be_lowered(monkeypatch):
    monkeypatch.setenv("BUILD_BUILD_TIMEOUT_SECONDS", "600")
    t = effective_timeouts({"build": 9999, "tests": 30})
    assert t["build"] == 600 and t["tests"] == 30


def test_api_validates_build_run_requests(tmp_path):
    app = build_app(settings(tmp_path), docker=ScriptedDocker(), gateway=FakeGateway())
    auth = {"Authorization": "Bearer " + "x" * 32}
    with TestClient(app) as c:
        up = c.post("/uploads", content=b"PK\x03\x04" + b"0" * 100, headers=auth).json()["upload_id"]
        base = {"kind": "build_run", "source": "zip", "upload_id": up, "test_plan": PLAN}
        bad_patch = c.post("/runs", json={**base, "patch": "--- a/../../etc/passwd\n+++ b/../../etc/passwd\n@@ -1 +1 @@\n-a\n+b\n"},
                           headers=auth)
        assert bad_patch.status_code == 422 and "patch rejected" in bad_patch.json()["detail"]
        bad_plan = c.post("/runs", json={**base, "test_plan": {"tests": [{"id": "x", "name": "x", "request": {
            "path": "http://169.254.169.254/latest"}, "expect": {}}]}}, headers=auth)
        assert bad_plan.status_code == 422
        assert not (tmp_path / up).exists()            # rejected requests discard their upload

        def fresh():
            return c.post("/uploads", content=b"PK\x03\x04" + b"0" * 100, headers=auth).json()["upload_id"]

        unknown = c.post("/runs", json={**base, "upload_id": str(uuid.uuid4())}, headers=auth)
        assert unknown.status_code == 422
        raise_timeouts = c.post("/runs", json={**base, "upload_id": fresh(), "options": {"timeouts": {"bogus": 10}}},
                                headers=auth)
        assert raise_timeouts.status_code == 422
        base["upload_id"] = fresh()
        assert c.post("/runs", json=base).status_code == 403
        ok = c.post("/runs", json=base, headers=auth)
        assert ok.status_code == 201 and ok.json()["kind"] == "build_run" and ok.json()["phase"] in ("CREATED", None)
