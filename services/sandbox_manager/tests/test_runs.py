"""Sandbox Manager orchestration tests using in-memory Docker and gateway fakes."""

import asyncio
import json
import os
import uuid

import pytest

from manager.config import Settings
from manager.credentials import CredentialStore
from manager.docker_api import DockerError, demux
from manager.runs import RESULT_PREFIX, RunManager, parse_events, parse_result

PAT = "github_pat_" + "Z" * 60


class FakeDocker:
    def __init__(self, *, stdout=b"", stderr=b"", fail_start=False, run_forever=False, oom=False, exit_code=0):
        self.calls: list[tuple] = []
        self.containers: dict[str, dict] = {}
        self.networks: dict[str, dict] = {}
        self.stdout, self.stderr = stdout, stderr
        self.fail_start, self.run_forever, self.oom, self.exit_code = fail_start, run_forever, oom, exit_code
        self.polls = 0

    async def create_network(self, name, run_id):
        self.calls.append(("create_network", name))
        self.networks[name] = {"IPAM": {"Config": [{"Subnet": "10.123.0.0/24"}]}, "Containers": {}}

    async def connect(self, network, container):
        self.calls.append(("connect", network, container))
        self.networks[network]["Containers"]["gw"] = {"Name": container, "IPv4Address": "10.123.0.2/24"}

    async def inspect_network(self, name):
        return self.networks[name]

    async def disconnect(self, network, container):
        self.calls.append(("disconnect", network, container))

    async def remove_network(self, name):
        self.calls.append(("remove_network", name))
        self.networks.pop(name, None)

    async def create_container(self, name, spec):
        self.calls.append(("create_container", name))
        self.containers[name] = spec
        return name

    async def start(self, cid):
        if self.fail_start:
            raise DockerError(500, "start failed")
        self.calls.append(("start", cid))

    async def inspect(self, cid):
        self.polls += 1
        running = self.run_forever or self.polls < 2
        return {"State": {"Running": running, "ExitCode": self.exit_code, "OOMKilled": self.oom}}

    async def logs(self, cid, *, stdout, stderr, max_bytes):
        return self.stdout if stdout else self.stderr

    async def kill(self, cid):
        self.calls.append(("kill", cid))

    async def remove(self, cid):
        self.calls.append(("remove", cid))
        self.containers.pop(cid, None)

    async def list_containers(self):
        return [{"Id": "leftover"}]

    async def list_networks(self):
        return [{"Name": "routes-sbx-old"}, {"Name": "routes_backend"}]


class FakeGateway:
    def __init__(self):
        self.opened: list[dict] = []
        self.closed: list[str] = []

    async def open_web(self, host, port, subnet, *, ttl):
        self.opened.append({"mode": "web", "host": host, "port": port, "subnet": subnet})
        return {"id": "s1", "token": "proxy-token"}

    async def open_github(self, owner, repo, ref, token, subnet, *, ttl):
        self.opened.append({"mode": "github", "owner": owner, "token": token, "subnet": subnet})
        return {"id": "s2", "token": "import-token"}

    async def close(self, sid):
        self.closed.append(sid)
        return {"requests": 3}


def settings(tmp_path):
    return Settings(token="x" * 32, docker_url="", gateway_url="", gateway_token="", gateway_container="routes-network-gateway",
                    upload_volume="routes_uploads", uploads_dir=str(tmp_path), max_concurrent_runs=2, max_crawl_pages=25)


async def _run(manager, kind, spec):
    run = manager.start(kind, spec)
    await asyncio.wait_for(run.task, 10)
    return run


def result_line(data):
    return (RESULT_PREFIX + json.dumps(data) + "\n").encode()


def test_discovery_run_lifecycle(tmp_path):
    async def go():
        docker = FakeDocker(stdout=b"noise\n" + result_line({"pages": []}),
                            stderr=b'ROUTES_EVENT {"stage": "discovering_pages", "message": "3 pages"}\n')
        gw = FakeGateway()
        m = RunManager(settings(tmp_path), docker, gw, CredentialStore())
        run = await _run(m, "discovery", {"target_url": "https://example.com/", "target_host": "example.com", "target_port": 443})
        assert run.status == "completed" and run.result == {"pages": []}
        assert run.events == [{"stage": "discovering_pages", "message": "3 pages"}]
        spec = next(iter(docker.containers.values()), None)
        assert spec is None  # container removed
        names = [c[0] for c in docker.calls]
        assert names.index("create_network") < names.index("connect") < names.index("create_container")
        assert {"remove", "disconnect", "remove_network"} <= set(names)
        assert gw.opened[0] == {"mode": "web", "host": "example.com", "port": 443, "subnet": "10.123.0.0/24"}
        assert gw.closed == ["s1"] and run.network_summary == {"requests": 3}
    asyncio.run(go())


def test_container_spec_is_locked_down(tmp_path):
    async def go():
        docker = FakeDocker(stdout=result_line({}))
        captured = {}
        orig = docker.create_container

        async def capture(name, spec):
            captured.update(spec)
            return await orig(name, spec)

        docker.create_container = capture
        m = RunManager(settings(tmp_path), docker, FakeGateway(), CredentialStore())
        await _run(m, "discovery", {"target_url": "https://example.com/", "target_host": "example.com", "target_port": 443})
        host = captured["HostConfig"]
        assert captured["User"] == "10001:10001"
        assert host["ReadonlyRootfs"] is True and host["CapDrop"] == ["ALL"]
        assert "no-new-privileges:true" in host["SecurityOpt"]
        assert host["Memory"] > 0 and host["NanoCpus"] > 0 and host["PidsLimit"] > 0
        assert "Binds" not in host and "Privileged" not in host
        assert host["NetworkMode"].startswith("routes-sbx-")
        assert all("noexec" in v for v in host["Tmpfs"].values())
    asyncio.run(go())


def test_private_github_token_never_reaches_container(tmp_path):
    async def go():
        docker = FakeDocker(stdout=result_line({"ok": True}))
        gw = FakeGateway()
        creds = CredentialStore()
        handle = creds.put(PAT, "github:acme/app")
        m = RunManager(settings(tmp_path), docker, gw, creds)
        captured = {}
        orig = docker.create_container

        async def capture(name, spec):
            captured.update(spec)
            return await orig(name, spec)

        docker.create_container = capture
        run = await _run(m, "source", {"source": "github", "owner": "acme", "repo": "app", "ref": None,
                                       "credential_handle": handle, "target_host": "example.com"})
        assert run.status == "completed"
        assert gw.opened[0]["token"] == PAT  # handed only to the gateway
        assert PAT not in json.dumps(captured)
        assert any(e.startswith("ROUTES_IMPORT_URL=") for e in captured["Env"])
        assert len(creds) == 0  # single use
        # A second run with the same handle cannot obtain the token.
        run2 = await _run(m, "source", {"source": "github", "owner": "acme", "repo": "app", "ref": None,
                                        "credential_handle": handle, "target_host": ""})
        assert run2.status == "failed" and "token" in run2.error
    asyncio.run(go())


def test_credential_scope_enforced():
    creds = CredentialStore()
    handle = creds.put(PAT, "github:acme/app")
    assert creds.take(handle, "github:acme/other") is None
    assert creds.take(handle, "github:acme/app") is None  # consumed by the failed attempt


def test_zip_run_has_no_network_and_upload_removed(tmp_path):
    async def go():
        upload_id = str(uuid.uuid4())
        (tmp_path / upload_id).mkdir()
        (tmp_path / upload_id / "source.zip").write_bytes(b"PK")
        docker = FakeDocker(stdout=result_line({}))
        captured = {}
        orig = docker.create_container

        async def capture(name, spec):
            captured.update(spec)
            return await orig(name, spec)

        docker.create_container = capture
        m = RunManager(settings(tmp_path), docker, FakeGateway(), CredentialStore())
        await _run(m, "source", {"source": "zip", "upload_id": upload_id, "target_host": ""})
        assert captured["HostConfig"]["NetworkMode"] == "none"
        mount = captured["HostConfig"]["Mounts"][0]
        assert mount["ReadOnly"] is True and mount["VolumeOptions"]["Subpath"] == upload_id
        assert not any(c[0] == "create_network" for c in docker.calls)
        assert not os.path.exists(tmp_path / upload_id)
    asyncio.run(go())


@pytest.mark.parametrize("kwargs,status", [
    ({"fail_start": True}, "failed"),
    ({"oom": True, "stdout": b""}, "failed"),
    ({"stdout": b"no result here"}, "failed"),
    ({"stdout": result_line({"fatal": True, "error": "Website unavailable"})}, "failed"),
])
def test_failures_still_clean_up(tmp_path, kwargs, status):
    async def go():
        docker = FakeDocker(**kwargs)
        gw = FakeGateway()
        m = RunManager(settings(tmp_path), docker, gw, CredentialStore())
        run = await _run(m, "discovery", {"target_url": "https://example.com/", "target_host": "example.com", "target_port": 443})
        assert run.status == status and run.error
        names = [c[0] for c in docker.calls]
        assert "remove" in names and "remove_network" in names and gw.closed == ["s1"]
    asyncio.run(go())


def test_timeout_and_cancel_kill_container(tmp_path, monkeypatch):
    import policies.limits as limits

    async def go():
        monkeypatch.setenv("DISCOVERY_TIMEOUT_SECONDS", "1")
        docker = FakeDocker(run_forever=True)
        m = RunManager(settings(tmp_path), docker, FakeGateway(), CredentialStore())
        run = await _run(m, "discovery", {"target_url": "https://example.com/", "target_host": "example.com", "target_port": 443})
        assert run.status == "timeout"
        assert ("kill", run.task and f"routes-sbx-{run.id}") in docker.calls

        docker2 = FakeDocker(run_forever=True)
        monkeypatch.setenv("DISCOVERY_TIMEOUT_SECONDS", "60")
        m2 = RunManager(settings(tmp_path), docker2, FakeGateway(), CredentialStore())
        run2 = m2.start("discovery", {"target_url": "https://example.com/", "target_host": "example.com", "target_port": 443})
        await asyncio.sleep(0.2)
        m2.cancel(run2.id)
        await asyncio.wait_for(run2.task, 10)
        assert run2.status == "cancelled" and any(c[0] == "remove" for c in docker2.calls)
    assert limits  # module imported for env-driven profile
    asyncio.run(go())


def test_orphan_cleanup_only_touches_sandbox_networks(tmp_path):
    async def go():
        docker = FakeDocker()
        m = RunManager(settings(tmp_path), docker, FakeGateway(), CredentialStore())
        assert await m.cleanup_orphans() == 2
        assert ("remove_network", "routes-sbx-old") in docker.calls
        assert ("remove_network", "routes_backend") not in docker.calls
    asyncio.run(go())


def test_event_and_result_parsing():
    text = 'x\nROUTES_EVENT {"stage":"a","message":"m"}\nROUTES_EVENT not-json\nROUTES_EVENT {"nostage":1}\n'
    assert parse_events(text) == [{"stage": "a", "message": "m"}]
    assert parse_result("ROUTES_RESULT [1]\n") is None
    assert parse_result('ROUTES_RESULT {"a": 1}\n') == {"a": 1}


def test_demux():
    frame = b"\x01\x00\x00\x00" + (5).to_bytes(4, "big") + b"hello" + b"\x02\x00\x00\x00" + (3).to_bytes(4, "big") + b"err"
    assert demux(frame) == b"helloerr"
    assert demux(b"plain text") == b"plain text"
