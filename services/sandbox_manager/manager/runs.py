"""Sandbox run orchestration.

Each run gets: its own internal Docker network (or no network at all), a
gateway session scoped to exactly what the run may reach, one disposable
container, and unconditional cleanup of all three.
"""

from __future__ import annotations

import asyncio
import json
import logging
import shutil
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from routes_shared.events import parse_events  # noqa: F401  (re-exported)

from manager.config import Settings
from manager.credentials import CredentialStore
from manager.docker_api import DockerAPI, DockerError
from manager.gateway_client import GatewayClient
from policies.limits import analyzer_profile, container_spec, discovery_profile

log = logging.getLogger("routes.sandbox.runs")

RESULT_PREFIX = "ROUTES_RESULT "
MAX_RESULT_BYTES = 16 * 1024 * 1024
MAX_EVENTS = 200


@dataclass
class Run:
    id: str
    kind: str
    status: str = "pending"  # pending | running | completed | failed | cancelled | timeout
    events: list[dict] = field(default_factory=list)
    result: dict | None = None
    error: str | None = None
    exit_code: int | None = None
    network_summary: dict | None = None
    # build_run: what cleanup removed and what it could not (never silent).
    cleanup: dict | None = None
    created_at: float = field(default_factory=time.time)
    finished_at: float | None = None
    cancel: asyncio.Event = field(default_factory=asyncio.Event)
    task: asyncio.Task | None = None
    # build_run only: explicit phases, ownership and an audit trail of manager actions.
    phase: str | None = None
    phase_history: list[dict] = field(default_factory=list)
    audit: list[dict] = field(default_factory=list)
    owner: str | None = None

    def public(self) -> dict:
        data = {
            "id": self.id, "kind": self.kind, "status": self.status, "events": self.events[-MAX_EVENTS:],
            "result": self.result, "error": self.error, "exit_code": self.exit_code,
            "network_summary": self.network_summary, "created_at": self.created_at, "finished_at": self.finished_at,
        }
        if self.kind == "build_run":
            data.update(phase=self.phase, phase_history=self.phase_history, audit=self.audit[-300:], owner=self.owner,
                        cleanup=self.cleanup)
        return data


class SandboxError(Exception):
    pass


def parse_result(text: str) -> dict | None:
    for line in reversed(text.splitlines()):
        if line.startswith(RESULT_PREFIX):
            try:
                value = json.loads(line[len(RESULT_PREFIX):])
            except ValueError:
                return None
            return value if isinstance(value, dict) else None
    return None


class RunManager:
    def __init__(self, settings: Settings, docker: DockerAPI, gateway: GatewayClient, credentials: CredentialStore):
        self.settings = settings
        self.docker = docker
        self.gateway = gateway
        self.credentials = credentials
        self.runs: dict[str, Run] = {}
        self._slots = asyncio.Semaphore(settings.max_concurrent_runs)
        self.build_slots = asyncio.Semaphore(settings.max_concurrent_build_runs)

    # ------------------------------------------------------------- public API
    def start(self, kind: str, spec: dict) -> Run:
        self._prune()
        run = Run(id=uuid.uuid4().hex[:20], kind=kind, owner=spec.get("requested_by"))
        self.runs[run.id] = run
        if kind == "build_run":
            from manager.buildrun import BuildRunExecutor

            run.task = asyncio.create_task(BuildRunExecutor(self, run, spec).execute())
        else:
            run.task = asyncio.create_task(self._execute(run, spec))
        return run

    def cancel(self, run_id: str) -> Run | None:
        run = self.runs.get(run_id)
        if run is not None:
            run.cancel.set()
        return run

    def _prune(self) -> None:
        cutoff = time.time() - 3600
        for rid in [r.id for r in self.runs.values() if r.finished_at and r.finished_at < cutoff]:
            self.runs.pop(rid, None)

    # -------------------------------------------------------------- execution
    async def _execute(self, run: Run, spec: dict) -> None:
        name = f"routes-sbx-{run.id}"
        network_created = gateway_connected = False
        container_id: str | None = None
        session_id: str | None = None
        upload_id = spec.get("upload_id")
        secret: str | None = None
        if run.kind == "source" and spec.get("patch"):
            # The patch travels like an upload: a private directory mounted
            # read-only at /input, removed with the run.
            upload_id = upload_id or str(uuid.uuid4())
            input_dir = Path(self.settings.uploads_dir) / upload_id
            input_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
            (input_dir / "patch.diff").write_text(spec["patch"], "utf-8")
        try:
            async with self._slots:
                if run.cancel.is_set():
                    run.status = "cancelled"
                    return
                run.status = "running"
                env: dict[str, str] = {"ROUTES_RUN_ID": run.id}
                network = "none"
                if run.kind == "discovery":
                    profile = discovery_profile()
                    env.update({
                        "ROUTES_TARGET_URL": spec["target_url"],
                        "ROUTES_MAX_PAGES": str(self.settings.max_crawl_pages),
                    })
                    needs_network = True
                else:
                    profile = analyzer_profile()
                    env.update({"ROUTES_SOURCE_KIND": spec["source"], "ROUTES_TARGET_HOST": spec.get("target_host", "")})
                    needs_network = spec["source"] == "github"
                    if spec["source"] == "github" and spec.get("credential_handle"):
                        secret = self.credentials.take(spec["credential_handle"], f"github:{spec['owner']}/{spec['repo']}")
                        if secret is None:
                            raise SandboxError(
                                "The private repository token expired or was already used. Provide it again."
                            )

                if needs_network:
                    await self.docker.create_network(name, run.id)
                    network_created = True
                    await self.docker.connect(name, self.settings.gateway_container)
                    gateway_connected = True
                    info = await self.docker.inspect_network(name)
                    subnet, gateway_ip = _network_details(info, self.settings.gateway_container)
                    if run.kind == "discovery":
                        session = await self.gateway.open_web(spec["target_host"], spec["target_port"], subnet,
                                                              ttl=profile.timeout_seconds + 120)
                        env["ROUTES_PROXY_URL"] = f"http://routes:{session['token']}@{gateway_ip}:3128"
                    else:
                        session = await self.gateway.open_github(spec["owner"], spec["repo"], spec.get("ref"), secret,
                                                                 subnet, ttl=profile.timeout_seconds + 120)
                        secret = None  # now held only by the gateway, for one use
                        env["ROUTES_IMPORT_URL"] = f"http://{gateway_ip}:3128/import"
                        env["ROUTES_PROXY_TOKEN"] = session["token"]
                    session_id = session["id"]
                    network = name

                container_spec_ = container_spec(
                    profile, run_id=run.id, kind=run.kind, env=env, network=network,
                    upload_volume=self.settings.upload_volume if upload_id else None, upload_id=upload_id,
                )
                container_id = await self.docker.create_container(name, container_spec_)
                await self.docker.start(container_id)
                await self._supervise(run, container_id, profile.timeout_seconds)
        except SandboxError as exc:
            run.status, run.error = "failed", str(exc)
        except DockerError as exc:
            log.error("docker error in run %s: %s", run.id, exc)
            run.status, run.error = "failed", f"The sandbox could not be started ({exc.message[:200]})."
        except Exception as exc:  # noqa: BLE001
            log.exception("run %s failed", run.id)
            run.status, run.error = "failed", f"Sandbox failure: {type(exc).__name__}."
        finally:
            secret = None
            if spec.get("credential_handle"):
                self.credentials.discard(spec["credential_handle"])
            await self._cleanup(run, name, container_id, network_created, gateway_connected, session_id, upload_id)
            run.finished_at = time.time()

    async def _supervise(self, run: Run, cid: str, timeout: int) -> None:
        deadline = time.monotonic() + timeout
        while True:
            state = (await self.docker.inspect(cid)).get("State", {})
            try:
                stderr = await self.docker.logs(cid, stdout=False, stderr=True, max_bytes=2 * 1024 * 1024)
                run.events = parse_events(stderr.decode("utf-8", "replace"))
            except DockerError:
                pass
            if not state.get("Running"):
                break
            if run.cancel.is_set():
                await self.docker.kill(cid)
                run.status, run.error = "cancelled", "Cancelled."
                return
            if time.monotonic() > deadline:
                await self.docker.kill(cid)
                run.status, run.error = "timeout", f"The sandbox exceeded its {timeout}s time limit."
                return
            await asyncio.sleep(1.5)
        run.exit_code = state.get("ExitCode")
        if state.get("OOMKilled"):
            run.status, run.error = "failed", "The sandbox ran out of memory."
            return
        stdout = await self.docker.logs(cid, stdout=True, stderr=False, max_bytes=MAX_RESULT_BYTES)
        result = parse_result(stdout.decode("utf-8", "replace"))
        if result is None:
            run.status = "failed"
            run.error = f"The sandbox exited (code {run.exit_code}) without producing a result."
            if run.events:
                run.error += f" Last stage: {run.events[-1]['stage']}."
            return
        if result.get("fatal"):
            run.status, run.error, run.result = "failed", str(result.get("error", "The sandbox reported a failure."))[:500], result
            return
        run.status, run.result = "completed", result

    async def _cleanup(self, run, name, container_id, network_created, gateway_connected, session_id, upload_id):
        steps = []
        if container_id:
            steps.append(self.docker.remove(container_id))
        if gateway_connected:
            steps.append(self.docker.disconnect(name, self.settings.gateway_container))
        for step in steps:
            try:
                await step
            except Exception:  # noqa: BLE001
                log.exception("cleanup step failed for run %s", run.id)
        if network_created:
            try:
                await self.docker.remove_network(name)
            except Exception:  # noqa: BLE001
                log.exception("network removal failed for run %s", run.id)
        if session_id:
            try:
                run.network_summary = await self.gateway.close(session_id)
            except Exception:  # noqa: BLE001
                log.exception("gateway session close failed for run %s", run.id)
        if upload_id:
            remove_upload(self.settings.uploads_dir, upload_id)

    async def cleanup_orphans(self) -> int:
        """Remove sandbox containers and networks left behind by a crash/restart."""
        removed = 0
        try:
            for c in await self.docker.list_containers():
                await self.docker.remove(c["Id"])
                removed += 1
            for n in await self.docker.list_networks():
                if n.get("Name", "").startswith("routes-sbx-"):
                    try:
                        await self.docker.disconnect(n["Name"], self.settings.gateway_container)
                    except Exception:  # noqa: BLE001  (the gateway is usually not attached)
                        pass
                    await self.docker.remove_network(n["Name"])
                    removed += 1
        except Exception:  # noqa: BLE001
            log.exception("orphan cleanup failed")
        removed += sweep_stale_uploads(self.settings.uploads_dir)
        return removed


def _network_details(info: dict, gateway_container: str) -> tuple[str, str]:
    configs = (info.get("IPAM") or {}).get("Config") or []
    subnet = next((c.get("Subnet") for c in configs if c.get("Subnet") and ":" not in c.get("Subnet")), None)
    gateway_ip = None
    for c in (info.get("Containers") or {}).values():
        if c.get("Name") == gateway_container:
            gateway_ip = (c.get("IPv4Address") or "").split("/")[0]
    if not subnet or not gateway_ip:
        raise SandboxError("The sandbox network could not be prepared.")
    return subnet, gateway_ip


def sweep_stale_uploads(root: str, max_age: float = 1800) -> int:
    """After a restart no run owns an upload; remove those older than the claim window."""
    removed = 0
    cutoff = time.time() - max_age
    try:
        entries = list(Path(root).iterdir())
    except OSError:
        return 0
    for entry in entries:
        try:
            uuid.UUID(entry.name)
            if entry.is_dir() and not entry.is_symlink() and entry.stat().st_mtime < cutoff:
                shutil.rmtree(entry, ignore_errors=True)
                removed += 1
        except (ValueError, OSError):
            continue
    return removed


def remove_upload(root: str, upload_id: str) -> None:
    try:
        uuid.UUID(upload_id)
    except ValueError:
        return
    shutil.rmtree(Path(root) / upload_id, ignore_errors=True)
