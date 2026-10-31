"""Build-and-run sandbox orchestration (run kind ``build_run``).

Uses the same Docker proxy, gateway and run lifecycle as discovery and source
analysis. One build-run owns, and always removes:

  networks   <base>-pkgnet   internal, gateway attached, registry-only session
                             (exists only while dependencies are installed)
             <base>-dbnet    internal, build runner + database only
             <base>-testnet  internal, build runner + test runner only
  containers <base>-app      routes/build-runner (fixed entrypoint): source, install,
                             build, start; the application never gets a host port
             <base>-db       routes/build-db: disposable PostgreSQL on tmpfs
             <base>-test     routes/test-runner: executes the declarative test plan
  files      uploads/<id>    source snapshot, candidate patch, synthetic seed
             uploads/<id>    test plan (separate directory, mounted only into the test runner)

Phases are advanced only by observed events (from the build runner) or by the
manager's own completed actions. The manager never judges whether a patch is
secure; it assembles the evidence the sandboxes produced.
"""

from __future__ import annotations

import asyncio
import logging
import secrets
import time
import uuid
from pathlib import Path

from routes_shared.buildrun import (
    STAGE_APPLICATION_READY, STAGE_AWAITING_ISOLATION, STAGE_PHASES, Phase, TestPlan, Verification,
)
from routes_shared.events import parse_events

from manager.docker_api import DockerError
from policies.limits import build_db_profile, build_runner_profile, build_timeouts, container_spec, test_runner_profile

log = logging.getLogger("routes.sandbox.buildrun")

POLL_SECONDS = 1.5
PHASE_MARGIN = 120          # manager-side watchdog on top of the runner's own stage timeouts
RETRY_DELAY = 2.0
MAX_RESULT_BYTES = 16 * 1024 * 1024


class BuildRunError(Exception):
    def __init__(self, message: str, verification: Verification = Verification.INCONCLUSIVE):
        super().__init__(message)
        self.verification = verification


def effective_timeouts(requested: dict[str, int] | None) -> dict[str, int]:
    """Callers may only lower the engine's configured limits."""
    limits = build_timeouts()
    for key, value in (requested or {}).items():
        if key in limits and isinstance(value, int) and value > 0:
            limits[key] = min(limits[key], value)
    return limits


class BuildRunExecutor:
    def __init__(self, manager, run, spec: dict):
        self.m = manager
        self.docker = manager.docker
        self.gateway = manager.gateway
        self.settings = manager.settings
        self.run = run
        self.spec = spec
        base = f"routes-sbx-{run.id}"
        self.pkg_net, self.db_net, self.test_net = f"{base}-pkgnet", f"{base}-dbnet", f"{base}-testnet"
        self.app_name, self.db_name, self.test_name = f"{base}-app", f"{base}-db", f"{base}-test"
        self.timeouts = effective_timeouts(spec.get("options", {}).get("timeouts"))
        self.networks: list[str] = []
        self.containers: list[str] = []
        self.gateway_on: str | None = None
        self.session_id: str | None = None
        self.dirs: list[str] = []
        self.gateway_ip: str | None = None
        self.needs_db = False
        self.app_events: list[dict] = []
        self.test_events: list[dict] = []
        self.test_result: dict | None = None
        self.app_result: dict | None = None
        self.phase_started = time.monotonic()
        self.db_password = secrets.token_urlsafe(24)   # synthetic database only; never a developer credential

    # -------------------------------------------------------------- bookkeeping
    def phase(self, phase: Phase) -> None:
        if self.run.phase == phase:
            return
        self.run.phase = phase.value
        self.run.phase_history.append({"phase": phase.value, "at": round(time.time(), 3)})
        self.phase_started = time.monotonic()

    def audit(self, action: str, target: str = "", **detail) -> None:
        entry = {"at": round(time.time(), 3), "action": action, "target": target}
        entry.update({k: v for k, v in detail.items() if v is not None})
        self.run.audit.append(entry)
        log.info("run %s: %s %s", self.run.id, action, target)

    async def retry(self, what: str, fn, *args, **kwargs):
        """One retry for transient Docker failures (5xx / connection problems), never for policy denials."""
        for attempt in (1, 2):
            try:
                return await fn(*args, **kwargs)
            except DockerError as exc:
                if attempt == 2 or exc.status < 500:
                    raise
                self.audit("retry", what, reason=exc.message[:120])
                await asyncio.sleep(RETRY_DELAY)
            except OSError:
                if attempt == 2:
                    raise
                self.audit("retry", what, reason="connection error")
                await asyncio.sleep(RETRY_DELAY)

    # -------------------------------------------------------------- artefacts
    def _dir(self, upload_id: str | None = None) -> tuple[str, Path]:
        upload_id = upload_id or str(uuid.uuid4())
        path = Path(self.settings.uploads_dir) / upload_id
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
        if upload_id not in self.dirs:
            self.dirs.append(upload_id)
        return upload_id, path

    def stage_artefacts(self, plan: TestPlan) -> tuple[str, str]:
        input_id, input_dir = self._dir(self.spec.get("upload_id"))
        if self.spec.get("patch"):
            (input_dir / "patch.diff").write_text(self.spec["patch"], "utf-8")
        if plan.database.seed_sql:
            (input_dir / "seed.sql").write_text(plan.database.seed_sql, "utf-8")
        plan_id, plan_dir = self._dir()
        (plan_dir / "testplan.json").write_text(plan.model_dump_json(by_alias=True), "utf-8")
        self.audit("artefacts_staged", input_id, patch=bool(self.spec.get("patch")), tests=len(plan.tests))
        return input_id, plan_id

    # -------------------------------------------------------------- execution
    async def execute(self) -> None:
        run = self.run
        secret: str | None = None
        try:
            self.phase(Phase.CREATED)
            plan = TestPlan.model_validate(self.spec["test_plan"])
            input_id, plan_id = self.stage_artefacts(plan)
            async with self.m.build_slots:
                if run.cancel.is_set():
                    raise asyncio.CancelledError
                run.status = "running"
                github = None
                if self.spec["source"] == "github":
                    if self.spec.get("credential_handle"):
                        secret = self.m.credentials.take(self.spec["credential_handle"],
                                                         f"github:{self.spec['owner']}/{self.spec['repo']}")
                        if secret is None:
                            raise BuildRunError("The private repository token expired or was already used.")
                    github = {"owner": self.spec["owner"], "repo": self.spec["repo"], "ref": self.spec.get("ref"),
                              "token": secret}
                # Package network: the only network with a route to the gateway.
                await self.retry("create_network", self.docker.create_network, self.pkg_net, run.id, egress=True)
                self.networks.append(self.pkg_net)
                await self.retry("connect_gateway", self.docker.connect, self.pkg_net, self.settings.gateway_container)
                self.gateway_on = self.pkg_net
                info = await self.docker.inspect_network(self.pkg_net)
                from manager.runs import _network_details
                subnet, self.gateway_ip = _network_details(info, self.settings.gateway_container)
                session = await self.gateway.open_packages(subnet, ttl=self.timeouts["install"] + 600,
                                                           max_bytes=self.settings.build_download_max_bytes,
                                                           github=github)
                secret = None
                if github:
                    github["token"] = None
                self.session_id = session["id"]
                self.audit("egress_session_opened", "registry.npmjs.org:443", repository_import=bool(github))
                env = {
                    "ROUTES_RUN_ID": run.id, "ROUTES_SOURCE_KIND": self.spec["source"],
                    "ROUTES_PROXY_URL": f"http://routes:{session['token']}@{self.gateway_ip}:3128",
                    "ROUTES_GATEWAY_ADDR": f"{self.gateway_ip}:3128",
                    "ROUTES_DB_HOST": self.db_name, "ROUTES_DB_PASSWORD": self.db_password,
                    "ROUTES_HEALTH_PATH": plan.health.path,
                    "ROUTES_HEALTH_STATUS": ",".join(str(s) for s in plan.health.expect_status),
                    "ROUTES_APPROVED_SCRIPTS": ",".join(self.spec.get("options", {}).get("approved_scripts", [])),
                }
                env.update({f"ROUTES_TIMEOUT_{k.upper()}": str(v) for k, v in self.timeouts.items() if k != "total"})
                if github:
                    env.update({"ROUTES_IMPORT_URL": f"http://{self.gateway_ip}:3128/import",
                                "ROUTES_PROXY_TOKEN": session["token"]})
                spec = container_spec(build_runner_profile(), run_id=run.id, kind="build_run", env=env,
                                      network=self.pkg_net, upload_volume=self.settings.upload_volume, upload_id=input_id)
                await self.retry("create_container", self.docker.create_container, self.app_name, spec)
                self.containers.append(self.app_name)
                await self.retry("start_container", self.docker.start, self.app_name)
                self.audit("container_started", self.app_name, image=spec["Image"], network=self.pkg_net)
                await self.supervise(plan, plan_id)
            self.finish()
        except asyncio.CancelledError:
            self.finish(cancelled=True)
        except BuildRunError as exc:
            self.finish(error=str(exc), verification=exc.verification)
        except DockerError as exc:
            log.error("docker error in build-run %s: %s", run.id, exc)
            self.finish(error=f"The sandbox could not be prepared ({exc.message[:200]}).")
        except Exception as exc:  # noqa: BLE001
            log.exception("build-run %s failed", run.id)
            self.finish(error=f"Sandbox failure: {type(exc).__name__}.")
        finally:
            secret = None
            if self.spec.get("credential_handle"):
                self.m.credentials.discard(self.spec["credential_handle"])
            await self.cleanup()
            self.phase(Phase.CLEANED_UP)
            run.finished_at = time.time()

    async def _events(self, name: str) -> list[dict]:
        try:
            raw = await self.docker.logs(name, stdout=False, stderr=True, max_bytes=2 * 1024 * 1024)
        except DockerError:
            return []
        return parse_events(raw.decode("utf-8", "replace"))

    async def supervise(self, plan: TestPlan, plan_id: str) -> None:
        run = self.run
        deadline = time.monotonic() + self.timeouts["total"]
        isolated = tests_started = False
        while True:
            self.app_events = await self._events(self.app_name)
            for ev in self.app_events:
                new = STAGE_PHASES.get(ev["stage"])
                if new is not None and _later(run.phase, new):
                    self.phase(new)
            stages = {e["stage"] for e in self.app_events}
            if STAGE_AWAITING_ISOLATION in stages and not isolated:
                needs_db = next((e.get("data", {}).get("needs_database") for e in self.app_events
                                 if e["stage"] == STAGE_AWAITING_ISOLATION), 0)
                await self.isolate(bool(needs_db))
                isolated = True
            if STAGE_APPLICATION_READY in stages and not tests_started:
                await self.start_tests(plan_id)
                tests_started = True
                self.phase(Phase.TESTING)
            self._publish_events()

            if run.cancel.is_set():
                self.audit("cancel_requested", run.id)
                raise asyncio.CancelledError
            if time.monotonic() > deadline:
                raise BuildRunError(f"The build-run exceeded its {self.timeouts['total']}s lifetime.")
            self._phase_watchdog()

            if tests_started and self.test_result is None:
                state = (await self.docker.inspect(self.test_name)).get("State", {})
                if not state.get("Running"):
                    self.test_events = await self._events(self.test_name)
                    self.test_result = await self._result(self.test_name) or {
                        "fatal": True, "error": f"The test runner exited (code {state.get('ExitCode')}) without results."}
                    self.audit("tests_finished", self.test_name, exit_code=state.get("ExitCode"))
                    self.phase(Phase.COLLECTING_RESULTS)
                    await self.docker.stop(self.app_name, 20)       # SIGTERM: the runner reports and exits
                    self.audit("container_stopped", self.app_name)
                else:
                    self.test_events = await self._events(self.test_name)
            app_state = (await self.docker.inspect(self.app_name)).get("State", {})
            if not app_state.get("Running"):
                if app_state.get("OOMKilled"):
                    raise BuildRunError("The build runner ran out of memory.", Verification.BUILD_FAILED)
                self.phase(Phase.COLLECTING_RESULTS)
                self.app_result = await self._result(self.app_name)
                self.audit("container_exited", self.app_name, exit_code=app_state.get("ExitCode"))
                if self.app_result is None:
                    raise BuildRunError(f"The build runner exited (code {app_state.get('ExitCode')}) without a result.")
                return
            await asyncio.sleep(POLL_SECONDS)

    def _phase_watchdog(self) -> None:
        limits = {Phase.DEPENDENCIES_INSTALLING.value: 2 * self.timeouts["install"],
                  Phase.DATABASE_STARTING.value: self.timeouts["database"] * 4,
                  Phase.BUILDING.value: self.timeouts["build"],
                  Phase.APPLICATION_STARTING.value: self.timeouts["startup"],
                  Phase.TESTING.value: self.timeouts["tests"]}
        limit = limits.get(self.run.phase)
        if limit and time.monotonic() - self.phase_started > limit + PHASE_MARGIN:
            raise BuildRunError(f"The {self.run.phase.lower().replace('_', ' ')} stage exceeded its time limit.")

    def _publish_events(self) -> None:
        self.run.events = (self.app_events + self.test_events)[-200:]

    async def _result(self, name: str) -> dict | None:
        from manager.runs import parse_result

        try:
            out = await self.docker.logs(name, stdout=True, stderr=False, max_bytes=MAX_RESULT_BYTES)
        except DockerError:
            return None
        return parse_result(out.decode("utf-8", "replace"))

    async def isolate(self, needs_db: bool) -> None:
        """Remove every egress path, then attach the private networks. Fail closed on any error."""
        self.needs_db = needs_db
        try:
            if self.session_id:
                self.run.network_summary = await self.gateway.close(self.session_id)
                self.audit("egress_session_closed", self.session_id)
                self.session_id = None
            # Egress is gone from here on: the package network is internal and the
            # gateway (its only exit) has left it.
            await self.docker.disconnect(self.pkg_net, self.settings.gateway_container)
            self.gateway_on = None
            self.audit("gateway_detached", self.pkg_net)
            if needs_db:
                await self.retry("create_network", self.docker.create_network, self.db_net, self.run.id, egress=False)
                self.networks.append(self.db_net)
                db_spec = container_spec(build_db_profile(), run_id=self.run.id, kind="build_run-db",
                                         env={"POSTGRES_USER": "app", "POSTGRES_DB": "app",
                                              "POSTGRES_PASSWORD": self.db_password,
                                              "PGDATA": "/var/lib/postgresql/data/pgdata"},
                                         network=self.db_net)
                await self.retry("create_container", self.docker.create_container, self.db_name, db_spec)
                self.containers.append(self.db_name)
                await self.retry("start_container", self.docker.start, self.db_name)
                self.audit("container_started", self.db_name, image=db_spec["Image"], network=self.db_net)
                await self.docker.connect(self.db_net, self.app_name)
                self.audit("network_attached", self.db_net, container=self.app_name)
            await self.retry("create_network", self.docker.create_network, self.test_net, self.run.id, egress=False)
            self.networks.append(self.test_net)
            await self.docker.connect(self.test_net, self.app_name)
            self.audit("network_attached", self.test_net, container=self.app_name)
            # Docker cannot attach networks to a container whose original network was
            # deleted, so the (already egress-free) package network is left last.
            await self.docker.disconnect(self.pkg_net, self.app_name)
            await self.docker.remove_network(self.pkg_net)
            self.networks.remove(self.pkg_net)
            self.audit("network_removed", self.pkg_net)
        except (DockerError, OSError, RuntimeError) as exc:
            raise BuildRunError(f"Network isolation could not be completed; the run was stopped ({exc}).") from exc

    async def start_tests(self, plan_id: str) -> None:
        peers = [f"{self.gateway_ip}:3128", "169.254.169.254:80", "1.1.1.1:443"]
        if self.needs_db:
            peers.insert(0, f"{self.db_name}:5432")
        env = {"ROUTES_RUN_ID": self.run.id, "ROUTES_APP_URL": f"http://{self.app_name}:3000",
               "ROUTES_FORBIDDEN_PEERS": ",".join(peers)}
        spec = container_spec(test_runner_profile(), run_id=self.run.id, kind="build_run-test", env=env,
                              network=self.test_net, upload_volume=self.settings.upload_volume, upload_id=plan_id)
        await self.retry("create_container", self.docker.create_container, self.test_name, spec)
        self.containers.append(self.test_name)
        await self.retry("start_container", self.docker.start, self.test_name)
        self.audit("container_started", self.test_name, image=spec["Image"], network=self.test_net)

    # ---------------------------------------------------------------- outcome
    def finish(self, *, cancelled: bool = False, error: str | None = None,
               verification: Verification = Verification.INCONCLUSIVE) -> None:
        run = self.run
        app = self.app_result or {}
        tests = self.test_result
        stages = app.get("stages") or {}
        if cancelled:
            run.status, run.error, verdict = "cancelled", "Cancelled.", Verification.INCONCLUSIVE
            self.phase(Phase.CANCELLED)
        elif error:
            run.status, run.error, verdict = ("timeout" if "exceeded" in error else "failed"), error, verification
        elif app.get("verification"):
            verdict = Verification(app["verification"])
            run.status, run.error = "failed", app.get("error") or "The build runner reported a failure."
        elif tests is None or tests.get("fatal"):
            verdict = Verification.INCONCLUSIVE
            run.status, run.error = "failed", (tests or {}).get("error") or "The test plan did not run."
        else:
            counts = tests.get("tests") or {}
            violations = [p for p in tests.get("isolation", []) if not p.get("ok")]
            if violations:
                verdict, run.status = Verification.INCONCLUSIVE, "failed"
                run.error = "The test runner could reach a destination it must not reach: " + \
                            ", ".join(f"{p['host']}:{p['port']}" for p in violations)
            elif not counts.get("total"):
                verdict, run.status, run.error = Verification.INCONCLUSIVE, "completed", "The test plan contains no tests."
            elif counts.get("failed"):
                verdict, run.status, run.error = Verification.TESTS_FAILED, "completed", None
            else:
                verdict, run.status, run.error = Verification.VERIFIED_RUN, "completed", None
        if not cancelled:
            self.phase(Phase.COMPLETED if run.status == "completed" else Phase.FAILED)
        if not stages:
            stages = self._stages_from_events()
        build = (stages.get("build") or {}).get("status", "not_run")
        startup = (stages.get("startup") or {}).get("status", "not_run")
        by_cat = (tests or {}).get("by_category") or {}
        run.result = {
            "run_id": run.id,
            "status": run.status,
            "verification": verdict.value,
            "error": run.error,
            "failed_stage": app.get("failed_stage"),
            "application": {"build": build, "startup": startup,
                            "health_check": "passed" if startup == "passed" else ("not_run" if startup == "not_run" else "failed")},
            "tests": (tests or {}).get("tests") or {"total": 0, "passed": 0, "failed": 0, "errors": 0},
            **{cat: by_cat.get(cat, {"total": 0, "passed": 0, "failed": 0}) for cat in ("security", "functional", "edge", "health")},
            "cases": (tests or {}).get("cases") or [],
            "stages": stages,
            "project": app.get("project"),
            "isolation": {"build_runner": app.get("isolation"), "test_runner": (tests or {}).get("isolation")},
            "duration_seconds": app.get("duration_seconds"),
        }

    def _stages_from_events(self) -> dict:
        """When the build runner could not report (killed, cancelled), describe only
        what its events prove happened; unfinished stages are marked interrupted."""
        seen = {e["stage"]: e for e in self.app_events}
        out: dict = {}
        if "source_ready" in seen:
            out["source"] = {"status": "ready", "files": (seen["source_ready"].get("data") or {}).get("files", 0),
                             "patch": {"applied": "patch applied" in seen["source_ready"].get("message", "")}}
        if "dependencies_installing" in seen:
            out["dependencies"] = {"status": "installed" if STAGE_AWAITING_ISOLATION in seen else "interrupted"}
        if "database_starting" in seen:
            out["database"] = {"status": "ready" if "building" in seen else "interrupted"}
        if "building" in seen:
            out["build"] = {"status": "passed" if "application_starting" in seen else "interrupted"}
        if "application_starting" in seen:
            out["startup"] = {"status": "passed" if STAGE_APPLICATION_READY in seen else "interrupted"}
        return out

    async def cleanup(self) -> None:
        """Idempotent: every step tolerates resources that are already gone."""
        for name in reversed(self.containers):
            try:
                await self.docker.remove(name)
                self.audit("container_removed", name)
            except Exception:  # noqa: BLE001
                log.exception("container removal failed for %s", name)
        self.containers.clear()
        if self.gateway_on:
            try:
                await self.docker.disconnect(self.gateway_on, self.settings.gateway_container)
                self.audit("gateway_detached", self.gateway_on)
            except Exception:  # noqa: BLE001
                log.exception("gateway disconnect failed for %s", self.gateway_on)
            self.gateway_on = None
        for name in list(self.networks):
            try:
                await self.docker.remove_network(name)
                self.audit("network_removed", name)
            except Exception:  # noqa: BLE001
                log.exception("network removal failed for %s", name)
        self.networks.clear()
        if self.session_id:
            try:
                self.run.network_summary = await self.gateway.close(self.session_id)
                self.audit("egress_session_closed", self.session_id)
            except Exception:  # noqa: BLE001
                log.exception("gateway session close failed")
            self.session_id = None
        from manager.runs import remove_upload

        for upload_id in self.dirs:
            remove_upload(self.settings.uploads_dir, upload_id)
            self.audit("artefacts_deleted", upload_id)
        self.dirs.clear()


_ORDER = [p.value for p in (Phase.CREATED, Phase.SOURCE_READY, Phase.DEPENDENCIES_INSTALLING, Phase.DATABASE_STARTING,
                            Phase.BUILDING, Phase.APPLICATION_STARTING, Phase.TESTING, Phase.COLLECTING_RESULTS)]


def _later(current: str | None, new: Phase) -> bool:
    """Phases only move forward."""
    if current not in _ORDER:
        return True
    return _ORDER.index(new.value) > _ORDER.index(current)
