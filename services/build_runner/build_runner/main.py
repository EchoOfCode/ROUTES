"""Build runner sandbox entrypoint (fixed; the repository cannot change it).

Stages, each announced only when it actually starts:

  source_ready            source extracted to tmpfs, candidate patch applied to this copy
  dependencies_installing npm ci --ignore-scripts through the gateway's registry-only session
  awaiting_isolation      handshake: the Sandbox Manager removes all egress
  isolated                runner observed the change and probed forbidden destinations
  database_starting       schema/seed SQL applied to the run's disposable PostgreSQL
  building                production build, no network
  application_starting    production start, health check on the sandbox port
  application_ready       handshake: the manager starts the independent test runner

The runner then keeps the application up until the manager stops the
container (SIGTERM), and writes one structured, redacted result to stdout.
Nothing here decides whether a patch is secure.
"""

from __future__ import annotations

import os
import shutil
import signal
import sys
import threading
import time
from pathlib import Path

import httpx

from routes_shared.buildrun import (
    APP_PORT, STAGE_APPLICATION_READY, STAGE_AWAITING_ISOLATION, STAGE_ISOLATED, PatchRejected, Verification,
    validate_patch,
)
from routes_shared.events import emit
from routes_shared.redaction import redact_structure, redact_text
from routes_shared.sourcefiles import BUILD_EXCLUDED_DIRS, BUILD_SKIPPED_SUFFIXES

from build_runner import database, isolation, procs
from build_runner.project import BuildPlan, Unsupported, count_packages, inspect, packages_with_install_scripts

RESULT_PREFIX = "ROUTES_RESULT "
WORK = Path(os.environ.get("ROUTES_WORK_DIR", "/work"))
INPUT = Path(os.environ.get("ROUTES_INPUT_DIR", "/input"))
PLACEHOLDER = "routes-sandbox-placeholder"
NETWORK_ERRORS = ("ECONNRESET", "ETIMEDOUT", "EAI_AGAIN", "ENOTFOUND", "socket hang up", "network")


def _int_env(name: str, default: int) -> int:
    try:
        return max(1, int(os.environ.get(name, default)))
    except ValueError:
        return default


class Stop(Exception):
    """A stage failed; the result explains why."""

    def __init__(self, verification: Verification, stage: str, message: str):
        super().__init__(message)
        self.verification, self.stage, self.message = verification, stage, message


class Runner:
    def __init__(self) -> None:
        self.started = time.monotonic()
        self.src = WORK / "app"
        self.stop_requested = threading.Event()
        self.timeouts = {k: _int_env(f"ROUTES_TIMEOUT_{k.upper()}", d) for k, d in
                         (("install", 600), ("database", 120), ("build", 600), ("startup", 180), ("tests", 300),
                          ("isolation", 90))}
        self.result: dict = {"status": "failed", "stages": {}}
        self.app: procs.Background | None = None
        self.db_password = os.environ.get("ROUTES_DB_PASSWORD", "")
        self.db_host = os.environ.get("ROUTES_DB_HOST", "")
        gw = os.environ.get("ROUTES_GATEWAY_ADDR", "")
        self.gateway = (gw.rsplit(":", 1)[0], int(gw.rsplit(":", 1)[1])) if ":" in gw else None

    # ---------------------------------------------------------------- helpers
    def stage(self, name: str, message: str, **data: int) -> None:
        emit(name, message, **data)

    def record(self, key: str, value: dict) -> None:
        self.result["stages"][key] = value

    def base_env(self) -> dict[str, str]:
        return {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": os.environ.get("HOME", "/home/sandbox"),
                "LANG": "C.UTF-8", "TMPDIR": str(WORK / "tmp"), "NEXT_TELEMETRY_DISABLED": "1",
                "npm_config_update_notifier": "false", "npm_config_fund": "false", "npm_config_audit": "false",
                "npm_config_userconfig": str(WORK / ".routes-npmrc"), "npm_config_cache": str(WORK / ".npm-cache"),
                "npm_config_registry": "https://registry.npmjs.org/", "npm_config_offline": "true",
                "CI": "1"}

    def app_env(self, plan: BuildPlan) -> dict[str, str]:
        env = self.base_env()
        # Every variable the code references gets an inert placeholder, never a real secret.
        env.update({name: PLACEHOLDER for name in plan.env_names if name not in env and not name.startswith("npm_")})
        env.update({"NODE_ENV": "production", "PORT": str(APP_PORT), "HOSTNAME": "0.0.0.0"})
        if plan.needs_database:
            name = plan.db_name
            url = f"postgresql://app:{self.db_password}@{self.db_host}:5432/{name}"
            env.update(database.pg_env({}, host=self.db_host, password=self.db_password, dbname=name))
            env.update({"DATABASE_URL": url, "POSTGRES_URL": url, "POSTGRES_PRISMA_URL": url,
                        "POSTGRES_URL_NON_POOLING": url, "DB_HOST": self.db_host, "DB_PORT": "5432", "DB_USER": "app",
                        "DB_PASSWORD": self.db_password, "DB_NAME": name, "POSTGRES_DB": name,
                        "POSTGRES_USER": "app", "POSTGRES_PASSWORD": self.db_password})
        return env

    # ----------------------------------------------------------------- stages
    def acquire(self) -> None:
        from source_analyzer.acquisition.archive import ArchiveError, extract_tar_gz, extract_zip
        from source_analyzer.acquisition.github import ImportFailed, download

        self.src.mkdir(parents=True, exist_ok=True)
        (WORK / "tmp").mkdir(exist_ok=True)
        opts = {"skip_suffixes": BUILD_SKIPPED_SUFFIXES, "excluded_dirs": BUILD_EXCLUDED_DIRS, "keep_exec": True}
        try:
            if os.environ.get("ROUTES_SOURCE_KIND") == "github":
                archive = WORK / "repo.tar.gz"
                download(os.environ["ROUTES_IMPORT_URL"], os.environ["ROUTES_PROXY_TOKEN"], archive)
                report = extract_tar_gz(archive, self.src, **opts)
                archive.unlink(missing_ok=True)
            else:
                archive = INPUT / "source.zip"
                if not archive.is_file():
                    raise ArchiveError("The source snapshot is no longer available.")
                report = extract_zip(archive, self.src, **opts)
        except (ArchiveError, ImportFailed, KeyError) as exc:
            raise Stop(Verification.INCONCLUSIVE, "source", f"The source snapshot could not be prepared: {exc}") from exc
        os.environ.pop("ROUTES_PROXY_TOKEN", None)
        if report.files_written == 0:
            raise Stop(Verification.INCONCLUSIVE, "source", "The source snapshot contains no files.")
        patch = self.apply_patch()
        self.record("source", {"status": "ready", "files": report.files_written,
                               "skipped_links": report.skipped_links, "skipped_excluded": report.skipped_excluded,
                               "skipped_binaries": report.skipped_binary, "patch": patch})
        self.stage("source_ready", f"{report.files_written} files ready" + (", patch applied" if patch["applied"] else ""),
                   files=report.files_written)

    def apply_patch(self) -> dict:
        path = INPUT / "patch.diff"
        if not path.is_file():
            return {"applied": False, "files": []}
        text = path.read_text("utf-8", "replace")
        try:
            files = validate_patch(text)
        except PatchRejected as exc:
            raise Stop(Verification.INCONCLUSIVE, "patch", f"The candidate patch was rejected: {exc}") from exc
        local = WORK / "tmp" / "candidate.diff"
        local.write_text(text, "utf-8")
        env = {**self.base_env(), "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null"}
        check = procs.run(["git", "apply", "--check", "--whitespace=nowarn", str(local)], cwd=str(self.src), env=env,
                          timeout=60, tail_bytes=4096)
        if not check.ok:
            raise Stop(Verification.BUILD_FAILED, "patch",
                       "The candidate patch does not apply to the source snapshot: " + redact_text(check.tail, max_length=600))
        applied = procs.run(["git", "apply", "--whitespace=nowarn", str(local)], cwd=str(self.src), env=env, timeout=60)
        if not applied.ok:
            raise Stop(Verification.BUILD_FAILED, "patch", "The candidate patch could not be applied.")
        return {"applied": True, "files": files}

    def plan(self) -> BuildPlan:
        try:
            plan = inspect(self.src)
        except Unsupported as exc:
            raise Stop(Verification.DYNAMIC_VERIFICATION_UNSUPPORTED, "profiling", str(exc)) from exc
        # Repository registry configuration (custom registries, tokens) is never used.
        for name in (".npmrc", ".yarnrc", ".yarnrc.yml"):
            p = self.src / name
            if p.exists() and not p.is_symlink():
                p.rename(self.src / f"{name}.routes-ignored")
        (WORK / ".routes-npmrc").write_text("", "utf-8")
        self.result["project"] = plan.describe()
        return plan

    def install(self, plan: BuildPlan) -> list[str]:
        self.stage("dependencies_installing", f"Installing dependencies from {plan.lockfile} (install scripts disabled)")
        proxy = os.environ.get("ROUTES_PROXY_URL", "")
        env = {**self.base_env(), "npm_config_offline": "false", "npm_config_https_proxy": proxy,
               "npm_config_proxy": proxy, "npm_config_fetch_retries": "2", "npm_config_loglevel": "warn"}
        attempts, result = 0, None
        deadline = time.monotonic() + self.timeouts["install"]
        while attempts < 2:
            attempts += 1
            result = procs.run(plan.install, cwd=str(self.src), env=env, timeout=max(5, deadline - time.monotonic()))
            if result.ok or result.timed_out or not any(m in result.tail for m in NETWORK_ERRORS):
                break
            shutil.rmtree(self.src / "node_modules", ignore_errors=True)   # retry once, only for network errors
        packages = count_packages(self.src)
        scripts = packages_with_install_scripts(self.src) if result.ok else []
        self.record("dependencies", {"status": "installed" if result.ok else ("timeout" if result.timed_out else "failed"),
                                     "command": " ".join(plan.install), "attempts": attempts,
                                     "duration_seconds": result.duration, "packages": packages,
                                     "packages_with_install_scripts": scripts,
                                     "log_tail": redact_text(result.tail, max_length=6000)})
        shutil.rmtree(WORK / ".npm-cache", ignore_errors=True)
        if not result.ok:
            what = "timed out" if result.timed_out else f"failed (exit code {result.exit_code})"
            raise Stop(Verification.BUILD_FAILED, "dependencies", f"Dependency installation {what}.")
        return scripts

    def isolate(self, plan: BuildPlan) -> None:
        expected = 2 if plan.needs_database else 1
        self.stage(STAGE_AWAITING_ISOLATION, "Dependencies installed; removing network access",
                   needs_database=int(plan.needs_database))
        if not isolation.wait_for_cut(self.gateway, expected, self.timeouts["isolation"]):
            raise Stop(Verification.INCONCLUSIVE, "isolation",
                       "Network access was not removed after dependency installation; the run was stopped (fail closed).")
        # The run's own database is checked (and waited for) in the database stage.
        evidence = isolation.run_probes(isolation.forbidden_probes(self.gateway[0] if self.gateway else None))
        self.result["isolation"] = evidence
        if evidence["verdict"] != "isolated":
            raise Stop(Verification.INCONCLUSIVE, "isolation",
                       "Isolation check failed (fail closed): " + "; ".join(evidence["violations"])[:600])
        self.stage(STAGE_ISOLATED, f"Network isolation verified ({len(evidence['probes'])} probes)")

    def lifecycle_scripts(self, plan: BuildPlan, detected: list[str]) -> None:
        approved = [s.strip() for s in os.environ.get("ROUTES_APPROVED_SCRIPTS", "").split(",") if s.strip()]
        ran, failed = [], []
        env = self.base_env()
        deps = [d for d in detected if d in approved]
        if deps:
            r = procs.run(["npm", "rebuild", "--ignore-scripts=false", *deps], cwd=str(self.src), env=env,
                          timeout=self.timeouts["install"])
            (ran if r.ok else failed).extend(deps)
        if "<root>" in approved:
            for script in plan.root_scripts:
                r = procs.run(["npm", "run", script, "--if-present"], cwd=str(self.src), env=env,
                              timeout=self.timeouts["install"])
                (ran if r.ok else failed).append(f"<root>:{script}")
        self.result["stages"]["dependencies"].update({
            "scripts_run": ran, "scripts_failed": failed,
            "scripts_not_run": [d for d in detected if d not in approved],
            "root_scripts_not_run": [] if "<root>" in approved else plan.root_scripts,
        })
        if failed:
            raise Stop(Verification.BUILD_FAILED, "dependencies",
                       "Approved install scripts failed: " + ", ".join(failed)[:300])

    def provision_database(self, plan: BuildPlan) -> None:
        if not plan.needs_database:
            self.record("database", {"status": "not_required"})
            return
        self.stage("database_starting", f"Preparing disposable PostgreSQL ({len(plan.schema_files)} schema file(s))")
        env = database.pg_env(self.base_env(), host=self.db_host, password=self.db_password)
        ready, detail = database.wait_ready(env, str(self.src), self.timeouts["database"])
        info: dict = {"status": "failed", "engine": "PostgreSQL (disposable, private network)", "schema": [], "seed": []}
        self.record("database", info)
        if not ready:
            info["error"] = redact_text(detail, max_length=1000)
            raise Stop(Verification.BUILD_FAILED, "database", "The disposable database did not become ready.")
        info.update(name=plan.db_name, name_source=plan.db_name_source)
        if plan.db_name != "app":
            created, detail = database.create_database(plan.db_name, env, str(self.src), self.timeouts["database"])
            if not created:
                info["error"] = redact_text(detail, max_length=1000)
                raise Stop(Verification.BUILD_FAILED, "database", f"Creating the database {plan.db_name} failed.")
        # psql gets the application's environment (placeholders for referenced variables) and its database.
        env = self.app_env(plan)
        for f in plan.schema_files:
            step = database.apply_sql(f, env, str(self.src), self.timeouts["database"])
            info["schema"].append(step)
            if step["status"] != "applied":
                raise Stop(Verification.BUILD_FAILED, "database", f"Applying {f} to the disposable database failed.")
        for f in plan.seed_files:
            step = database.apply_sql(f, env, str(self.src), self.timeouts["database"])
            info["seed"].append(step)
            if step["status"] != "applied":
                raise Stop(Verification.BUILD_FAILED, "database", f"Applying seed file {f} failed.")
        synthetic = INPUT / "seed.sql"
        if synthetic.is_file():
            step = database.apply_sql(str(synthetic), env, str(self.src), self.timeouts["database"])
            step["file"] = "ROUTES synthetic seed data"
            info["seed"].append(step)
            if step["status"] != "applied":
                raise Stop(Verification.BUILD_FAILED, "database", "Applying the synthetic test data failed.")
        info["status"] = "ready"

    def build(self, plan: BuildPlan) -> None:
        self.stage("building", f"Building for production: {plan.build_label[:120]}")
        r = procs.run(plan.build, cwd=str(self.src), env=self.app_env(plan), timeout=self.timeouts["build"])
        status = "passed" if r.ok else ("timeout" if r.timed_out else "failed")
        self.record("build", {"status": status, "command": plan.build_label, "duration_seconds": r.duration,
                              "exit_code": r.exit_code, "log_tail": redact_text(r.tail, max_length=8000)})
        if not r.ok:
            raise Stop(Verification.BUILD_FAILED, "build", "The production build timed out." if r.timed_out else
                       f"The production build failed (exit code {r.exit_code}).")

    def start_app(self, plan: BuildPlan) -> None:
        self.stage("application_starting", f"Starting: {plan.start_label[:120]}")
        health_path = os.environ.get("ROUTES_HEALTH_PATH", "/")
        expected = {int(x) for x in os.environ.get("ROUTES_HEALTH_STATUS", "").split(",") if x.strip().isdigit()} \
            or set(range(200, 400))
        self.app = procs.start(plan.start, cwd=str(self.src), env=self.app_env(plan))
        deadline = time.monotonic() + self.timeouts["startup"]
        last = None
        info = {"status": "failed", "command": plan.start_label, "port": APP_PORT, "publish_host_port": False,
                "health": {"path": health_path, "last_status": None}}
        self.record("startup", info)
        with httpx.Client(timeout=5, trust_env=False, follow_redirects=False) as client:
            while time.monotonic() < deadline and not self.stop_requested.is_set():
                if not self.app.alive():
                    info["exit_code"] = self.app.proc.returncode
                    info["log_tail"] = redact_text(self.app.tail.text(), max_length=6000)
                    raise Stop(Verification.BUILD_FAILED, "startup",
                               f"The application exited during startup (exit code {self.app.proc.returncode}).")
                try:
                    last = client.get(f"http://127.0.0.1:{APP_PORT}{health_path}").status_code
                    info["health"]["last_status"] = last
                    if last in expected:
                        break
                except httpx.HTTPError:
                    pass
                time.sleep(1.0)
            else:
                info["log_tail"] = redact_text(self.app.tail.text(), max_length=6000)
                raise Stop(Verification.BUILD_FAILED, "startup",
                           f"The application did not pass its health check within {self.timeouts['startup']}s "
                           f"(last status: {last}).")
        info.update(status="passed", duration_seconds=round(time.monotonic() - self.app.started, 1))
        self.stage(STAGE_APPLICATION_READY, f"Application healthy on port {APP_PORT} ({health_path} -> {last})")

    def serve_until_stopped(self) -> None:
        deadline = time.monotonic() + self.timeouts["tests"] + 60
        while not self.stop_requested.wait(1.0):
            if time.monotonic() > deadline:
                break
            if self.app is not None and not self.app.alive():
                self.result["stages"]["startup"]["exited_during_tests"] = self.app.proc.returncode
                break

    # ------------------------------------------------------------------- main
    def run(self) -> dict:
        try:
            self.acquire()
            plan = self.plan()
            detected = self.install(plan)
            self.isolate(plan)
            self.lifecycle_scripts(plan, detected)
            self.provision_database(plan)
            self.build(plan)
            self.start_app(plan)
            self.serve_until_stopped()
            self.result["status"] = "completed"
        except Stop as stop:
            self.result.update(status="unsupported" if stop.verification == Verification.DYNAMIC_VERIFICATION_UNSUPPORTED
                               else "failed", verification=stop.verification.value, failed_stage=stop.stage,
                               error=stop.message[:800])
        except Exception as exc:  # noqa: BLE001
            self.result.update(status="failed", verification=Verification.INCONCLUSIVE.value, failed_stage="runner",
                               error=f"The build runner failed unexpectedly ({type(exc).__name__}).")
        finally:
            if self.app is not None:
                code = self.app.stop()
                self.result.setdefault("stages", {}).setdefault("startup", {})["app_log_tail"] = \
                    redact_text(self.app.tail.text(), max_length=8000)
                self.result["stages"]["startup"]["final_exit_code"] = code
            self.result["duration_seconds"] = round(time.monotonic() - self.started, 1)
            shutil.rmtree(self.src, ignore_errors=True)
        return redact_structure(self.result, max_length=9000)


def main() -> int:
    runner = Runner()
    signal.signal(signal.SIGTERM, lambda *_: runner.stop_requested.set())
    result = runner.run()
    sys.stdout.write(RESULT_PREFIX + __import__("json").dumps(result, separators=(",", ":")) + "\n")
    sys.stdout.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
