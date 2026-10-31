"""`routes doctor`: check every dependency and report PASS / WARN / FAIL."""

from __future__ import annotations

import json
import platform
import sqlite3
import sys
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

from routes_core.engine import EngineUnavailable
from routes_storage.db import SCHEMA_VERSION

from routes_cli import __version__
from routes_cli.context import Context
from routes_cli.engine_ctl import SANDBOX_IMAGES, docker_available, run_quiet

PASS, WARN, FAIL = "PASS", "WARN", "FAIL"

_ANALYZER_PROBE = ("import importlib.metadata as m, json; "
                   "print(json.dumps({k: m.version(k) for k in ('semgrep', 'tree-sitter', 'tree-sitter-javascript', "
                   "'tree-sitter-typescript')}))")
_DISCOVERY_PROBE = ("import importlib.metadata as m, json, glob; "
                    "print(json.dumps({'playwright': m.version('playwright'), "
                    "'chromium': bool(glob.glob('/ms-playwright/chromium*/chrome-linux*/chrome') "
                    "or glob.glob('/ms-playwright/chromium_headless_shell*/chrome-*/headless_shell'))}))")


@dataclass(frozen=True)
class Check:
    group: str
    name: str
    status: str
    detail: str
    hint: str = ""


def _probe_image(image: str, code: str) -> dict | None:
    """Read tool versions from a sandbox image: no network, read-only, no capabilities,
    non-root, nothing mounted. Only ROUTES' own image code runs."""
    rc, out = run_quiet(["docker", "run", "--rm", "--network", "none", "--read-only", "--cap-drop", "ALL",
                         "--security-opt", "no-new-privileges", "--user", "10001:10001", "--memory", "256m",
                         "--pids-limit", "64", "--label", "routes.doctor=true", "--entrypoint", "python",
                         image, "-c", code], timeout=60)
    if rc != 0:
        return None
    try:
        return json.loads(out.splitlines()[-1])
    except (ValueError, IndexError):
        return None


def run_checks(ctx: Context, *, probe_images: bool = True) -> list[Check]:
    checks: list[Check] = []
    add = checks.append
    py = sys.version_info
    add(Check("Local", "Python runtime", PASS if py >= (3, 11) else FAIL,
              f"{platform.python_implementation()} {platform.python_version()}",
              "" if py >= (3, 11) else "ROUTES needs Python 3.11 or newer."))
    add(Check("Local", "ROUTES installation", PASS, f"routes-cli {__version__}"))

    try:
        with ctx.session() as db:
            version = db.connection().exec_driver_sql("PRAGMA user_version").scalar()
            db.connection().exec_driver_sql("PRAGMA quick_check").scalar()
        add(Check("Local", "SQLite database", PASS if version == SCHEMA_VERSION else WARN,
                  f"{ctx.home.db} (schema v{version}, SQLite {sqlite3.sqlite_version})"))
    except Exception as exc:  # noqa: BLE001
        add(Check("Local", "SQLite database", FAIL, f"{type(exc).__name__}: {exc}"[:200], "Run `routes init`."))

    es = ctx.engine
    if es.compose_file and es.compose_file.is_file():
        add(Check("Configuration", "Engine definition", PASS, str(es.compose_file)))
    else:
        add(Check("Configuration", "Engine definition", FAIL, "docker-compose.yml not found",
                  "Run `routes init` inside the ROUTES folder or set ROUTES_COMPOSE_FILE."))
    if es.token and len(es.token) >= 24:
        add(Check("Configuration", "Engine credentials", PASS, f"token loaded from {es.env_file}"))
    else:
        add(Check("Configuration", "Engine credentials", FAIL, "SANDBOX_MANAGER_TOKEN missing", "Run `routes init`."))
    if ctx.dev_allow_hosts():
        add(Check("Configuration", "Development allowlist", WARN, ", ".join(sorted(ctx.dev_allow_hosts())),
                  "GATEWAY_DEV_ALLOW_HOSTS lets these hosts resolve to private addresses. Keep it empty for real use."))

    if not docker_available():
        add(Check("Docker", "Docker daemon", FAIL, "docker command not found", "Install Docker Desktop or Docker Engine."))
        docker_ok = False
    else:
        rc, out = run_quiet(["docker", "version", "--format", "{{.Server.Version}}"])
        docker_ok = rc == 0 and bool(out)
        add(Check("Docker", "Docker daemon", PASS if docker_ok else FAIL, f"Engine {out}" if docker_ok else out[:200],
                  "" if docker_ok else "Start Docker Desktop (or the Docker service) and try again."))

    images: dict[str, bool] = {}
    if docker_ok:
        for image in SANDBOX_IMAGES:
            rc, out = run_quiet(["docker", "image", "inspect", image, "--format", "{{.Created}}"])
            images[image] = rc == 0
            add(Check("Docker", f"Image {image}", PASS if rc == 0 else FAIL,
                      f"built {out[:19].replace('T', ' ')}" if rc == 0 else "not built",
                      "" if rc == 0 else "Run `routes engine up` to build it."))

    health = None
    try:
        with ctx.engine_client() as client:
            health = client.health()
        add(Check("Engine", "Sandbox Manager", PASS, f"{es.url} · {health.get('active_runs', 0)} active run(s)"))
    except EngineUnavailable as exc:
        add(Check("Engine", "Sandbox Manager", FAIL, str(exc), "Run `routes engine up`."))
    if health is not None:
        add(Check("Engine", "Docker API proxy", PASS if health.get("docker") else FAIL,
                  "reachable, default-deny policy" if health.get("docker") else "manager cannot reach the proxy",
                  "" if health.get("docker") else "docker compose logs docker-proxy"))
        add(Check("Engine", "Network gateway", PASS if health.get("gateway") else FAIL,
                  "reachable, egress restricted per run" if health.get("gateway") else "manager cannot reach the gateway",
                  "" if health.get("gateway") else "docker compose logs network-gateway"))
    else:
        for name in ("Docker API proxy", "Network gateway"):
            add(Check("Engine", name, WARN, "not checked (Sandbox Manager unavailable)"))

    tool_checks = [("routes/analyzer:local", _ANALYZER_PROBE), ("routes/discovery:local", _DISCOVERY_PROBE)]
    results: dict[str, dict | None] = {}
    if probe_images and docker_ok:
        with ThreadPoolExecutor(2) as pool:
            futures = {img: pool.submit(_probe_image, img, code) for img, code in tool_checks if images.get(img)}
            results = {img: f.result() for img, f in futures.items()}
    a = results.get("routes/analyzer:local")
    d = results.get("routes/discovery:local")
    not_checked = "not checked" + ("" if probe_images else " (--quick)")
    for name, value in (("Semgrep", a and a.get("semgrep")),
                        ("Tree-sitter", a and f"{a.get('tree-sitter')} (javascript {a.get('tree-sitter-javascript')}, "
                                              f"typescript {a.get('tree-sitter-typescript')})")):
        add(Check("Analysis tools", name, PASS if value else (WARN if not probe_images or not docker_ok else FAIL),
                  f"{value} in analyzer sandbox" if value else not_checked))
    pw = d and d.get("playwright")
    add(Check("Analysis tools", "Playwright", PASS if pw else (WARN if not probe_images or not docker_ok else FAIL),
              f"{pw} in discovery sandbox" if pw else not_checked))
    chromium = d and d.get("chromium")
    add(Check("Analysis tools", "Chromium", PASS if chromium else (WARN if not d else FAIL),
              "installed in discovery sandbox" if chromium else (not_checked if not d else "missing from image")))
    return checks


def summary(checks: list[Check]) -> tuple[int, int, int]:
    return (sum(c.status == PASS for c in checks), sum(c.status == WARN for c in checks),
            sum(c.status == FAIL for c in checks))
