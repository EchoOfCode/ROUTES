"""Live end-to-end checks for build-and-run sandboxes.

Runs against the local engine (`routes engine up`) with the synthetic fixture
application only (services/build_runner/tests/fixtures/shop-app). No external
repository is executed. Every scenario must end with all run-owned Docker
resources and staged files removed.

    .venv/Scripts/python scripts/build_run_e2e.py [--only name,name] [--skip-restart]
"""

from __future__ import annotations

import argparse
import io
import json
import shutil
import subprocess
import sys
import tempfile
import time
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for p in ("packages/shared", "packages/core", "packages/storage", "apps/cli"):
    sys.path.insert(0, str(ROOT / p))

from routes_cli.context import Context  # noqa: E402
from routes_core.buildrun import BuildRunRequest, submit, wait  # noqa: E402
from routes_core.sources import classify  # noqa: E402

FIX = ROOT / "services/build_runner/tests/fixtures"
APP = FIX / "shop-app"
PLAN = json.loads((FIX / "shop-app.testplan.json").read_text("utf-8"))
PATCH = (FIX / "shop-app.fix.diff").read_text("utf-8")
RESULTS: list[tuple[str, bool, str]] = []


def docker(*args: str) -> str:
    return subprocess.run(["docker", *args], capture_output=True, text=True, check=False).stdout.strip()


def leftovers() -> list[str]:
    out = docker("ps", "-aq", "--filter", "label=routes.sandbox=true").split()
    out += [n for n in docker("network", "ls", "--format", "{{.Name}}").split() if n.startswith("routes-sbx-")]
    uploads = docker("compose", "-f", str(ROOT / "docker-compose.yml"), "exec", "-T", "sandbox-manager",
                     "ls", "/data/uploads")
    return out + [f"upload:{u}" for u in uploads.split()]


def variant(mutate) -> Path:
    tmp = Path(tempfile.mkdtemp(prefix="routes-br-"))
    dest = tmp / "app"
    shutil.copytree(APP, dest)
    mutate(dest)
    return dest


def run_case(ctx, name: str, *, source, plan=PLAN, patch=None, approved=(), timeouts=None, during=None,
             expect: dict) -> dict:
    client = ctx.engine_client()
    started = time.monotonic()
    req = BuildRunRequest(source=source, test_plan=plan, patch=patch, approved_scripts=list(approved),
                          timeouts=timeouts or {}, requested_by="e2e:" + "".join(ch if ch.isalnum() else "-" for ch in name)[:100])
    run = submit(client, req, cache_dir=ctx.home.cache)
    hook = {"done": False}

    def on_state(state):
        if during and not hook["done"]:
            hook["done"] = during(client, state)

    final = wait(client, run, on_state=on_state, poll_seconds=2)
    client.close()
    result = final.get("result") or {}
    problems = []
    for key, want in expect.items():
        got = result.get(key) if key != "status" else final.get("status")
        if key == "failed_stage":
            got = result.get("failed_stage")
        if callable(want):
            if not want(final):
                problems.append(f"{key} check failed")
        elif got != want:
            problems.append(f"{key}={got!r}, expected {want!r}")
    time.sleep(2)
    left = leftovers()
    if left:
        problems.append(f"leftover resources: {left}")
    detail = f"{result.get('verification')} {final.get('status')} in {time.monotonic() - started:.0f}s"
    if result.get("error"):
        detail += f" ({str(result['error'])[:110]})"
    ok = not problems
    RESULTS.append((name, ok, detail + ("" if ok else " | " + "; ".join(problems))))
    print(("PASS " if ok else "FAIL ") + name + ": " + RESULTS[-1][2], flush=True)
    return final


def rewrite(path: str, old: str, new: str):
    def go(root: Path):
        p = root / path
        p.write_text(p.read_text("utf-8").replace(old, new), "utf-8")
    return go


def case_by_category(cat: str, **want):
    return lambda f: all((f.get("result") or {}).get(cat, {}).get(k) == v for k, v in want.items())


def zip_with(entries: dict[str, bytes]) -> Path:
    tmp = Path(tempfile.mkdtemp(prefix="routes-br-zip-")) / "source.zip"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for f in APP.rglob("*"):
            if f.is_file():
                zf.write(f, f.relative_to(APP).as_posix())
        for name, data in entries.items():
            zf.writestr(name, data)
    tmp.write_bytes(buf.getvalue())
    return tmp


def proxy_denials() -> None:
    """Live docker-proxy checks run from inside the sandbox-manager container (its only Docker path)."""
    script = r'''
import httpx, json, uuid
c = httpx.Client(base_url="http://docker-proxy:2375/v1.47", timeout=20)
out = {}
def spec(run, net, **host):
    h = {"Memory": 268435456, "MemorySwap": 268435456, "NanoCpus": 500000000, "PidsLimit": 64, "ReadonlyRootfs": True,
         "CapDrop": ["ALL"], "SecurityOpt": ["no-new-privileges:true"], "NetworkMode": net,
         "Tmpfs": {"/tmp": "rw,noexec,nosuid,size=16m"}}
    h.update(host)
    return {"Image": "routes/test-runner:local", "Cmd": ["sleep", "1"], "User": "10001:10001",
            "Labels": {"routes.sandbox": "true", "routes.run": run}, "HostConfig": h}
a, b = "e2ea" + uuid.uuid4().hex[:8], "e2eb" + uuid.uuid4().hex[:8]
na, nb = f"routes-sbx-{a}-net", f"routes-sbx-{b}-net"
for n, r in ((na, a), (nb, b)):
    c.post("/networks/create", json={"Name": n, "Driver": "bridge", "Internal": True,
                                     "Labels": {"routes.sandbox": "true", "routes.run": r}})
ca = f"routes-sbx-{a}-c"
out["create_ok"] = c.post("/containers/create", params={"name": ca}, json=spec(a, na)).status_code
out["cross_run_connect"] = c.post(f"/networks/{nb}/connect", json={"Container": ca}).json().get("message", "")
out["gateway_to_private"] = c.post(f"/networks/{na}/connect", json={"Container": "routes-p1-gateway"}).json().get("message", "")
for name, extra in [("privileged", {"Privileged": True}), ("docker_socket", {"Binds": ["/var/run/docker.sock:/var/run/docker.sock"]}),
                    ("host_network", {"NetworkMode": "host"}), ("published_port", {"PortBindings": {"80/tcp": [{"HostPort": "8081"}]}}),
                    ("exec_tmpfs", {"Tmpfs": {"/tmp": "rw,exec,size=16m"}})]:
    out[name] = c.post("/containers/create", params={"name": f"routes-sbx-{a}-{name.replace('_','')}"}, json=spec(a, na, **extra)).json().get("message", "")
out["exec"] = c.post(f"/containers/{ca}/exec", json={"Cmd": ["id"]}).json().get("message", "")
out["archive_upload"] = c.put(f"/containers/{ca}/archive", params={"path": "/tmp"}, content=b"x").json().get("message", "")
out["unlabelled_container"] = c.post("/containers/routes-sandbox-manager-1/kill").json().get("message", "")
c.delete(f"/containers/{ca}", params={"force": "true"})
for n in (na, nb):
    c.delete(f"/networks/{n}")
print(json.dumps(out))
'''
    raw = docker("compose", "-f", str(ROOT / "docker-compose.yml"), "exec", "-T", "sandbox-manager", "python", "-c", script)
    out = json.loads(raw.splitlines()[-1])
    checks = {
        "cross_run_connect": "cross_run_attachment_forbidden", "gateway_to_private": "gateway_network_forbidden",
        "privileged": "privileged_forbidden", "docker_socket": "binds_forbidden", "host_network": "network_forbidden",
        "published_port": "portbindings_forbidden", "exec_tmpfs": "tmpfs_exec_forbidden",
        "exec": "container_operation_forbidden", "archive_upload": "container_operation_forbidden", "unlabelled_container": "container_not_sandbox",
    }
    problems = [f"{k}: {out.get(k)!r}" for k, reason in checks.items() if reason not in str(out.get(k))]
    if out.get("create_ok") != 201:
        problems.append(f"valid labelled create returned {out.get('create_ok')}")
    left = leftovers()
    RESULTS.append(("docker-proxy live denials", not problems and not left,
                    f"{len(checks)} denials confirmed" if not problems else "; ".join(problems) + (f" leftovers {left}" if left else "")))
    print(("PASS" if RESULTS[-1][1] else "FAIL") + " docker-proxy live denials: " + RESULTS[-1][2], flush=True)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", default="")
    ap.add_argument("--skip-restart", action="store_true")
    args = ap.parse_args()
    only = {x for x in args.only.split(",") if x}
    ctx = Context.load()
    pre = leftovers()
    if pre:
        print(f"Refusing to start: sandbox resources already exist: {pre}")
        return 2

    def want(name):
        return not only or name in only

    if want("proxy"):
        proxy_denials()
    if want("vulnerable"):
        run_case(ctx, "vulnerable app: security tests fail", source=classify(str(APP)),
                 expect={"verification": "TESTS_FAILED", "status": "completed",
                         "security": lambda f: f["result"]["security"]["failed"] == 3,
                         "functional": case_by_category("functional", failed=0)})
    if want("patched"):
        run_case(ctx, "patched copy: verified run", source=classify(str(APP)), patch=PATCH,
                 expect={"verification": "VERIFIED_RUN", "status": "completed",
                         "tests": lambda f: f["result"]["tests"]["passed"] == len(PLAN["tests"]),
                         "original_untouched": lambda f: "${q}" in (APP / "app/api/products/route.js").read_text()})
    if want("install"):
        bad_lock = variant(rewrite("package-lock.json", '"version": "8.13.1"', '"version": "8.13.999"'))
        run_case(ctx, "dependency installation fails", source=classify(str(bad_lock)),
                 expect={"verification": "BUILD_FAILED", "failed_stage": "dependencies"})
    if want("build"):
        broken = variant(rewrite("app/page.js", "export default async function Home() {", "export default async function Home( {"))
        run_case(ctx, "build fails", source=classify(str(broken)), expect={"verification": "BUILD_FAILED", "failed_stage": "build"})
    if want("startup"):
        crash = variant(rewrite("package.json", '"start": "next start"', '"start": "node -e \\"process.exit(7)\\""'))
        run_case(ctx, "application startup fails", source=classify(str(crash)),
                 expect={"verification": "BUILD_FAILED", "failed_stage": "startup"})
    if want("database"):
        bad_sql = variant(rewrite("db/schema.sql", "CREATE TABLE users (", "CREATE TABLE users ( this is not sql,"))
        run_case(ctx, "database setup fails", source=classify(str(bad_sql)),
                 expect={"verification": "BUILD_FAILED", "failed_stage": "database"})
    if want("unsupported"):
        def no_lock(root: Path):
            (root / "package-lock.json").unlink()
        run_case(ctx, "no lockfile: unsupported", source=classify(str(variant(no_lock))),
                 expect={"verification": "DYNAMIC_VERIFICATION_UNSUPPORTED", "status": "failed"})
    if want("timeout"):
        run_case(ctx, "build exceeds its time limit", source=classify(str(APP)), timeouts={"build": 5},
                 expect={"verification": "BUILD_FAILED", "failed_stage": "build",
                         "message": lambda f: "timed out" in (f["result"].get("error") or "")})
    if want("scripts"):
        run_case(ctx, "approved root lifecycle script runs only inside the sandbox", source=classify(str(APP)),
                 patch=PATCH, approved=["<root>"],
                 expect={"verification": "TESTS_FAILED",
                         "only_sandbox_test_fails": lambda f: [c["id"] for c in f["result"]["cases"] if c["status"] != "passed"] == ["sec-sandbox"],
                         "host_untouched": lambda f: not (APP / ".postinstall-ran").exists()})
    if want("traversal"):
        evil = zip_with({"../../escape.js": b"x"})
        run_case(ctx, "ZIP path traversal is rejected", source=classify(str(evil)),
                 expect={"verification": "INCONCLUSIVE", "message": lambda f: "unsafe" in (f["result"].get("error") or "")})
    if want("cancel"):
        def cancel_when_installing(client, state):
            if state.get("phase") in ("DEPENDENCIES_INSTALLING", "BUILDING"):
                client.cancel(state["id"])
                return True
            return False
        run_case(ctx, "user cancels the run", source=classify(str(APP)), during=cancel_when_installing,
                 expect={"status": "cancelled", "verification": "INCONCLUSIVE",
                         "phases": lambda f: f.get("phase") == "CLEANED_UP"})
    if want("restart") and not args.skip_restart:
        def restart_when_building(client, state):
            if state.get("phase") == "BUILDING":
                docker("compose", "-f", str(ROOT / "docker-compose.yml"), "restart", "sandbox-manager")
                return True
            return False
        run_case(ctx, "sandbox manager restarts mid-run (startup reconciliation)", source=classify(str(APP)),
                 during=restart_when_building,
                 expect={"status": "failed", "lost": lambda f: "lost" in (f.get("error") or "")})

    print()
    failed = [r for r in RESULTS if not r[1]]
    print(f"{len(RESULTS) - len(failed)}/{len(RESULTS)} build-run scenarios passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
