"""Build-runner unit tests (run inside routes/build-runner:local)."""

import json
import shutil
import time
import zipfile
from pathlib import Path

import pytest

from build_runner import isolation, procs
from build_runner.project import Unsupported, inspect, packages_with_install_scripts

FIXTURE = Path(__file__).parent / "fixtures" / "shop-app"


def copy_fixture(tmp_path) -> Path:
    dest = tmp_path / "app"
    shutil.copytree(FIXTURE, dest)
    return dest


def write_pkg(root: Path, **pkg) -> None:
    (root / "package.json").write_text(json.dumps(pkg))


# ------------------------------------------------------------------ profiling
def test_fixture_plan_uses_production_commands_and_ignores_repository_container_config(tmp_path):
    plan = inspect(copy_fixture(tmp_path))
    assert plan.install == ["npm", "ci", "--ignore-scripts", "--no-audit", "--no-fund"]
    assert plan.build == ["npm", "run", "build"] and plan.start == ["npm", "run", "start"]
    assert plan.needs_database and plan.db_packages == ["pg"]
    assert plan.schema_files == ["db/schema.sql"] and plan.seed_files == ["db/seed.sql"]
    assert {"Dockerfile", "docker-compose.yml", ".npmrc"} <= set(plan.ignored)
    assert "DATABASE_URL" in plan.env_names and plan.root_scripts == ["postinstall"]


def test_dev_server_start_script_is_replaced_with_next_start(tmp_path):
    root = tmp_path
    write_pkg(root, dependencies={"next": "14.2.25"}, scripts={"start": "next dev -p 4000"})
    (root / "package-lock.json").write_text("{}")
    plan = inspect(root)
    assert plan.start == ["node", "node_modules/next/dist/bin/next", "start"]
    assert plan.build == ["node", "node_modules/next/dist/bin/next", "build"]
    assert any("development server" in n for n in plan.notes)


@pytest.mark.parametrize("setup, message", [
    (lambda r: None, "No package.json"),
    (lambda r: write_pkg(r, dependencies={"next": "14"}), "No package-lock.json"),
    (lambda r: (write_pkg(r, dependencies={"next": "14"}), (r / "pnpm-lock.yaml").write_text("")), "pnpm"),
    (lambda r: (write_pkg(r, dependencies={"express": "4"}), (r / "package-lock.json").write_text("{}")), "Next.js"),
    (lambda r: (write_pkg(r, dependencies={"next": "14", "pg": "8"}), (r / "package-lock.json").write_text("{}")),
     "no SQL schema"),
])
def test_unsupported_projects_are_reported_not_guessed(tmp_path, setup, message):
    setup(tmp_path)
    with pytest.raises(Unsupported, match=message):
        inspect(tmp_path)


def test_install_script_detection_covers_scoped_nested_and_native_packages(tmp_path):
    nm = tmp_path / "node_modules"
    for rel, manifest in [("plain", {}), ("esbuild", {"scripts": {"postinstall": "node install.js"}}),
                          ("@scope/native", {}), ("outer/node_modules/inner", {"scripts": {"preinstall": "x"}})]:
        (nm / rel).mkdir(parents=True)
        (nm / rel / "package.json").write_text(json.dumps(manifest))
    (nm / "@scope/native/binding.gyp").write_text("{}")
    assert packages_with_install_scripts(tmp_path) == ["@scope/native", "esbuild", "inner"]


# ---------------------------------------------------------------- processes
def test_commands_are_time_limited_and_whole_process_groups_are_killed(tmp_path):
    started = time.monotonic()
    r = procs.run(["sh", "-c", "sleep 30 & sleep 30; echo never"], cwd=str(tmp_path), env={"PATH": "/usr/bin:/bin"},
                  timeout=1)
    assert r.timed_out and not r.ok and time.monotonic() - started < 10
    assert "never" not in r.tail


def test_output_is_kept_as_a_bounded_tail(tmp_path):
    r = procs.run(["sh", "-c", "yes routes | head -c 200000; echo; echo LAST"], cwd=str(tmp_path),
                  env={"PATH": "/usr/bin:/bin"}, timeout=20, tail_bytes=1024)
    assert r.ok and r.tail.rstrip().endswith("LAST") and len(r.tail) < 1200 and "omitted" in r.tail


# ---------------------------------------------------------------- isolation
def test_route_table_parsing(tmp_path):
    routes = tmp_path / "route"
    routes.write_text("Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n"
                      "eth0\t0000A8C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\n")   # 192.168.0.0/24, no default route
    nets = isolation.local_subnets(str(routes))
    assert [str(n) for n in nets] == ["192.168.0.0/24"] and not isolation.has_default_route(str(routes))
    routes.write_text(routes.read_text() + "eth0\t00000000\t0100A8C0\t0003\t0\t0\t0\t00000000\n")
    assert isolation.has_default_route(str(routes))


def test_probe_results_fail_closed_on_any_connection(monkeypatch):
    states = {("169.254.169.254", 80): "timeout", ("db", 5432): "connected", ("1.1.1.1", 443): "connected"}
    monkeypatch.setattr(isolation, "tcp_state", lambda h, p, timeout=1.5: states.get((h, p), "dns_failed"))
    ok = isolation.run_probes([isolation.Probe("metadata", "169.254.169.254", 80),
                               isolation.Probe("db", "db", 5432, expected="allowed")])
    assert ok["verdict"] == "isolated" and ok["violations"] == []
    bad = isolation.run_probes([isolation.Probe("internet", "1.1.1.1", 443)])
    assert bad["verdict"] == "violated" and "internet" in bad["violations"][0]


# ----------------------------------------------------------- source & patch
def _zip_fixture(tmp_path, extra=None) -> Path:
    archive = tmp_path / "input" / "source.zip"
    archive.parent.mkdir()
    with zipfile.ZipFile(archive, "w") as zf:
        for f in FIXTURE.rglob("*"):
            if f.is_file():
                zf.write(f, f.relative_to(FIXTURE).as_posix())
        for name, data in (extra or {}).items():
            zf.writestr(name, data)
    return archive


def _runner(tmp_path, monkeypatch):
    import build_runner.main as main

    monkeypatch.setattr(main, "WORK", tmp_path / "work")
    monkeypatch.setattr(main, "INPUT", tmp_path / "input")
    monkeypatch.setenv("ROUTES_SOURCE_KIND", "zip")
    events = []
    r = main.Runner()
    r.stage = lambda name, msg, **d: events.append(name)
    return main, r, events


def test_patch_is_applied_to_the_temporary_copy_only(tmp_path, monkeypatch):
    _zip_fixture(tmp_path)
    (tmp_path / "input" / "patch.diff").write_text((FIXTURE.parent / "shop-app.fix.diff").read_text())
    main, r, events = _runner(tmp_path, monkeypatch)
    original = (FIXTURE / "app/api/products/route.js").read_text()
    r.acquire()
    patched = (r.src / "app/api/products/route.js").read_text()
    assert "$1" in patched and "${q}" not in patched
    assert (FIXTURE / "app/api/products/route.js").read_text() == original
    assert events == ["source_ready"] and r.result["stages"]["source"]["patch"]["files"] == ["app/api/products/route.js"]


def test_patch_that_does_not_apply_is_a_build_failure(tmp_path, monkeypatch):
    _zip_fixture(tmp_path)
    (tmp_path / "input" / "patch.diff").write_text("--- a/lib/db.js\n+++ b/lib/db.js\n@@ -1 +1 @@\n-nope\n+x\n")
    main, r, _ = _runner(tmp_path, monkeypatch)
    with pytest.raises(main.Stop) as exc:
        r.acquire()
    assert exc.value.verification.value == "BUILD_FAILED" and exc.value.stage == "patch"


def test_traversal_in_the_snapshot_is_rejected(tmp_path, monkeypatch):
    _zip_fixture(tmp_path, extra={"../../escape.js": "x"})
    main, r, _ = _runner(tmp_path, monkeypatch)
    with pytest.raises(main.Stop, match="unsafe file path"):
        r.acquire()
    assert not (tmp_path / "escape.js").exists()


def test_repository_registry_configuration_is_disabled(tmp_path, monkeypatch):
    _zip_fixture(tmp_path)
    main, r, _ = _runner(tmp_path, monkeypatch)
    r.acquire()
    r.plan()
    assert not (r.src / ".npmrc").exists() and (r.src / ".npmrc.routes-ignored").exists()
    assert r.base_env()["npm_config_registry"] == "https://registry.npmjs.org/"


def test_application_environment_uses_placeholders_and_the_disposable_database(tmp_path, monkeypatch):
    _zip_fixture(tmp_path)
    main, r, _ = _runner(tmp_path, monkeypatch)
    r.db_host, r.db_password = "routes-sbx-x-db", "synthetic"
    r.acquire()
    env = r.app_env(r.plan())
    assert env["DATABASE_URL"] == "postgresql://app:synthetic@routes-sbx-x-db:5432/app"
    assert env["NODE_ENV"] == "production" and env["PORT"] == "3000"
    assert not any(k.startswith("ROUTES_") for k in env)


# ------------------------------------------------------ database name & env
def _db_project(root: Path, schema: str, **files) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    write_pkg(root, dependencies={"next": "14", "pg": "8"})
    (root / "package-lock.json").write_text("{}")
    (root / "database").mkdir()
    (root / "database" / "schema.sql").write_text(schema)
    for name, body in files.items():
        (root / name.replace("__", "/")).write_text(body)
    return root


def test_database_name_comes_from_the_schema_then_env_example_then_compose(tmp_path):
    schema = r"\getenv demo_password DB_DEMO_PASSWORD" + "\nGRANT CONNECT ON DATABASE nova_db TO x;\n"
    plan = inspect(_db_project(tmp_path / "a", schema))
    assert (plan.db_name, plan.db_name_source) == ("nova_db", "referenced by the SQL schema")
    assert "DB_DEMO_PASSWORD" in plan.env_names                 # \getenv variables get placeholders
    plan = inspect(_db_project(tmp_path / "b", "create table t (id int);",
                               **{".env.example": "DATABASE_URL=postgresql://u:p@localhost:5432/shopdb\n"}))
    assert (plan.db_name, plan.db_name_source) == ("shopdb", ".env.example")
    plan = inspect(_db_project(tmp_path / "c", "create table t (id int);",
                               **{"docker-compose.yml": "services:\n  db:\n    environment:\n      POSTGRES_DB: storedb\n"}))
    assert plan.db_name == "storedb" and "hint" in plan.db_name_source
    plan = inspect(_db_project(tmp_path / "d", "CREATE DATABASE own_db;\nGRANT CONNECT ON DATABASE own_db TO x;"))
    assert plan.db_name == "app"                                 # the SQL creates it itself
    plan = inspect(_db_project(tmp_path / "e", "create table t (id int);"))
    assert (plan.db_name, plan.db_name_source) == ("app", "default")


def test_extra_seed_files_follow_the_standard_one(tmp_path):
    root = _db_project(tmp_path, "create table t (id int);",
                       **{"database__seed.sql": "insert into t values (1);", "database__demo_seed.sql": "select 1;"})
    plan = inspect(root)
    assert plan.schema_files == ["database/schema.sql"]
    assert plan.seed_files == ["database/seed.sql", "database/demo_seed.sql"]


def test_app_and_psql_environment_use_the_expected_database(tmp_path, monkeypatch):
    _zip_fixture(tmp_path)
    main, r, _ = _runner(tmp_path, monkeypatch)
    r.db_host, r.db_password = "routes-sbx-x-db", "synthetic"
    r.acquire()
    plan = r.plan()
    plan.db_name = "nova_db"
    env = r.app_env(plan)
    assert env["DATABASE_URL"].endswith("/nova_db") and env["PGDATABASE"] == "nova_db" and env["DB_NAME"] == "nova_db"
