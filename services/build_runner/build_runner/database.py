"""Disposable PostgreSQL provisioning from inside the build runner.

The database runs in its own sandbox container (routes/build-db) on a private
network shared only with this build runner. Schema and seed SQL from the
repository, and synthetic seed data supplied by ROUTES, are applied here with
``psql``; nothing ever connects to a database outside the run.
"""

from __future__ import annotations

import time

from build_runner.procs import run


def pg_env(base: dict[str, str], *, host: str, password: str, dbname: str = "app") -> dict[str, str]:
    return {**base, "PGHOST": host, "PGPORT": "5432", "PGUSER": "app", "PGPASSWORD": password, "PGDATABASE": dbname,
            "PGCONNECT_TIMEOUT": "5"}


def create_database(name: str, env: dict[str, str], cwd: str, timeout: float) -> tuple[bool, str]:
    """Create the database the project expects (name already validated as an identifier)."""
    r = run(["psql", "-X", "-q", "-v", "ON_ERROR_STOP=1", "-d", "app", "-c", f'CREATE DATABASE "{name}"'],
            cwd=cwd, env=env, timeout=timeout, tail_bytes=2048)
    return r.ok, r.tail[-1000:]


def wait_ready(env: dict[str, str], cwd: str, timeout: float) -> tuple[bool, str]:
    deadline = time.monotonic() + timeout
    last = ""
    while time.monotonic() < deadline:
        r = run(["pg_isready", "-q"], cwd=cwd, env=env, timeout=10)
        if r.ok:
            # pg_isready can succeed during the image's init phase; require a real query.
            q = run(["psql", "-X", "-q", "-t", "-c", "select 1"], cwd=cwd, env=env, timeout=15)
            if q.ok:
                return True, ""
            last = q.tail
        else:
            last = r.tail or "database not accepting connections yet"
        time.sleep(1.5)
    return False, last[-2000:]


def apply_sql(path: str, env: dict[str, str], cwd: str, timeout: float) -> dict:
    r = run(["psql", "-X", "-q", "-v", "ON_ERROR_STOP=1", "--single-transaction", "-f", path], cwd=cwd, env=env,
            timeout=timeout, tail_bytes=4096)
    return {"file": path, "status": "applied" if r.ok else ("timeout" if r.timed_out else "failed"),
            "duration_seconds": r.duration, "output": r.tail[-2000:] if not r.ok else ""}
