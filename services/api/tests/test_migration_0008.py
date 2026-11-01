"""Migration 0008 against a database that already holds pre-0008 data.

Uses its own scratch database so the shared test database stays at head.
Upgrade -> backfill checks -> downgrade (pre-0008 data intact, schema back to
0007) -> upgrade again.
"""

import os
import subprocess
import sys
import uuid
from pathlib import Path

import pytest
from sqlalchemy import create_engine, text

API_ROOT = Path(__file__).resolve().parents[1]
BASE_URL = os.environ["DATABASE_URL"].rsplit("/", 1)[0]
DB_NAME = "routes_migration_test"


def _alembic(*args):
    env = {**os.environ, "DATABASE_URL": f"{BASE_URL}/{DB_NAME}"}
    subprocess.run([sys.executable, "-m", "alembic", *args], cwd=API_ROOT, env=env, check=True,
                   capture_output=True)


@pytest.fixture(scope="module")
def engine():
    admin = create_engine(f"{BASE_URL}/postgres", isolation_level="AUTOCOMMIT")
    with admin.connect() as c:
        c.execute(text(f"DROP DATABASE IF EXISTS {DB_NAME}"))
        c.execute(text(f"CREATE DATABASE {DB_NAME}"))
    eng = create_engine(f"{BASE_URL}/{DB_NAME}")
    yield eng
    eng.dispose()
    with admin.connect() as c:
        c.execute(text(f"DROP DATABASE IF EXISTS {DB_NAME}"))
    admin.dispose()


def _seed_0007(conn) -> dict:
    ids = {k: uuid.uuid4() for k in ("user", "project", "assessment", "f1", "f2", "r_ok", "r_old", "r_new", "r_fail")}
    conn.execute(text("INSERT INTO users (id, email, password_hash, display_name) VALUES (:u, 'm@x.io', 'x', '')"),
                 {"u": ids["user"]})
    conn.execute(text("""INSERT INTO projects (id, owner_id, name, website_url, hostname, authorised_at,
                         authorisation_statement) VALUES (:p, :u, 'p', 'https://e.com', 'e.com', now(), 'ok')"""),
                 {"p": ids["project"], "u": ids["user"]})
    conn.execute(text("""INSERT INTO assessments (id, project_id, status, target_url, manifest_detected,
                         discovery_summary, cancel_requested) VALUES (:a, :p, 'completed', 'https://e.com', false,
                         '{}', false)"""), {"a": ids["assessment"], "p": ids["project"]})
    for f in ("f1", "f2"):
        conn.execute(text("""INSERT INTO security_findings (id, assessment_id, type, status, severity, confidence,
                             title, rule_id, plain_description, evidence_summary, technical_details, recommendation,
                             fingerprint) VALUES (:f, :a, 'SQL Injection', 'potential', 'high', 'medium', 't',
                             'routes.sqli.x', 'p', 'e', '{}', 'r', :fp)"""),
                     {"f": ids[f], "a": ids["assessment"], "fp": uuid.uuid4().hex})
    for run, finding, status, minutes in (("r_ok", "f1", "succeeded", 30), ("r_old", "f2", "pending", 20),
                                          ("r_new", "f2", "pending", 10), ("r_fail", "f1", "failed", 5)):
        conn.execute(text("""INSERT INTO remediations (id, finding_id, status, finding_status, cancel_requested,
                             created_at, updated_at) VALUES (:r, :f, :s, 'open', false,
                             now() - make_interval(mins => :m), now())"""),
                     {"r": ids[run], "f": ids[finding], "s": status, "m": minutes})
    conn.execute(text("""INSERT INTO remediation_iterations (id, remediation_id, iteration_no, candidate_code,
                         test_results, rescan_diff) VALUES (:i, :r, 1, 'legacy code', '{}', '{}')"""),
                 {"i": uuid.uuid4(), "r": ids["r_ok"]})
    return ids


def test_upgrade_backfills_and_downgrade_round_trips(engine):
    _alembic("upgrade", "0007")
    with engine.begin() as conn:
        ids = _seed_0007(conn)
        before = conn.execute(text("SELECT id, finding_id, status, finding_status FROM remediations ORDER BY id")).all()

    _alembic("upgrade", "head")
    with engine.connect() as conn:
        rows = {r.id: r for r in conn.execute(text(
            "SELECT id, project_id, assessment_id, stage, verdict, attempts_total, correlation_id, version "
            "FROM remediations")).all()}
        assert all(r.project_id == ids["project"] and r.assessment_id == ids["assessment"] for r in rows.values())
        assert rows[ids["r_ok"]].stage == "completed" and rows[ids["r_ok"]].verdict is None  # not retro-verified
        assert rows[ids["r_ok"]].attempts_total == 1
        assert rows[ids["r_fail"]].verdict == "failed" and rows[ids["r_new"]].stage == "queued"
        assert all(len(r.correlation_id) == 32 and r.version == 1 for r in rows.values())
        rfs = {r.remediation_id: r for r in conn.execute(text(
            "SELECT remediation_id, resolution, is_active, is_primary FROM remediation_findings")).all()}
        assert rfs[ids["r_ok"]].resolution == "inconclusive"
        assert rfs[ids["r_new"]].is_active and not rfs[ids["r_old"]].is_active  # one active run per finding
        assert all(r.is_primary for r in rfs.values())
        assert conn.scalar(text("SELECT count(*) FROM remediation_audit_events WHERE event_type = 'migrated'")) == 4
        assert conn.scalar(text("SELECT candidate_code FROM remediation_iterations")) == "legacy code"

    _alembic("downgrade", "0007")
    with engine.connect() as conn:
        after = conn.execute(text("SELECT id, finding_id, status, finding_status FROM remediations ORDER BY id")).all()
        assert after == before
        assert conn.scalar(text("SELECT to_regclass('remediation_findings')")) is None
        assert conn.scalar(text("SELECT count(*) FROM information_schema.columns WHERE table_name = 'remediations' "
                                "AND column_name = 'stage'")) == 0

    _alembic("upgrade", "head")
    with engine.connect() as conn:
        assert conn.scalar(text("SELECT version_num FROM alembic_version")) == "0008"
        assert conn.scalar(text("SELECT count(*) FROM remediation_findings")) == 4
