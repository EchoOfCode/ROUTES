"""Shared fixtures for worker job tests: real PostgreSQL (routes_test), schema reset per session."""

import os
import subprocess
import sys
from pathlib import Path

if "DATABASE_URL" in os.environ:
    _base = os.environ["DATABASE_URL"].rsplit("/", 1)[0]
    os.environ["DATABASE_URL"] = f"{_base}/routes_test"

import pytest  # noqa: E402
from sqlalchemy import text  # noqa: E402

from app.core.db import get_engine, get_sessionmaker  # noqa: E402


@pytest.fixture(scope="session", autouse=True)
def database():
    if "DATABASE_URL" not in os.environ:
        return
    with get_engine().begin() as conn:
        conn.execute(text("DROP SCHEMA public CASCADE; CREATE SCHEMA public;"))
    api_dir = Path("/srv/api") if Path("/srv/api").exists() else Path(__file__).resolve().parents[2] / "api"
    subprocess.run([sys.executable, "-m", "alembic", "upgrade", "head"], cwd=api_dir, check=True)


@pytest.fixture
def db():
    if "DATABASE_URL" not in os.environ:
        pytest.skip("DATABASE_URL not set in environment")
    with get_sessionmaker()() as s:
        yield s
