"""Shared fixtures for worker job tests: real PostgreSQL (routes_test), schema reset per session."""

import os
import subprocess
import sys
from pathlib import Path

_base = os.environ["DATABASE_URL"].rsplit("/", 1)[0]
os.environ["DATABASE_URL"] = f"{_base}/routes_test"

import pytest  # noqa: E402
from sqlalchemy import text  # noqa: E402

from app.core.db import get_engine, get_sessionmaker  # noqa: E402


@pytest.fixture(scope="session", autouse=True)
def database():
    with get_engine().begin() as conn:
        conn.execute(text("DROP SCHEMA public CASCADE; CREATE SCHEMA public;"))
    subprocess.run([sys.executable, "-m", "alembic", "upgrade", "head"], cwd=Path("/srv/api"), check=True)


@pytest.fixture
def db():
    with get_sessionmaker()() as s:
        yield s
