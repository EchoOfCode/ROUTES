import os
import subprocess
import sys
from pathlib import Path

# Point everything at the dedicated test database before app modules load.
_base = os.environ["DATABASE_URL"].rsplit("/", 1)[0]
os.environ["DATABASE_URL"] = f"{_base}/routes_test"
os.environ.setdefault("UPLOADS_DIR", "/tmp/routes-test-uploads")
os.environ.setdefault("ARTIFACTS_DIR", "/tmp/routes-test-artifacts")
os.environ["ALLOWED_ORIGINS"] = "http://localhost:3000"

import fakeredis  # noqa: E402
import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import text  # noqa: E402

from app.core import redis as redis_module  # noqa: E402
from app.core.db import get_engine, get_sessionmaker  # noqa: E402
from app.models import Base  # noqa: E402

API_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="session", autouse=True)
def migrated_database():
    with get_engine().begin() as conn:
        conn.execute(text("DROP SCHEMA public CASCADE; CREATE SCHEMA public;"))
    # Exercise the real migrations rather than metadata.create_all().
    subprocess.run([sys.executable, "-m", "alembic", "upgrade", "head"], cwd=API_ROOT, check=True)
    yield


@pytest.fixture(autouse=True)
def clean_tables():
    yield
    tables = ", ".join(t.name for t in reversed(Base.metadata.sorted_tables))
    with get_engine().begin() as conn:
        conn.execute(text(f"TRUNCATE {tables} RESTART IDENTITY CASCADE"))


@pytest.fixture(autouse=True)
def fake_redis(monkeypatch):
    server = fakeredis.FakeRedis()
    redis_module.get_redis.cache_clear()
    monkeypatch.setattr(redis_module, "get_redis", lambda: server)
    import app.api.auth as auth_api

    monkeypatch.setattr(auth_api, "get_redis", lambda: server)
    return server


@pytest.fixture(autouse=True)
def enqueued(monkeypatch):
    calls: list[tuple] = []
    from app.services import queueing

    def fake_enqueue(kind, job_id, **kwargs):
        calls.append((str(kind), str(job_id), kwargs))

    monkeypatch.setattr(queueing, "enqueue_job", fake_enqueue)
    monkeypatch.setattr(queueing, "cancel_job", lambda kind, job_id: None)
    return calls


@pytest.fixture(autouse=True)
def credentials(monkeypatch):
    store: dict[str, str] = {}
    from app.services import sandbox_client

    def fake_store(token, owner, repo):
        handle = f"handle-{len(store) + 1}"
        store[handle] = token
        return handle

    monkeypatch.setattr(sandbox_client, "store_ephemeral_credential", fake_store)
    monkeypatch.setattr(sandbox_client, "discard_credential", lambda h: store.pop(h, None))
    return store


@pytest.fixture
def db():
    with get_sessionmaker()() as session:
        yield session


@pytest.fixture
def app():
    from app.main import create_app

    return create_app()


def _csrf(client: TestClient) -> None:
    token = client.get("/api/v1/auth/csrf").json()["csrf_token"]
    client.headers["X-CSRF-Token"] = token


@pytest.fixture
def make_client(app):
    def _make(email: str | None = None, password: str = "correct horse battery") -> TestClient:
        client = TestClient(app)
        _csrf(client)
        if email:
            r = client.post("/api/v1/auth/register", json={"email": email, "password": password})
            assert r.status_code == 201, r.text
        return client

    return _make


@pytest.fixture
def alice(make_client):
    return make_client("alice@example.com")


@pytest.fixture
def bob(make_client):
    return make_client("bob@example.com")


def create_project(client: TestClient, url: str = "https://example.com") -> dict:
    r = client.post("/api/v1/projects", json={"website_url": url, "authorised": True})
    assert r.status_code == 201, r.text
    return r.json()
