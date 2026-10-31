import io
import zipfile

from conftest import create_project
from sqlalchemy import text

from app.core.config import get_settings
from app.core.db import get_engine

TOKEN = "github_pat_" + "A1b2C3d4" * 8


def _zip_bytes() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("package.json", '{"name": "demo"}')
    return buf.getvalue()


def test_connect_public_repo_attaches_source_job(alice, enqueued):
    body = create_project(alice)
    pid = body["project"]["id"]
    r = alice.post(
        f"/api/v1/projects/{pid}/integrations/github",
        json={"repo_url": "https://github.com/vercel/next.js/tree/canary"},
    )
    assert r.status_code == 201, r.text
    integ = r.json()["integration"]
    assert (integ["kind"], integ["repo_owner"], integ["repo_name"], integ["repo_ref"]) == (
        "github_public", "vercel", "next.js", "canary",
    )
    # Attached to the already-running assessment rather than starting another.
    assert r.json()["assessment_id"] == body["assessment_id"]
    kinds = [c[0] for c in enqueued]
    assert kinds == ["discovery", "source"]
    assert enqueued[1][2]["credential_handle"] is None


def test_invalid_repo_url(alice):
    pid = create_project(alice)["project"]["id"]
    for url in ["https://gitlab.com/a/b", "github.com/onlyowner", "https://github.com/a/b/../../x"]:
        r = alice.post(f"/api/v1/projects/{pid}/integrations/github", json={"repo_url": url})
        assert r.status_code == 422, url


def test_private_repo_token_is_never_persisted(alice, enqueued, credentials):
    pid = create_project(alice)["project"]["id"]
    r = alice.post(f"/api/v1/projects/{pid}/integrations/github",
                   json={"repo_url": "https://github.com/acme/private-app", "visibility": "private"})
    assert r.status_code == 422  # token required
    r = alice.post(
        f"/api/v1/projects/{pid}/integrations/github",
        json={"repo_url": "https://github.com/acme/private-app", "visibility": "private", "token": TOKEN},
    )
    assert r.status_code == 201, r.text
    assert TOKEN not in r.text
    # Only an opaque handle travels through the queue.
    handle = enqueued[-1][2]["credential_handle"]
    assert handle and TOKEN not in str(enqueued)
    assert credentials[handle] == TOKEN
    # Scan every table for the token.
    with get_engine().connect() as conn:
        tables = conn.execute(text("SELECT tablename FROM pg_tables WHERE schemaname='public'")).scalars().all()
        for t in tables:
            dump = conn.execute(text(f'SELECT CAST(t AS text) FROM "{t}" t')).scalars().all()
            assert not any(TOKEN in row for row in dump), t


def test_private_reassessment_without_token_skips_source(alice, db):
    body = create_project(alice)
    pid = body["project"]["id"]
    alice.post(f"/api/v1/projects/{pid}/integrations/github",
               json={"repo_url": "https://github.com/acme/app", "visibility": "private", "token": TOKEN})
    alice.post(f"/api/v1/assessments/{body['assessment_id']}/cancel")
    db.execute(text("UPDATE assessments SET status='cancelled'"))
    db.commit()
    r = alice.post(f"/api/v1/projects/{pid}/assessments", json={"include_source": True})
    assert r.status_code == 201
    assert any("never stored" in n for n in r.json()["notes"])
    a = alice.get(f"/api/v1/assessments/{r.json()['assessment_id']}").json()
    assert "source" not in [j["kind"] for j in a["jobs"]]


def test_zip_upload_validation(alice, monkeypatch):
    pid = create_project(alice)["project"]["id"]
    url = f"/api/v1/projects/{pid}/integrations/zip"
    r = alice.post(url, files={"file": ("notes.txt", b"hello", "text/plain")})
    assert r.status_code == 400
    r = alice.post(url, files={"file": ("fake.zip", b"not a zip at all", "application/zip")})
    assert r.status_code == 400
    monkeypatch.setattr(get_settings(), "max_upload_bytes", 100)
    r = alice.post(url, files={"file": ("big.zip", b"PK\x03\x04" + b"0" * 5000, "application/zip")})
    assert r.status_code == 413


def test_zip_upload_staged_and_queued(alice, enqueued):
    pid = create_project(alice)["project"]["id"]
    r = alice.post(f"/api/v1/projects/{pid}/integrations/zip",
                   files={"file": ("../../evil name.zip", _zip_bytes(), "application/zip")})
    assert r.status_code == 201, r.text
    integ = r.json()["integration"]
    assert integ["kind"] == "zip" and integ["upload_filename"] == "evil name.zip"
    a = alice.get(f"/api/v1/assessments/{r.json()['assessment_id']}").json()
    source = next(j for j in a["jobs"] if j["kind"] == "source")
    assert source["status"] == "queued"


def test_match_decision(alice):
    pid = create_project(alice)["project"]["id"]
    assert alice.post(f"/api/v1/projects/{pid}/integrations/match", json={"matches": True}).status_code == 404
    alice.post(f"/api/v1/projects/{pid}/integrations/github", json={"repo_url": "https://github.com/a/b"})
    r = alice.post(f"/api/v1/projects/{pid}/integrations/match", json={"matches": True})
    assert r.status_code == 200 and r.json()["match_status"] == "confirmed"
