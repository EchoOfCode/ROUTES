import socket

from conftest import create_project
from sqlalchemy import select

from app.models import Assessment, AssessmentJob


def test_project_requires_authorisation(alice):
    r = alice.post("/api/v1/projects", json={"website_url": "https://example.com", "authorised": False})
    assert r.status_code == 422
    assert "authorised" in r.json()["error"]["details"]


def test_project_creation_starts_discovery(alice, db, enqueued):
    body = create_project(alice, "example.com/some/path")
    project = body["project"]
    assert project["website_url"] == "https://example.com/some/path"
    assert project["hostname"] == "example.com"
    assert project["latest_assessment"]["status"] == "queued"
    jobs = db.scalars(select(AssessmentJob).where(AssessmentJob.assessment_id == body["assessment_id"])).all()
    assert sorted(j.kind for j in jobs) == ["discovery", "results"]
    assert [c[0] for c in enqueued] == ["discovery"]


def test_rejects_private_and_invalid_targets(alice):
    for url in ["http://localhost:3000", "http://10.0.0.1", "ftp://example.com", "http://169.254.169.254/"]:
        r = alice.post("/api/v1/projects", json={"website_url": url, "authorised": True})
        assert r.status_code == 422, url


def test_rejects_hostnames_resolving_privately(alice, monkeypatch):
    monkeypatch.setattr(
        socket, "getaddrinfo", lambda *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.1.10", 443))]
    )
    r = alice.post("/api/v1/projects", json={"website_url": "https://sneaky.example.com", "authorised": True})
    assert r.status_code == 422
    assert "private" in r.json()["error"]["message"]


def test_users_only_see_their_own_projects(alice, bob):
    a = create_project(alice)
    pid, aid = a["project"]["id"], a["assessment_id"]
    assert [p["id"] for p in alice.get("/api/v1/projects").json()] == [pid]
    assert bob.get("/api/v1/projects").json() == []
    for path in [
        f"/api/v1/projects/{pid}",
        f"/api/v1/projects/{pid}/assessments",
        f"/api/v1/assessments/{aid}",
        f"/api/v1/assessments/{aid}/pages",
        f"/api/v1/assessments/{aid}/endpoints",
        f"/api/v1/assessments/{aid}/findings",
        f"/api/v1/assessments/{aid}/source",
        f"/api/v1/assessments/{aid}/technologies",
    ]:
        assert bob.get(path).status_code == 404, path
    assert bob.post(f"/api/v1/assessments/{aid}/cancel").status_code == 404
    assert bob.post(f"/api/v1/projects/{pid}/assessments", json={}).status_code == 404
    assert bob.patch(f"/api/v1/projects/{pid}", json={"name": "pwned"}).status_code == 404
    assert bob.delete(f"/api/v1/projects/{pid}").status_code == 404
    assert bob.post(
        f"/api/v1/projects/{pid}/integrations/github", json={"repo_url": "https://github.com/a/b"}
    ).status_code == 404
    assert bob.get("/api/v1/assessments").json() == []
    assert bob.get("/api/v1/findings").json() == []


def test_duplicate_start_is_rejected(alice, db, enqueued):
    body = create_project(alice)
    pid = body["project"]["id"]
    r = alice.post(f"/api/v1/projects/{pid}/assessments", json={})
    assert r.status_code == 409
    assert r.json()["error"]["code"] == "assessment_active"
    assert db.scalar(select(Assessment).where(Assessment.project_id == pid)) is not None
    assert len([c for c in enqueued if c[0] == "discovery"]) == 1


def test_cancel_queued_assessment(alice, db, enqueued):
    body = create_project(alice)
    r = alice.post(f"/api/v1/assessments/{body['assessment_id']}/cancel")
    assert r.status_code == 200
    jobs = {j["kind"]: j["status"] for j in r.json()["jobs"]}
    assert jobs["discovery"] == "cancelled"
    assert any(c[0] == "results" for c in enqueued)


def test_delete_blocked_while_running(alice):
    body = create_project(alice)
    assert alice.delete(f"/api/v1/projects/{body['project']['id']}").status_code == 409


def test_rename_project(alice):
    body = create_project(alice)
    r = alice.patch(f"/api/v1/projects/{body['project']['id']}", json={"name": "Marketing site"})
    assert r.status_code == 200 and r.json()["name"] == "Marketing site"
