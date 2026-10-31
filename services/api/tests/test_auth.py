from fastapi.testclient import TestClient
from sqlalchemy import select

from app.models import User, UserSession


def test_register_sets_httponly_session_cookie(make_client):
    client = make_client()
    r = client.post("/api/v1/auth/register", json={"email": "New@Example.com", "password": "a sufficiently long pw"})
    assert r.status_code == 201
    assert r.json()["email"] == "new@example.com"
    set_cookie = r.headers["set-cookie"].lower()
    assert "routes_session=" in set_cookie and "httponly" in set_cookie and "samesite=lax" in set_cookie
    assert client.get("/api/v1/auth/me").status_code == 200


def test_password_is_hashed_with_argon2id(alice, db):
    user = db.scalar(select(User).where(User.email == "alice@example.com"))
    assert user.password_hash.startswith("$argon2id$")
    assert "correct horse" not in user.password_hash


def test_session_token_stored_hashed(alice, db):
    raw = alice.cookies.get("routes_session")
    stored = db.scalars(select(UserSession.token_hash)).all()
    assert raw not in stored and len(stored[0]) == 64


def test_duplicate_email_case_insensitive(alice, make_client):
    c = make_client()
    r = c.post("/api/v1/auth/register", json={"email": "ALICE@example.com", "password": "another long password"})
    assert r.status_code == 409


def test_weak_password_rejected(make_client):
    c = make_client()
    r = c.post("/api/v1/auth/register", json={"email": "x@example.com", "password": "short"})
    assert r.status_code == 422
    r = c.post("/api/v1/auth/register", json={"email": "x@example.com", "password": "aaaaaaaaaaaaaa"})
    assert r.status_code == 422


def test_login_logout_flow(alice, make_client):
    c = make_client()
    bad = c.post("/api/v1/auth/login", json={"email": "alice@example.com", "password": "wrong password!"})
    assert bad.status_code == 401
    assert bad.json()["error"]["code"] == "invalid_credentials"
    unknown = c.post("/api/v1/auth/login", json={"email": "nobody@example.com", "password": "wrong password!"})
    assert unknown.status_code == 401
    assert unknown.json() == bad.json()  # no user enumeration
    ok = c.post("/api/v1/auth/login", json={"email": "alice@example.com", "password": "correct horse battery"})
    assert ok.status_code == 200
    token = c.cookies.get("routes_session")
    assert c.post("/api/v1/auth/logout").status_code == 204
    # The old token is revoked server-side, not just cleared client-side.
    replay = TestClient(c.app, cookies={"routes_session": token})
    assert replay.get("/api/v1/auth/me").status_code == 401


def test_unauthenticated_requests_rejected(make_client):
    c = make_client()
    assert c.get("/api/v1/auth/me").status_code == 401
    assert c.get("/api/v1/projects").status_code == 401
    assert c.get("/api/v1/overview").status_code == 401


def test_csrf_required_for_unsafe_methods(app):
    c = TestClient(app)
    r = c.post("/api/v1/auth/register", json={"email": "c@example.com", "password": "long enough password"})
    assert r.status_code == 403
    assert r.json()["error"]["code"] == "csrf_failed"


def test_foreign_origin_rejected(make_client):
    c = make_client()
    r = c.post(
        "/api/v1/auth/login",
        json={"email": "a@example.com", "password": "whatever pass"},
        headers={"Origin": "https://evil.example"},
    )
    assert r.status_code == 403


def test_login_rate_limited(alice, make_client):
    c = make_client()
    codes = [
        c.post("/api/v1/auth/login", json={"email": "alice@example.com", "password": "nope nope nope"}).status_code
        for _ in range(12)
    ]
    assert codes[-1] == 429


def test_change_password_revokes_other_sessions(alice, make_client):
    other = make_client()
    other.post("/api/v1/auth/login", json={"email": "alice@example.com", "password": "correct horse battery"})
    assert other.get("/api/v1/auth/me").status_code == 200
    r = alice.post(
        "/api/v1/auth/change-password",
        json={"current_password": "correct horse battery", "new_password": "a brand new passphrase"},
    )
    assert r.status_code == 204
    assert alice.get("/api/v1/auth/me").status_code == 200
    assert other.get("/api/v1/auth/me").status_code == 401
