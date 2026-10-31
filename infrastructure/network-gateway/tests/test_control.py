import ipaddress

import pytest
from starlette.testclient import TestClient

from gateway.control import SessionRequest, build_control_app
from gateway.sessions import SessionStore

TOKEN = "t" * 32
AUTH = {"Authorization": f"Bearer {TOKEN}"}
CONTROL_NET = ipaddress.ip_network("10.250.0.0/24")
BODY = {"mode": "web", "allowed_host": "Example.com", "subnet": "10.200.0.0/24"}


def client(peer="10.250.0.5"):
    store = SessionStore()
    app = build_control_app(store, token=TOKEN, allowed_peers=[CONTROL_NET])
    return store, TestClient(app, client=(peer, 50000))


def test_requires_token():
    _, c = client()
    assert c.post("/sessions", json=BODY).status_code == 403
    assert c.post("/sessions", json=BODY, headers={"Authorization": "Bearer nope"}).status_code == 403


def test_rejects_peers_outside_control_network():
    # e.g. a sandbox container on a per-run network that obtained the token.
    _, c = client(peer="10.200.0.9")
    assert c.post("/sessions", json=BODY, headers=AUTH).status_code == 403


def test_create_and_close_session():
    store, c = client()
    r = c.post("/sessions", json=BODY, headers=AUTH)
    assert r.status_code == 201
    sid = r.json()["id"]
    session = store.by_token(r.json()["token"])
    assert session.allowed_hosts == frozenset({"example.com"})
    closed = c.delete(f"/sessions/{sid}", headers=AUTH)
    assert closed.status_code == 200 and closed.json()["requests"] == 0
    assert store.by_token(r.json()["token"]) is None


def test_sandbox_subnet_may_not_overlap_control_network():
    _, c = client()
    r = c.post("/sessions", json={**BODY, "subnet": "10.250.0.0/16"}, headers=AUTH)
    assert r.status_code == 422


def test_github_session_token_wiped_on_close():
    store, c = client()
    r = c.post("/sessions", headers=AUTH, json={
        "mode": "github_import", "subnet": "10.201.0.0/24",
        "github": {"owner": "acme", "repo": "app", "token": "ghp_" + "x" * 36},
    })
    assert r.status_code == 201
    session = store.by_token(r.json()["token"])
    c.delete(f"/sessions/{r.json()['id']}", headers=AUTH)
    assert session.github.token is None


def test_invalid_specs():
    for bad in [
        {**BODY, "allowed_ports": [22]},
        {**BODY, "mode": "anything"},
    ]:
        with pytest.raises(Exception):
            SessionRequest.model_validate(bad)
    _, c = client()
    assert c.post("/sessions", headers=AUTH, json={"mode": "github_import", "subnet": "10.201.0.0/24",
                                                    "github": {"owner": "../x", "repo": "a"}}).status_code == 422
