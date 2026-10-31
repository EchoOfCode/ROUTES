"""In-memory egress sessions. One session per sandbox run."""

from __future__ import annotations

import hashlib
import ipaddress
import secrets
import time
from dataclasses import dataclass, field
from typing import Literal

MAX_EVENTS = 2000


@dataclass
class GithubImport:
    owner: str
    repo: str
    ref: str | None
    token: str | None  # wiped after the single permitted import
    used: bool = False


@dataclass
class Session:
    id: str
    token: str
    mode: Literal["web", "github_import"]
    allowed_hosts: frozenset[str]
    allowed_ports: frozenset[int]
    subnet: ipaddress.IPv4Network | ipaddress.IPv6Network
    expires_at: float
    max_bytes: int
    github: GithubImport | None = None
    bytes_in: int = 0
    bytes_out: int = 0
    events: list[dict] = field(default_factory=list)
    dropped_events: int = 0
    connections: int = 0

    def record(self, **event) -> None:
        if len(self.events) >= MAX_EVENTS:
            self.dropped_events += 1
            return
        event["ts"] = round(time.time(), 3)
        self.events.append(event)

    @property
    def expired(self) -> bool:
        return time.time() > self.expires_at

    def summary(self) -> dict:
        allowed = sum(1 for e in self.events if e.get("decision") == "allow")
        denied = [e for e in self.events if e.get("decision") == "deny"]
        return {
            "requests": len(self.events) + self.dropped_events,
            "allowed": allowed,
            "denied": len(denied),
            "denied_reasons": sorted({e.get("reason", "") for e in denied}),
            "bytes_in": self.bytes_in,
            "bytes_out": self.bytes_out,
            "destinations": sorted({f"{e.get('host')}:{e.get('port')}" for e in self.events if e.get("host")})[:50],
            "events": self.events[-200:],
        }


class SessionStore:
    def __init__(self) -> None:
        self._by_token: dict[str, Session] = {}
        self._by_id: dict[str, Session] = {}

    def create(self, **kwargs) -> Session:
        token = secrets.token_urlsafe(32)
        sid = hashlib.sha256(token.encode()).hexdigest()[:24]
        session = Session(id=sid, token=token, **kwargs)
        self._by_token[token] = session
        self._by_id[sid] = session
        return session

    def by_token(self, token: str | None) -> Session | None:
        if not token:
            return None
        session = self._by_token.get(token)
        if session is None:
            return None
        if session.expired:
            self.close(session.id)
            return None
        return session

    def close(self, sid: str) -> Session | None:
        session = self._by_id.pop(sid, None)
        if session is not None:
            self._by_token.pop(session.token, None)
            if session.github is not None:
                session.github.token = None
        return session

    def sweep(self) -> None:
        for sid in [s.id for s in self._by_id.values() if s.expired]:
            self.close(sid)

    def __len__(self) -> int:
        return len(self._by_id)
