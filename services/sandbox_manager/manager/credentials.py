"""Ephemeral credential store. Holds private-repository tokens in process
memory only, for a short TTL, and releases each exactly once."""

from __future__ import annotations

import secrets
import time
from dataclasses import dataclass

DEFAULT_TTL = 15 * 60


@dataclass
class _Entry:
    secret: str
    scope: str
    expires_at: float


class CredentialStore:
    def __init__(self, ttl: int = DEFAULT_TTL, max_entries: int = 256):
        self._entries: dict[str, _Entry] = {}
        self.ttl = ttl
        self.max_entries = max_entries

    def put(self, secret: str, scope: str) -> str:
        self.sweep()
        if len(self._entries) >= self.max_entries:
            raise OverflowError("too many pending credentials")
        handle = "cred_" + secrets.token_urlsafe(24)
        self._entries[handle] = _Entry(secret=secret, scope=scope, expires_at=time.time() + self.ttl)
        return handle

    def take(self, handle: str, scope: str) -> str | None:
        """Remove and return the secret if the handle is valid for this scope."""
        entry = self._entries.pop(handle, None)
        if entry is None or entry.expires_at < time.time() or entry.scope != scope:
            return None
        secret, entry.secret = entry.secret, ""
        return secret

    def discard(self, handle: str) -> None:
        entry = self._entries.pop(handle, None)
        if entry is not None:
            entry.secret = ""

    def sweep(self) -> None:
        now = time.time()
        for handle in [h for h, e in self._entries.items() if e.expires_at < now]:
            self.discard(handle)

    def __len__(self) -> int:
        return len(self._entries)
