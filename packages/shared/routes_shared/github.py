"""GitHub repository reference parsing and token format checks."""

from __future__ import annotations

import re

GITHUB_URL_RE = re.compile(
    r"^(?:https?://)?(?:www\.)?github\.com/(?P<owner>[A-Za-z0-9](?:[A-Za-z0-9-]{0,38}))/"
    r"(?P<repo>[A-Za-z0-9._-]{1,100}?)(?:\.git)?/?(?:tree/(?P<ref>[A-Za-z0-9._/-]{1,255}))?/?$"
)
REF_RE = re.compile(r"^[A-Za-z0-9._/-]{1,255}$")
_TOKEN_RE = re.compile(r"[A-Za-z0-9_]{20,400}")


def is_github_url(value: str) -> bool:
    return bool(GITHUB_URL_RE.match(value.strip()))


def parse_github_url(value: str, ref: str | None = None) -> tuple[str, str, str | None]:
    """Return (owner, repo, ref). Raises ValueError with a user-facing message."""
    m = GITHUB_URL_RE.match(value.strip())
    if not m:
        raise ValueError("Enter a GitHub repository URL such as https://github.com/owner/repository.")
    return m.group("owner"), m.group("repo"), validate_ref(ref) or m.group("ref")


def validate_ref(v: str | None) -> str | None:
    if v is None or v.strip() == "":
        return None
    v = v.strip()
    if not REF_RE.match(v) or ".." in v:
        raise ValueError("The branch, tag or commit name is not valid.")
    return v


def validate_github_token(v: str | None) -> str | None:
    if v is None or v.strip() == "":
        return None
    v = v.strip()
    if not _TOKEN_RE.fullmatch(v):
        raise ValueError("The access token format is not recognised.")
    return v
