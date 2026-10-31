"""Secret redaction helpers.

Used inside the analyzer sandbox before results leave the container and again
in the worker before anything is written to PostgreSQL (defence in depth).
"""

from __future__ import annotations

import re

_SECRET_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}"),
    re.compile(r"github_pat_[A-Za-z0-9_]{40,}"),
    re.compile(r"(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{10,}"),
    re.compile(r"sk-(?:proj-|ant-)?[A-Za-z0-9_\-]{20,}"),
    re.compile(r"xox[abprs]-[A-Za-z0-9-]{10,}"),
    re.compile(r"AIza[0-9A-Za-z_\-]{35}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)"),
    re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
    # Connection strings with embedded credentials: keep scheme, hide credentials.
    re.compile(r"(?<=://)[^\s:/@'\"`]+:[^\s@'\"`]+(?=@)"),
]

# key = "value" / key: 'value' where the key name looks sensitive.
_ASSIGNMENT_RE = re.compile(
    r"""(?ix)
    (?P<key>[A-Za-z0-9_.\-]*(?:secret|password|passwd|pwd|token|api[_-]?key|apikey|
        private[_-]?key|client[_-]?secret|access[_-]?key|auth|credential)[A-Za-z0-9_.\-]*)
    (?P<sep>\s*[:=]\s*|\s*=>\s*)
    (?P<quote>['"`])(?P<value>[^'"`\n]{4,})(?P=quote)
    """
)

REDACTED = "[redacted]"


def mask_value(value: str) -> str:
    """Return a hint that never reveals more than 4 characters of a secret."""
    value = value or ""
    if len(value) <= 8:
        return REDACTED
    return f"{value[:4]}…{REDACTED}"


def redact_text(text: str | None, *, max_length: int = 400) -> str:
    if not text:
        return ""
    out = _ASSIGNMENT_RE.sub(
        lambda m: f"{m.group('key')}{m.group('sep')}{m.group('quote')}{mask_value(m.group('value'))}{m.group('quote')}",
        text,
    )
    for pattern in _SECRET_PATTERNS:
        out = pattern.sub(lambda m: mask_value(m.group(0)), out)
    if len(out) > max_length:
        out = out[: max_length - 1] + "…"
    return out


def contains_secret_like(text: str) -> bool:
    return any(p.search(text) for p in _SECRET_PATTERNS) or bool(_ASSIGNMENT_RE.search(text))


def redact_structure(value, *, max_length: int = 400):
    """Recursively redact every string inside a JSON-like structure."""
    if isinstance(value, str):
        return redact_text(value, max_length=max_length)
    if isinstance(value, list):
        return [redact_structure(v, max_length=max_length) for v in value]
    if isinstance(value, dict):
        return {k: redact_structure(v, max_length=max_length) for k, v in value.items()}
    return value
