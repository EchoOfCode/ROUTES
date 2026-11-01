"""Secret redaction helpers.

Used inside the analyzer sandbox before results leave the container and again
in the worker before anything is written to PostgreSQL (defence in depth), and
by redact_for_llm()/restore() before/after anything leaves worker-remediate
for an external LLM.
"""

from __future__ import annotations

import math
import re
from collections import Counter

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

# Recorded with every remediation context so a later reader knows exactly
# which rules sanitised what an external model received. Bump it whenever
# _SECRET_PATTERNS, _ASSIGNMENT_RE or the entropy rule change.
REDACTION_ENGINE = "routes_shared.redaction.redact_for_llm"
REDACTION_RULESET_VERSION = "2026.11.1"


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


_STRING_LITERAL_RE = re.compile(r"""(['"`])((?:\\.|(?!\1)[^\\\n])*)\1""")
# A module specifier is not a credential, and masking it makes a snippet unreadable.
_MODULE_SPECIFIER_RE = re.compile(r"(?i)(?:\bfrom\s*|\brequire\s*\(\s*|\bimport\s*\(?\s*)$")


def mask_string_literals(text: str | None, *, min_length: int = 8) -> str:
    """Mask the contents of quoted literals, keeping the surrounding code.

    redact_text() only masks a literal when a sensitive-looking key name sits
    next to it, so it cannot see a secret passed positionally
    (jwt.sign(payload, "...")). Code snippets are kept for triage, where the
    structure matters and a long literal almost never does.
    """
    if not text:
        return ""

    def replace(match: re.Match[str]) -> str:
        quote, value = match.group(1), match.group(2)
        if len(value) < min_length or _MODULE_SPECIFIER_RE.search(text[: match.start()]):
            return match.group(0)
        return f"{quote}{mask_value(value)}{quote}"

    return _STRING_LITERAL_RE.sub(replace, text)


def redact_structure(value, *, max_length: int = 400):
    """Recursively redact every string inside a JSON-like structure."""
    if isinstance(value, str):
        return redact_text(value, max_length=max_length)
    if isinstance(value, list):
        return [redact_structure(v, max_length=max_length) for v in value]
    if isinstance(value, dict):
        return {k: redact_structure(v, max_length=max_length) for k, v in value.items()}
    return value


# --------------------------------------------------------------------------
# Reversible redaction for text sent to an external LLM (worker-remediate).
# Unlike redact_text()/mask_value() above (irreversible, used for storage and
# logging), redact_for_llm() keeps a placeholder->real-value map so the real
# secret can be restored locally once the LLM's response comes back. The LLM
# itself only ever sees <SECRET_n> placeholders, never a real value.

def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    length = len(s)
    counts = Counter(s)
    return -sum((n / length) * math.log2(n / length) for n in counts.values())


# Quoted string literals of 16+ characters; backreference keeps the quote
# kind consistent (a '...' literal is never closed by a " or `).
_ENTROPY_STRING_RE = re.compile(r"""(['"`])((?:\\.|(?!\1).){16,})\1""")
_ENTROPY_THRESHOLD = 4.0


def redact_for_llm(text: str | None) -> tuple[str, dict[str, str]]:
    """Deterministic, reversible redaction. Replaces secrets with numbered
    placeholders (<SECRET_1>, <SECRET_2>, ...) using, in order: the same
    context-keyword assignments and known secret-format regexes as
    redact_text(), then Shannon entropy > 4.0 on any remaining quoted string
    literal of 16+ characters. The same real value always gets the same
    placeholder. Returns (redacted_text, placeholder_map); pass the map to
    restore() to put the real values back after the LLM responds.
    """
    if not text:
        return "", {}

    value_to_placeholder: dict[str, str] = {}
    placeholder_to_value: dict[str, str] = {}

    def _placeholder_for(value: str) -> str:
        existing = value_to_placeholder.get(value)
        if existing is not None:
            return existing
        placeholder = f"<SECRET_{len(value_to_placeholder) + 1}>"
        value_to_placeholder[value] = placeholder
        placeholder_to_value[placeholder] = value
        return placeholder

    out = _ASSIGNMENT_RE.sub(
        lambda m: f"{m.group('key')}{m.group('sep')}{m.group('quote')}{_placeholder_for(m.group('value'))}{m.group('quote')}",
        text,
    )
    for pattern in _SECRET_PATTERNS:
        out = pattern.sub(lambda m: _placeholder_for(m.group(0)), out)

    def _entropy_sub(m: re.Match[str]) -> str:
        value = m.group(2)
        if "<SECRET_" in value:
            return m.group(0)  # already redacted by an earlier pass - never re-wrap
        if shannon_entropy(value) > _ENTROPY_THRESHOLD:
            return f"{m.group(1)}{_placeholder_for(value)}{m.group(1)}"
        return m.group(0)

    out = _ENTROPY_STRING_RE.sub(_entropy_sub, out)
    return out, placeholder_to_value


def restore(text: str, placeholder_map: dict[str, str]) -> str:
    """Undo redact_for_llm(): substitute every <SECRET_n> back to its real value."""
    out = text
    for placeholder, value in placeholder_map.items():
        out = out.replace(placeholder, value)
    return out


_PLACEHOLDER_VALUE_RE = re.compile(r"^<SECRET_\d+>$")


def unredacted_secret_count(text: str | None) -> int:
    """Independent check run on text *after* redaction, before it may leave
    ROUTES: how many secret-like values are still present. Placeholders
    (<SECRET_n>) and already-masked values (…[redacted]) do not count. A
    non-zero result means the text must not be sent to an external model."""
    if not text:
        return 0
    count = 0
    for m in _ASSIGNMENT_RE.finditer(text):
        value = m.group("value")
        if _PLACEHOLDER_VALUE_RE.match(value) or value.endswith(REDACTED):
            continue
        count += 1
    for pattern in _SECRET_PATTERNS:
        count += sum(1 for m in pattern.finditer(text) if not m.group(0).endswith(REDACTED))
    return count
