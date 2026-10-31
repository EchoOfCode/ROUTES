"""Content-based finding fingerprints.

fingerprint = hash(rule_id + file + normalised_snippet). Deliberately never
takes a line number: reformatting (reindenting, adding/removing blank lines)
must not change the fingerprint, only an actual code change should.
"""

from __future__ import annotations

import hashlib
import re

_COMMENT_RE = re.compile(r"//[^\n]*|/\*.*?\*/", re.DOTALL)
_WHITESPACE_RE = re.compile(r"\s+")


def normalize_snippet(snippet: str | None) -> str:
    """Strip comments, then ALL whitespace - not just collapse it - so that
    reindenting, wrapping onto new lines, or adding/removing blank lines
    never changes the result."""
    without_comments = _COMMENT_RE.sub("", snippet or "")
    return _WHITESPACE_RE.sub("", without_comments)


def fingerprint(rule_id: str, file: str | None, snippet: str | None) -> str:
    normalised = normalize_snippet(snippet)
    return hashlib.sha256(f"{rule_id}|{file or ''}|{normalised}".encode()).hexdigest()[:32]
