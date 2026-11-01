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


def finding_identity(f: dict) -> tuple[str, str, str, str]:
    """What a finding *is*, independent of the exact code text: rule, file,
    endpoint and method. Used to recognise the same issue after a patch has
    changed the code its content fingerprint was computed from."""
    return (str(f.get("rule_id") or ""), str(f.get("file") or ""), str(f.get("endpoint") or ""),
            str(f.get("method") or "").upper())


def match_reanalysis(baseline: dict[str, tuple], targeted: set[str], after: list[tuple[str, tuple]]) -> dict:
    """Compare the original findings with a rescan of the patched tree.

    `baseline`: fingerprint -> identity of every original finding.
    `targeted`: fingerprints of the findings the patch was meant to fix.
    `after`: (fingerprint, identity) of every finding on the patched tree.

    A new fingerprint whose identity matches an original finding that
    disappeared is that same finding, re-fingerprinted because its code
    changed:
      - for an untargeted finding it is *remaining* (never "resolved"; and
        not a newly introduced issue);
      - for a targeted finding it means the vulnerability is still there.
    Everything else new is a newly introduced finding.
    """
    after_fps = {fp for fp, _ in after}
    disappeared = {fp: ident for fp, ident in baseline.items() if fp not in after_fps}
    carried: dict[str, str] = {}      # new fingerprint -> original fingerprint
    new: list[str] = []
    for fp, ident in after:
        if fp in baseline:
            continue
        match = next((old for old, old_ident in disappeared.items()
                      if old_ident == ident and old not in carried.values()), None)
        if match is None:
            new.append(fp)
        else:
            carried[fp] = match
    still = set(carried.values())
    resolved = [fp for fp in disappeared if fp not in still]
    remaining = [fp for fp in baseline if fp in after_fps] + sorted(still)
    return {"resolved": sorted(resolved), "remaining": remaining, "new": sorted(new), "carried": carried,
            "targeted_still_present": sorted(t for t in targeted if t in after_fps or t in still)}
