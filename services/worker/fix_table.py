"""Deterministic known-bad -> known-good fixes.

Per the S10 spec: prefer a lookup table and call LLM B only when no entry
applies. An entry earns its place only if the rewrite is *mechanical*: it
stays inside the snapshot's own line range (worker.llm.validation.validate_fix
enforces that), adds no import, and does not change the shape or type of the
expression it replaces. Anything needing judgement - what the right bcrypt
cost is, which origins belong in a CORS allow-list, whether a schema even has
an owner column - is deliberately absent and falls through to LLM B.

Declining is cheap and getting it wrong is not, so every entry returns None
when it does not recognise the exact shape it knows how to rewrite.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass


@dataclass
class FixTableHit:
    rule_id: str
    entry: str  # which entry fired; recorded on the round
    fixed_code: str
    note: str  # plain-language description of the single change made


@dataclass
class _Entry:
    name: str
    rule_ids: tuple[str, ...]
    apply: Callable[[str], tuple[str, str] | None]  # code -> (fixed_code, note)


# ---------------------------------------------------------------- rewrites

# Math.random().toString(36) + a slice is the idiomatic "random token" shape.
# Only this shape is rewritten: a bare Math.random() could be an OTP's digits,
# a jitter factor or an array index, and a UUID is the wrong type for those.
_TOKEN_SHAPE = re.compile(
    r"""Math\s*\.\s*random\s*\(\s*\)\s*
        \.\s*toString\s*\(\s*36\s*\)\s*
        (?:\.\s*(?:substring|substr|slice)\s*\([^()]*\)\s*)+""",
    re.X,
)
# globalThis.crypto is the WebCrypto global (Node 18+, and every browser), so
# this needs no import and therefore stays inside the snapshot's line range.
_TOKEN_REPLACEMENT = 'globalThis.crypto.randomUUID().replace(/-/g, "")'


def _random_token(code: str) -> tuple[str, str] | None:
    fixed, count = _TOKEN_SHAPE.subn(_TOKEN_REPLACEMENT, code)
    if not count:
        return None
    return fixed, (f"Replaced {count} predictable Math.random() token generator(s) with "
                   "globalThis.crypto.randomUUID(), which is cryptographically random.")


_WEAK_HASH = re.compile(r"""(createHash\s*\(\s*)(['"])(md5|sha1|sha-1)\2""", re.I)


def _strong_hash(code: str) -> tuple[str, str] | None:
    fixed, count = _WEAK_HASH.subn(lambda m: f'{m.group(1)}{m.group(2)}sha256{m.group(2)}', code)
    if not count:
        return None
    return fixed, (f"Changed {count} weak hash algorithm(s) to sha256. The digest is longer, so a "
                   "fixed-width column storing it may need widening.")


_TLS_OPTION = re.compile(r"(rejectUnauthorized\s*:\s*)false\b")
_TLS_ENV = re.compile(r"""(NODE_TLS_REJECT_UNAUTHORIZED["'\]]*\s*=\s*)(['"])0\2""")


def _enable_tls_verification(code: str) -> tuple[str, str] | None:
    fixed, a = _TLS_OPTION.subn(r"\1true", code)
    fixed, b = _TLS_ENV.subn(lambda m: f"{m.group(1)}{m.group(2)}1{m.group(2)}", fixed)
    if not a + b:
        return None
    return fixed, ("Re-enabled TLS certificate verification. If this connection uses a private "
                   "certificate authority, its certificate must be supplied via the 'ca' option.")


_COOKIE_FLAGS = re.compile(r"((?:httpOnly|secure)\s*:\s*)false\b")


def _secure_cookie_flags(code: str) -> tuple[str, str] | None:
    fixed, count = _COOKIE_FLAGS.subn(r"\1true", code)
    if not count:
        return None
    return fixed, (f"Set {count} cookie flag(s) to true. A Secure cookie is not sent over plain "
                   "HTTP, which affects local development over http://.")


ENTRIES: tuple[_Entry, ...] = (
    _Entry("random-token-to-crypto", ("routes.crypto.math-random-token",), _random_token),
    _Entry("weak-hash-to-sha256", ("routes.crypto.weak-hash",), _strong_hash),
    _Entry("enable-tls-verification", ("routes.config.tls-verification-disabled",), _enable_tls_verification),
    _Entry("secure-cookie-flags", ("routes.config.insecure-cookie",), _secure_cookie_flags),
)

# Rule ids a table entry can fix. The API uses this to decide which findings
# may be remediated deterministically, so the two cannot drift apart.
COVERED_RULE_IDS: tuple[str, ...] = tuple(sorted({r for e in ENTRIES for r in e.rule_ids}))


def lookup_fix(rule_id: str, code: str) -> FixTableHit | None:
    """The deterministic fix for this finding, or None to fall through to LLM B."""
    for entry in ENTRIES:
        if rule_id not in entry.rule_ids:
            continue
        result = entry.apply(code)
        if result is None:
            continue
        fixed_code, note = result
        if fixed_code == code:  # a rewrite that changes nothing is not a fix
            continue
        return FixTableHit(rule_id=rule_id, entry=entry.name, fixed_code=fixed_code, note=note)
    return None
