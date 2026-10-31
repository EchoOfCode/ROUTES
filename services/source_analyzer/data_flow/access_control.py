"""Broken access control (A01) detection over the discovered route map.

Not a Semgrep rule: deciding whether a route is protected needs the route
map, the handler's AST, and the DB interactions already attributed to that
handler - none of which a per-file pattern match can see.

Two things are reported:

* ``unprotected-db-route`` - a route handler that reaches the database and
  calls no recognised authentication helper.
* ``missing-ownership-check`` - a handler that *is* authenticated, takes a
  record id from the request, and queries with it without ever referring to
  the signed-in user. That is the shape of an IDOR: logging in as any user
  lets you read or change another user's row.

NextAuth only, deliberately (the spec's "support NextAuth only first").
Clerk/Supabase/Lucia/custom middleware are not recognised, so a project
using them reads as unprotected here - see ``AUTH_HELPERS``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from tree_sitter import Node

from source_analyzer.structure.parser import pattern_names, text, unwrap, walk

# NextAuth's session accessors. `auth` is v5, `getServerSession` is v4,
# `getToken` is the JWT helper.
AUTH_HELPERS = {"getServerSession", "auth", "getToken", "getSession"}

# Reading a session is not the same as acting on it: a handler that fetches a
# session and ignores the result is not protected. These are the checks that
# turn a session into a decision.
REJECTION_HINTS = re.compile(r"\b(?:401|403|redirect|unauthorized|unauthorised|forbidden|notFound)\b", re.I)

# Columns that plausibly record who owns a row. Used to tell "this query has
# no owner condition" from "this schema may not have an owner column at all".
OWNER_COLUMNS = re.compile(r"\b(user_?id|owner_?id|account_?id|created_?by|author_?id|member_?id|tenant_?id)\b", re.I)

# A session-derived expression: session.user.id, token.sub, user.id, ...
SESSION_MEMBERS = re.compile(r"\b(?:id|sub|user_?id|email|userId)\b")

MUTATING_METHODS = ("POST", "PUT", "PATCH", "DELETE")

# Request-derived identifier names. A route parameter called `id` or `slug`
# is the usual IDOR vector.
ID_PARAM = re.compile(r"(^|_|\b)(id|uuid|slug|key|ref|number|no)$", re.I)


@dataclass
class AccessFinding:
    kind: str  # "unprotected" | "ownership"
    rel: str
    endpoint: str
    method: str
    line: int
    end_line: int
    snippet: str
    db_calls: list[str] = field(default_factory=list)
    session_names: list[str] = field(default_factory=list)
    owner_columns: list[str] = field(default_factory=list)
    id_source: str | None = None
    protected_example: dict | None = None


def _callee_name(call: Node) -> str:
    fn = unwrap(call.child_by_field_name("function"))
    if fn is None:
        return ""
    if fn.type == "identifier":
        return text(fn)
    if fn.type == "member_expression":
        prop = fn.child_by_field_name("property")
        return text(prop) if prop is not None else ""
    return ""


def _is_auth_import(specifier: str) -> bool:
    lowered = specifier.lower()
    if "next-auth" in lowered:
        return True
    # NextAuth v5's documented setup re-exports auth() from a local module
    # (`export const { auth } = NextAuth(...)` in auth.ts), so a relative or
    # aliased import whose final segment mentions auth is accepted.
    return (lowered.startswith((".", "@/", "~/", "src/")) or lowered.startswith("@/"))\
        and "auth" in lowered.rsplit("/", 1)[-1]


def _bound_names(call: Node) -> list[str]:
    """Names the call's result is assigned to, if any."""
    node = call
    for _ in range(4):
        parent = node.parent
        if parent is None:
            return []
        if parent.type == "variable_declarator":
            name = parent.child_by_field_name("name")
            return pattern_names(name) if name is not None else []
        if parent.type in ("await_expression", "parenthesized_expression", "non_null_expression", "as_expression"):
            node = parent
            continue
        return []
    return []


def _auth_calls(fn: Node, imports: dict[str, tuple[str, str]]) -> tuple[list[str], bool]:
    """(names bound to a session, whether an unimported helper name was seen).

    The second value matters for honesty: seeing `getServerSession(...)` with
    no resolvable import means the handler probably *is* protected even though
    this module cannot prove it is NextAuth, so it is not reported.
    """
    names: list[str] = []
    unresolved = False
    for node in walk(fn):
        if node.type != "call_expression":
            continue
        callee = _callee_name(node)
        if callee not in AUTH_HELPERS:
            continue
        imported = imports.get(callee)
        if imported is not None and _is_auth_import(imported[0]):
            names.extend(_bound_names(node) or [callee])
        else:
            unresolved = True
    return list(dict.fromkeys(names)), unresolved


def _request_id_name(fn: Node) -> str | None:
    """An identifier bound from a route param / query string that looks like a record id."""
    for node in walk(fn):
        if node.type != "variable_declarator":
            continue
        name_node = node.child_by_field_name("name")
        value = node.child_by_field_name("value")
        if name_node is None or value is None:
            continue
        value_text = text(value)
        if not re.search(r"\bparams\b|\bsearchParams\b|\bquery\b|\bget\(", value_text):
            continue
        for bound in pattern_names(name_node):
            if ID_PARAM.search(bound):
                return bound
    return None


def _references_session(query_text: str, session_names: list[str]) -> bool:
    for name in session_names:
        if not re.search(rf"\b{re.escape(name)}\b", query_text):
            continue
        # `session` alone in a query is not an ownership condition; it has to
        # reach an identifying field.
        after = query_text.split(name, 1)[1][:60]
        if SESSION_MEMBERS.search(after) or name.lower() in ("userid", "user_id", "sub"):
            return True
    return False


def detect_access_control(analyzer) -> list[AccessFinding]:
    """Walk the route map; return A01 findings. Needs a run() SqliAnalyzer."""
    by_route: dict[tuple[str, str], list] = {}
    for interaction in analyzer.interactions:
        if interaction.endpoint:
            by_route.setdefault((interaction.endpoint, interaction.method or "ANY"), []).append(interaction)

    def db_calls_for(endpoint: str, method: str) -> list:
        calls = list(by_route.get((endpoint, method), []))
        if method == "ANY":
            for (ep, _), group in by_route.items():
                if ep == endpoint:
                    calls.extend(c for c in group if c not in calls)
        return calls

    # Pass 1: classify every handler, so pass 2 can point at a protected
    # sibling as a worked example of the project's own auth pattern.
    classified = []
    for route in analyzer.routes:
        module = analyzer.modules.get(route.rel)
        imports = module.imports if module is not None else {}
        for handler in route.handlers:
            session_names, unresolved = _auth_calls(handler.function, imports)
            classified.append((route, handler, session_names, unresolved))

    protected = [
        (route, handler, names) for route, handler, names, _ in classified if names
        and REJECTION_HINTS.search(text(handler.function))
    ]

    def example_for(rel: str) -> dict | None:
        """A protected handler to show as an example, preferring a sibling file."""
        if not protected:
            return None
        route, handler, names = min(
            protected,
            key=lambda item: (item[0].rel != rel, len(text(item[1].function))),
        )
        return {"file": route.rel, "endpoint": route.endpoint, "method": handler.method,
                "line": handler.line, "session_variable": names[0],
                "code": text(handler.function)[:1200]}

    findings: list[AccessFinding] = []
    for route, handler, session_names, unresolved in classified:
        calls = db_calls_for(route.endpoint, handler.method)
        if not calls or unresolved:
            continue
        fn = handler.function
        snippet = text(fn)[:400]
        query_text = " ".join(c.call for c in calls)
        common = {
            "rel": route.rel, "endpoint": route.endpoint, "method": handler.method,
            "line": handler.line, "end_line": fn.end_point[0] + 1, "snippet": snippet,
            "db_calls": [c.call[:200] for c in calls][:5],
            "owner_columns": sorted(set(OWNER_COLUMNS.findall(query_text)))[:5],
            "protected_example": example_for(route.rel),
        }

        if not session_names:
            findings.append(AccessFinding(kind="unprotected", **common))
            continue

        id_name = _request_id_name(fn)
        if id_name and not _references_session(query_text, session_names):
            findings.append(AccessFinding(kind="ownership", id_source=id_name,
                                          session_names=session_names, **common))
    return findings
