"""Turn analysis facts into findings with plain-English explanations.

Language rules: say what was seen, what it could allow, and how to fix it,
without overstating impact. Every finding produced in Phase 1 is either
"potential" (pattern + traced data flow) or "inconclusive" (pattern found,
data flow could not be resolved). Nothing here is "confirmed".
"""

from __future__ import annotations

from routes_shared.fingerprint import fingerprint

from source_analyzer.data_flow.sqli import Export, Interaction
from source_analyzer.data_flow.xss import XssFinding

CONSTRUCTION_TEXT = {
    "interpolated": "template-string interpolation",
    "concatenated": "string concatenation",
    "direct": "being used as the SQL text itself",
}

SQLI_RECOMMENDATION = (
    "Keep the SQL text constant and pass user input separately as query parameters, for example "
    "pool.query('SELECT * FROM products WHERE name = $1', [name]). Values that cannot be parameters, "
    "such as column names or sort direction, should be checked against a fixed allow-list before use."
)

XSS_DOM_RECOMMENDATION = (
    "Avoid writing to innerHTML or calling document.write() with data that could be influenced by the URL, "
    "the referrer or other browser state. Use textContent for plain text, or sanitise the HTML with a library "
    "such as DOMPurify before inserting it."
)

XSS_REFLECTED_RECOMMENDATION = (
    "Do not build a response body by inserting request input into an HTML string. Return JSON "
    "(for example NextResponse.json(...)) for data responses, or HTML-escape the value before including it "
    "in markup."
)


def _source_phrase(interaction: Interaction) -> tuple[str, str]:
    src = interaction.taint.sources[0] if interaction.taint and interaction.taint.sources else None
    if src is None:
        return "user input", ""
    name = f" \"{src.name}\"" if src.name and src.name not in ("request", "req") else ""
    return src.kind, name


def sqli_finding(i: Interaction) -> dict:
    kind, name = _source_phrase(i)
    how = CONSTRUCTION_TEXT.get(i.construction, "dynamic string building")
    sink_file = i.sink_file or i.file
    sink_line = i.sink_line or i.line
    sink_end_line = i.sink_end_line or sink_line
    snippet = i.sink_snippet or i.call
    rule_id = "routes.sqli.pg-tainted-query" if not i.via_helper else "routes.sqli.pg-tainted-helper"
    endpoint_text = f" in the {i.method} {i.endpoint} handler" if i.endpoint and i.method not in (None, "ANY") else (
        f" in the {i.endpoint} handler" if i.endpoint else "")
    if i.via_helper:
        plain = (f"Input from the {kind}{name}{endpoint_text} is passed to {i.via_helper}(), which inserts it directly "
                 f"into a database query. Someone could craft that input to change what the query does, for example "
                 f"to read or modify data they should not be able to access.")
        evidence = (f"Untrusted {kind}{name} is passed to {i.via_helper}() at {i.file}:{i.line}; that function builds "
                    f"its SQL by {how} at {sink_file}:{sink_line}.")
    elif i.construction == "direct":
        plain = (f"Input from the {kind}{name}{endpoint_text} appears to be used as an entire database query. "
                 f"Anyone who can send this request could run their own SQL against the database.")
        evidence = f"Untrusted {kind}{name} is passed as the SQL text to {i.client} at {i.file}:{i.line}."
    else:
        plain = (f"Input from the {kind}{name}{endpoint_text} appears to be inserted directly into a database query. "
                 f"Someone could craft that input to change what the query does, for example to read or modify data "
                 f"they should not be able to access.")
        evidence = f"Untrusted {kind}{name} reaches {i.client} through {how} at {i.file}:{i.line}."
    steps = list(i.taint.steps) if i.taint else []
    src = i.taint.sources[0] if i.taint and i.taint.sources else None
    return {
        "type": "SQL Injection",
        "status": "potential",
        "severity": "critical" if i.construction == "direct" else "high",
        "confidence": "high" if i.confidence == "high" and not i.via_helper else "medium",
        "title": "User input used to build a SQL query" if i.construction != "direct" else "User input used as a SQL query",
        "file": sink_file,
        "line": sink_line,
        "end_line": sink_end_line,
        "endpoint": i.endpoint,
        "method": None if i.method == "ANY" else i.method,
        "rule_id": rule_id,
        "plain_description": plain,
        "evidence_summary": evidence,
        "recommendation": SQLI_RECOMMENDATION,
        "technical_details": {
            "cwe": "CWE-89",
            "classification": "Static analysis: tainted data reaches a SQL sink without parameterisation.",
            "source": {"kind": src.kind, "name": src.name, "line": src.line, "expression": src.expression} if src else None,
            "sink": {"call": i.call, "client": i.client, "file": sink_file, "line": sink_line},
            "call_site": {"file": i.file, "line": i.line} if i.via_helper else None,
            "query_construction": i.construction,
            "flow": steps,
            "handler_line": i.handler_line,
            "verification": "Not dynamically verified. Phase 1 reports static evidence only.",
        },
        "_fingerprint": fingerprint(rule_id, sink_file, snippet),
    }


def sqli_inconclusive(exp: Export) -> dict:
    how = CONSTRUCTION_TEXT.get(exp.construction or "", "string building")
    rule_id = "routes.sqli.pg-dynamic-helper"
    return {
        "type": "SQL Injection",
        "status": "inconclusive",
        "severity": "medium",
        "confidence": "low",
        "title": "SQL query built from a function argument",
        "file": exp.file,
        "line": exp.sink_line,
        "end_line": exp.sink_end_line or exp.sink_line,
        "endpoint": None,
        "method": None,
        "rule_id": rule_id,
        "plain_description": (
            f"{exp.function_name}() builds a database query by inserting one of its arguments into the SQL text. "
            "ROUTES could not trace whether user input reaches this function, so it cannot say whether this is exploitable."),
        "evidence_summary": f"Argument {(exp.param_index or 0) + 1} of {exp.function_name}() is added to the SQL by {how} "
                            f"at {exp.file}:{exp.sink_line}; no caller passing user input was found.",
        "recommendation": SQLI_RECOMMENDATION,
        "technical_details": {"cwe": "CWE-89", "query_construction": exp.construction, "function": exp.function_name,
                              "parameter_index": exp.param_index,
                              "verification": "Inconclusive: data flow from user input could not be established."},
        "_fingerprint": fingerprint(rule_id, exp.file, exp.sink_snippet or ""),
    }


def _xss_source_phrase(f: XssFinding) -> tuple[str, str]:
    src = f.taint.sources[0] if f.taint.sources else None
    if src is None:
        return "browser-controlled data", ""
    name = f" \"{src.name}\"" if src.name and src.name not in ("request", "req") else ""
    return src.kind, name


def xss_dom_sink_finding(f: XssFinding) -> dict:
    kind, name = _xss_source_phrase(f)
    plain = (f"{f.sink_label} is set from {kind}{name} without sanitising it first. Someone could craft a URL "
             "or referrer that runs their own script in another visitor's browser.")
    evidence = f"{f.sink_label} is written from {kind}{name} at {f.file}:{f.line}."
    src = f.taint.sources[0] if f.taint.sources else None
    return {
        "type": "Cross-Site Scripting",
        "status": "potential",
        "severity": "high",
        "confidence": "medium",
        "title": "Browser-controlled data written to the page without sanitising",
        "file": f.file,
        "line": f.line,
        "end_line": f.end_line,
        "endpoint": None,
        "method": None,
        "rule_id": "routes.xss.dom-sink-tainted",
        "plain_description": plain,
        "evidence_summary": evidence,
        "recommendation": XSS_DOM_RECOMMENDATION,
        "technical_details": {
            "cwe": "CWE-79",
            "classification": "Static analysis: tainted browser state reaches a DOM sink unsanitised.",
            "source": {"kind": src.kind, "name": src.name, "line": src.line, "expression": src.expression} if src else None,
            "sink": {"label": f.sink_label, "file": f.file, "line": f.line},
            "flow": list(f.taint.steps),
            "verification": "Not dynamically verified. Phase 1 reports static evidence only.",
        },
        "_fingerprint": fingerprint("routes.xss.dom-sink-tainted", f.file, f.snippet),
    }


def xss_reflected_finding(f: XssFinding) -> dict:
    kind, name = _xss_source_phrase(f)
    endpoint_text = f" in the {f.method} {f.endpoint} handler" if f.endpoint and f.method not in (None, "ANY") else (
        f" in the {f.endpoint} handler" if f.endpoint else "")
    plain = (f"Input from the {kind}{name}{endpoint_text} is inserted directly into the response body. Anyone "
             "who can send this request could run their own script in another visitor's browser.")
    evidence = f"Untrusted {kind}{name} is written into the response at {f.file}:{f.line}."
    src = f.taint.sources[0] if f.taint.sources else None
    return {
        "type": "Cross-Site Scripting",
        "status": "potential",
        "severity": "high",
        "confidence": "high",
        "title": "Request input reflected into the response without escaping",
        "file": f.file,
        "line": f.line,
        "end_line": f.end_line,
        "endpoint": f.endpoint,
        "method": None if f.method == "ANY" else f.method,
        "rule_id": "routes.xss.reflected-response",
        "plain_description": plain,
        "evidence_summary": evidence,
        "recommendation": XSS_REFLECTED_RECOMMENDATION,
        "technical_details": {
            "cwe": "CWE-79",
            "classification": "Static analysis: tainted request data reaches the response body unescaped.",
            "source": {"kind": src.kind, "name": src.name, "line": src.line, "expression": src.expression} if src else None,
            "sink": {"label": "response body", "file": f.file, "line": f.line},
            "flow": list(f.taint.steps),
            "verification": "Not dynamically verified. Phase 1 reports static evidence only.",
        },
        "_fingerprint": fingerprint("routes.xss.reflected-response", f.file, f.snippet),
    }


A01_UNPROTECTED_RECOMMENDATION = (
    "Read the session at the top of the handler and reject the request before touching the database, for "
    "example: const session = await auth(); if (!session?.user) return new Response('Unauthorized', "
    "{status: 401}). If this endpoint is genuinely meant to be public, no change is needed - but the check "
    "belongs in the handler rather than being left implicit."
)

A01_OWNERSHIP_RECOMMENDATION = (
    "Do not trust a record id from the request on its own. Make the signed-in user part of the query itself, "
    "for example: WHERE id = $1 AND user_id = $2 with [id, session.user.id]. Filtering in the handler after "
    "the row has been fetched is weaker, and returning 404 rather than 403 for someone else's row avoids "
    "confirming that it exists."
)


def _a01_common(f, rule_id: str) -> dict:
    return {
        "type": "Broken Access Control",
        "status": "potential",
        "file": f.rel,
        "line": f.line,
        "end_line": f.end_line,
        "endpoint": f.endpoint,
        "method": None if f.method == "ANY" else f.method,
        "rule_id": rule_id,
        "_fingerprint": fingerprint(rule_id, f.rel, f.snippet),
    }


def a01_unprotected_finding(f) -> dict:
    mutating = f.method in ("POST", "PUT", "PATCH", "DELETE")
    verb = "change" if mutating else "read"
    plain = (
        f"The {f.method} {f.endpoint} handler queries the database but never checks who is asking. Anyone who "
        f"can reach this URL - signed in or not - can {verb} this data."
    )
    return {
        **_a01_common(f, "routes.a01.unprotected-db-route"),
        # A public read may be entirely intentional, which a mutation rarely is.
        "severity": "high" if mutating else "medium",
        "confidence": "medium" if mutating else "low",
        "title": f"Database {'write' if mutating else 'read'} endpoint with no authentication check",
        "plain_description": plain,
        "evidence_summary": (
            f"No NextAuth session helper is called in the handler at {f.rel}:{f.line}, which makes "
            f"{len(f.db_calls)} database call(s)."
        ),
        "recommendation": A01_UNPROTECTED_RECOMMENDATION,
        "technical_details": {
            "cwe": "CWE-306",
            "classification": "Static analysis: route handler reaches the database with no session check.",
            "db_calls": f.db_calls,
            "owner_columns_seen": f.owner_columns,
            "protected_example": f.protected_example,
            "auth_support": "NextAuth only. Another auth library, or a check in middleware, is not recognised.",
            "verification": "Not dynamically verified. Phase 1 reports static evidence only.",
        },
    }


def a01_ownership_finding(f) -> dict:
    plain = (
        f"The {f.method} {f.endpoint} handler checks that someone is signed in, then looks up a record using "
        f"\"{f.id_source}\" from the request without tying the query to that user. Any signed-in user could "
        f"change the id and reach another user's record."
    )
    return {
        **_a01_common(f, "routes.a01.missing-ownership-check"),
        "severity": "high",
        # An owner column in the query means there is something to filter on;
        # with none visible the schema may not support ownership at all.
        "confidence": "medium" if f.owner_columns else "low",
        "title": "Record looked up by request id without an ownership check",
        "plain_description": plain,
        "evidence_summary": (
            f"The handler at {f.rel}:{f.line} reads a session into "
            f"\"{f.session_names[0]}\" but no database call references it."
            + (f" Owner-like column(s) seen in the query: {', '.join(f.owner_columns)}."
               if f.owner_columns else " No owner-like column was visible in the query.")
        ),
        "recommendation": A01_OWNERSHIP_RECOMMENDATION,
        "technical_details": {
            "cwe": "CWE-639",
            "classification": "Static analysis: authenticated handler queries by request id with no owner condition.",
            "request_id_variable": f.id_source,
            "session_variables": f.session_names,
            "db_calls": f.db_calls,
            "owner_columns_seen": f.owner_columns,
            "protected_example": f.protected_example,
            "verification": "Not dynamically verified. Phase 1 reports static evidence only.",
        },
    }
