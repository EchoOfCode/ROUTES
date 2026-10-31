"""Turn analysis facts into findings with plain-English explanations.

Language rules: say what was seen, what it could allow, and how to fix it,
without overstating impact. Every finding produced in Phase 1 is either
"potential" (pattern + traced data flow) or "inconclusive" (pattern found,
data flow could not be resolved). Nothing here is "confirmed".
"""

from __future__ import annotations

from source_analyzer.data_flow.sqli import Export, Interaction, fingerprint

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
        "endpoint": i.endpoint,
        "method": None if i.method == "ANY" else i.method,
        "rule_id": "routes.sqli.pg-tainted-query" if not i.via_helper else "routes.sqli.pg-tainted-helper",
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
        "_fingerprint": fingerprint("sqli", sink_file, sink_line, i.file, i.line, i.method),
    }


def sqli_inconclusive(exp: Export) -> dict:
    how = CONSTRUCTION_TEXT.get(exp.construction or "", "string building")
    return {
        "type": "SQL Injection",
        "status": "inconclusive",
        "severity": "medium",
        "confidence": "low",
        "title": "SQL query built from a function argument",
        "file": exp.file,
        "line": exp.sink_line,
        "endpoint": None,
        "method": None,
        "rule_id": "routes.sqli.pg-dynamic-helper",
        "plain_description": (
            f"{exp.function_name}() builds a database query by inserting one of its arguments into the SQL text. "
            "ROUTES could not trace whether user input reaches this function, so it cannot say whether this is exploitable."),
        "evidence_summary": f"Argument {(exp.param_index or 0) + 1} of {exp.function_name}() is added to the SQL by {how} "
                            f"at {exp.file}:{exp.sink_line}; no caller passing user input was found.",
        "recommendation": SQLI_RECOMMENDATION,
        "technical_details": {"cwe": "CWE-89", "query_construction": exp.construction, "function": exp.function_name,
                              "parameter_index": exp.param_index,
                              "verification": "Inconclusive: data flow from user input could not be established."},
        "_fingerprint": fingerprint("sqli-helper", exp.file, exp.sink_line),
    }
