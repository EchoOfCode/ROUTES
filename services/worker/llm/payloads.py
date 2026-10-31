"""Fixed, per-class exploit payload lists (rule 5, relaxed): LLM A still
writes the testbench from the report and snapshot, but its prompt must
include these known payloads - it may add more based on the specific
report, but these are never left to the LLM to invent from scratch.
"""

from __future__ import annotations

KNOWN_EXPLOIT_PAYLOADS: dict[str, list[str]] = {
    "routes.sqli": [
        "' OR '1'='1",
        "'; DROP TABLE users; --",
        "' UNION SELECT NULL, NULL, NULL --",
    ],
    "routes.xss": [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "\"><script>alert(document.cookie)</script>",
    ],
}


def payloads_for(rule_id: str) -> list[str]:
    for prefix, payloads in KNOWN_EXPLOIT_PAYLOADS.items():
        if rule_id.startswith(prefix):
            return payloads
    return []
