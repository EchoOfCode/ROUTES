"""Security-header check on next.config.*.

Deliberately not a Semgrep rule: the finding is about something the project
does *not* say anywhere, and Semgrep reports matches rather than absences.
This reads the Next.js config (and middleware, which is the other place
projects set headers) and reports the headers it cannot find.
"""

from __future__ import annotations

import re

from routes_shared.fingerprint import fingerprint
from routes_shared.redaction import redact_text

NEXT_CONFIG = re.compile(r"(^|/)next\.config\.(js|mjs|cjs|ts|mts)$")
MIDDLEWARE = re.compile(r"(^|/)(middleware|proxy)\.(js|ts|mjs)$")
HEADERS_FN = re.compile(r"\bheaders\s*\(\s*\)|\bheaders\s*:", re.I)

# Header -> what the developer loses by not sending it.
EXPECTED = {
    "content-security-policy": "limits which scripts the browser will run, the main defence-in-depth "
                               "against cross-site scripting",
    "strict-transport-security": "tells browsers to only ever reach the site over HTTPS",
    "x-content-type-options": "stops the browser guessing a response's type and running it as script",
    "x-frame-options": "stops other sites embedding the pages in a frame to trick users into clicking",
    "referrer-policy": "stops full URLs, which may contain tokens or identifiers, leaking to other sites",
}


def _mentions(text: str, header: str) -> bool:
    if header in text.lower():
        return True
    # CSP's frame-ancestors is the modern replacement for X-Frame-Options.
    return header == "x-frame-options" and "frame-ancestors" in text.lower()


def check_security_headers(profile) -> list[dict]:
    """Return at most one finding. Empty if the framework is not Next.js."""
    if profile.framework != "Next.js":
        return []

    configs = [f for f in profile.files if NEXT_CONFIG.search(f.rel)]
    others = [f for f in profile.files if MIDDLEWARE.search(f.rel)]

    config_text = ""
    for f in configs:
        try:
            config_text += f.read()
        except OSError:
            continue
    elsewhere = ""
    for f in others:
        try:
            elsewhere += f.read()
        except OSError:
            continue

    searched = f"{config_text}\n{elsewhere}"
    missing = [h for h in EXPECTED if not _mentions(searched, h)]
    if not missing:
        return []

    rel = configs[0].rel if configs else None
    if not configs:
        where = ("No next.config file was found, and no security headers are set in middleware either, "
                 "so the application sends none of them.")
    elif not HEADERS_FN.search(config_text):
        where = f"{rel} does not define a headers() function, and none of the missing headers are set in middleware."
    else:
        where = f"{rel} defines headers(), but these are not among the headers it sets."

    listed = ", ".join(sorted(missing))
    return [{
        "type": "Insecure Configuration",
        "status": "potential",
        "severity": "medium" if len(missing) >= 3 else "low",
        # A proxy, CDN or hosting platform in front of the app can add these,
        # and the repository cannot show that.
        "confidence": "medium",
        "title": "Security response headers are not configured",
        "file": rel,
        "line": None,
        "end_line": None,
        "endpoint": None,
        "method": None,
        "rule_id": "routes.config.missing-security-headers",
        "plain_description": " ".join(
            f"""The application does not appear to send {len(missing)} security response header(s):
            {listed}. Each one asks the visitor's browser to enforce a restriction on its behalf - for
            example, Content-Security-Policy {EXPECTED['content-security-policy']}. Without them the
            browser applies its permissive defaults.""".split()),
        "evidence_summary": " ".join(where.split()),
        "recommendation": " ".join(
            """Add an async headers() function to next.config that returns these headers for all paths
            (source: '/:path*'). Set Content-Security-Policy last and roll it out with
            Content-Security-Policy-Report-Only first, because a strict policy can block the
            application's own scripts. If a CDN or proxy in front of the application already sends
            these, no change is needed here.""".split()),
        "technical_details": {
            "engine": "next-config-check",
            "rule": "routes.config.missing-security-headers",
            "cwe": "CWE-693",
            "missing_headers": sorted(missing),
            "config_files": [f.rel for f in configs],
            "snippet": redact_text(config_text[:400], max_length=400) if config_text else "",
        },
        "_fingerprint": fingerprint("routes.config.missing-security-headers", rel or "next.config", listed),
    }]
