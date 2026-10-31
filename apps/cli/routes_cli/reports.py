"""Assessment reports written to ~/.routes/reports/<project>/<assessment>/.

Reports contain only what is stored: redacted evidence and metadata. The HTML
report is a single self-contained file with inline CSS, no scripts and every
value escaped.
"""

from __future__ import annotations

import json
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

from jinja2 import Environment, select_autoescape

from routes_storage.models import as_utc

from routes_cli import __version__
from routes_cli.renderers.results import LIMITATIONS, WHY_IT_MATTERS
from routes_cli.stages import STEP_TITLES

FORMATS = {"markdown": "report.md", "html": "report.html", "json": "findings.json"}
SEV_ORDER = ("critical", "high", "medium", "low", "info")


def report_data(a) -> dict:
    s = a.summary or {}
    sr = a.source_result
    counts = Counter(f.severity for f in a.findings)
    return {
        "generator": f"ROUTES {__version__}",
        "generated_at": datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC"),
        "assessment": {
            "id": a.id, "project": a.project.display_name, "status": a.status, "error": a.error,
            "target_url": a.target_url, "source": a.source_label,
            "started_at": as_utc(a.started_at).isoformat() if a.started_at else None,
            "finished_at": as_utc(a.finished_at).isoformat() if a.finished_at else None,
            "steps": [{"kind": st.kind, "title": STEP_TITLES.get(st.kind, st.kind), "status": st.status,
                       "error": st.error} for st in a.steps],
        },
        "discovery": {
            "manifest_detected": a.manifest_detected,
            "pages_inspected": s.get("pages_inspected"), "pages_failed": s.get("pages_failed"),
            "page_limit_reached": s.get("page_limit_reached"), "stack": s.get("stack"),
            "pages": [{"url": p.url, "status": p.status_code, "title": p.title, "rendered": p.rendered,
                       "login": p.is_login, "registration": p.is_registration, "error": p.error} for p in a.pages],
            "endpoints": [{"method": e.method, "path": e.path, "origin": e.origin, "parameters": e.parameters}
                          for e in a.endpoints],
            "technologies": [{"name": t.name, "category": t.category, "version": t.version,
                              "confidence": t.confidence, "source": t.source, "evidence": t.evidence}
                             for t in a.technologies],
        } if any(st.kind == "discovery" for st in a.steps) else None,
        "source": {
            "support_status": sr.support_status, "support_reason": sr.support_reason, "framework": sr.framework,
            "runtime": sr.runtime, "routes": len(sr.routes), "db_interactions": len(sr.db_interactions),
            "warnings": sr.warnings,
        } if sr is not None else None,
        "severity_counts": {k: counts[k] for k in SEV_ORDER if counts[k]},
        "findings": [{
            "id": f"{f.seq:02d}", "type": f.type, "title": f.title, "severity": f.severity, "status": f.status,
            "confidence": f.confidence, "file": f.file, "line": f.line, "endpoint": f.endpoint, "method": f.method,
            "rule_id": f.rule_id, "what_is_wrong": f.plain_description,
            "why_it_matters": WHY_IT_MATTERS.get(f.type, ""), "evidence": f.evidence_summary,
            "data_flow": [str(x) for x in (f.technical_details or {}).get("flow") or []],
            "cwe": (f.technical_details or {}).get("cwe"), "recommendation": f.recommendation,
            "limitations": LIMITATIONS.get(f.status, LIMITATIONS["potential"]),
        } for f in a.findings],
        "scope_note": "ROUTES Phase 1 performs website discovery and static source analysis. It does not attack "
                      "the website or verify findings dynamically; findings are potential issues backed by static "
                      "evidence.",
    }


MARKDOWN = """# ROUTES assessment: {{ a.project }}

{{ d.generator }} · generated {{ d.generated_at }} · assessment `{{ a.id[:8] }}`

| | |
|---|---|
| Status | **{{ a.status | replace('_', ' ') }}**{% if a.error %} ({{ a.error }}){% endif %} |
{% if a.target_url %}| Website | {{ a.target_url }} |
{% endif %}{% if a.source %}| Source | {{ a.source }} |
{% endif %}{% for st in a.steps %}| {{ st.title }} | {{ st.status }}{% if st.error and st.status != 'completed' %}: {{ st.error }}{% endif %} |
{% endfor %}
{% if d.discovery %}
## Website discovery

- Pages inspected: {{ d.discovery.pages_inspected or 0 }} ({{ d.discovery.pages_failed or 0 }} failed){% if d.discovery.page_limit_reached %}, 25-page limit reached{% endif %}
- ROUTES manifest: {{ 'found' if d.discovery.manifest_detected else 'not found' }}
- Endpoints: {{ d.discovery.endpoints | length }}

{% if d.discovery.technologies %}| Technology | Category | Version | Confidence | Evidence |
|---|---|---|---|---|
{% for t in d.discovery.technologies %}| {{ t.name }} | {{ t.category }} | {{ t.version or '-' }} | {{ t.confidence }} | {{ t.evidence[:2] | join('; ') }} |
{% endfor %}{% endif %}
{% endif %}{% if d.source %}
## Source analysis

- Support: **{{ d.source.support_status }}**. {{ d.source.support_reason }}
- Framework: {{ d.source.framework }} ({{ d.source.runtime }})
- Route handlers: {{ d.source.routes }}, database calls: {{ d.source.db_interactions }}
{% endif %}
## Findings
{% if not d.findings %}
No findings. The checks ROUTES ran found nothing; this does not mean the application is secure.
{% else %}
| ID | Vulnerability | Severity | Status | Location |
|---|---|---|---|---|
{% for f in d.findings %}| {{ f.id }} | {{ f.type }} | {{ f.severity | upper }} | {{ f.status | upper }} | {{ (f.file ~ ':' ~ f.line) if f.file else (f.endpoint or '-') }} |
{% endfor %}
{% for f in d.findings %}
### {{ f.id }} · {{ f.title }}

**{{ f.severity | upper }}** · {{ f.status }} · confidence {{ f.confidence }} · {{ f.type }}{% if f.cwe %} · {{ f.cwe }}{% endif %}

**What is wrong.** {{ f.what_is_wrong }}

**Why it matters.** {{ f.why_it_matters }}

**Where.** {% if f.file %}`{{ f.file }}`{% if f.line %} line {{ f.line }}{% endif %}{% endif %}{% if f.endpoint %} · endpoint `{{ f.method or 'ANY' }} {{ f.endpoint }}`{% endif %}

**What ROUTES detected.** {{ f.evidence }}
{% if f.data_flow %}
{% for step in f.data_flow %}{{ loop.index }}. {{ step }}
{% endfor %}{% endif %}
**Suggested fix.** {{ f.recommendation }}

*{{ f.limitations }}*
{% endfor %}{% endif %}
---

{{ d.scope_note }}
"""

HTML = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>ROUTES · {{ a.project }}</title>
<style>
:root{--fg:#1c1d20;--muted:#6b7078;--line:#e4e4e1;--accent:#1f8f84;--red:#c43c3c;--amber:#b5761a;--blue:#3b6fc4}
body{font:15px/1.55 system-ui,-apple-system,"Segoe UI",sans-serif;color:var(--fg);max-width:920px;margin:40px auto;padding:0 24px;background:#fbfbfa}
h1{font-size:22px;margin:0 0 4px}h2{font-size:17px;margin:36px 0 10px;border-bottom:1px solid var(--line);padding-bottom:6px}
h3{font-size:15px;margin:0 0 6px}.muted{color:var(--muted)}code{font:13px ui-monospace,Consolas,monospace;background:#f0f0ee;padding:1px 4px;border-radius:4px}
table{border-collapse:collapse;width:100%;font-size:14px}td,th{text-align:left;padding:6px 10px 6px 0;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--muted);font-weight:500}.sev{font-weight:600;font-size:12px;letter-spacing:.04em}
.critical,.high{color:var(--red)}.medium{color:var(--amber)}.low,.info{color:var(--blue)}
.finding{border:1px solid var(--line);border-radius:6px;padding:16px 18px;margin:14px 0;background:#fff}
.finding p{margin:6px 0}.brand{color:var(--accent);font-weight:700;letter-spacing:.08em}
</style></head><body>
<div class="brand">ROUTES</div>
<h1>{{ a.project }}</h1>
<div class="muted">{{ d.generator }} · generated {{ d.generated_at }} · assessment <code>{{ a.id[:8] }}</code></div>
<h2>Overview</h2>
<table>
<tr><th>Status</th><td><strong>{{ a.status | replace('_', ' ') }}</strong>{% if a.error %} <span class="muted">{{ a.error }}</span>{% endif %}</td></tr>
{% if a.target_url %}<tr><th>Website</th><td>{{ a.target_url }}</td></tr>{% endif %}
{% if a.source %}<tr><th>Source</th><td>{{ a.source }}</td></tr>{% endif %}
{% for st in a.steps %}<tr><th>{{ st.title }}</th><td>{{ st.status }}{% if st.error and st.status != 'completed' %} <span class="muted">{{ st.error }}</span>{% endif %}</td></tr>{% endfor %}
<tr><th>Findings</th><td>{% for k, v in d.severity_counts.items() %}<span class="sev {{ k }}">{{ v }} {{ k | upper }}</span>&nbsp; {% else %}<span class="muted">none</span>{% endfor %}</td></tr>
</table>
{% if d.discovery %}<h2>Website discovery</h2>
<p>{{ d.discovery.pages_inspected or 0 }} pages inspected ({{ d.discovery.pages_failed or 0 }} failed){% if d.discovery.page_limit_reached %}, 25-page limit reached{% endif %} · manifest {{ 'found' if d.discovery.manifest_detected else 'not found' }} · {{ d.discovery.endpoints | length }} endpoints</p>
{% if d.discovery.technologies %}<table><tr><th>Technology</th><th>Category</th><th>Version</th><th>Confidence</th><th>Evidence</th></tr>
{% for t in d.discovery.technologies %}<tr><td>{{ t.name }}</td><td>{{ t.category }}</td><td>{{ t.version or '-' }}</td><td>{{ t.confidence }}</td><td class="muted">{{ t.evidence[:2] | join('; ') }}</td></tr>{% endfor %}</table>{% endif %}
{% endif %}
{% if d.source %}<h2>Source analysis</h2>
<p><strong>{{ d.source.support_status }}</strong>. {{ d.source.support_reason }}<br>{{ d.source.framework }} ({{ d.source.runtime }}) · {{ d.source.routes }} route handlers · {{ d.source.db_interactions }} database calls</p>{% endif %}
<h2>Findings</h2>
{% if not d.findings %}<p class="muted">No findings. The checks ROUTES ran found nothing; this does not mean the application is secure.</p>{% endif %}
{% for f in d.findings %}<div class="finding">
<h3><span class="muted">{{ f.id }}</span> · {{ f.title }}</h3>
<div><span class="sev {{ f.severity }}">{{ f.severity | upper }}</span> <span class="muted">· {{ f.status }} · confidence {{ f.confidence }} · {{ f.type }}{% if f.cwe %} · {{ f.cwe }}{% endif %}</span></div>
<p><strong>What is wrong.</strong> {{ f.what_is_wrong }}</p>
<p><strong>Why it matters.</strong> {{ f.why_it_matters }}</p>
<p><strong>Where.</strong> {% if f.file %}<code>{{ f.file }}{% if f.line %}:{{ f.line }}{% endif %}</code>{% endif %}{% if f.endpoint %} endpoint <code>{{ f.method or 'ANY' }} {{ f.endpoint }}</code>{% endif %}</p>
<p><strong>What ROUTES detected.</strong> {{ f.evidence }}</p>
{% if f.data_flow %}<ol class="muted">{% for step in f.data_flow %}<li>{{ step }}</li>{% endfor %}</ol>{% endif %}
<p><strong>Suggested fix.</strong> {{ f.recommendation }}</p>
<p class="muted"><em>{{ f.limitations }}</em></p>
</div>{% endfor %}
<p class="muted" style="margin-top:32px">{{ d.scope_note }}</p>
</body></html>
"""

_env = Environment(autoescape=select_autoescape(default=False, default_for_string=False), trim_blocks=False)
_html_env = Environment(autoescape=True)


def render(a, fmt: str) -> str:
    data = report_data(a)
    if fmt == "json":
        return json.dumps(data, indent=2, ensure_ascii=False)
    if fmt == "html":
        return _html_env.from_string(HTML).render(d=data, a=data["assessment"])
    if fmt == "markdown":
        text = _env.from_string(MARKDOWN).render(d=data, a=data["assessment"])
        while "\n\n\n" in text:
            text = text.replace("\n\n\n", "\n\n")
        return text
    raise ValueError(f"Unknown report format: {fmt}")


def write_report(home, a, fmt: str) -> Path:
    if fmt not in FORMATS:
        raise ValueError("Report format must be markdown, html or json.")
    directory: Path = home.report_dir(a.project_id, a.id)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / FORMATS[fmt]
    path.write_text(render(a, fmt), encoding="utf-8")
    return path
