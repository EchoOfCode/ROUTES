# REST API

Base path: `/api/v1`. Interactive docs (development): `/api/docs`.

**Authentication:** the `routes_session` HttpOnly cookie, set by register/login.
**CSRF:** every `POST/PATCH/PUT/DELETE` must send `X-CSRF-Token` equal to the `routes_csrf` cookie (from `GET /auth/csrf`). A present `Origin` header must be in `ALLOWED_ORIGINS`.
**Errors:** `{"error": {"code": "...", "message": "...", "details": {"field": "message"}}}`. Resources owned by other users return `404`.

## Auth

| Method | Path | Notes |
|---|---|---|
| GET | `/auth/csrf` | Sets/returns the CSRF token |
| POST | `/auth/register` | `{email, password (≥10), display_name?}` → 201 user, signs in |
| POST | `/auth/login` | `{email, password}`; rate-limited per email and IP |
| POST | `/auth/logout` | Revokes the session server-side |
| GET / PATCH | `/auth/me` | Current user / `{display_name}` |
| POST | `/auth/change-password` | `{current_password, new_password}`; signs out other sessions |
| GET | `/auth/sessions` | Active sessions |
| POST | `/auth/sessions/revoke-others` | |

## Projects and integrations

| Method | Path | Notes |
|---|---|---|
| GET | `/projects` | Includes integration, latest assessment, framework |
| POST | `/projects` | `{website_url, name?, authorised: true}` → `{project, assessment_id}`; discovery starts automatically |
| GET / PATCH / DELETE | `/projects/{id}` | Delete is refused while an assessment runs |
| GET | `/projects/{id}/assessments` | Retained history (≤5) |
| POST | `/projects/{id}/assessments` | `{include_source?, token?}` → `{assessment_id, notes}`; 409 if one is active |
| POST | `/projects/{id}/integrations/github` | `{repo_url, ref?, visibility: public\|private, token?}`; the token is used once and never stored |
| POST | `/projects/{id}/integrations/zip` | `multipart/form-data` field `file` (.zip, ≤100 MB) |
| POST | `/projects/{id}/integrations/match` | `{matches: bool}`: the developer's repository/website decision |
| DELETE | `/projects/{id}/integrations` | Disconnect source |

Connecting a source joins the running assessment if it can still accept work; otherwise it starts a new one.

## Assessments and results

| Method | Path | Notes |
|---|---|---|
| GET | `/assessments` | All of the user's assessments |
| GET | `/assessments/{id}` | Status, child jobs (`stage`, `message`, `stages_completed`, `error`), counts, discovery summary. Poll this. |
| POST | `/assessments/{id}/cancel` | |
| GET | `/assessments/{id}/pages` | |
| GET | `/assessments/{id}/endpoints?origin=` | `form`, `link_query`, `js_reference`, `openapi`, `source_route` |
| GET | `/assessments/{id}/technologies` | With evidence and `source` (website/repository) |
| GET | `/assessments/{id}/source` | Profile, routes, db interactions, env var names, matching evidence |
| GET | `/assessments/{id}/findings[/{finding_id}]` | |
| GET | `/overview` | Counts and recent items for the dashboard |
| GET | `/findings?severity=&type=` | Findings from each project's latest finished assessment |

### Finding object

```json
{
  "id": "…", "type": "SQL Injection", "status": "potential", "severity": "high", "confidence": "high",
  "title": "User input used to build a SQL query",
  "file": "app/api/search/route.ts", "line": 6, "endpoint": "/api/search", "method": "GET",
  "rule_id": "routes.sqli.pg-tainted-query",
  "plain_description": "Input from the URL query parameter \"q\" in the GET /api/search handler appears to be inserted directly into a database query…",
  "evidence_summary": "Untrusted URL query parameter \"q\" reaches pool.query() (pg) through template-string interpolation at app/api/search/route.ts:6.",
  "recommendation": "Keep the SQL text constant and pass user input separately as query parameters…",
  "technical_details": {"cwe": "CWE-89", "source": {…}, "sink": {…}, "flow": […], "query_construction": "interpolated"}
}
```

## Health

`GET /api/health` → `{"api": "ok", "database": "ok", "redis": "ok"}`
