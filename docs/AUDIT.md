# Remediation loop — implementation audit

Read-only audit, 2026-11-01. Branch: **`feat/remediation-loop`** (2 commits ahead of
`main`: `003fbf0` "M0: remediation loop foundations", `66a8f6a` "M1: content-based
fingerprints, line ranges, and real XSS detection"). Working tree clean, nothing
uncommitted.

No files other than this one were created or changed to produce this audit. No
commits were made.

## Status by item

### 1. Remediation + RemediationIteration DB tables, migration, `remediate` worker phase, config

**PARTIAL — plumbing DONE, remediation logic STUBBED (no-op).**

- Tables: `services/api/app/models/remediation.py` — `Remediation` (finding_id, status,
  error, started_at, finished_at) and `RemediationIteration` (remediation_id,
  iteration_no, candidate_hash, test_results, rescan_diff, failure_output).
- Migration: `services/api/alembic/versions/0002_remediation_tables.py`.
- Enums: `packages/shared/routes_shared/enums.py` — `JobKind.REMEDIATE`,
  `RemediationStatus` (pending/running/succeeded/needs_human_review/failed/cancelled).
- Worker phase: `services/worker/queues/run_worker.py` (`"remediate"` added to
  `QUEUES`), `services/api/app/services/queueing.py` (`JOB_FUNCS`/`JOB_TIMEOUTS`
  entries), `services/worker/jobs/remediate.py`.
- Config: `services/api/app/core/config.py` — `local_llm_endpoint`, `local_llm_model`
  (default `mistral-nemo`), `big_llm_endpoint`, `big_llm_api_key`, `big_llm_model`,
  `max_remediation_iters` (`MAX_ITERS`, default 3), `remediation_token_budget`.
- Infra: `docker-compose.yml` — new `ollama` service (backend-only, no internet) and
  new `worker-remediate` service.

**Fake/hardcoded:** `services/worker/jobs/remediate.py::run_remediate_job` does
**no real work**. It locks the `Remediation` row, marks it `RUNNING`, logs a line,
then unconditionally marks it `SUCCEEDED`. There is no snapshot, no redaction, no
LLM call, no sandbox verification, no rescan. This exists only to prove the queue/DB
plumbing works end to end (M0's literal acceptance bar), not to fix anything.

Test: `services/worker/tests/test_remediate_job.py` (enqueues a real RQ job on the
`remediate` queue, confirms it lands in Redis, runs the stub, confirms the DB row
reaches `SUCCEEDED`).

### 2. Finding fingerprints (rule_id + file + normalized snippet, no line numbers)

**DONE.**

- `packages/shared/routes_shared/fingerprint.py` — `fingerprint(rule_id, file, snippet)`
  = sha256 of `rule_id|file|normalize_snippet(snippet)`, truncated to 32 hex chars.
  `normalize_snippet` strips `//`/`/* */` comments then **all** whitespace (not just
  collapses it), so reindenting/rewrapping never changes the result. Never takes a
  line number as input.
- Wired into: `services/source_analyzer/static_analysis/findings.py` (SQLi findings,
  using a real multi-line sink snippet, not the old 200-char single-line call text),
  `services/source_analyzer/static_analysis/semgrep_runner.py` (was previously hashing
  `rule_id, file, line, col` — now hashes the match's own source snippet instead),
  `services/worker/jobs/source.py::_fingerprint` (safety-net fallback, also snippet-based
  now, previously `rule_id|file|line|method`).
- `end_line` (the "line range" requirement) added to `Finding` contract
  (`packages/shared/routes_shared/contracts.py`), `SecurityFinding` DB model
  (`services/api/app/models/results.py`), migration
  `services/api/alembic/versions/0003_finding_end_line.py`.

Acceptance test exists and passes: `services/source_analyzer/tests/test_analysis.py::
test_fingerprint_survives_reformatting` — reformats `app/api/search/route.ts`
(3 leading blank lines + respaced assignment), asserts the line number changes but
the fingerprint does not.

### 3. VulnClass plugin interface and which classes are behind it

**NOT STARTED.** No such abstraction exists anywhere in the repo (confirmed by
repo-wide grep for `VulnClass`/`vuln_class` — zero hits). SQLi
(`services/source_analyzer/data_flow/sqli.py::SqliAnalyzer`) and XSS
(`services/source_analyzer/data_flow/xss.py::XssAnalyzer`) are two independent,
concretely-named classes called directly and separately from
`services/source_analyzer/main.py::analyse()`. There is no shared interface,
registry, or plugin-loading mechanism — adding a third vulnerability class today
would mean writing a third bespoke `main.py` branch, not registering a plugin.

### 4. Snapshot extraction (data-flow slice via tree-sitter)

**NOT STARTED.** No module, class, or function with "snapshot" in its name exists
anywhere under `services/` (confirmed by grep). The SQLi/XSS engines compute taint
*at scan time* for reporting purposes, but nothing extracts or persists a
function+source+sink+helper-functions code slice for a later remediation step. This
is M2 work, not begun.

### 5. Deterministic redaction (regex, entropy, keywords, numbered placeholders)

**PARTIAL — this is pre-existing Phase-1 code, not new, and not yet extended to meet
the remediation spec.**

`packages/shared/routes_shared/redaction.py` (unchanged by this branch) has:
- Regex secret patterns (AWS keys, GitHub/Stripe/OpenAI/Slack/Google tokens, PEM
  keys, JWTs, credential-in-URL) — **done**.
- A context-keyword heuristic (`password=`, `api_key:`, etc. via `_ASSIGNMENT_RE`)
  — **done**.
- Masking: `mask_value()` replaces the secret with `first 4 chars…[redacted]` — this
  is **irreversible** masking, not a reversible placeholder scheme.

Missing, confirmed by grep (zero hits for `entropy` in `packages/shared/`, zero hits
for `SECRET_1`/`<SECRET_` anywhere):
- **No Shannon entropy check** on string literals.
- **No numbered placeholder scheme** (`<SECRET_1>`, `<SECRET_2>`, …) and **no
  placeholder→real-value map** — `redact_text`/`redact_structure` mask in place and
  throw the original value away; there is nothing to re-insert later. The spec's
  "re-insert real secrets locally via placeholder map" (M4) has no map to work from
  yet.

### 6. Local LLM / Ollama client

**NOT STARTED.** `ollama` only appears in `docker-compose.yml` (the service
definition) and `services/api/app/core/config.py` (the `LOCAL_LLM_ENDPOINT`/
`LOCAL_LLM_MODEL` settings, unused). No HTTP client, no prompt template, no call
site anywhere in `services/worker/` or `services/api/app/`. The `ollama` container
also has no model pulled by default — nothing automates `ollama pull mistral-nemo`
yet (`.env.example` documents it as a manual step).

### 7. Testbench generation and the validation gate

**NOT STARTED.** Zero hits for "testbench" anywhere in the repo. No PGlite, no JS/TS
test template, no gate logic.

### 8. Big LLM client and fix-response validation

**NOT STARTED.** `BIG_LLM_*` exist only as unused config fields
(`services/api/app/core/config.py`). No client, no prompt builder, no response
parser/validator, no patch-apply logic.

### 9. Loop controller

**NOT STARTED.** `MAX_ITERS`/`max_remediation_iters` is a config field that nothing
reads yet (confirmed by grep — no hits in `services/worker/`). `remediate.py` has no
loop, no oscillation/regression checks, no feedback-into-next-prompt logic.

### 10. Verify sandbox kind, docker-proxy changes

**NOT STARTED.** `services/sandbox_manager/manager/app.py` still only recognizes
`kind: Literal["discovery"]` and `kind: Literal["source"]` — no `"verify"` kind.
`docker-compose.yml`'s `ALLOWED_IMAGES` is still exactly
`routes/discovery:local,routes/analyzer:local` — no `routes/verify:local`. No
`infrastructure/docker/verify.Dockerfile`. No Node+PGlite image anywhere.

### 11. API endpoints and UI

**NOT STARTED.** No `remediat*` match anywhere under `services/api/app/api/` or
`apps/web/`. No `POST /assessments/{id}/findings/{fid}/remediate`, no GET/cancel
routes, no "Fix this" button, no iteration timeline, no diff view.

### 12. Any detectors added (A02 rules, A01, XSS)

- **XSS: DONE** (this branch, M1) — two new taint-based rules in
  `services/source_analyzer/data_flow/xss.py`:
  - `routes.xss.dom-sink-tainted` — `innerHTML`/`document.write()` fed by
    `location.*`/`document.referrer`/`window.name`/`useSearchParams()`.
  - `routes.xss.reflected-response` — request parameter reflected unescaped into a
    `Response`/`NextResponse` body.
  Both reuse the SQLi engine's `TaintEngine` via a new `extra_seed` hook
  (`services/source_analyzer/data_flow/taint.py`). The pre-existing Semgrep pattern
  rule `routes.xss.dangerously-set-inner-html` is untouched and still runs
  independently.
- **A01 (Broken Access Control): NOT STARTED.** No rule of this category exists.
- **A02 (Cryptographic Failures): pre-existing only, nothing added this branch.**
  `services/source_analyzer/static_analysis/rules/routes.yml` already has
  `routes.crypto.weak-hash` (MD5/SHA-1), `routes.config.tls-verification-disabled`,
  and the various `routes.secrets.*` hardcoded-secret rules — none of these were
  touched or added by M0/M1.
- SQLi detection (`services/source_analyzer/data_flow/sqli.py`) is pre-existing,
  untouched in substance (only extended with `sink_end_line`/`sink_snippet` fields
  for fingerprinting, no detection-logic change).

## Network/sandbox restriction changes

**One change, already flagged and approved before it was made (see commit
`003fbf0`):** a brand-new `worker-remediate` service was added to
`docker-compose.yml` on **both** `backend` *and* `egress` networks — it is the only
worker-tier service with any route to the internet (`worker-discovery` and
`worker-source` remain exactly as internal-only as before, `backend` is still
`internal: true`). This is additive (a new, separate service getting a new
capability), not a weakening of any existing sandbox, docker-proxy, or
network-gateway restriction — `sandbox_manager`, `docker-proxy`, and
`network-gateway` source code are all untouched by this branch (confirmed above:
no `verify` kind, no `ALLOWED_IMAGES` change). `ollama` itself has no internet access
(`backend` only).

## Test runs (raw output, just executed)

```
$ docker run --rm -v "$PWD/packages/shared:/src" -w /src python:3.12-slim \
    sh -c "pip install -q . pytest && pytest -q tests"
.............................................                            [100%]
45 passed in 0.05s
```

```
$ docker run --rm --user 10001:10001 --read-only --tmpfs /tmp:uid=10001,gid=10001 \
    --tmpfs /home/sandbox:uid=10001,gid=10001 --tmpfs /work:uid=10001,gid=10001 \
    -w /srv routes/analyzer:local python -m pytest -q source_analyzer/tests
..................................                                       [100%]
=============================== warnings summary ===============================
.../_pytest/cacheprovider.py:487: PytestCacheWarning: could not create cache path
  /srv/.pytest_cache/... [Errno 30] Read-only file system (expected: image is read-only)
34 passed, 1 warning in 6.85s
```

```
$ docker compose run --rm --no-deps -v "$PWD/services/api/tests:/srv/api/tests" \
    migrate python -m pytest -q tests
................................                                         [100%]
=============================== warnings summary ===============================
.../fastapi/testclient.py:1: StarletteDeprecationWarning: httpx testclient usage
.../_pytest/cacheprovider.py:487: PytestCacheWarning: permission denied (read-only mount)
32 passed, 2 warnings in 4.07s
```

```
$ docker compose run --rm --no-deps -v "$PWD/services/worker:/srv/worker" -w /srv \
    -e PYTHONPATH=/srv:/srv/api --entrypoint python migrate -m pytest -q worker/tests
........                                                                 [100%]
=============================== warnings summary ===============================
.../_pytest/cacheprovider.py:487: PytestCacheWarning: permission denied (read-only mount)
8 passed, 1 warning in 1.00s
```

Not run (no code under them changed on this branch, so nothing to regress):
`services/sandbox_manager/tests`, `infrastructure/docker-proxy/tests`,
`infrastructure/network-gateway/tests`, `services/discovery/tests`, `apps/web`
typecheck/lint/build.

## One-line summary per item

| # | Item | Status |
|---|------|--------|
| 1 | Remediation tables/migration/worker phase/config | PARTIAL (plumbing done, job is a no-op stub) |
| 2 | Content-based fingerprints + line range | DONE |
| 3 | VulnClass plugin interface | NOT STARTED |
| 4 | Snapshot extraction | NOT STARTED |
| 5 | Deterministic redaction (entropy, placeholders) | PARTIAL (regex+keywords only; no entropy, no placeholders, irreversible) |
| 6 | Local LLM / Ollama client | NOT STARTED (service exists, unused) |
| 7 | Testbench + validation gate | NOT STARTED |
| 8 | Big LLM client + validation | NOT STARTED (config only) |
| 9 | Loop controller | NOT STARTED |
| 10 | Verify sandbox + docker-proxy | NOT STARTED |
| 11 | API + UI | NOT STARTED |
| 12 | New detectors | XSS DONE; A01 NOT STARTED; A02 pre-existing, untouched |
