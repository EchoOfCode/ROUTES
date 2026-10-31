# Local development

## Prerequisites

- Docker Desktop 4.30+ or Docker Engine 26+ (volume subpath mounts are required), Compose v2
- Optional, for frontend work outside Docker: Bun 1.1+

## Environment variables (`.env`)

Create it with `scripts/init-env.sh` or `scripts/init-env.ps1`, which generate random secrets.

| Variable | Default | Purpose |
|---|---|---|
| `POSTGRES_USER` / `POSTGRES_PASSWORD` / `POSTGRES_DB` | routes / *generated* / routes | Database credentials |
| `SANDBOX_MANAGER_TOKEN` | *generated* | API/workers ↔ Sandbox Manager |
| `GATEWAY_CONTROL_TOKEN` | *generated* | Sandbox Manager ↔ gateway control API |
| `ALLOWED_ORIGINS` | `http://localhost:3000,http://127.0.0.1:3000` | Origins accepted for state-changing requests. Must match the URL you open. |
| `COOKIE_SECURE` | false | Set true only behind HTTPS |
| `SESSION_TTL_HOURS` | 72 | Session lifetime |
| `WEB_PORT` / `API_PORT` | 3000 / 8000 | Host ports (bound to 127.0.0.1) |
| `ASSESSMENT_HISTORY_LIMIT` | 5 | Assessments kept per project |
| `MAX_CRAWL_PAGES` | 25 | Page cap (cannot exceed 25) |
| `DISCOVERY_TIMEOUT_SECONDS` / `SOURCE_TIMEOUT_SECONDS` | 600 / 900 | Sandbox wall-clock limits |
| `ROUTES_CONTROL_SUBNET` | 172.31.250.0/28 | Fixed subnet of the gateway control network |
| `GATEWAY_DEV_ALLOW_HOSTS` | *(empty)* | **Development only.** Hostnames allowed to resolve to private addresses (e.g. `sample-site`). |

If you change `WEB_PORT`, add the matching origin to `ALLOWED_ORIGINS`.

## How services communicate

- Browser → `web:3000` → (Next.js rewrite) `api:8000/api/*`
- `api` → PostgreSQL, Redis (enqueue), Sandbox Manager (`POST /credentials` for private-repo tokens only)
- workers → Redis (dequeue), PostgreSQL, Sandbox Manager (`/runs`)
- Sandbox Manager → `docker-proxy:2375` (filtered Docker API), `network-gateway:8080` (sessions)
- sandbox → gateway `:3128` on its per-run network → internet

## Running tests

All suites run inside containers, so no host Python is needed. Start Postgres and Redis first (`docker compose up -d postgres redis`).

```bash
# Shared package
docker run --rm -v "$PWD/packages/shared:/src" -w /src python:3.12-slim sh -c "pip install -q . pytest && pytest -q tests"

# API (unit, integration, auth, ownership, lifecycle; uses the routes_test database)
docker compose build migrate
docker compose run --rm --no-deps -v "$PWD/services/api/tests:/srv/api/tests" migrate python -m pytest -q tests

# Workers (lifecycle with a fake sandbox, real PostgreSQL)
docker compose run --rm --no-deps -v "$PWD/services/worker:/srv/worker" -w /srv -e PYTHONPATH=/srv:/srv/api \
  --entrypoint python migrate -m pytest -q worker/tests

# Network gateway, Docker proxy, Sandbox Manager
docker run --rm routes/network-gateway:local python -m pytest -q tests
docker run --rm routes/docker-proxy:local python -m pytest -q tests
docker run --rm routes/sandbox-manager:local python -m pytest -q tests

# Discovery (sample site, 25-page limit, scope, redirects, manifest, real Chromium rendering)
docker run --rm --user 10001:10001 --read-only --tmpfs /tmp:uid=10001,gid=10001 \
  --tmpfs /home/sandbox:uid=10001,gid=10001 --shm-size 128m -w /srv routes/discovery:local \
  python -m pytest -q discovery/tests

# Source analyzer (archive safety, profiling, SQLi true and false positives, Semgrep, redaction)
docker run --rm --user 10001:10001 --read-only --tmpfs /tmp:uid=10001,gid=10001 \
  --tmpfs /home/sandbox:uid=10001,gid=10001 --tmpfs /work:uid=10001,gid=10001 -w /srv routes/analyzer:local \
  python -m pytest -q source_analyzer/tests

# Frontend
cd apps/web && bun install && bun run typecheck && bun run lint && bun run build

# End to end (whole stack, sample site, fixture repository, docker-proxy probes, cleanup, retention)
GATEWAY_DEV_ALLOW_HOSTS=sample-site docker compose --profile testing up -d --build
python scripts/e2e.py --api http://127.0.0.1:8000
```

On Windows Git Bash, prefix `docker run` commands that use `-w /srv` with `MSYS_NO_PATHCONV=1`.

## Frontend development

```bash
docker compose up -d                       # backend stack
cd apps/web && bun install
API_INTERNAL_URL=http://127.0.0.1:8000 bun run dev    # http://localhost:3000 (stop the web container first)
```

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `ports are not available … 3000` or `8000` | Another application uses the port. Set `WEB_PORT`/`API_PORT` in `.env` and add the web origin to `ALLOWED_ORIGINS`. |
| `container name … already in use` | Another stack uses the same container name. ROUTES names its gateway `routes-p1-gateway`; remove or rename the conflicting container only if it is yours. |
| Sign-in fails with "Request origin is not allowed" | The URL in your browser is not in `ALLOWED_ORIGINS`. |
| "The website could not be reached: … gateway refused" | DNS failed, the site resolves to a private/internal address, or the port is not 80/443/8080/8443. For the local sample site, set `GATEWAY_DEV_ALLOW_HOSTS=sample-site`. |
| Assessment stuck in *Queued* | Workers are not running: `docker compose ps`, `docker compose logs worker-discovery`. |
| "The sandbox could not be started (… denied …)" | The Docker proxy refused a request. Check `docker compose logs docker-proxy`; Docker Engine < 26 lacks volume subpath support (ZIP uploads). |
| "GitHub's rate limit for this network has been reached" | GitHub limits requests per IP address. Public imports avoid the API, but private imports use your token's limit (5,000/hour). Wait until the reset time shown, or upload a ZIP. |
| Private repository import fails with 403/404 | The token needs *Contents: Read-only* on that repository; fine-grained tokens must be approved by organisations that require it. Tokens are not stored; supply it again. |
| Source analysis "unsupported" | Detailed analysis covers Next.js + pg only. Other stacks get a profile and general rules. |
| Everything was interrupted by a restart | Expected: the `migrate` service marks interrupted assessments as failed on startup. Run a new assessment. |
| Reset all data | `docker compose down -v` (deletes the database, queues and staged uploads). |
