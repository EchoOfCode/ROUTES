# ROUTES

ROUTES is a local-first application security assessment platform for developers. You give it a website you own, and it:

- discovers the site's public pages, forms, API endpoints and technology stack, inside an isolated sandbox
- optionally analyses the site's source code (GitHub or ZIP) to map routes, database queries and configuration
- runs static security analysis, mainly for **SQL injection** in Next.js + PostgreSQL (`pg`) applications
- shows evidence-backed findings in plain language, with technical details for developers

This is **Phase 1**: platform foundation and discovery. It does not execute attacks, reproduce exploits or generate fixes. See [docs/PHASE_1_SCOPE.md](docs/PHASE_1_SCOPE.md).

## Quick start

Requirements: Docker Desktop (or Docker Engine 26+) with Compose v2. Nothing else is needed on the host.

```bash
# 1. Create .env with random secrets
./scripts/init-env.sh            # macOS / Linux
# or: powershell -File scripts\init-env.ps1   (Windows)

# 2. Build and start everything (the first build downloads Chromium and Semgrep; allow several minutes)
docker compose up -d --build

# 3. Open the interface
#    http://localhost:3000  (or the WEB_PORT you set in .env)
```

Then:

1. **Register** an account (email and password; stored only in your local PostgreSQL).
2. Click **New project** and enter the website URL.
3. Tick *"I confirm that I own this website or have permission to assess it."* and click **Start discovery**.
4. Optionally connect a **public GitHub repository**, a **private repository** (fine-grained token, read-only), or **upload a ZIP** (up to 100 MB).
5. Follow progress live. When the assessment finishes, review **Technologies, Pages, Forms, API endpoints, Database interactions, Security findings** and **Source repository**.

Stop with `docker compose down`. Your data is kept in Docker volumes, so `docker compose up -d` resumes where you left off.

## Trying it locally with the bundled sample site

Real assessments block private and internal addresses. To try ROUTES offline against the bundled sample site:

```bash
GATEWAY_DEV_ALLOW_HOSTS=sample-site docker compose --profile testing up -d --build
python scripts/e2e.py --api http://127.0.0.1:8000        # automated acceptance run
```

In the UI, create a project for `http://sample-site:8080/`. **Never** set `GATEWAY_DEV_ALLOW_HOSTS` for real use. See [docs/LOCAL_DEVELOPMENT.md](docs/LOCAL_DEVELOPMENT.md).

## Architecture at a glance

```
browser ─► web (Next.js) ─► api (FastAPI) ─► PostgreSQL, Redis/RQ
                                   │
                    workers ───────┴─► sandbox-manager ─► docker-proxy ─► Docker
                                                │
                       per-run internal network: [sandbox] ◄─► network-gateway ─► internet
```

Discovery and source analysis run in disposable, non-root, read-only containers. Their only route out is a policy-enforcing gateway that blocks private, loopback, link-local and metadata addresses and keeps traffic to the exact submitted hostname. Details: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) and [docs/SECURITY.md](docs/SECURITY.md).

## Documentation

| Document | Contents |
|---|---|
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | Services, networks, data flow, job lifecycle |
| [PHASE_1_SCOPE.md](docs/PHASE_1_SCOPE.md) | What is and is not included, supported stacks |
| [API.md](docs/API.md) | REST endpoints |
| [DATABASE.md](docs/DATABASE.md) | Schema, retention |
| [SECURITY.md](docs/SECURITY.md) | Threat model, isolation, secrets handling, known limitations |
| [LOCAL_DEVELOPMENT.md](docs/LOCAL_DEVELOPMENT.md) | Environment variables, tests, troubleshooting |

## Repository layout

```
apps/web                 Next.js interface (Bun, Tailwind, shadcn/ui, Lucide)
services/api             FastAPI REST API, SQLAlchemy models, Alembic migrations
services/worker          RQ jobs: discovery, source analysis, results processing
services/discovery       Sandbox: HTTP crawler, Playwright renderer, endpoint and technology detection
services/source_analyzer Sandbox: safe extraction, profiling, tree-sitter structure, Semgrep, data-flow engine
services/sandbox_manager Orchestrates disposable containers through the Docker proxy
infrastructure/          Dockerfiles, Docker API proxy, network gateway, Postgres/Redis config
packages/shared          Python contracts, enums, network policy, redaction (shared by services)
scripts/                 init-env, e2e acceptance script
```
