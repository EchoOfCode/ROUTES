# ROUTES

ROUTES is a local-first application security assessment tool for developers, used from the terminal. Point it at a website you own, or at your code, and it:

- discovers the site's public pages, forms, API endpoints and technology stack, inside an isolated sandbox
- analyses source code (a GitHub repository, a local folder or a ZIP) to map routes, database queries and configuration
- runs static security analysis, mainly for **SQL injection** in Next.js + PostgreSQL (`pg`) applications
- explains each finding in plain language, with evidence, a suggested fix and the limits of the analysis

This is **Phase 1**: discovery and static analysis. ROUTES does not attack sites, reproduce exploits or generate fixes. See [docs/PHASE_1_SCOPE.md](docs/PHASE_1_SCOPE.md).

## Quick start

Requirements:
- Python 3.11+ (3.12 recommended)
- Docker Desktop, or Docker Engine 26+ with Compose v2

```bash
python -m venv .venv
.venv\Scripts\activate                 # Windows   (macOS/Linux: source .venv/bin/activate)
pip install -e packages/shared -e packages/core -e packages/storage -e apps/cli

routes init                            # ~/.routes: database, config, engine credentials
routes engine up                       # build and start the sandbox engine (first build: several minutes)
routes doctor                          # check every dependency
routes                                 # open the interactive interface
```

In the interactive interface, type `/scan https://your-site.example` or `/analyze ./your-project`, then follow the live progress. `/help` lists every command. You can also run each command directly in your shell:

```bash
routes scan https://your-site.example --source ./your-project
routes findings
routes findings --id 01
routes report --format html
```

Full guide: [docs/CLI.md](docs/CLI.md).

## Trying it offline with the bundled sample site

Real assessments block private and internal addresses. To try ROUTES against the bundled sample site:

```bash
# macOS / Linux
GATEWAY_DEV_ALLOW_HOSTS=sample-site routes engine up --with-sample-site
GATEWAY_DEV_ALLOW_HOSTS=sample-site routes scan http://sample-site:8080 --authorised
GATEWAY_DEV_ALLOW_HOSTS=sample-site python scripts/cli_e2e.py      # automated end-to-end check

# Windows PowerShell: set the variable first
$env:GATEWAY_DEV_ALLOW_HOSTS = "sample-site"; routes engine up --with-sample-site
```

**Never** set `GATEWAY_DEV_ALLOW_HOSTS` for real use. Run `routes engine up` without it to restore the normal policy.

## Architecture at a glance

```
routes (CLI + interactive UI) ─► ~/.routes (SQLite, reports)
        │ 127.0.0.1, token
        ▼
  sandbox-manager ─► docker-proxy ─► Docker
        │
        └─ per-run internal network: [sandbox] ◄─► network-gateway ─► internet (exact host only)
```

Discovery and source analysis run in disposable containers that are non-root and read-only. Their only route out is a gateway that enforces policy:
- it blocks private, loopback, link-local and metadata addresses;
- it keeps traffic to the exact submitted hostname.

Assessments never execute repository code. `routes verify` is separate: it builds, runs and tests an application inside a disposable three-container environment. Its egress is limited to the npm registry during install and removed before any repository code runs. See [docs/BUILD_RUN.md](docs/BUILD_RUN.md). Details: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), [docs/SECURITY.md](docs/SECURITY.md).

## Documentation

| Document | Contents |
|---|---|
| [CLI.md](docs/CLI.md) | Installing and using `routes`: commands, keys, storage, animation settings |
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | Engine, sandboxes, networks, assessment lifecycle |
| [PHASE_1_SCOPE.md](docs/PHASE_1_SCOPE.md) | What is and is not included, supported stacks |
| [SECURITY.md](docs/SECURITY.md) | Isolation, secrets handling, known limitations |
| [BUILD_RUN.md](docs/BUILD_RUN.md) | Build-and-run sandboxes: lifecycle, test plans, results, security boundaries |
| [LOCAL_DEVELOPMENT.md](docs/LOCAL_DEVELOPMENT.md) | Tests, environment variables, troubleshooting |
| [DATABASE.md](docs/DATABASE.md), [API.md](docs/API.md) | Legacy web stack: PostgreSQL schema and REST API |

## Repository layout

```
apps/cli                 routes CLI: Typer commands, Textual interface, Rich renderers, reports
packages/shared          Contracts, enums, network policy, redaction, event protocol, upload staging
packages/core            Engine client, run supervision, result mapping, status/retention rules
packages/storage         ~/.routes layout, config, SQLite models and repository
services/discovery       Sandbox: HTTP crawler, Playwright renderer, endpoint and technology detection
services/source_analyzer Sandbox: safe extraction, profiling, tree-sitter, Semgrep, data-flow engine
services/sandbox_manager Orchestrates disposable containers through the Docker proxy (incl. build-runs)
services/build_runner    Sandbox: fixed-entrypoint install/build/start of a Next.js app (+ synthetic fixture)
services/test_runner     Sandbox: executes a declarative test plan against one application
infrastructure/          Dockerfiles, Docker API proxy, network gateway
apps/web, services/api,  Legacy browser stack (Compose profile `web`), kept during the migration
  services/worker
scripts/                 cli_e2e.py (CLI end-to-end), build_run_e2e.py (build-run scenarios), e2e.py (web stack), init-env
```
