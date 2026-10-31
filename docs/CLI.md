# ROUTES CLI

`routes` is the main way to use ROUTES. It is a local Python application that keeps its data in `~/.routes`, uses the sandbox engine (Docker) for all untrusted work, and offers both an interactive interface and direct commands.

## Install

Requirements:
- Python 3.11 or newer (3.12 recommended)
- Docker Desktop, or Docker Engine 26+ with Compose v2

From the repository root:

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate     macOS/Linux: source .venv/bin/activate
pip install -e packages/shared -e packages/core -e packages/storage -e apps/cli

routes init          # creates ~/.routes (database, config, engine credentials)
routes engine up     # builds and starts the sandbox engine (first build takes several minutes)
routes doctor        # PASS / WARN / FAIL for every dependency
routes               # opens the interactive interface
```

`routes init` finds `docker-compose.yml` next to the installed package, or uses `ROUTES_COMPOSE_FILE`. If the repository has a `.env` with engine secrets (the web stack's), the CLI uses it, so both share one engine. Otherwise it generates `~/.routes/engine.env` with random secrets.

## Interactive interface

Run `routes` with no arguments in a terminal.

```
ROUTES 0.2.0                                                   project shop

█▀█ █▀█ █ █ ▀█▀ █▀▀ █▀
█▀▄ █▄█ █▄█  █  ██▄ ▄█

Application security assessment
✓ Docker 29.8.2    ✓ Engine ready    ✓ Database 4 assessments

What would you like to do?
  Scan a website
  Analyse a repository or folder
  ...
────────────────────────────────────────────────────────────────────────
› /scan https://example.com
```

The prompt at the bottom is always available. Commands may be typed with or without the leading `/`.

| Command | What it does |
|---|---|
| `/scan <url> [--source <repo/folder/zip>] [--project <name>]` | Website discovery, optionally with source analysis |
| `/analyze <github-url/folder/zip> [--url <site>] [--ref <branch>] [--private]` | Static source analysis |
| `/verify <github-url/folder/zip> --tests <plan.json> [--patch <fix.diff>] [--ref <branch>] [--approve <pkg,...>] [--private]` | Build, run and test the app in a disposable sandbox ([BUILD_RUN.md](BUILD_RUN.md)). Asks for confirmation first, shows each phase live as the engine enters it, Ctrl+C cancels, and the full result is saved under `~/.routes/reports/build-runs/` |
| `/findings [id] [--severity high]` | Findings table with a detail pane |
| `/history [project]` | Previous assessments |
| `/report [markdown/html/json]` | Write a report of the latest assessment |
| `/projects`, `/project add/use/show` | Projects |
| `/doctor` | Environment checks |
| `/engine up/status/stop` | Control the sandbox engine |
| `/home`, `/clear`, `/help`, `/exit` | Navigation |

| Key | Action |
|---|---|
| Enter | Run the command |
| ↑ / ↓ | Command history (kept in `~/.routes/history`) |
| Tab | Complete commands, options, project names and paths |
| Esc | Back to the prompt |
| Ctrl+L | Clear the screen |
| Ctrl+C | Cancel a running assessment (asks first); press twice when idle to exit |

The prompt only accepts the commands above. Nothing typed into it is ever passed to a shell.

**Starting a website scan** always shows a permission dialog first, which you must confirm. If you give both a website and a source, ROUTES asks whether the repository belongs to the website; this only affects how endpoints are linked to code.

**Private repositories** use a hidden token field in a dialog. The token never goes on the command line, into the prompt history, the database, the logs or the sandbox.

### Progress and animation

The assessment screen is driven only by events the sandboxes actually emit:

- A stage is ticked only after the sandbox has moved on to the next one.
- The page bar appears only once the crawler reports pages inspected out of the 25-page limit.
- Counters (files extracted, static-rule matches, routes traced, SQL injection flows) are measured values.
- *Removing sandbox* is shown until the engine confirms that the container, network and gateway session are gone.

Motion is short and restrained: a wordmark fade, spinners on active stages, and view fades. To turn it off:

- `routes --no-animation` for this session
- `reduced_motion = true` under `[ui]` in `~/.routes/config.toml`, permanently
- set `ROUTES_ASCII=1` if your terminal font lacks the symbols

## Direct commands

Every command works without the interactive interface, for scripts and CI:

```bash
routes scan https://example.com --authorised            # --authorised is required without a TTY
routes scan https://example.com --source ./my-app -y
routes analyze https://github.com/owner/repo            # public repository
routes analyze https://github.com/owner/repo --private  # prompts for the token (hidden); needs a TTY
routes analyze ./my-project                             # local folder: packed, never modified
routes analyze ./project.zip                            # up to 100 MB
routes findings                                         # table of the latest assessment
routes findings --id 01                                 # one finding in detail
routes findings --json
routes history [--project shop] [--json]
routes report --format markdown|html|json
routes projects
routes project add ./my-project --name "My Project" --url https://my.site
routes project use my-project
routes project show
routes verify ./my-app --tests plan.json [--patch fix.diff] [--json] [-o result.json]
                                                        # build, run and test in a disposable sandbox (docs/BUILD_RUN.md)
routes doctor [--quick] [--json]
routes engine up | status | stop
routes --version
```

| Exit code | Meaning |
|---|---|
| 0 | Completed |
| 1 | Error, or the assessment failed |
| 2 | Not started: permission not confirmed |
| 3 | Partially completed (one step failed); for `verify`: tests failed |
| 4 | `verify` only: dynamic verification unsupported for this project |

When output is not a terminal (a pipe or a file), or with `--no-animation`, the commands print plain lines without colours or live rendering.

## Storage

```
~/.routes/                       (ROUTES_HOME overrides the location)
  routes.db                      SQLite: projects, assessments, pages, endpoints, technologies, findings
  config.toml                    engine location, UI settings, current project, default report format
  engine.env                     only when ROUTES generated the engine secrets
  history                        prompt history (commands only)
  reports/<project>/<assessment>/report.md, report.html, findings.json
  cache/                         temporary packed folders, deleted right after upload
  logs/
```

**What is kept:**
- Five assessments per project. Older ones, and their report folders, are deleted automatically.
- Metadata and redacted evidence only.

**What is never stored:** HTML, source files, tokens, or secret values found in code.

An assessment whose `routes` process stops (terminal closed, crash) is marked *failed (interrupted)* the next time ROUTES runs.

## How it fits together

```
routes (Typer · Textual · Rich)
  ├─ routes_storage   SQLite + report files
  ├─ routes_core      engine client · run supervision · result mapping · status & retention rules
  └─ 127.0.0.1:8190 ──► sandbox-manager ─► docker-proxy ─► Docker
                                     └─► network-gateway ─► internet (exact host only)
```

The CLI reuses the existing engine and analysis code:
- the Sandbox Manager, Docker API proxy and network gateway, unchanged in their controls
- the discovery and analyzer sandbox images
- the shared result contracts and redaction (`routes_shared`)
- the mapping, final-status and retention rules (`routes_core`), which the web stack's workers use too

The only additions to the engine are:
- a published port on `127.0.0.1` (token required)
- a streaming `POST /uploads` endpoint for archives and packed folders, with the same 100 MB cap and ZIP check
- measured counters in sandbox progress events

See [ARCHITECTURE.md](ARCHITECTURE.md) and [SECURITY.md](SECURITY.md).

## Legacy web interface

The browser stack (Next.js, FastAPI, PostgreSQL, Redis, RQ) still works. It is now the `web` Compose profile: `docker compose --profile web up -d`. It shares the engine with the CLI but has its own database. It is kept until the CLI migration is signed off and is not otherwise developed further.
