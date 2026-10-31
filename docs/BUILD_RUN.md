# Build-and-run sandboxes (`build_run`)

ROUTES can build, run and test a developer's application inside a disposable
environment. This is the execution half of future remediation work: a
Remediation Engine produces a candidate patch and a test plan, and ROUTES
returns structured evidence of what happened. **The Sandbox Manager never
decides whether a patch is secure.** It runs the approved plan and reports.

The developer's repository is never modified. Any patch is applied to a
temporary copy of the source snapshot inside the sandbox.

Supported today: Node.js + Next.js projects with an npm lockfile
(`package-lock.json`), optionally using PostgreSQL through `pg` with SQL schema
or migration files. Anything else returns `DYNAMIC_VERIFICATION_UNSUPPORTED`
with the reason.

## Using it

```bash
routes verify ./my-app --tests plan.json                    # build, run, test
routes verify ./my-app --tests plan.json --patch fix.diff   # same, with a candidate patch
routes verify https://github.com/owner/repo --tests plan.json [--ref main] [--private]
routes verify ./my-app -t plan.json --json -o result.json   # structured result
```

Exit codes: `0` verified run, `3` tests failed, `4` dynamic verification
unsupported, `1` build failure or inconclusive. Ctrl+C cancels the run and waits
until the environment has been removed.

From code (the interface for the future Remediation Engine), see
`packages/core/routes_core/buildrun.py`:

```python
from routes_core.buildrun import BuildRunRequest, submit, wait
run = submit(client, BuildRunRequest(source=classify(path), test_plan=plan, patch=diff), cache_dir=cache)
final = wait(client, run, on_state=show_progress)
final["result"]["verification"]
```

Engine API: the existing `POST /runs` with `kind: "build_run"`, then `GET` and
`DELETE /runs/{id}` as for every other run. Fields: `source` (`zip` with an
`upload_id` from `POST /uploads`, or `github` with `owner`/`repo`/`ref` and an
optional `credential_handle`), `patch` (unified diff, ≤ 1 MB), `test_plan`,
`options` (`timeouts` that may only *lower* the engine's limits, and
`approved_scripts`) and `requested_by`.

### Generating a test plan

```bash
routes analyze ./my-app                       # static analysis first (routes + SQL injection flows)
routes testplan ./my-app -o plan.json         # generate, then review/edit the file
routes verify ./my-app --tests plan.json      # or skip the file: --tests auto (also /verify ... --tests auto)
```

`routes_core.testplan.generate` builds the plan from the stored analysis:

* **health:** `/` answers without a server error;
* **smoke:** every GET route without dynamic segments answers without a 5xx;
* **security:** for each traced SQL injection flow, using exactly the input the data-flow analysis found (a query
  parameter, route parameter, JSON body field or header):
  * a lone quote must not cause a 5xx or leak a PostgreSQL error message (error-based);
  * a stacked `pg_sleep(3)` must not delay the response beyond 2.5 s (time-based, which also catches injection whose
    errors are hidden). For ID-like inputs a numeric variant is added.

Payloads never write, drop or change data, and they pass on a correctly parameterised implementation, so the same plan
checks both the vulnerable code and a fix.

The generator explains what it skipped:
* inconclusive findings;
* flows without a known route or input name;
* dynamic routes, whose valid IDs depend on your data;
* POST-only routes, whose request bodies are application-specific.

Add tests for these by hand. A passing generated plan is evidence about the probed inputs only, not proof that the
application has no SQL injection.

### Test plan

Declarative, validated by `routes_shared.buildrun.TestPlan`. Tests address the
application under test by **path only**; URLs, other hosts and header
smuggling are refused.

```json
{
  "version": 1,
  "health": {"path": "/api/health", "expect_status": [200]},
  "database": {"seed_sql": "INSERT INTO users (email) VALUES ('synthetic@example.test');"},
  "tests": [
    {"id": "sec-sqli", "name": "Injection does not return every row", "category": "security",
     "request": {"method": "GET", "path": "/api/products", "query": {"q": "x%' OR 1=1 --"}},
     "expect": {"status": [200], "body_not_contains": ["Widget"]}}
  ]
}
```

Categories are `security`, `functional`, `edge` and `health`. Expectations are
`status`, `status_not`, `body_contains`, `body_not_contains`, `json_equals`
(top-level keys) and `max_ms`.

### Result

```json
{
  "run_id": "…", "status": "completed", "verification": "VERIFIED_RUN",
  "application": {"build": "passed", "startup": "passed", "health_check": "passed"},
  "tests": {"total": 10, "passed": 10, "failed": 0, "errors": 0},
  "security": {"total": 4, "passed": 4, "failed": 0}, "functional": {…}, "edge": {…}, "health": {…},
  "cases": [ … per test: status, HTTP status, duration, reasons, redacted excerpt on failure … ],
  "stages": { "source": …, "dependencies": …, "database": …, "build": …, "startup": … },
  "isolation": {"build_runner": {"verdict": "isolated", "probes": [ … ]}, "test_runner": [ … ]}
}
```

The run state also carries `phase`, `phase_history`, `audit` (every manager
action with a timestamp), `owner` and the gateway's `network_summary` for the
install stage.

| `verification` | Meaning |
|---|---|
| `VERIFIED_RUN` | Built, started, healthy, and every test in the plan passed. |
| `TESTS_FAILED` | The application ran but at least one test failed. |
| `BUILD_FAILED` | Patch, dependency install, database setup, build or start failed. |
| `DYNAMIC_VERIFICATION_UNSUPPORTED` | The project cannot be reconstructed reliably (no npm lockfile, not Next.js, database without schema, …). |
| `INCONCLUSIVE` | Timeout, cancellation, isolation failure, infrastructure error, or an empty test plan. |

Logs are bounded tails (a few KB per stage), redacted for secrets before they
leave the sandbox.

## Lifecycle

```
CREATED ─► SOURCE_READY ─► DEPENDENCIES_INSTALLING ─► (egress removed) ─► DATABASE_STARTING
        ─► BUILDING ─► APPLICATION_STARTING ─► TESTING ─► COLLECTING_RESULTS
        ─► COMPLETED | FAILED | CANCELLED ─► CLEANED_UP
```

Phases move forward only, and each is entered when that work actually starts:
either the build runner's event says so or the manager has completed its own
step. The database is provisioned **before** the build because Next.js may
render database-backed pages while building.

```
             package network (internal)         database network (internal)
           ┌──────────────────────────┐       ┌────────────────────────────┐
 gateway ──┤  build runner  (install) │       │ build runner ── PostgreSQL │
 (registry │                          │       └────────────────────────────┘
  only)    └──────────────────────────┘       test network (internal)
             removed after install            ┌────────────────────────────┐
                                              │ build runner ── test runner│
                                              └────────────────────────────┘
```

1. **Created.** The manager validates the request (test plan, patch,
   timeouts). It stages the patch and synthetic seed next to the uploaded
   snapshot, and the test plan in a separate directory.
2. **Package network.** An internal network for this run only. The gateway
   joins it, with a `packages` session whose destinations are fixed in the
   gateway itself (`registry.npmjs.org:443`, HTTPS `CONNECT` only, optionally
   one GitHub import) and a byte cap.
3. **Build runner** (`routes/build-runner`, fixed entrypoint
   `build_runner.main`):
   * extracts the snapshot to tmpfs with the analyzer's safe extractor, which
     refuses traversal and absolute paths, skips symlinks and devices, applies
     size and ratio caps, and keeps the owner executable bit only;
   * validates and applies the patch with `git apply` to that copy;
   * profiles `package.json` and the lockfile. Repository `Dockerfile`,
     Compose, `.npmrc` and `.yarnrc` files are never used; `.npmrc` is
     disabled so the repository cannot point npm at another registry or add
     credentials;
   * runs `npm ci --ignore-scripts`.
4. **Egress removed.** The runner announces `awaiting_isolation`. The manager:
   * closes the gateway session;
   * detaches the gateway;
   * creates the database network and the PostgreSQL container;
   * creates the test network;
   * attaches the runner to both;
   * detaches the runner from the package network, then deletes that network.

   The runner waits until it can observe the change, then probes forbidden
   destinations: metadata IP, public IPs, registry, GitHub,
   `host.docker.internal`, the gateway, and each network's bridge address on
   common ports. **Any destination that accepts a connection fails the run
   closed.**
5. **Install scripts.** Dependency install scripts that were skipped are
   listed. Only packages the developer approved (`--approve-script`; `<root>`
   for the project's own lifecycle scripts) are rebuilt, offline. Unapproved
   scripts are reported, never silently enabled.
6. **Database.** PostgreSQL (`routes/build-db`, tmpfs data, UID 10001) on the
   run's private network. Repository `schema.sql`/migrations and seed files,
   then ROUTES' synthetic seed, are applied with `psql`. The application's
   `DATABASE_URL`/`PG*` variables point only at this database. Other
   referenced environment variables get an inert placeholder; no real secret
   is provided.
7. **Build and start.** `npm run build` (or `next build`) and a production
   start (`npm run start` unless it runs a dev server or pins its own port; then
   `next start`) on port 3000. **No host port is published.**
8. **Tests.** After the health check passes, the manager starts the test
   runner (`routes/test-runner`) on the test network. It can reach only the
   application. It records evidence that the database, gateway, metadata IP and
   internet are unreachable from it.
9. **Results and cleanup.** The manager stops the runner with SIGTERM, so it
   stops the application and writes its report, then collects both results.
   It then removes all three containers, any remaining networks and the
   gateway session, and deletes the staged snapshot, patch, seed and test plan.
   This happens on success, failure, timeout and cancellation. Every step
   tolerates already-removed resources. On startup the manager removes leftover
   `routes.sandbox=true` containers and `routes-sbx-*` networks and stale
   upload directories, and nothing else.

## Security boundaries

| Control | Where enforced |
|---|---|
| No Docker socket, no host mounts, no privileged mode, no host networking, no published ports, non-root, `CapDrop: ALL`, `no-new-privileges`, read-only root filesystem, memory/CPU/PID limits | docker-proxy `check_container_create` (unchanged rules; tests in `infrastructure/docker-proxy/tests`) |
| Only the five ROUTES sandbox images may run | docker-proxy `ALLOWED_IMAGES` |
| A container may only join networks of **its own run** | docker-proxy `check_attachment` (new) |
| The gateway may only join networks created for egress (`routes.gateway=allowed`); database and test networks never get it | docker-proxy `check_attachment` (new) |
| Egress during install: registry only, HTTPS only, byte-capped, fixed by the gateway | gateway `packages` mode (new) |
| No egress after install (network-level, not proxy variables) | manager handshake + runner self-check, fail closed |
| Test runner can reach only the application | private test network; evidence in the result |
| PAT never reaches the build runner or application | credential handle → gateway session only |

### Documented exceptions

* **Executable `/work` for the build runner only.** Node native add-ons
  (Next.js' SWC compiler, for example) are loaded with `dlopen`, which fails on
  `noexec` mounts. The docker-proxy allows `exec` only for images listed in
  `BUILD_IMAGES`, only on `/work`, and never with `suid` or `dev`. Every other
  tmpfs stays `noexec`, and the `TmpfsOptions` mount form can no longer pass
  raw options at all.
* **Larger caps for the build runner.** Up to 4 GiB of memory and 3 GiB per
  tmpfs (`MAX_BUILD_MEMORY_BYTES`, `MAX_BUILD_TMPFS_BYTES`), because tmpfs
  counts against memory and production builds are memory-hungry. Other images
  keep the original caps.
* **Network attach/detach during a run.** These use the existing
  proxy-filtered `connect`/`disconnect` operations, now additionally limited
  to the same run. There is no `exec`, no archive upload into containers and
  no volume creation.

### Known limitations

* **Bridge address.** On Docker's internal networks the bridge (host-side)
  address of each network still answers at the IP level. In tests every probed
  port there was refused or closed (see the isolation evidence in each
  result), and the run fails closed if any of them accepts a connection. Only
  the probed ports are checked, so a service listening on the Docker host's
  bridge interface on another port is not covered.
* Only npm lockfiles, Next.js and SQL-file schemas are supported. Prisma/Knex
  migrations written in JavaScript, Yarn, pnpm and monorepos are reported as
  unsupported.
* Fonts or other assets fetched from the internet at build time (for example
  `next/font/google`) fail, because builds have no network access.
* One build-run at a time by default (`MAX_CONCURRENT_BUILD_RUNS=1`).

## Limits (environment variables on `sandbox-manager`)

| Variable | Default |
|---|---|
| `BUILD_RUNNER_MEMORY_MB` / `BUILD_RUNNER_MILLICPUS` / `BUILD_RUNNER_PIDS` | 3072 / 2000 / 512 |
| `BUILD_WORK_TMPFS` (source, `node_modules`, build output) | 2g |
| `BUILD_DB_MEMORY_MB` | 512 |
| `BUILD_DOWNLOAD_MAX_BYTES` (gateway cap for the install stage) | 512 MiB |
| `BUILD_INSTALL_TIMEOUT_SECONDS`, `…_DATABASE_…`, `…_BUILD_…`, `…_STARTUP_…`, `…_TESTS_…`, `…_TOTAL_…` | 600, 120, 600, 180, 300, 2400 |
| `MAX_CONCURRENT_BUILD_RUNS` | 1 |

Logs are capped per stage (about 6–8 KB of tail), and each container's Docker
log is capped at 32 MB.
