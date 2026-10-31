# Security

ROUTES handles two kinds of untrusted input: **websites** (anything they return, including scripts run by the renderer) and **source code** (archives and repositories). Both are processed only inside disposable sandboxes. This document describes the controls and their limits.

## Sandboxes

Every discovery or source run is a fresh container created by the Sandbox Manager:

| Control | Setting |
|---|---|
| User | UID/GID 10001 (non-root) |
| Root filesystem | read-only |
| Writable space | tmpfs only (`/tmp`, `/home/sandbox`, `/work`), `noexec,nosuid,nodev`, size-capped, owned by the sandbox user |
| Capabilities | all dropped; `no-new-privileges` |
| Resources | memory (no swap), CPU, PID limits; ulimits |
| Time | wall-clock timeout (default 10 / 15 min) enforced by the manager; RQ job timeouts above it |
| Mounts | none, except a ZIP upload mounted read-only through a per-upload volume **subpath** |
| Docker socket | never present |
| Network | per-run `internal` network shared only with the gateway, or no network (ZIP) |
| Cleanup | container, network and gateway session removed in `finally`; orphans removed when the manager starts |

Repository code is never executed: there is no `npm install`, build or lifecycle script. The analyzer reads files with tree-sitter and Semgrep only.

Chromium runs with `--no-sandbox` because its namespace sandbox needs privileges the container deliberately lacks; the container is the isolation boundary.

## Engine API for the CLI

The Sandbox Manager is published on `127.0.0.1` only (`ROUTES_ENGINE_PORT`, default 8190), through a dedicated `cli` network that only the manager joins. Sandboxes never join it.

- Every call needs `SANDBOX_MANAGER_TOKEN`, compared in constant time. The CLI reads the token from the engine env file, never from config.toml.
- `POST /uploads` streams an archive (≤100 MB, ZIP signature checked, never opened) into the uploads volume.
- An upload is claimed by exactly one run, and deleted when that run finishes, or after 30 minutes if no run claims it.
- At most 8 uploads may be pending.
- The CLI packs local folders itself:
  - it only reads them;
  - it skips dependency, build and VCS folders, binaries, and files over 50 MB;
  - it never follows symlinks;
  - it deletes the temporary ZIP immediately after upload.
- Private-repository tokens are entered in a hidden field (Textual password input or `getpass`). They are never accepted as command-line arguments or recorded in the prompt history. They are sent once to `POST /credentials`; only the opaque handle is used afterwards.
- `routes doctor` reads tool versions by running the sandbox images briefly with no network, a read-only filesystem, no capabilities, a non-root user and no mounts. Only ROUTES' own image code runs.

## Restricted Docker API (`infrastructure/docker-proxy`)

The worker has no Docker access. The Sandbox Manager reaches Docker only through the proxy, which is default-deny:

- **Allowed:** ping/version, inspect of allow-listed images, container create/start/wait/kill/stop/logs (non-follow)/inspect/delete, and network create/inspect/connect/disconnect/delete. Lists are forcibly filtered to `routes.sandbox=true`.
- **Container create is validated field by field:** allow-listed image, `routes-sbx-` name, sandbox label, non-root user and group, `CapDrop: ALL`, `no-new-privileges`, read-only rootfs, memory/CPU/PID limits within caps, no swap. Refused: privileged mode, bind mounts, devices, host PID/IPC/UTS/user namespaces, `CapAdd`, sysctls, port publishing, unconfined seccomp/AppArmor, custom runtimes, `MaskedPaths` overrides, and executable tmpfs. Volume mounts are allowed only for the uploads volume, read-only, at `/input`, with a UUID subpath.
- Operations on existing containers and networks require the sandbox label (checked by inspecting first). Network connect is limited to sandbox containers or the gateway.
- Everything else (exec, attach, archive, build, image pull, volumes, swarm, plugins, `/info`) returns 403.

Tests: `infrastructure/docker-proxy/tests` (60 cases) and `scripts/e2e.py` (live probe).

## Controlled network gateway (`infrastructure/network-gateway`)

Sandbox networks are created with `internal: true`, so a sandbox has **no route** to anything except the gateway. Ignoring the proxy settings does not give it internet access; it simply has none. This is enforced by Docker's network isolation, not by `HTTP_PROXY` variables.

For each run the manager opens a session bound to (a) a random token, (b) the run network's subnet and (c) a mode:

- **web** (discovery): only the exact submitted hostname; ports 80/443 (+8080/8443 if submitted); only `CONNECT` and absolute-form `GET/HEAD`; no request bodies.
- **github_import** (source): only `GET /import`. The gateway itself fetches the archive, with a 100 MB cap. Private repositories: `api.github.com` with the token, following a redirect only to `codeload.github.com` (without the token). Public repositories: `codeload.github.com` directly, so imports do not use GitHub's unauthenticated API limit of 60 requests per hour.

For every connection the gateway resolves DNS itself, rejects the destination if **any** resolved address is loopback, private (RFC 1918 / ULA), link-local (including `169.254.169.254` and `fd00:ec2::254`), CGNAT, multicast, reserved, NAT64/6to4/Teredo-wrapped internal, or unspecified, and then connects to the **validated IP** (no second lookup). This prevents DNS rebinding. Each redirect is a new request and is validated again. Per-session byte limits and idle and lifetime timeouts apply. Allowed and denied destinations are logged per session and summarised on the assessment.

The control API is reachable only from the fixed control subnet and requires a bearer token. Sandbox subnets may not overlap it. IP forwarding is disabled in the gateway's network namespace.

## Credentials and secrets

- **Passwords:** Argon2id (`argon2-cffi`, t=3, m=64 MiB, p=2), with rehash on login if parameters change. Equal error messages and timing for unknown emails.
- **Sessions:** 256-bit random tokens; only SHA-256 hashes stored; HttpOnly, `SameSite=Lax`, `Secure` when `COOKIE_SECURE=true`; revoked on logout and on password change (other sessions).
- **CSRF:** double-submit token plus an Origin allow-list for every unsafe request.
- **Rate limits:** login per email and per IP; registration per IP (Redis).
- **GitHub tokens:** frontend → API (request body, memory only) → Sandbox Manager in-memory store (15-minute TTL, single use, scoped to `owner/repo`), which returns an opaque handle. Only the handle goes into the RQ job. The manager passes the token to the gateway session and the gateway uses it once for `api.github.com` (never for redirect targets) and wipes it. It is never written to PostgreSQL, Redis, logs, environment variables, git remotes or the sandbox. Verified by `test_private_repo_token_is_never_persisted` and the manager tests.
- **Secrets in analysed code:** Semgrep secret matches are masked (at most four characters shown) inside the sandbox; the whole result is passed through `routes_shared.redaction` in the sandbox and again in the worker. Environment variables are recorded by name only.

## Archive handling (`source_analyzer/acquisition/archive.py`)

ZIP signature check (API) and full validation (sandbox); ≤20,000 entries; ≤500 MB total and ≤50 MB per file, counted on actual bytes so lying headers are caught; compression-ratio limit (ZIP bombs); rejection of absolute paths, drive letters, `..`, NUL bytes, duplicate and case-colliding names, and encrypted entries; symlinks, hardlinks and devices skipped; files created with `O_EXCL|O_NOFOLLOW` and mode 0600; dependency and build directories excluded; truncated or corrupt tarballs rejected.

## Web application

Only `web` (and `api`, for scripts) are published, on 127.0.0.1. Security headers: `X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy`, `Permissions-Policy`. All inputs are validated with Pydantic at the API boundary and again at the sandbox boundary. Every data query is scoped through ownership helpers; cross-user access returns 404 (`tests/test_projects.py::test_users_only_see_their_own_projects`).

## Known limitations

- **Docker host trust:** the proxy needs the Docker socket. Anyone who compromises the proxy controls Docker. The proxy is small, dependency-light, read-only and capability-free to reduce that risk.
- **HTTPS content:** `CONNECT` tunnels are end-to-end TLS, so the gateway enforces host, port and IP but cannot see the HTTP method inside HTTPS. The crawler and the browser route guard only issue GET/HEAD.
- **Development allowlist:** `GATEWAY_DEV_ALLOW_HOSTS` permits private addresses for the named hosts (still never loopback, link-local or metadata). It exists for the bundled sample site only and must be empty for real use; the gateway logs a warning when it is set.
- **Ownership** is a manual confirmation, not verified proof.
- **Cookies are not port-isolated by browsers:** other applications on `localhost` can read the `routes_csrf` cookie. The Origin allow-list remains the effective CSRF defence; do not add origins of other local applications to `ALLOWED_ORIGINS`.
- **Docker Desktop:** isolation relies on Docker's `internal` networks inside the Desktop VM, which behaves like Linux Docker. Rootless Docker or alternative runtimes have not been tested.
- **Not dynamically verified:** findings are static evidence; there is no exploit confirmation in Phase 1.
- **CLI port:** the `cli` network is not `internal`, which is what makes publishing to 127.0.0.1 possible. As a result, the Sandbox Manager (ROUTES' own code, not a sandbox) has an outbound route. Other local processes running as your user can reach the port but need the token. Keep the engine env file private.
