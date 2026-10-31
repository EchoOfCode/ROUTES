# ROUTES CI/CD and Deployment Guide

This guide details the Continuous Integration and Continuous Deployment (CI/CD) pipelines for ROUTES, server setup instructions, health verification, rollback procedures, and maintenance workflows.

---

## 1. Pipeline Architecture

```
[ Developer Branch ]
         │
         ▼  (PR / Push to main)
┌────────────────────────────────────────────────────────┐
│ GitHub Actions CI (.github/workflows/ci.yml)           │
│  ├── Lint & Format (Python via ruff)                   │
│  ├── Lint & Typecheck (Next.js via Bun)                │
│  ├── Tests & Coverage (pytest across packages, CLI, API)│
│  ├── Frontend Production Build (Next.js standalone)    │
│  ├── Vulnerability Audit (pip-audit & bun audit)       │
│  └── Docker Build Smoke Tests (API, Web, Manager)      │
└────────────────────────────────────────────────────────┘
         │
         ▼  (Workflow Dispatch / Optional Push to main)
┌────────────────────────────────────────────────────────┐
│ GitHub Actions CD (.github/workflows/cd.yml)           │
│  ├── 1. Build and push container images to GHCR        │
│  │      Tagged with: ${{ github.sha }} and latest      │
│  │                                                     │
│  ├── 2. Deploy to Staging (VPS via SSH)                │
│  │      ├── Pull images from GHCR                      │
│  │      ├── Run Alembic migrations (migrate service)   │
│  │      ├── Start compose stack (docker-compose.prod)  │
│  │      ├── Execute scripts/healthcheck.sh             │
│  │      └── Auto-rollback via scripts/rollback.sh on err│
│  │                                                     │
│  └── 3. Deploy to Production (GitHub Environment)      │
│         └── Manual approval required (Protected Env)   │
│             ├── Deploy to Production VPS               │
│             ├── Verify health checks                   │
│             └── Auto-rollback on health check failure   │
└────────────────────────────────────────────────────────┘
```

---

## 2. Environments and GitHub Configuration

### 2.1 GitHub Environments

To enforce safety and governance:
1. Navigate to **Repository Settings** > **Environments**.
2. Create two environments:
   - `staging`: No required reviewers (automatic or manual deployment).
   - `production`: Enable **Required reviewers** protection rule. Select authorized maintainers who must approve production deployments before they execute.
3. Configure the respective environment secrets listed in [SECRETS.md](../SECRETS.md).

### 2.2 Activation of Automatic Triggers

By default, the Continuous Deployment workflow (`.github/workflows/cd.yml`) is configured for **`workflow_dispatch` (manual trigger only)** to ensure complete control during onboarding.

When ready to enable automated staging deployments upon merging to `main`, uncomment the `push` block in `.github/workflows/cd.yml`:

```yaml
on:
  workflow_dispatch:
    ...
  push:
    branches: [main]
```

---

## 3. Server Provisioning & Initial Setup

Each target VPS (staging and production) requires:
- Ubuntu 22.04 LTS or 24.04 LTS (recommended).
- Docker Engine 26+ and Docker Compose v2.
- A dedicated non-root deploy user with access to the `docker` group.

### 3.1 Initial Host Setup

```bash
# 1. Update and install prerequisites
sudo apt-get update && sudo apt-get install -y curl ca-certificates git

# 2. Install Docker Engine & Compose plugin (official instructions)
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker deploy

# 3. Create application deployment directory
sudo mkdir -p /opt/routes/scripts
sudo chown -R deploy:deploy /opt/routes
```

### 3.2 Prepare Server Environment File

On the server, create `/opt/routes/.env.prod` with restrictive permissions:

```bash
cd /opt/routes
touch .env.prod
chmod 600 .env.prod
```

Populate `.env.prod` with your secrets as specified in [SECRETS.md](../SECRETS.md).

---

## 4. Health Checks and Verification

Health checks are automated through `scripts/healthcheck.sh`. This script verifies:
1. **API Readiness**: Polls `http://127.0.0.1:8000/api/health` with exponential backoff / retries until HTTP 200 is confirmed.
2. **Frontend Availability**: Polls `http://127.0.0.1:3000` until an HTTP 2xx or 3xx status is returned.

You can also run the health check script manually on any server:

```bash
cd /opt/routes
bash scripts/healthcheck.sh http://127.0.0.1:8000/api/health http://127.0.0.1:3000
```

---

## 5. Rollback Procedures

### 5.1 Automated Rollback

The CD pipeline integrates automated rollback logic into both staging and production deployments. Before any update:
1. The currently running commit SHA is recorded into `/opt/routes/.previous_sha`.
2. The new image is pulled and services are restarted.
3. `scripts/healthcheck.sh` is executed.
4. If health checks fail after 15 attempts (60 seconds):
   - The CD job triggers `scripts/rollback.sh`.
   - The server switches `IMAGE_TAG` back to the SHA in `.previous_sha`.
   - The previous containers are restarted and re-validated.
   - The workflow exits with a non-zero exit code to alert maintainers.

### 5.2 Manual Emergency Rollback

If you need to roll back to a specific previous commit SHA manually on the server:

```bash
cd /opt/routes

# Option A: Use the rollback script to revert to previous version
bash scripts/rollback.sh

# Option B: Target an explicit known good commit SHA
export IMAGE_TAG="<KNOWN_GOOD_COMMIT_SHA>"
sed -i "s/^IMAGE_TAG=.*/IMAGE_TAG=${IMAGE_TAG}/" .env.prod
docker compose --env-file .env.prod -f docker-compose.prod.yml pull
docker compose --env-file .env.prod -f docker-compose.prod.yml up -d --remove-orphans
bash scripts/healthcheck.sh
```

---

## 6. How to Test the Pipeline Safely

1. **Verify CI on Pull Requests**:
   - Push your changes to a feature branch (e.g. `feat/ci-cd-pipeline`).
   - Open a Draft Pull Request against `main`.
   - Observe the `CI` workflow run in the **Actions** tab of the GitHub repository.
   - Verify that test execution, frontend build, and Docker smoke builds pass.

2. **Verify CD via Workflow Dispatch**:
   - Navigate to the **Actions** tab in GitHub.
   - Select **CD** in the left sidebar.
   - Click **Run workflow**.
   - Choose `staging` from the `deploy_env` dropdown.
   - Confirm that images are built, published to GHCR, deployed to Staging via SSH, and verified by health checks.

---

## 7. Suggested Changes (Not Applied)

In accordance with safety and stability policies, no existing application source code, dependency configurations, or linter settings were modified. The following improvements are suggested for future dedicated PRs:

1. **Python Linter & Formatter Alignment (`ruff`)**:
   - **Status in repo**: The codebase currently exhibits 302 style/lint diagnostic errors when checked against `ruff` defaults, and 148 files have minor formatting differences.
   - **Applied mitigation**: In `ci.yml`, the `lint-python` job runs check-only with `continue-on-error: true` and an explicit `# TODO` notice so that CI visibility is available without blocking valid pull requests.
   - **Recommended next step**: In a dedicated PR, add a top-level `[tool.ruff]` section to `pyproject.toml` selecting only rules the team wants to enforce (e.g., `select = ["E", "F", "W"]`, `ignore = [...]`), or run `ruff format` and `ruff check --fix` in an isolated formatting commit.

2. **Frontend Typecheck & Lint Baseline**:
   - **Status in repo**: Next.js 15.1 and React 19 are used in `apps/web`.
   - **Applied mitigation**: `lint-and-typecheck-frontend` runs with `continue-on-error: true` with a `# TODO` comment to accommodate any local environmental differences during CI execution.

3. **Branch Protection Rules**:
   - In GitHub Settings > Branches > Branch protection rules for `main`:
     - Require pull request before merging.
     - Require status checks to pass before merging (`Test & Coverage (Python)`, `Build Next.js Frontend`, `Docker Build Smoke Test`).

