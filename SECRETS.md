# ROUTES Secret Configuration Guide

This document lists all secrets and environment variables required for the CI/CD pipeline and deployment infrastructure.

> **Security Note:** Never commit secrets, credentials, private keys, or actual `.env` files to Git. All secrets should be configured either in GitHub Secrets or created directly on target servers with restricted permissions (`chmod 600`).

---

## 1. GitHub Actions Secrets

Add these secrets under your GitHub repository:
- **Repository-level secrets**: Go to **Settings** > **Secrets and variables** > **Actions** > **New repository secret**.
- **Environment-level secrets**: Go to **Settings** > **Environments** > Select **staging** or **production** > **Add secret**.

| Secret Name | Scope | Description | Example / Recommended Format |
|---|---|---|---|
| `GHCR_PULL_TOKEN` | Repository | Personal Access Token (classic or fine-grained) with `read:packages` permission. Used by the VPS to pull container images from GitHub Container Registry. | `ghp_xxxxxxxxxxxxxxxxxxxx` |
| `STAGING_HOST` | Environment (`staging`) | Public IP or DNS hostname of the Staging VPS. | `staging.routes.example.com` or `198.51.100.10` |
| `STAGING_USER` | Environment (`staging`) | SSH deploy username on the Staging server. | `deploy` or `ubuntu` |
| `STAGING_SSH_KEY` | Environment (`staging`) | Private OpenSSH key for connecting to the Staging server. | `-----BEGIN OPENSSH PRIVATE KEY-----...` |
| `STAGING_SSH_PORT` | Environment (`staging`) | SSH port on the Staging server (defaults to 22 if omitted). | `22` |
| `STAGING_DEPLOY_PATH` | Environment (`staging`) | Directory on the Staging server where the compose stack resides. | `/opt/routes` |
| `PROD_HOST` | Environment (`production`) | Public IP or DNS hostname of the Production VPS. | `routes.example.com` or `203.0.113.10` |
| `PROD_USER` | Environment (`production`) | SSH deploy username on the Production server. | `deploy` or `ubuntu` |
| `PROD_SSH_KEY` | Environment (`production`) | Private OpenSSH key for connecting to the Production server. | `-----BEGIN OPENSSH PRIVATE KEY-----...` |
| `PROD_SSH_PORT` | Environment (`production`) | SSH port on the Production server (defaults to 22 if omitted). | `22` |
| `PROD_DEPLOY_PATH` | Environment (`production`) | Directory on the Production server where the compose stack resides. | `/opt/routes` |

---

## 2. Server Runtime Environment Variables (`.env.prod`)

On each target VPS (at `${DEPLOY_PATH}/.env.prod`), create a secure configuration file with `chmod 600 .env.prod`. These variables are used by `docker-compose.prod.yml`:

```ini
# =============================================================================
# ROUTES Production Server Environment Configuration (.env.prod)
# Permissions: chmod 600 .env.prod
# =============================================================================

# Image configuration (managed automatically by CD on deployment)
IMAGE_PREFIX=ghcr.io/echoofcode/routes
IMAGE_TAG=latest

# Database configuration
POSTGRES_USER=routes
POSTGRES_PASSWORD=<GENERATE_SECURE_PASSWORD>
POSTGRES_DB=routes

# Internal Service Tokens (must be 64-character random hex strings)
# Generate with: openssl rand -hex 32
SANDBOX_MANAGER_TOKEN=<GENERATE_64_CHAR_HEX>
GATEWAY_CONTROL_TOKEN=<GENERATE_64_CHAR_HEX>

# Web and Security Settings
# Must match your public domain name
ALLOWED_ORIGINS=https://routes.example.com
COOKIE_SECURE=true
SESSION_TTL_HOURS=72
ASSESSMENT_HISTORY_LIMIT=10

# Network Settings
ROUTES_CONTROL_SUBNET=172.31.250.0/28
GATEWAY_DEV_ALLOW_HOSTS=

# Host Port Bindings (only Web and API bound to localhost, behind reverse proxy)
WEB_PORT=3000
API_PORT=8000
```

---

## 3. Secret Generation Helpers

To generate cryptographic tokens and passwords for the server configuration:

```bash
# Generate 32-byte (64 hex characters) token for SANDBOX_MANAGER_TOKEN and GATEWAY_CONTROL_TOKEN
openssl rand -hex 32

# Generate a strong password for POSTGRES_PASSWORD
openssl rand -base64 24
```

---

## 4. SSH Key Setup for VPS Deployments

To generate a dedicated deployment SSH key pair on your local machine:

```bash
# Generate a dedicated ed25519 deploy key
ssh-keygen -t ed25519 -C "github-actions-deploy" -f id_deploy_routes -N ""

# Copy the public key to your VPS authorized_keys:
ssh-copy-id -i id_deploy_routes.pub deploy@<VPS_HOST>

# Paste the private key content into GitHub Secrets (STAGING_SSH_KEY / PROD_SSH_KEY):
cat id_deploy_routes
```

