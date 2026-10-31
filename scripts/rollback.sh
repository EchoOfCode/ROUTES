#!/usr/bin/env bash
# =============================================================================
# ROUTES Deployment Rollback Script
# Reverts the running production stack to the previous known good image tag.
# =============================================================================

set -euo pipefail

DEPLOY_DIR="${DEPLOY_DIR:-$(pwd)}"
COMPOSE_FILE="${COMPOSE_FILE:-docker-compose.prod.yml}"
ENV_FILE="${ENV_FILE:-.env.prod}"
STATE_FILE="${STATE_FILE:-.previous_sha}"

log() {
  echo "[$(date -u +'%Y-%m-%dT%H:%M:%SZ')] [ROLLBACK] $*"
}

cd "$DEPLOY_DIR"

if [ ! -f "$STATE_FILE" ]; then
  log "ERROR: No previous version record found ($STATE_FILE is missing). Cannot auto-rollback."
  exit 1
fi

PREVIOUS_TAG=$(cat "$STATE_FILE" | tr -d ' \t\n\r')

if [ -z "$PREVIOUS_TAG" ]; then
  log "ERROR: Previous version record is empty. Aborting rollback."
  exit 1
fi

log "Initiating rollback to previous known good image tag: ${PREVIOUS_TAG}..."

if [ -f "$ENV_FILE" ]; then
  if grep -q "^IMAGE_TAG=" "$ENV_FILE"; then
    sed -i "s/^IMAGE_TAG=.*/IMAGE_TAG=${PREVIOUS_TAG}/" "$ENV_FILE"
  else
    echo "IMAGE_TAG=${PREVIOUS_TAG}" >> "$ENV_FILE"
  fi
fi

export IMAGE_TAG="$PREVIOUS_TAG"

log "Pulling restored image versions..."
docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" pull || {
  log "Warning: Docker pull failed, proceeding to recreate containers from existing local cache..."
}

log "Restarting services with tag ${PREVIOUS_TAG}..."
docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" up -d --remove-orphans

log "Verifying health after rollback..."
if [ -f "scripts/healthcheck.sh" ]; then
  bash scripts/healthcheck.sh || {
    log "CRITICAL: Health check failed even after rollback. Manual operator intervention required!"
    exit 1
  }
fi

log "Rollback completed successfully. Running on tag: ${PREVIOUS_TAG}"
exit 0

