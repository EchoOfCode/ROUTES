#!/usr/bin/env bash
# =============================================================================
# ROUTES Deployment Health Check Script
# Verifies that both the REST API and the Web Frontend are responsive and healthy.
# Exit 0 on success; Exit 1 on failure.
# =============================================================================

set -euo pipefail

API_URL="${1:-http://127.0.0.1:8000/api/health}"
WEB_URL="${2:-http://127.0.0.1:3000}"
MAX_RETRIES="${MAX_RETRIES:-15}"
RETRY_INTERVAL="${RETRY_INTERVAL:-4}"

log() {
  echo "[$(date -u +'%Y-%m-%dT%H:%M:%SZ')] $*"
}

check_endpoint() {
  local target_url="$1"
  local service_name="$2"
  local attempt=1

  log "Checking ${service_name} at ${target_url}..."

  while [ "$attempt" -le "$MAX_RETRIES" ]; do
    status_code=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 3 --max-time 5 "$target_url" || echo "000")

    if [ "$status_code" -ge 200 ] && [ "$status_code" -lt 400 ]; then
      log "SUCCESS: ${service_name} returned HTTP ${status_code} (attempt ${attempt}/${MAX_RETRIES})"
      return 0
    else
      log "WAIT: ${service_name} returned HTTP ${status_code} (attempt ${attempt}/${MAX_RETRIES}). Retrying in ${RETRY_INTERVAL}s..."
      sleep "$RETRY_INTERVAL"
      attempt=$((attempt + 1))
    fi
  done

  log "ERROR: ${service_name} failed health check after ${MAX_RETRIES} attempts (last HTTP code: ${status_code})"
  return 1
}

# Run checks
check_endpoint "$API_URL" "ROUTES API" || exit 1
check_endpoint "$WEB_URL" "ROUTES Web" || exit 1

log "ALL HEALTH CHECKS PASSED SUCCESSFULLY."
exit 0

