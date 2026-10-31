#!/usr/bin/env sh
# Create .env from .env.example with freshly generated secrets.
set -eu
cd "$(dirname "$0")/.."
if [ -f .env ]; then
  echo ".env already exists; leaving it unchanged." >&2
  exit 0
fi
rand() { head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n'; }
sed \
  -e "s/^POSTGRES_PASSWORD=.*/POSTGRES_PASSWORD=$(rand)/" \
  -e "s/^SANDBOX_MANAGER_TOKEN=.*/SANDBOX_MANAGER_TOKEN=$(rand)/" \
  -e "s/^GATEWAY_CONTROL_TOKEN=.*/GATEWAY_CONTROL_TOKEN=$(rand)/" \
  .env.example > .env
echo "Created .env with random secrets."
