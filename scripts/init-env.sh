#!/usr/bin/env sh
# Create .env from .env.example with freshly generated secrets.
set -eu
cd "$(dirname "$0")/.."
if [ -f .env ]; then
  echo ".env exists; checking for missing keys from .env.example..."
  added=0
  while IFS='=' read -r key val || [ -n "$key" ]; do
    case "$key" in
      '#'*|'') continue ;;
      *)
        if ! grep -q "^${key}=" .env; then
          echo "Adding missing key ${key} to .env"
          echo "${key}=${val}" >> .env
          added=$((added + 1))
        fi
        ;;
    esac
  done < .env.example
  if [ "$added" -gt 0 ]; then
    echo "Added $added missing setting(s) to .env."
  else
    echo ".env is fully up to date."
  fi
  exit 0
fi
rand() { head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n'; }
sed \
  -e "s/^POSTGRES_PASSWORD=.*/POSTGRES_PASSWORD=$(rand)/" \
  -e "s/^SANDBOX_MANAGER_TOKEN=.*/SANDBOX_MANAGER_TOKEN=$(rand)/" \
  -e "s/^GATEWAY_CONTROL_TOKEN=.*/GATEWAY_CONTROL_TOKEN=$(rand)/" \
  .env.example > .env
echo "Created .env with random secrets."
