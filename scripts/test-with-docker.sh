#!/usr/bin/env bash
#
# Run vitest against a MySQL instance started via docker-compose.
# Usage:
#   scripts/test-with-docker.sh                  # runs all tests
#   scripts/test-with-docker.sh tests/integration
#   scripts/test-with-docker.sh tests/e2e/server.test.ts
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
COMPOSE_FILE="$REPO_ROOT/docker-compose.test.yml"

cleanup() {
  echo ""
  echo "==> Stopping MySQL test container"
  docker compose -f "$COMPOSE_FILE" down -v --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

# If something is already listening on 3306, refuse rather than conflict
if lsof -iTCP:3306 -sTCP:LISTEN >/dev/null 2>&1; then
  echo "Error: something is already listening on port 3306."
  echo "Stop your local MySQL (e.g. 'brew services stop mysql') and rerun."
  exit 1
fi

echo "==> Starting MySQL test container"
docker compose -f "$COMPOSE_FILE" up -d --wait

echo "==> Seeding test schema"
cd "$REPO_ROOT"
pnpm exec tsx scripts/setup-test-db.ts

echo "==> Running tests"
if [ "$#" -eq 0 ]; then
  pnpm exec vitest run --no-coverage
else
  pnpm exec vitest run --no-coverage "$@"
fi
