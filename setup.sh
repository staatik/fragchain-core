#!/usr/bin/env bash
# setup.sh — populate a fresh FragChain deployment with the built-in datasets.
#
# A fresh ``docker compose up`` boots an empty platform by design — no
# prompts, no logsource profiles, no import presets, no ATT&CK coverage map.
# The UI handles those empty states gracefully but the analysis pipeline
# cannot do anything until the seeds run. This script does that.
#
# Idempotent: every seed skips rows it already created, so re-running is safe.
#
# Usage:
#   ./setup.sh                 # seeds prompts + profiles + presets + ATT&CK
#   ./setup.sh --with-fixture  # also imports the Dirty Frag fixture
#                              # (CVE-2026-43284 + 3 source documents)
#   ./setup.sh --help          # show this message
#
# Requirements: the stack must be running (``docker compose up -d``) and
# the API container must be healthy. If you don't have a stack yet, run
# ``docker compose up -d`` first, wait ~30 s, then run this script.
#
# Exit codes:
#   0 — every seed completed
#   1 — usage error / unknown flag
#   2 — API container not running or unhealthy

set -euo pipefail

API_CONTAINER="${FRAGCHAIN_API_CONTAINER:-fragchain-fragchain-api-1}"

WITH_FIXTURE=0
for arg in "$@"; do
  case "$arg" in
    --with-fixture)
      WITH_FIXTURE=1
      ;;
    -h|--help)
      sed -n '2,30p' "$0"
      exit 0
      ;;
    *)
      echo "setup.sh: unknown flag '$arg'" >&2
      echo "Run './setup.sh --help' for usage." >&2
      exit 1
      ;;
  esac
done

if ! docker ps --format '{{.Names}}' | grep -q "^${API_CONTAINER}$"; then
  echo "setup.sh: API container '${API_CONTAINER}' is not running." >&2
  echo "Start the stack first:  docker compose up -d" >&2
  echo "Then re-run this script once the container is healthy." >&2
  exit 2
fi

status=$(docker inspect --format='{{.State.Health.Status}}' "${API_CONTAINER}" 2>/dev/null || echo "unknown")
if [ "$status" != "healthy" ]; then
  echo "setup.sh: API container is '${status}', not 'healthy'." >&2
  echo "Wait a few seconds and re-run. If it stays unhealthy, check:" >&2
  echo "  docker compose logs fragchain-api" >&2
  exit 2
fi

run_seed() {
  local label="$1"
  local module="$2"
  shift 2
  echo ""
  echo "── ${label} ──"
  docker exec -i "${API_CONTAINER}" python -m "${module}" "$@"
}

flush_matrix_cache() {
  # The matrix endpoint caches its response in Redis. Seeds bypass the
  # normal cache-invalidation paths (Celery map_coverage / approve), so
  # the first /api/v1/matrix request after a seed would serve a stale
  # entry showing zero techniques even though coverage_map is populated.
  # Flush ``matrix:*`` keys to force a fresh build on next request.
  local redis_container="${FRAGCHAIN_REDIS_CONTAINER:-fragchain-redis-1}"
  local redis_pw=""
  if [ -f .env ]; then
    redis_pw=$(grep -E '^REDIS_PASSWORD=' .env | head -1 | cut -d= -f2-)
  fi

  if [ -z "$redis_pw" ]; then
    echo "  (skipped — REDIS_PASSWORD not found in .env)"
    return
  fi

  local cleared
  cleared=$(docker exec -i "${redis_container}" redis-cli \
    -a "${redis_pw}" --no-auth-warning \
    EVAL "local k = redis.call('KEYS', 'matrix:*') for i=1,#k do redis.call('DEL', k[i]) end return #k" 0 \
    2>/dev/null)
  echo "  matrix:* keys cleared: ${cleared:-?}"
}

echo "FragChain setup — seeding built-in datasets."
echo "Target container: ${API_CONTAINER}"

run_seed "Prompt templates (chain / rule / coverage_verify)"  scripts.seed_prompts
run_seed "Logsource profiles (7 built-ins)"                   scripts.seed_profiles
run_seed "Historical-import filter presets (6 built-ins)"     scripts.seed_filter_presets
run_seed "ATT&CK techniques (≈700 rows + Qdrant embeddings)"  scripts.seed_attck_techniques

if [ "$WITH_FIXTURE" -eq 1 ]; then
  run_seed "Dirty Frag fixture (CVE-2026-43284)"              scripts.seed_dirty_frag
fi

echo ""
echo "── Flush stale Redis caches ──"
flush_matrix_cache

if [ "$WITH_FIXTURE" -eq 1 ]; then
  echo ""
  echo "Fixture loaded. To analyse it through the LLM pipeline now:"
  echo "  1. Sign in to the UI as admin"
  echo "  2. Open /cves and click CVE-2026-43284"
  echo "  3. Open the Chain Viewer → Re-synthesize"
  echo "  Or via API:"
  echo "    JWT=\$(curl -ks -X POST -H 'Content-Type: application/json' \\"
  echo "      -d '{\"username\":\"admin\",\"password\":\"<password>\"}' \\"
  echo "      https://localhost/api/v1/auth/login | jq -r .access_token)"
  echo "    curl -ks -X POST -H \"Authorization: Bearer \$JWT\" \\"
  echo "      https://localhost/api/v1/cves/CVE-2026-43284/resynthesize"
fi

echo ""
echo "Done. The dashboard / matrix / prompts screens should now show real data."
