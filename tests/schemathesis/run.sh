#!/usr/bin/env bash
# Schemathesis against the running API (ADR-016, technical test PT-03). Same command in CI and
# locally. Needs HINDAMA_TEST_DATABASE_URL, HINDAMA_TEST_OWNER_DATABASE_URL and the migrated
# hindama_test database; the contract comes from HINDAMA_CONTRACT_PATH or the sibling hindama-docs.
# Extra arguments go to `schemathesis run` (for example: --max-examples 200).
set -euo pipefail

cd "$(dirname "$0")/../.."
contract="${HINDAMA_CONTRACT_PATH:-../hindama-docs/03-api/openapi.yaml}"
port="${HINDAMA_SCHEMATHESIS_PORT:-8765}"
token_file="${HINDAMA_SCHEMATHESIS_TOKEN:-.schemathesis-token}"
export HINDAMA_SCHEMATHESIS_PORT="$port" HINDAMA_SCHEMATHESIS_TOKEN="$token_file"

rm -f "$token_file"
uv run python -m tests.schemathesis.serve &
server=$!
cleanup() {
  kill -TERM "$server" 2>/dev/null || true
  wait "$server" 2>/dev/null || true
  rm -f "$token_file"
  uv run python -m tests.schemathesis.serve --cleanup
}
trap cleanup EXIT

for _ in $(seq 1 60); do
  [ -s "$token_file" ] && break
  kill -0 "$server" 2>/dev/null || { echo "La API no arrancó" >&2; exit 1; }
  sleep 1
done
[ -s "$token_file" ] || { echo "La API no estuvo lista en 60 s" >&2; exit 1; }

uv run schemathesis run "$contract" \
  --url "http://127.0.0.1:$port" \
  --header "Authorization: Bearer $(cat "$token_file")" \
  --checks all \
  --max-examples 50 \
  --seed 20261105 \
  "$@"
