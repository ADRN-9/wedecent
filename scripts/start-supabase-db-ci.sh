#!/usr/bin/env bash
set -euo pipefail

fail() {
  printf 'start-supabase-db-ci: %s\n' "$*" >&2
  exit 1
}

ATTEMPTS="${WEDECENT_SUPABASE_START_ATTEMPTS:-5}"
BASE_DELAY="${WEDECENT_SUPABASE_RETRY_BASE_SECONDS:-10}"

[[ "$ATTEMPTS" =~ ^[1-9][0-9]*$ ]] || fail 'WEDECENT_SUPABASE_START_ATTEMPTS must be a positive integer'
[[ "$BASE_DELAY" =~ ^[0-9]+$ ]] || fail 'WEDECENT_SUPABASE_RETRY_BASE_SECONDS must be a non-negative integer'
command -v supabase >/dev/null 2>&1 || fail 'supabase CLI is required'
command -v env >/dev/null 2>&1 || fail 'env is required'
command -v mktemp >/dev/null 2>&1 || fail 'mktemp is required'
command -v tee >/dev/null 2>&1 || fail 'tee is required'
command -v grep >/dev/null 2>&1 || fail 'grep is required'
command -v sleep >/dev/null 2>&1 || fail 'sleep is required'

is_registry_throttle() {
  local log="$1"
  grep -Eqi 'toomanyrequests|429[[:space:]]+Too[[:space:]]+Many[[:space:]]+Requests|pull[[:space:]]+rate[[:space:]]+limit' "$log"
}

for ((attempt = 1; attempt <= ATTEMPTS; attempt++)); do
  log="$(mktemp)"
  set +e
  # supabase/setup-cli forces GHCR on GitHub runners. Clearing only this override
  # restores the pinned CLI's built-in public-ECR -> GHCR -> source-image fallback chain.
  env -u SUPABASE_INTERNAL_IMAGE_REGISTRY supabase db start 2>&1 | tee "$log"
  status="${PIPESTATUS[0]}"
  set -e

  if ((status == 0)); then
    rm -f -- "$log"
    exit 0
  fi

  if ! is_registry_throttle "$log"; then
    rm -f -- "$log"
    printf 'start-supabase-db-ci: non-registry startup failure; not retrying\n' >&2
    exit "$status"
  fi
  rm -f -- "$log"

  if ((attempt == ATTEMPTS)); then
    printf 'start-supabase-db-ci: registry throttling persisted after %d attempts\n' "$ATTEMPTS" >&2
    exit "$status"
  fi

  delay=$((BASE_DELAY * (1 << (attempt - 1))))
  printf 'start-supabase-db-ci: registry throttling detected; retrying startup (%d/%d) after %ds\n' \
    "$attempt" "$ATTEMPTS" "$delay" >&2
  sleep "$delay"
done

fail 'unreachable retry state'
