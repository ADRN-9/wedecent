#!/usr/bin/env bash
set -euo pipefail

fail() {
  printf 'test-device-access-grant-race: %s\n' "$*" >&2
  exit 1
}

command -v docker >/dev/null 2>&1 || fail 'docker is required'
command -v sleep >/dev/null 2>&1 || fail 'sleep is required'
command -v base32 >/dev/null 2>&1 || fail 'base32 is required'

HOLD_SECONDS="${WEDECENT_ACCESS_RACE_HOLD_SECONDS:-5}"
WAIT_SECONDS="${WEDECENT_ACCESS_RACE_WAIT_SECONDS:-30}"
[[ "$HOLD_SECONDS" =~ ^[1-9][0-9]*$ ]] || fail 'WEDECENT_ACCESS_RACE_HOLD_SECONDS must be a positive integer'
[[ "$WAIT_SECONDS" =~ ^[1-9][0-9]*$ ]] || fail 'WEDECENT_ACCESS_RACE_WAIT_SECONDS must be a positive integer'

EXPECTED_DB_CONTAINER="supabase_db_wedecent-local"
DB_CONTAINER="${WEDECENT_SUPABASE_DB_CONTAINER:-$EXPECTED_DB_CONTAINER}"
[[ "$DB_CONTAINER" == "$EXPECTED_DB_CONTAINER" ]] ||
  fail "refusing unexpected database container '$DB_CONTAINER'; expected '$EXPECTED_DB_CONTAINER'"
docker ps --format '{{.Names}}' | grep -Fx "$DB_CONTAINER" >/dev/null ||
  fail "disposable database container is not running: $DB_CONTAINER"
docker inspect "$DB_CONTAINER" >/dev/null 2>&1 || fail "database container is not running: $DB_CONTAINER"

WORK="$(mktemp -d)"
PIDS=()
cleanup() {
  for pid in "${PIDS[@]}"; do
    kill "$pid" >/dev/null 2>&1 || true
  done
  rm -rf -- "$WORK"
}
trap cleanup EXIT

forget_pid() {
  local finished_pid="$1"
  local active_pid
  local -a remaining=()
  for active_pid in "${PIDS[@]}"; do
    if [[ "$active_pid" != "$finished_pid" ]]; then
      remaining+=("$active_pid")
    fi
  done
  PIDS=("${remaining[@]}")
}

db_psql() {
  docker exec -u postgres -i "$DB_CONTAINER" psql -X -v ON_ERROR_STOP=1 -U postgres -d postgres "$@"
}

scalar() {
  db_psql -Atqc "$1"
}

wait_for_activity() {
  local app="$1"
  local predicate="$2"
  local deadline=$((SECONDS + WAIT_SECONDS))
  local found
  while ((SECONDS < deadline)); do
    found="$(scalar "select exists (select 1 from pg_stat_activity where application_name = '$app' and state = 'active' and $predicate)")"
    [[ "$found" == "t" ]] && return 0
    sleep 0.05
  done
  db_psql -c "select application_name, state, wait_event_type, wait_event, query from pg_stat_activity where application_name = '$app'" >&2 || true
  fail "timed out waiting for $app to reach: $predicate"
}

wait_for_exit() {
  local pid="$1"
  local expected="$2"
  local status
  set +e
  wait "$pid"
  status=$?
  set -e
  forget_pid "$pid"
  if [[ "$expected" == "success" && "$status" -ne 0 ]]; then
    fail "session $pid failed unexpectedly (exit $status); see its log"
  fi
  if [[ "$expected" == "failure" && "$status" -eq 0 ]]; then
    fail "session $pid unexpectedly succeeded"
  fi
}

new_uuid() {
  cat /proc/sys/kernel/random/uuid
}

new_device_id() {
  local suffix
  suffix="$(head -c 10 /dev/urandom | base32 | tr -d '=\n' | tr 'A-Z' 'a-z')"
  [[ "$suffix" =~ ^[a-z2-7]{16}$ ]] || fail 'could not generate a valid unique device ID'
  printf 'wd_%s' "$suffix"
}

OWNER_ID="$(new_uuid)"
ADMIN_ID="$(new_uuid)"
GRANTEE_FIRST_ID="$(new_uuid)"
GRANTEE_DOWNGRADE_ID="$(new_uuid)"
GRANTEE_REMOVE_ID="$(new_uuid)"
ORG_ID="$(new_uuid)"
DEVICE_ID="$(new_device_id)"
SLUG_TAG="$(printf '%s' "$DEVICE_ID" | cut -c4-)"
ORG_SLUG="wd-access-race-$SLUG_TAG"

# These fixtures are unique per run. Audit rows are append-only, so the
# disposable CI database is intentionally allowed to discard them at teardown.
db_psql <<SQL
insert into auth.users (id, aud, role, email)
values
  ('$OWNER_ID', 'authenticated', 'authenticated', 'wd-access-race-owner-$SLUG_TAG@example.test'),
  ('$ADMIN_ID', 'authenticated', 'authenticated', 'wd-access-race-admin-$SLUG_TAG@example.test'),
  ('$GRANTEE_FIRST_ID', 'authenticated', 'authenticated', 'wd-access-race-first-$SLUG_TAG@example.test'),
  ('$GRANTEE_DOWNGRADE_ID', 'authenticated', 'authenticated', 'wd-access-race-downgrade-$SLUG_TAG@example.test'),
  ('$GRANTEE_REMOVE_ID', 'authenticated', 'authenticated', 'wd-access-race-remove-$SLUG_TAG@example.test');

insert into public.organizations (id, name, slug, created_by)
values ('$ORG_ID', 'Device Access Grant Race $SLUG_TAG', '$ORG_SLUG', '$OWNER_ID');

insert into public.organization_memberships (
  organization_id, user_id, role, created_by
)
values ('$ORG_ID', '$ADMIN_ID', 'admin', '$OWNER_ID');

insert into public.devices (
  device_id, public_key, kind, name, owner_user_id, organization_id
)
values (
  '$DEVICE_ID',
  repeat('R', 43),
  'agent',
  'Device Access Grant Race',
  '$OWNER_ID',
  '$ORG_ID'
);
SQL

# Case 1: grant creation locks the admin membership first. A concurrent
# downgrade must wait, then commit after the grant's authorization linearizes.
grant_first_app="wd-access-grant-first-$SLUG_TAG"
downgrade_after_app="wd-access-downgrade-after-$SLUG_TAG"

docker exec -u postgres -i -e "PGAPPNAME=$grant_first_app" "$DB_CONTAINER" \
  psql -X -v ON_ERROR_STOP=1 -U postgres -d postgres >"$WORK/grant-first.log" 2>&1 <<SQL &
begin;
set role authenticated;
select set_config('request.jwt.claim.role', 'authenticated', true);
select set_config('request.jwt.claim.sub', '$ADMIN_ID', true);
select public.create_device_access_grant(
  '$DEVICE_ID',
  '$GRANTEE_FIRST_ID',
  'terminal.connect',
  now() + interval '10 minutes'
);
select pg_sleep($HOLD_SECONDS);
commit;
SQL
grant_first_pid=$!
PIDS+=("$grant_first_pid")
wait_for_activity "$grant_first_app" "wait_event = 'PgSleep'"

docker exec -u postgres -i -e "PGAPPNAME=$downgrade_after_app" "$DB_CONTAINER" \
  psql -X -v ON_ERROR_STOP=1 -U postgres -d postgres >"$WORK/downgrade-after.log" 2>&1 <<SQL &
begin;
set role authenticated;
select set_config('request.jwt.claim.role', 'authenticated', true);
select set_config('request.jwt.claim.sub', '$OWNER_ID', true);
update public.organization_memberships
   set role = 'member'
 where organization_id = '$ORG_ID'
   and user_id = '$ADMIN_ID';
commit;
SQL
downgrade_after_pid=$!
PIDS+=("$downgrade_after_pid")
wait_for_activity "$downgrade_after_app" "wait_event_type = 'Lock'"
wait_for_exit "$grant_first_pid" success
wait_for_exit "$downgrade_after_pid" success

[[ "$(scalar "select count(*) from public.device_access where device_id = '$DEVICE_ID' and user_id = '$GRANTEE_FIRST_ID'")" == "1" ]] ||
  fail 'grant-first ordering did not preserve the authorized grant'
[[ "$(scalar "select role from public.organization_memberships where organization_id = '$ORG_ID' and user_id = '$ADMIN_ID'")" == "member" ]] ||
  fail 'membership downgrade did not complete after grant creation'

# Restore the admin fixture for the reverse ordering.
db_psql -c "update public.organization_memberships set role = 'admin' where organization_id = '$ORG_ID' and user_id = '$ADMIN_ID'"

# Case 2: downgrade holds the membership row first. Grant creation waits, then
# observes the committed member role and fails closed.
downgrade_first_app="wd-access-downgrade-first-$SLUG_TAG"
grant_after_downgrade_app="wd-access-grant-after-downgrade-$SLUG_TAG"

docker exec -u postgres -i -e "PGAPPNAME=$downgrade_first_app" "$DB_CONTAINER" \
  psql -X -v ON_ERROR_STOP=1 -U postgres -d postgres >"$WORK/downgrade-first.log" 2>&1 <<SQL &
begin;
set role authenticated;
select set_config('request.jwt.claim.role', 'authenticated', true);
select set_config('request.jwt.claim.sub', '$OWNER_ID', true);
update public.organization_memberships
   set role = 'member'
 where organization_id = '$ORG_ID'
   and user_id = '$ADMIN_ID';
select pg_sleep($HOLD_SECONDS);
commit;
SQL
downgrade_first_pid=$!
PIDS+=("$downgrade_first_pid")
wait_for_activity "$downgrade_first_app" "wait_event = 'PgSleep'"

docker exec -u postgres -i -e "PGAPPNAME=$grant_after_downgrade_app" "$DB_CONTAINER" \
  psql -X -v ON_ERROR_STOP=1 -U postgres -d postgres >"$WORK/grant-after-downgrade.log" 2>&1 <<SQL &
begin;
set role authenticated;
select set_config('request.jwt.claim.role', 'authenticated', true);
select set_config('request.jwt.claim.sub', '$ADMIN_ID', true);
select public.create_device_access_grant(
  '$DEVICE_ID',
  '$GRANTEE_DOWNGRADE_ID',
  'terminal.connect',
  now() + interval '10 minutes'
);
commit;
SQL
grant_after_downgrade_pid=$!
PIDS+=("$grant_after_downgrade_pid")
wait_for_activity "$grant_after_downgrade_app" "wait_event_type = 'Lock'"
wait_for_exit "$downgrade_first_pid" success
wait_for_exit "$grant_after_downgrade_pid" failure

grep -q 'device access grant is not authorized' "$WORK/grant-after-downgrade.log" ||
  fail 'grant after downgrade did not fail with the expected authorization denial'
[[ "$(scalar "select count(*) from public.device_access where device_id = '$DEVICE_ID' and user_id = '$GRANTEE_DOWNGRADE_ID'")" == "0" ]] ||
  fail 'grant after downgrade unexpectedly created a device_access row'

# Case 3: membership removal holds the row first. Grant creation waits, then
# observes that the manager membership no longer exists and fails closed.
remove_first_app="wd-access-remove-first-$SLUG_TAG"
grant_after_remove_app="wd-access-grant-after-remove-$SLUG_TAG"

docker exec -u postgres -i -e "PGAPPNAME=$remove_first_app" "$DB_CONTAINER" \
  psql -X -v ON_ERROR_STOP=1 -U postgres -d postgres >"$WORK/remove-first.log" 2>&1 <<SQL &
begin;
set role authenticated;
select set_config('request.jwt.claim.role', 'authenticated', true);
select set_config('request.jwt.claim.sub', '$OWNER_ID', true);
delete from public.organization_memberships
 where organization_id = '$ORG_ID'
   and user_id = '$ADMIN_ID';
select pg_sleep($HOLD_SECONDS);
commit;
SQL
remove_first_pid=$!
PIDS+=("$remove_first_pid")
wait_for_activity "$remove_first_app" "wait_event = 'PgSleep'"

docker exec -u postgres -i -e "PGAPPNAME=$grant_after_remove_app" "$DB_CONTAINER" \
  psql -X -v ON_ERROR_STOP=1 -U postgres -d postgres >"$WORK/grant-after-remove.log" 2>&1 <<SQL &
begin;
set role authenticated;
select set_config('request.jwt.claim.role', 'authenticated', true);
select set_config('request.jwt.claim.sub', '$ADMIN_ID', true);
select public.create_device_access_grant(
  '$DEVICE_ID',
  '$GRANTEE_REMOVE_ID',
  'terminal.connect',
  now() + interval '10 minutes'
);
commit;
SQL
grant_after_remove_pid=$!
PIDS+=("$grant_after_remove_pid")
wait_for_activity "$grant_after_remove_app" "wait_event_type = 'Lock'"
wait_for_exit "$remove_first_pid" success
wait_for_exit "$grant_after_remove_pid" failure

grep -q 'device access grant is not authorized' "$WORK/grant-after-remove.log" ||
  fail 'grant after membership removal did not fail with the expected authorization denial'
[[ "$(scalar "select count(*) from public.device_access where device_id = '$DEVICE_ID' and user_id = '$GRANTEE_REMOVE_ID'")" == "0" ]] ||
  fail 'grant after membership removal unexpectedly created a device_access row'

printf 'Device-access grant creation serialized with membership downgrade and removal.\n'
