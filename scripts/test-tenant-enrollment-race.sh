#!/usr/bin/env bash
set -euo pipefail

fail() {
  printf 'test-tenant-enrollment-race: %s\n' "$*" >&2
  exit 1
}

command -v docker >/dev/null 2>&1 || fail 'docker is required'
command -v sleep >/dev/null 2>&1 || fail 'sleep is required'

HOLD_SECONDS="${WEDECENT_RACE_HOLD_SECONDS:-8}"
WAIT_SECONDS="${WEDECENT_RACE_WAIT_SECONDS:-30}"
[[ "$HOLD_SECONDS" =~ ^[1-9][0-9]*$ ]] || fail 'WEDECENT_RACE_HOLD_SECONDS must be a positive integer'
[[ "$WAIT_SECONDS" =~ ^[1-9][0-9]*$ ]] || fail 'WEDECENT_RACE_WAIT_SECONDS must be a positive integer'

DB_CONTAINER="${WEDECENT_SUPABASE_DB_CONTAINER:-}"
if [[ -z "$DB_CONTAINER" ]]; then
  mapfile -t db_containers < <(docker ps --format '{{.Names}}' | grep '^supabase_db_' || true)
  if (("${#db_containers[@]}" == 1)); then
    DB_CONTAINER="${db_containers[0]}"
  else
    expected="supabase_db_wedecent-local"
    for candidate in "${db_containers[@]}"; do
      if [[ "$candidate" == "$expected" ]]; then
        DB_CONTAINER="$candidate"
        break
      fi
    done
  fi
fi
[[ -n "$DB_CONTAINER" ]] || fail 'could not identify the disposable Supabase database container'
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
  if [[ "$expected" == "success" && "$status" -ne 0 ]]; then
    fail "session $pid failed unexpectedly (exit $status); see its log"
  fi
  if [[ "$expected" == "failure" && "$status" -eq 0 ]]; then
    fail "session $pid unexpectedly succeeded"
  fi
  return 0
}

# Keep the fixtures isolated from the pgTAP transaction and make reruns safe.
db_psql <<'SQL'
delete from public.device_enrollment_challenges
 where id in (
   '60000000-0000-4000-8000-000000000001',
   '60000000-0000-4000-8000-000000000002'
 );
delete from public.devices
 where device_id in ('wd_aaaaaaaaaaaaaaaa', 'wd_bbbbbbbbbbbbbbbb');
delete from public.organizations
 where id in (
   '50000000-0000-4000-8000-000000000001',
   '50000000-0000-4000-8000-000000000002'
 );
delete from auth.users
 where id in (
   '40000000-0000-4000-8000-000000000001',
   '40000000-0000-4000-8000-000000000002'
 );

insert into auth.users (id, aud, role, email)
values
  ('40000000-0000-4000-8000-000000000001', 'authenticated', 'authenticated', 'wd-cp01-race-a@example.test'),
  ('40000000-0000-4000-8000-000000000002', 'authenticated', 'authenticated', 'wd-cp01-race-b@example.test');

insert into public.organizations (id, name, slug, created_by)
values
  ('50000000-0000-4000-8000-000000000001', 'WD CP01 Race A', 'wd-cp01-race-a', '40000000-0000-4000-8000-000000000001'),
  ('50000000-0000-4000-8000-000000000002', 'WD CP01 Race B', 'wd-cp01-race-b', '40000000-0000-4000-8000-000000000002');

insert into public.device_enrollment_challenges (
  id, user_id, device_id, challenge_sha256, expires_at
)
values
  ('60000000-0000-4000-8000-000000000001', '40000000-0000-4000-8000-000000000001', 'wd_aaaaaaaaaaaaaaaa', decode(repeat('00', 32), 'hex'), now() + interval '5 minutes'),
  ('60000000-0000-4000-8000-000000000002', '40000000-0000-4000-8000-000000000002', 'wd_bbbbbbbbbbbbbbbb', decode(repeat('00', 32), 'hex'), now() + interval '5 minutes');
SQL

# Case 1: enrollment locks the owner membership first; revocation must wait.
enroll_app="wd-cp01-enroll-first"
revoke_app="wd-cp01-revoke-after"
docker exec -u postgres -i -e "PGAPPNAME=$enroll_app" "$DB_CONTAINER" psql -X -v ON_ERROR_STOP=1 -U postgres -d postgres >"$WORK/enroll-first.log" 2>&1 <<SQL &
begin;
set role service_role;
select public.complete_device_enrollment(
  '60000000-0000-4000-8000-000000000001',
  '40000000-0000-4000-8000-000000000001',
  'wd_aaaaaaaaaaaaaaaa',
  repeat('A', 43),
  'client',
  'Race A device',
  '50000000-0000-4000-8000-000000000001',
  repeat('00', 32)
);
select pg_sleep($HOLD_SECONDS);
commit;
SQL
enroll_pid=$!
PIDS+=("$enroll_pid")
wait_for_activity "$enroll_app" "wait_event = 'PgSleep'"

docker exec -u postgres -i -e "PGAPPNAME=$revoke_app" "$DB_CONTAINER" psql -X -v ON_ERROR_STOP=1 -U postgres -d postgres >"$WORK/revoke-after.log" 2>&1 <<'SQL' &
begin;
set role service_role;
delete from public.organization_memberships
 where organization_id = '50000000-0000-4000-8000-000000000001'
   and user_id = '40000000-0000-4000-8000-000000000001';
commit;
SQL
revoke_pid=$!
PIDS+=("$revoke_pid")
wait_for_activity "$revoke_app" "wait_event_type = 'Lock'"
wait_for_exit "$enroll_pid" success
wait_for_exit "$revoke_pid" success

[[ "$(scalar "select count(*) from public.devices where device_id = 'wd_aaaaaaaaaaaaaaaa'")" == "1" ]] ||
  fail 'enrollment-first race did not persist the enrolled device'
[[ "$(scalar "select count(*) from public.organization_memberships where organization_id = '50000000-0000-4000-8000-000000000001' and user_id = '40000000-0000-4000-8000-000000000001'")" == "0" ]] ||
  fail 'revocation did not complete after enrollment committed'
grep -q 'wd_aaaaaaaaaaaaaaaa' "$WORK/enroll-first.log" ||
  fail 'enrollment-first session did not return the enrolled device'

# Case 2: revocation locks and deletes the owner membership first; enrollment
# must wait, then fail closed after the revocation commits.
revoke_first_app="wd-cp01-revoke-first"
enroll_after_app="wd-cp01-enroll-after"
docker exec -u postgres -i -e "PGAPPNAME=$revoke_first_app" "$DB_CONTAINER" psql -X -v ON_ERROR_STOP=1 -U postgres -d postgres >"$WORK/revoke-first.log" 2>&1 <<SQL &
begin;
set role service_role;
delete from public.organization_memberships
 where organization_id = '50000000-0000-4000-8000-000000000002'
   and user_id = '40000000-0000-4000-8000-000000000002';
select pg_sleep($HOLD_SECONDS);
commit;
SQL
revoke_first_pid=$!
PIDS+=("$revoke_first_pid")
wait_for_activity "$revoke_first_app" "wait_event = 'PgSleep'"

docker exec -u postgres -i -e "PGAPPNAME=$enroll_after_app" "$DB_CONTAINER" psql -X -v ON_ERROR_STOP=1 -U postgres -d postgres >"$WORK/enroll-after.log" 2>&1 <<'SQL' &
begin;
set role service_role;
select public.complete_device_enrollment(
  '60000000-0000-4000-8000-000000000002',
  '40000000-0000-4000-8000-000000000002',
  'wd_bbbbbbbbbbbbbbbb',
  repeat('B', 43),
  'client',
  'Race B device',
  '50000000-0000-4000-8000-000000000002',
  repeat('00', 32)
);
commit;
SQL
enroll_after_pid=$!
PIDS+=("$enroll_after_pid")
wait_for_activity "$enroll_after_app" "wait_event_type = 'Lock'"
wait_for_exit "$revoke_first_pid" success
wait_for_exit "$enroll_after_pid" failure

grep -q 'target organization enrollment is not authorized' "$WORK/enroll-after.log" ||
  fail 'revocation-first enrollment did not fail with the expected authorization denial'
[[ "$(scalar "select count(*) from public.devices where device_id = 'wd_bbbbbbbbbbbbbbbb'")" == "0" ]] ||
  fail 'revocation-first race unexpectedly created a device'
[[ "$(scalar "select count(*) from public.device_enrollment_challenges where id = '60000000-0000-4000-8000-000000000002' and consumed_at is null")" == "1" ]] ||
  fail 'revocation-first race consumed the challenge despite denied enrollment'

printf 'Tenant enrollment/revocation race ordering verified in both directions.\n'
