#!/usr/bin/env bash
set -euo pipefail

fail() {
  printf 'test-connection-grant-expiration: %s\n' "$*" >&2
  exit 1
}

command -v psql >/dev/null 2>&1 || fail 'psql is required'
command -v mktemp >/dev/null 2>&1 || fail 'mktemp is required'
command -v grep >/dev/null 2>&1 || fail 'grep is required'
command -v sleep >/dev/null 2>&1 || fail 'sleep is required'

DB_HOST="${WEDECENT_TEST_DB_HOST:-127.0.0.1}"
DB_PORT="${WEDECENT_TEST_DB_PORT:-54322}"
DB_USER="${WEDECENT_TEST_DB_USER:-postgres}"
DB_NAME="${WEDECENT_TEST_DB_NAME:-postgres}"
DB_PASSWORD="${WEDECENT_TEST_DB_PASSWORD:-postgres}"
ISSUER_APP="wd_grant_expiry_test_issuer"
CLIENT_USER="78000000-0000-4000-8000-000000000001"
TARGET_USER="78000000-0000-4000-8000-000000000002"
CLIENT_DEVICE="wd_7777777777777777"
TARGET_DEVICE="wd_6666666666666666"
LOCK_PID=""
ISSUER_PID=""
TMP_DIR="$(mktemp -d)"

PSQL_ARGS=(
  -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME"
  -X -q -v ON_ERROR_STOP=1
)

psql_test() {
  PGPASSWORD="$DB_PASSWORD" psql "${PSQL_ARGS[@]}" "$@"
}

cleanup_fixture() {
  psql_test -c "
    DELETE FROM public.connection_grants
     WHERE user_id IN ('$CLIENT_USER', '$TARGET_USER')
        OR client_device_id IN ('$CLIENT_DEVICE', '$TARGET_DEVICE')
        OR target_device_id IN ('$CLIENT_DEVICE', '$TARGET_DEVICE');
    DELETE FROM public.device_access
     WHERE device_id = '$TARGET_DEVICE' OR user_id = '$CLIENT_USER';
    DELETE FROM public.devices
     WHERE device_id IN ('$CLIENT_DEVICE', '$TARGET_DEVICE');
    DELETE FROM auth.users
     WHERE id IN ('$CLIENT_USER', '$TARGET_USER');
  " >/dev/null 2>&1 || true
}

cleanup() {
  status=$?
  trap - EXIT
  if [[ -n "$LOCK_PID" ]] && kill -0 "$LOCK_PID" 2>/dev/null; then
    kill "$LOCK_PID" 2>/dev/null || true
    wait "$LOCK_PID" 2>/dev/null || true
  fi
  if [[ -n "$ISSUER_PID" ]] && kill -0 "$ISSUER_PID" 2>/dev/null; then
    kill "$ISSUER_PID" 2>/dev/null || true
    wait "$ISSUER_PID" 2>/dev/null || true
  fi
  cleanup_fixture
  rm -rf -- "$TMP_DIR"
  exit "$status"
}
trap cleanup EXIT

# This test only connects to the disposable local Supabase database.
cleanup_fixture
psql_test -c "
  INSERT INTO auth.users (
    id, aud, role, email, encrypted_password, email_confirmed_at,
    raw_app_meta_data, raw_user_meta_data, created_at, updated_at
  ) VALUES
    ('$CLIENT_USER', 'authenticated', 'authenticated',
     'grant-clock-client-780@example.invalid', '', clock_timestamp(),
     '{}'::jsonb, '{}'::jsonb, clock_timestamp(), clock_timestamp()),
    ('$TARGET_USER', 'authenticated', 'authenticated',
     'grant-clock-target-780@example.invalid', '', clock_timestamp(),
     '{}'::jsonb, '{}'::jsonb, clock_timestamp(), clock_timestamp());

  INSERT INTO public.devices (device_id, public_key, kind, name, owner_user_id)
  VALUES
    ('$CLIENT_DEVICE', repeat('G', 43), 'client', 'grant-clock-client', '$CLIENT_USER'),
    ('$TARGET_DEVICE', repeat('H', 43), 'agent', 'grant-clock-target', '$TARGET_USER');

  INSERT INTO public.device_access (
    device_id, user_id, permission, created_at, expires_at
  ) VALUES (
    '$TARGET_DEVICE', '$CLIENT_USER', 'terminal.connect',
    clock_timestamp(), clock_timestamp() + interval '10 seconds'
  );
"

# Hold the target row lock in a separate psql session. Feed each command
# separately so the lock-held marker is flushed before the sleep completes.
PGPASSWORD="$DB_PASSWORD" psql "${PSQL_ARGS[@]}" -At >"$TMP_DIR/lock.log" 2>&1 <<SQL &
BEGIN;
SELECT device_id FROM public.devices WHERE device_id = '$TARGET_DEVICE' FOR UPDATE;
SELECT 'WD_GRANT_LOCK_HELD';
SELECT pg_sleep(15);
COMMIT;
SQL
LOCK_PID=$!

lock_held=false
for ((attempt = 0; attempt < 200; attempt++)); do
  if grep -q 'WD_GRANT_LOCK_HELD' "$TMP_DIR/lock.log"; then
    lock_held=true
    break
  fi
  if ! kill -0 "$LOCK_PID" 2>/dev/null; then
    cat "$TMP_DIR/lock.log" >&2
    fail 'lock session exited before acquiring the target row'
  fi
  sleep 0.05
done
if [[ "$lock_held" != true ]]; then
  cat "$TMP_DIR/lock.log" >&2
  fail 'timed out waiting for target device row lock'
fi

# The grant issuer must be observed waiting on that exact device-row lock.
PGPASSWORD="$DB_PASSWORD" PGAPPNAME="$ISSUER_APP" psql "${PSQL_ARGS[@]}" -c "
  SET ROLE service_role;
  SELECT (public.issue_connection_grant(
    '$CLIENT_USER'::uuid, '$CLIENT_DEVICE', '$TARGET_DEVICE'
  )).id;
" >"$TMP_DIR/issuer.log" 2>&1 &
ISSUER_PID=$!

waiting=false
for ((attempt = 0; attempt < 160; attempt++)); do
  state="$(psql_test -Atc "
    SELECT EXISTS (
      SELECT 1
        FROM pg_catalog.pg_stat_activity
       WHERE application_name = '$ISSUER_APP'
         AND state = 'active'
         AND wait_event_type = 'Lock'
         AND query LIKE '%issue_connection_grant%'
    );
  ")"
  if [[ "$state" == "t" ]]; then
    waiting=true
    break
  fi
  if ! kill -0 "$ISSUER_PID" 2>/dev/null; then
    cat "$TMP_DIR/issuer.log" >&2
    fail 'grant issuer exited before reaching the row-lock wait'
  fi
  sleep 0.05
done
[[ "$waiting" == true ]] || fail 'grant issuer was not observed waiting on the target row lock'

unexpired="$(psql_test -Atc "
  SELECT expires_at > clock_timestamp()
    FROM public.device_access
   WHERE device_id = '$TARGET_DEVICE'
     AND user_id = '$CLIENT_USER'
     AND permission = 'terminal.connect';
")"
[[ "$unexpired" == "t" ]] || fail 'delegated permission expired before the issuer was observed waiting'

# Let the permission expire while the issuer remains blocked by the row lock.
psql_test -c "
  SELECT pg_sleep(GREATEST(
    0,
    extract(epoch FROM (
      (SELECT expires_at FROM public.device_access
        WHERE device_id = '$TARGET_DEVICE'
          AND user_id = '$CLIENT_USER'
          AND permission = 'terminal.connect') - clock_timestamp()
    ))
  ));
"

expired="$(psql_test -Atc "
  SELECT expires_at <= clock_timestamp()
    FROM public.device_access
   WHERE device_id = '$TARGET_DEVICE'
     AND user_id = '$CLIENT_USER'
     AND permission = 'terminal.connect';
")"
[[ "$expired" == "t" ]] || fail 'delegated permission did not expire while the issuer was blocked'

wait "$LOCK_PID" || fail 'target-row lock session failed'
LOCK_PID=""

set +e
wait "$ISSUER_PID"
issuer_status=$?
set -e
ISSUER_PID=""
[[ "$issuer_status" -ne 0 ]] || fail 'expired delegated permission unexpectedly issued a connection grant'
grep -q 'terminal connection is not authorized' "$TMP_DIR/issuer.log" || {
  cat "$TMP_DIR/issuer.log" >&2
  fail 'grant issuer did not reject the expired delegated permission'
}

grant_count="$(psql_test -Atc "
  SELECT count(*)
    FROM public.connection_grants
   WHERE user_id = '$CLIENT_USER'
     AND client_device_id = '$CLIENT_DEVICE'
     AND target_device_id = '$TARGET_DEVICE';
")"
[[ "$grant_count" == "0" ]] || fail "found $grant_count connection grants after expiration"

printf 'connection grant expiration lock-wait regression passed\n'
