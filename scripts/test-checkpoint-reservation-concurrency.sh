#!/usr/bin/env bash
set -euo pipefail

fail() { printf 'checkpoint-reservation-concurrency: %s\n' "$*" >&2; exit 1; }
command -v supabase >/dev/null 2>&1 || fail 'supabase CLI required'
command -v psql >/dev/null 2>&1 || fail 'psql required'
command -v grep >/dev/null 2>&1 || fail 'grep required'
WORK="$(mktemp -d)"
cleanup() {
  for file in "$WORK"/*.pid; do
    [[ -f "$file" ]] || continue
    kill "$(cat "$file")" 2>/dev/null || true
  done
  rm -rf "$WORK"
}
trap cleanup EXIT

refresh_db_url() {
  DB_URL="$(supabase status -o env | sed -n 's/^DB_URL="\([^"]*\)"$/\1/p')"
  [[ -n "$DB_URL" ]] || fail 'local DB_URL unavailable'
}
refresh_db_url

psql "$DB_URL" -X -v ON_ERROR_STOP=1 <<'SQL'
insert into auth.users(id,aud,role,email)
values ('11000000-0000-4000-8000-000000000195','authenticated','authenticated','c195-concurrency@example.test')
on conflict (id) do nothing;

insert into public.organizations(id,name,slug,created_by)
values ('22000000-0000-4000-8000-000000000195','C195 concurrency','c195-concurrency','11000000-0000-4000-8000-000000000195')
on conflict (id) do nothing;

insert into public.devices(device_id,public_key,kind,name,owner_user_id,organization_id)
values
 ('wd_eeeeeeeeeeeeeeee',repeat('E',43),'client','C195 A','11000000-0000-4000-8000-000000000195','22000000-0000-4000-8000-000000000195'),
 ('wd_ffffffffffffffff',repeat('F',43),'agent','C195 B','11000000-0000-4000-8000-000000000195','22000000-0000-4000-8000-000000000195'),
 ('wd_gggggggggggggggg',repeat('G',43),'agent','C195 C','11000000-0000-4000-8000-000000000195','22000000-0000-4000-8000-000000000195')
on conflict (device_id) do nothing;

create or replace function public.wd_c195_participants(p_devices text[]) returns jsonb
language sql stable security definer set search_path=''
as $$
 select pg_catalog.jsonb_agg(
   pg_catalog.jsonb_build_object(
     'device_id',d.device_id,
     'account_id',d.owner_user_id,
     'organization_id',d.organization_id,
     'revocation_epoch',d.revocation_epoch,
     'head_generation',coalesce(a.checkpoint_head_generation,0),
     'head_hash',coalesce(pg_catalog.encode(a.checkpoint_head_hash,'hex'),pg_catalog.repeat('0',64))
   ) order by d.device_id
 )
 from public.devices d
 left join public.port_forward_replay_authority a on a.device_id=d.device_id
 where d.device_id=any(p_devices);
$$;

create or replace function public.wd_c195_acks(p_operation_id text,p_action text) returns jsonb
language sql immutable security definer set search_path=''
as $$
 select pg_catalog.jsonb_build_array(
  pg_catalog.jsonb_build_object(
   'witness_id','witness-a','token_sha256',pg_catalog.repeat('a',64),'generation',1,
   'action',p_action,'operation_id',p_operation_id,'witness_key_id','key-a',
   'committed_at_unix_ms',1000,'signature',pg_catalog.repeat('A',86)||'=='
  ),
  pg_catalog.jsonb_build_object(
   'witness_id','witness-b','token_sha256',pg_catalog.repeat('a',64),'generation',1,
   'action',p_action,'operation_id',p_operation_id,'witness_key_id','key-b',
   'committed_at_unix_ms',1001,'signature',pg_catalog.repeat('B',86)||'=='
  )
 );
$$;

create or replace function public.wd_c195_reserve(
 p_operation_id text,p_action text,p_request_hex text,p_devices text[]
) returns jsonb
language sql security definer set search_path=''
as $$
 select public.reserve_checkpoint_operation(
  p_operation_id,p_action,'22000000-0000-4000-8000-000000000195',
  '11000000-0000-4000-8000-000000000195',
  pg_catalog.decode(p_request_hex,'hex'),
  public.wd_c195_participants(p_devices),60
 );
$$;

create or replace function public.wd_c195_commit(p_operation_id text,p_action text) returns jsonb
language sql security definer set search_path=''
as $$
 select public.commit_checkpoint_operation(
  p_operation_id,
  (select fingerprint from public.checkpoint_operations where operation_id=p_operation_id),
  public.wd_c195_acks(p_operation_id,p_action)
 );
$$;
SQL

start() {
  local name="$1" app="$2" sql="$3"
  PGAPPNAME="$app" psql "$DB_URL" -X -qAt -v ON_ERROR_STOP=1 -c "$sql" >"$WORK/$name.log" 2>&1 &
  echo "$!" >"$WORK/$name.pid"
}
pid_of() { cat "$WORK/$1.pid"; }
wait_text() {
  local name="$1" needle="$2"
  for _ in $(seq 1 300); do
    grep -Fq "$needle" "$WORK/$name.log" && return 0
    kill -0 "$(pid_of "$name")" 2>/dev/null || { cat "$WORK/$name.log" >&2; fail "$name exited before $needle"; }
    sleep .05
  done
  cat "$WORK/$name.log" >&2
  fail "timed out waiting for $needle in $name"
}
wait_lock() {
  local app="$1"
  for _ in $(seq 1 300); do
    [[ "$(psql "$DB_URL" -X -Atqc "select count(*) from pg_stat_activity where application_name='$app' and wait_event_type='Lock'")" == 1 ]] && return 0
    sleep .05
  done
  fail "$app did not reach a PostgreSQL lock wait"
}
finish_ok() {
  local name="$1" pid
  pid="$(pid_of "$name")"
  rm -f "$WORK/$name.pid"
  wait "$pid" || { cat "$WORK/$name.log" >&2; fail "$name failed"; }
}
finish_error() {
  local name="$1" expected="$2" pid
  pid="$(pid_of "$name")"
  rm -f "$WORK/$name.pid"
  if wait "$pid"; then cat "$WORK/$name.log" >&2; fail "$name unexpectedly succeeded"; fi
  grep -Fq "$expected" "$WORK/$name.log" || { cat "$WORK/$name.log" >&2; fail "$name failed for the wrong reason"; }
}
assertq() {
  local expected="$1" sql="$2" actual
  actual="$(psql "$DB_URL" -X -Atqc "$sql")"
  [[ "$actual" == "$expected" ]] || fail "expected [$expected], got [$actual]: $sql"
}

OP_A="$(printf 'a%.0s' {1..64})"
OP_B="$(printf 'b%.0s' {1..64})"
OP_C="$(printf 'c%.0s' {1..64})"
OP_D="$(printf 'd%.0s' {1..64})"
OP_E="$(printf 'e%.0s' {1..64})"
OP_F="$(printf 'f%.0s' {1..64})"
OP_G="$(printf '1%.0s' {1..64})"

# Independent sessions compete for the same two participant heads.
start a wd-c195-same-a "begin; select public.wd_c195_reserve('$OP_A','finalize','$(printf '1%.0s' {1..64})',array['wd_eeeeeeeeeeeeeeee','wd_ffffffffffffffff']); select pg_sleep(2); commit;"
wait_text a '"status": "reserved"'
start b wd-c195-same-b "begin; select public.wd_c195_reserve('$OP_B','finalize','$(printf '2%.0s' {1..64})',array['wd_eeeeeeeeeeeeeeee','wd_ffffffffffffffff']); commit;"
wait_lock wd-c195-same-b
finish_ok a
finish_error b 'checkpoint participant is reserved by another operation'
assertq 2 "select count(*) from public.checkpoint_active_reservations where operation_id='$OP_A'"
assertq 0 "select count(*) from public.checkpoint_operations where operation_id='$OP_B'"
psql "$DB_URL" -X -v ON_ERROR_STOP=1 -c "select public.wd_c195_commit('$OP_A','finalize')" >/dev/null
psql "$DB_URL" -X -v ON_ERROR_STOP=1 -c "select public.wd_c195_commit('$OP_A','finalize')" >/dev/null
assertq 1 "select min(checkpoint_head_generation) from public.port_forward_replay_authority where device_id in ('wd_eeeeeeeeeeeeeeee','wd_ffffffffffffffff')"
assertq 1 "select max(checkpoint_head_generation) from public.port_forward_replay_authority where device_id in ('wd_eeeeeeeeeeeeeeee','wd_ffffffffffffffff')"

# Overlapping sets serialize on the common participant and never partially reserve.
start c wd-c195-overlap-a "begin; select public.wd_c195_reserve('$OP_C','finalize','$(printf '3%.0s' {1..64})',array['wd_eeeeeeeeeeeeeeee','wd_ffffffffffffffff']); select pg_sleep(2); commit;"
wait_text c '"status": "reserved"'
start d wd-c195-overlap-b "begin; select public.wd_c195_reserve('$OP_D','finalize','$(printf '4%.0s' {1..64})',array['wd_ffffffffffffffff','wd_gggggggggggggggg']); commit;"
wait_lock wd-c195-overlap-b
finish_ok c
finish_error d 'checkpoint participant is reserved by another operation'
assertq 0 "select count(*) from public.checkpoint_operations where operation_id='$OP_D'"
assertq 0 "select count(*) from public.checkpoint_active_reservations where operation_id='$OP_D'"
psql "$DB_URL" -X -v ON_ERROR_STOP=1 -c "select public.wd_c195_commit('$OP_C','finalize')" >/dev/null
assertq 2 "select min(checkpoint_head_generation) from public.port_forward_replay_authority where device_id in ('wd_eeeeeeeeeeeeeeee','wd_ffffffffffffffff')"
assertq 2 "select max(checkpoint_head_generation) from public.port_forward_replay_authority where device_id in ('wd_eeeeeeeeeeeeeeee','wd_ffffffffffffffff')"

# A backend killed after writing an uncommitted reservation leaves no operation.
start e wd-c195-interrupted "begin; select public.wd_c195_reserve('$OP_E','finalize','$(printf '5%.0s' {1..64})',array['wd_gggggggggggggggg']); select pg_sleep(60); commit;"
wait_text e '"status": "reserved"'
PID="$(psql "$DB_URL" -X -Atqc "select pid from pg_stat_activity where application_name='wd-c195-interrupted'")"
[[ "$PID" =~ ^[0-9]+$ ]] || fail 'could not find interrupted reservation backend'
psql "$DB_URL" -X -v ON_ERROR_STOP=1 -c "select pg_terminate_backend($PID)" >/dev/null
finish_error e 'terminating connection'
assertq 0 "select count(*) from public.checkpoint_operations where operation_id='$OP_E'"
assertq 0 "select count(*) from public.checkpoint_active_reservations where operation_id='$OP_E'"

# Revocation races with a pending finalization; whichever gets the device lock first wins.
start f wd-c195-revoke-reserve "begin; select public.wd_c195_reserve('$OP_F','finalize','$(printf '6%.0s' {1..64})',array['wd_gggggggggggggggg']); select pg_sleep(2); commit;"
wait_text f '"status": "reserved"'
start revoke wd-c195-device-revoke "begin; update public.devices set revoked_at=pg_catalog.clock_timestamp() where device_id='wd_gggggggggggggggg'; commit;"
wait_lock wd-c195-device-revoke
finish_ok f
finish_ok revoke
if psql "$DB_URL" -X -v ON_ERROR_STOP=1 -c "select public.wd_c195_commit('$OP_F','finalize')" >"$WORK/revoke-commit.log" 2>&1; then
  cat "$WORK/revoke-commit.log" >&2
  fail 'checkpoint finalization committed after participant revocation'
fi
grep -Fq 'checkpoint participant identity or revocation changed' "$WORK/revoke-commit.log" || {
  cat "$WORK/revoke-commit.log" >&2
  fail 'revocation race failed for the wrong reason'
}
assertq 2 "select checkpoint_head_generation from public.port_forward_replay_authority where device_id='wd_gggggggggggggggg'"

# Finalization audit and checkpoint reservation use the same operation advisory lock.
start g wd-c195-finalization-lock "begin; select pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended('$OP_G',0)); select pg_sleep(2); commit;"
wait_text g 'pg_sleep'
start h wd-c195-finalization-reserve "begin; select public.wd_c195_reserve('$OP_G','finalize','$(printf '7%.0s' {1..64})',array['wd_eeeeeeeeeeeeeeee']); commit;"
wait_lock wd-c195-finalization-reserve
finish_ok g
finish_ok h
psql "$DB_URL" -X -v ON_ERROR_STOP=1 -c "select public.wd_c195_commit('$OP_G','finalize')" >/dev/null
assertq 3 "select checkpoint_head_generation from public.port_forward_replay_authority where device_id='wd_eeeeeeeeeeeeeeee'"

# Simulate an ambiguous client response by discarding the first successful receipt,
# then recover it by exact operation retry without a second head advancement.
psql "$DB_URL" -X -v ON_ERROR_STOP=1 -c "select public.wd_c195_commit('$OP_G','finalize')" >/dev/null 2>&1
assertq 3 "select checkpoint_head_generation from public.port_forward_replay_authority where device_id='wd_eeeeeeeeeeeeeeee'"

# Restart local PostgreSQL and verify durable commit evidence survives.
supabase stop
./scripts/start-supabase-db-ci.sh
refresh_db_url
assertq 3 "select checkpoint_head_generation from public.port_forward_replay_authority where device_id='wd_eeeeeeeeeeeeeeee'"
assertq 1 "select count(*) from public.checkpoint_operation_events where operation_id='$OP_G' and event_type='committed'"

psql "$DB_URL" -X -v ON_ERROR_STOP=1 -c 'drop function public.wd_c195_commit(text,text); drop function public.wd_c195_reserve(text,text,text,text[]); drop function public.wd_c195_acks(text,text); drop function public.wd_c195_participants(text[]);' >/dev/null
printf 'Checkpoint reservation concurrency, interruption, revocation ordering, ambiguous retry and database restart checks passed.\n'
