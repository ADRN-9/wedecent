#!/usr/bin/env bash
set -euo pipefail

fail() { printf 'checkpoint-reservation-concurrency: %s\n' "$*" >&2; exit 1; }
command -v supabase >/dev/null 2>&1 || fail 'supabase CLI required'
command -v psql >/dev/null 2>&1 || fail 'psql required'
command -v grep >/dev/null 2>&1 || fail 'grep required'
command -v docker >/dev/null 2>&1 || fail 'docker required'
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
 ('wd_gggggggggggggggg',repeat('G',43),'agent','C195 C','11000000-0000-4000-8000-000000000195','22000000-0000-4000-8000-000000000195'),
 ('wd_hhhhhhhhhhhhhhhh',repeat('H',43),'client','C195 H','11000000-0000-4000-8000-000000000195','22000000-0000-4000-8000-000000000195'),
 ('wd_iiiiiiiiiiiiiiii',repeat('I',43),'agent','C195 I','11000000-0000-4000-8000-000000000195','22000000-0000-4000-8000-000000000195')
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
as $
 select public.commit_checkpoint_operation(
  p_operation_id,
  (select fingerprint from public.checkpoint_operations where operation_id=p_operation_id),
  public.wd_c195_acks(p_operation_id,p_action)
 );
$;

create or replace function public.wd_c195_reserve_fence(
 p_operation_id text,p_request_hex text,p_device text,p_primary_head_hex text
) returns jsonb
language sql security definer set search_path=''
as $
 select public.reserve_checkpoint_fence_operation(
  p_operation_id,'finalize','22000000-0000-4000-8000-000000000195',
  '11000000-0000-4000-8000-000000000195',
  pg_catalog.decode(p_request_hex,'hex'),
  public.wd_c195_participants(array[p_device]),
  1,pg_catalog.decode(p_primary_head_hex,'hex'),60
 );
$;
SQL

start() {
  local name="$1" app="$2"
  mkfifo "$WORK/$name.in"
  PGAPPNAME="$app" psql "$DB_URL" -X -qAt -v ON_ERROR_STOP=1 <"$WORK/$name.in" >"$WORK/$name.log" 2>&1 &
  echo "$!" >"$WORK/$name.pid"
  local fd
  exec {fd}>"$WORK/$name.in"
  echo "$fd" >"$WORK/$name.fd"
}
pid_of() { cat "$WORK/$1.pid"; }
send() {
  local fd
  fd="$(cat "$WORK/$1.fd")"
  printf '%s\n' "$2" >&"$fd"
}
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
close_input() {
  local fd
  fd="$(cat "$WORK/$1.fd")"
  exec {fd}>&-
  rm -f "$WORK/$1.fd"
}
finish_ok() {
  local name="$1" pid
  send "$name" 'commit;'
  send "$name" '\q'
  pid="$(pid_of "$name")"
  close_input "$name"
  rm -f "$WORK/$name.pid"
  wait "$pid" || { cat "$WORK/$name.log" >&2; fail "$name failed"; }
}
finish_error() {
  local name="$1" expected="$2" pid
  pid="$(pid_of "$name")"
  close_input "$name"
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
OP_H="$(printf '8%.0s' {1..64})"
OP_I="$(printf '9%.0s' {1..64})"

# Independent sessions compete for the same two participant heads.
start a wd-c195-same-a
send a "begin; select public.wd_c195_reserve('$OP_A','finalize','$(printf '1%.0s' {1..64})',array['wd_eeeeeeeeeeeeeeee','wd_ffffffffffffffff']);"
wait_text a '"status": "reserved"'
start b wd-c195-same-b
send b "begin; select public.wd_c195_reserve('$OP_B','finalize','$(printf '2%.0s' {1..64})',array['wd_eeeeeeeeeeeeeeee','wd_ffffffffffffffff']);"
wait_lock wd-c195-same-b
finish_ok a
finish_error b 'checkpoint participant is reserved by another operation'
assertq 2 "select count(*) from public.checkpoint_active_reservations where operation_id='$OP_A'"
assertq 0 "select count(*) from public.checkpoint_operations where operation_id='$OP_B'"

# Two simultaneous exact commits serialize and return one durable receipt.
start commit_a wd-c195-commit-a
send commit_a "begin; select public.wd_c195_commit('$OP_A','finalize');"
wait_text commit_a '"status": "committed"'
start commit_b wd-c195-commit-b
send commit_b "begin; select public.wd_c195_commit('$OP_A','finalize');"
wait_lock wd-c195-commit-b
finish_ok commit_a
wait_text commit_b '"status": "committed"'
finish_ok commit_b
assertq 1 "select min(checkpoint_head_generation) from public.port_forward_replay_authority where device_id in ('wd_eeeeeeeeeeeeeeee','wd_ffffffffffffffff')"
assertq 1 "select max(checkpoint_head_generation) from public.port_forward_replay_authority where device_id in ('wd_eeeeeeeeeeeeeeee','wd_ffffffffffffffff')"

# Overlapping sets serialize on the common participant and never partially reserve.
start c wd-c195-overlap-a
send c "begin; select public.wd_c195_reserve('$OP_C','finalize','$(printf '3%.0s' {1..64})',array['wd_eeeeeeeeeeeeeeee','wd_ffffffffffffffff']);"
wait_text c '"status": "reserved"'
start d wd-c195-overlap-b
send d "begin; select public.wd_c195_reserve('$OP_D','finalize','$(printf '4%.0s' {1..64})',array['wd_ffffffffffffffff','wd_gggggggggggggggg']);"
wait_lock wd-c195-overlap-b
finish_ok c
finish_error d 'checkpoint participant is reserved by another operation'
assertq 0 "select count(*) from public.checkpoint_operations where operation_id='$OP_D'"
assertq 0 "select count(*) from public.checkpoint_active_reservations where operation_id='$OP_D'"
psql "$DB_URL" -X -v ON_ERROR_STOP=1 -c "select public.wd_c195_commit('$OP_C','finalize')" >/dev/null
assertq 2 "select min(checkpoint_head_generation) from public.port_forward_replay_authority where device_id in ('wd_eeeeeeeeeeeeeeee','wd_ffffffffffffffff')"
assertq 2 "select max(checkpoint_head_generation) from public.port_forward_replay_authority where device_id in ('wd_eeeeeeeeeeeeeeee','wd_ffffffffffffffff')"

# A backend killed after writing an uncommitted reservation leaves no operation.
start e wd-c195-interrupted
send e "begin; select public.wd_c195_reserve('$OP_E','finalize','$(printf '5%.0s' {1..64})',array['wd_gggggggggggggggg']);"
wait_text e '"status": "reserved"'
send e 'select pg_sleep(60);'
PID="$(psql "$DB_URL" -X -Atqc "select pid from pg_stat_activity where application_name='wd-c195-interrupted'")"
[[ "$PID" =~ ^[0-9]+$ ]] || fail 'could not find interrupted reservation backend'
psql "$DB_URL" -X -v ON_ERROR_STOP=1 -c "select pg_terminate_backend($PID)" >/dev/null
finish_error e 'terminating connection'
assertq 0 "select count(*) from public.checkpoint_operations where operation_id='$OP_E'"
assertq 0 "select count(*) from public.checkpoint_active_reservations where operation_id='$OP_E'"

# Revocation races with a pending finalization; whichever gets the device lock first wins.
start f wd-c195-revoke-reserve
send f "begin; select public.wd_c195_reserve('$OP_F','finalize','$(printf '6%.0s' {1..64})',array['wd_gggggggggggggggg']);"
wait_text f '"status": "reserved"'
start revoke wd-c195-device-revoke
send revoke "begin; update public.devices set revoked_at=pg_catalog.clock_timestamp() where device_id='wd_gggggggggggggggg'; commit;"
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
assertq 0 "select checkpoint_head_generation from public.port_forward_replay_authority where device_id='wd_gggggggggggggggg'"

# Finalization audit and checkpoint reservation use the same operation advisory lock.
start g wd-c195-finalization-lock
send g "begin; select pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended('$OP_G',0));"
send g "select 'finalization-lock-ready';"
wait_text g 'finalization-lock-ready'
start h wd-c195-finalization-reserve
send h "begin; select public.wd_c195_reserve('$OP_G','finalize','$(printf '7%.0s' {1..64})',array['wd_eeeeeeeeeeeeeeee']);"
wait_lock wd-c195-finalization-reserve
finish_ok g
wait_text h '"status": "reserved"'
finish_ok h

# Organization fence serialization also blocks disjoint participant sets.
start fence_a wd-c197-fence-reserve-a
send fence_a "begin; select public.wd_c195_reserve_fence('$OP_H','$(printf '8%.0s' {1..64})','wd_hhhhhhhhhhhhhhhh','$(printf 'a%.0s' {1..64})');"
wait_text fence_a '"status": "reserved"'
start fence_b wd-c197-fence-reserve-b
send fence_b "begin; select public.wd_c195_reserve_fence('$OP_I','$(printf '9%.0s' {1..64})','wd_iiiiiiiiiiiiiiii','$(printf 'b%.0s' {1..64})');"
wait_lock wd-c197-fence-reserve-b
finish_ok fence_a
finish_error fence_b 'organization checkpoint fence is reserved by another operation'
assertq 1 "select count(*) from public.checkpoint_fence_authority where organization_id='22000000-0000-4000-8000-000000000195' and pending_operation_id='$OP_H'"
assertq 0 "select count(*) from public.checkpoint_operations where operation_id='$OP_I'"

# Lose the client connection after the database commit, then recover by exact retry.
start lost wd-c195-lost-receipt
send lost "begin; select public.wd_c195_commit('$OP_G','finalize');"
wait_text lost '"status": "committed"'
send lost 'commit;'
send lost "select 'commit-durable';"
wait_text lost 'commit-durable'
send lost 'select pg_sleep(60);'
PID="$(psql "$DB_URL" -X -Atqc "select pid from pg_stat_activity where application_name='wd-c195-lost-receipt'")"
[[ "$PID" =~ ^[0-9]+$ ]] || fail 'could not find lost-receipt backend'
psql "$DB_URL" -X -v ON_ERROR_STOP=1 -c "select pg_terminate_backend($PID)" >/dev/null
finish_error lost 'terminating connection'
assertq 3 "select checkpoint_head_generation from public.port_forward_replay_authority where device_id='wd_eeeeeeeeeeeeeeee'"
psql "$DB_URL" -X -v ON_ERROR_STOP=1 -c "select public.wd_c195_commit('$OP_G','finalize')" >/dev/null
assertq 3 "select checkpoint_head_generation from public.port_forward_replay_authority where device_id='wd_eeeeeeeeeeeeeeee'"

# Restart the database container itself and verify durable commit evidence survives.
DB_CONTAINER="$(docker ps --format '{{.Names}}' | grep '^supabase_db_' | head -n 1)"
[[ -n "$DB_CONTAINER" ]] || fail 'local Supabase PostgreSQL container not found'
docker restart "$DB_CONTAINER" >/dev/null
ready=false
for _ in $(seq 1 120); do
  if psql "$DB_URL" -X -Atqc 'select 1' >/dev/null 2>&1; then ready=true; break; fi
  sleep 1
done
[[ "$ready" == true ]] || fail 'PostgreSQL did not recover after container restart'
assertq 3 "select checkpoint_head_generation from public.port_forward_replay_authority where device_id='wd_eeeeeeeeeeeeeeee'"
assertq 1 "select count(*) from public.checkpoint_operation_events where operation_id='$OP_G' and event_type='committed'"

psql "$DB_URL" -X -v ON_ERROR_STOP=1 -c 'drop function public.wd_c195_commit(text,text); drop function public.wd_c195_reserve(text,text,text,text[]); drop function public.wd_c195_acks(text,text); drop function public.wd_c195_participants(text[]);' >/dev/null
printf 'Checkpoint reservation and organization-fence concurrency, concurrent commit, interruption, revocation ordering, lost-session recovery and database restart checks passed.\n'
