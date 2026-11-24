#!/usr/bin/env bash
set -euo pipefail
fail() { printf 'port-forward-db-concurrency: %s\n' "$*" >&2; exit 1; }
command -v supabase >/dev/null || fail 'supabase CLI required'
command -v psql >/dev/null || fail 'psql required'
WORK="$(mktemp -d)"
declare -A PIDS FDS
cleanup() { for n in "${!PIDS[@]}"; do kill "${PIDS[$n]}" 2>/dev/null || true; done; rm -rf "$WORK"; }
trap cleanup EXIT
DB_URL="$(supabase status -o env | sed -n 's/^DB_URL="\([^"]*\)"$/\1/p')"
[[ -n "$DB_URL" ]] || fail 'local DB_URL unavailable'

psql "$DB_URL" -X -v ON_ERROR_STOP=1 <<'SQL'
insert into auth.users (id,aud,role,email) values
 ('11000000-0000-4000-8000-0000000000c1','authenticated','authenticated','c145-a@example.test'),
 ('11000000-0000-4000-8000-0000000000c2','authenticated','authenticated','c145-b@example.test');
insert into public.organizations (id,name,slug,created_by)
values ('22000000-0000-4000-8000-0000000000c1','C145 concurrency','c145-concurrency','11000000-0000-4000-8000-0000000000c1');
update public.organization_memberships set role='member'
 where organization_id='22000000-0000-4000-8000-0000000000c1'
 and user_id='11000000-0000-4000-8000-0000000000c1';
insert into public.devices (device_id,public_key,kind,name,owner_user_id,organization_id) values
 ('wd_aaaaaaaaaaaaaaaa',repeat('A',43),'client','initiator','11000000-0000-4000-8000-0000000000c1','22000000-0000-4000-8000-0000000000c1'),
 ('wd_bbbbbbbbbbbbbbbb',repeat('B',43),'agent','destination','11000000-0000-4000-8000-0000000000c2','22000000-0000-4000-8000-0000000000c1'),
 ('wd_cccccccccccccccc',repeat('C',43),'agent','router','11000000-0000-4000-8000-0000000000c2','22000000-0000-4000-8000-0000000000c1');
insert into public.device_access (device_id,user_id,permission,granted_by) values
 ('wd_bbbbbbbbbbbbbbbb','11000000-0000-4000-8000-0000000000c1','port_forward.local','11000000-0000-4000-8000-0000000000c1'),
 ('wd_cccccccccccccccc','11000000-0000-4000-8000-0000000000c1','mesh.forward','11000000-0000-4000-8000-0000000000c1');
create function public.wd_c145_route(p_id uuid,p_jti text) returns void
language sql security definer set search_path=''
as $$
 insert into public.route_authorization_grants
 (id,jti,user_id,organization_id,source_device_id,router_device_id,destination_device_id,
  first_transport,second_transport,first_cost,second_cost,permission,issued_at,expires_at)
 values (p_id,p_jti,'11000000-0000-4000-8000-0000000000c1',
 '22000000-0000-4000-8000-0000000000c1','wd_aaaaaaaaaaaaaaaa','wd_cccccccccccccccc',
 'wd_bbbbbbbbbbbbbbbb','lan','lan',1,1,'mesh.forward',
 pg_catalog.clock_timestamp()-interval '5 seconds',pg_catalog.clock_timestamp()+interval '90 seconds');
$$;
create function public.wd_c145_consume(p_id uuid,p_jti text,p_route uuid,p_route_jti text,p_issued_at timestamptz,p_expires_at timestamptz)
returns jsonb language sql security definer set search_path=''
as $$
 select public.consume_port_forward_authorization(
 'wd_aaaaaaaaaaaaaaaa',(select public_key from public.devices where device_id='wd_aaaaaaaaaaaaaaaa'),
 p_id,'local','wd_aaaaaaaaaaaaaaaa','wd_bbbbbbbbbbbbbbbb','wd_cccccccccccccccc',
 p_route,p_route_jti,'wd_aaaaaaaaaaaaaaaa','wd_bbbbbbbbbbbbbbbb','lan','lan',1,1,p_jti,
 p_issued_at,p_expires_at,
 pg_catalog.decode(pg_catalog.repeat('a',64),'hex'));
$$;
SQL

# One capability timestamp pair is reused verbatim for retries.
ISSUED_AT="$(psql "$DB_URL" -X -Atqc "select clock_timestamp() - interval '1 second'")"
# Keep the fixture lifetime below the production 120-second maximum.
EXPIRES_AT="$(psql "$DB_URL" -X -Atqc "select clock_timestamp() + interval '90 seconds'")"

start() {
 local n="$1" app="$2"
 rm -f "$WORK/$n.in" "$WORK/$n.log"
 mkfifo "$WORK/$n.in"
 PGAPPNAME="$app" psql "$DB_URL" -X -qAt -v ON_ERROR_STOP=1 <"$WORK/$n.in" >"$WORK/$n.log" 2>&1 &
 PIDS[$n]=$!
 local fd
 exec {fd}>"$WORK/$n.in"
 FDS[$n]=$fd
}
send() { local fd="${FDS[$1]}"; printf '%s\n' "$2" >&"$fd"; }
wait_text() {
 local n="$1" p="$2"
 for _ in $(seq 1 300); do
  grep -Fq "$p" "$WORK/$n.log" && return
  kill -0 "${PIDS[$n]}" 2>/dev/null || { cat "$WORK/$n.log" >&2; fail "$n exited early"; }
  sleep .05
 done
 cat "$WORK/$n.log" >&2; fail "timed out waiting for $p"
}
wait_lock() {
 local app="$1"
 for _ in $(seq 1 300); do
  [[ "$(psql "$DB_URL" -X -Atqc "select count(*) from pg_stat_activity where application_name='$app' and wait_event_type='Lock'")" == 1 ]] && return
  sleep .05
 done
 fail "$app did not reach a PostgreSQL lock wait"
}
finish() {
 local n="$1" fd="${FDS[$1]}" pid="${PIDS[$1]}"
 printf 'commit;\n\\q\n' >&"$fd" 2>/dev/null || true
 exec {fd}>&-
 unset 'FDS[$n]' 'PIDS[$n]'
 wait "$pid"
}
assertq() { local want="$1" sql="$2" got; got="$(psql "$DB_URL" -X -Atqc "$sql")"; [[ "$got" == "$want" ]] || fail "expected $want got $got: $sql"; }
route() { psql "$DB_URL" -X -v ON_ERROR_STOP=1 -c "select public.wd_c145_route('$1','$2')" >/dev/null; }

race() {
 local name="$1" order="$2" mutation="$3" post="$4" rid="$5" rj="$6" fid="$7" jti="$8"
 local ca="wd-c145-$name-c" ra="wd-c145-$name-r"
 route "$rid" "$rj"
 if [[ "$order" == "consume-first" ]]; then
  start c "$ca"; send c "begin; select public.wd_c145_consume('$fid','$jti','$rid','$rj','$ISSUED_AT','$EXPIRES_AT');"
  wait_text c '"accepted": true'
  start r "$ra"; send r "begin; $mutation; select 'mutation-ready';"
  wait_lock "$ra"
  finish c || fail "$name consumer commit failed"
  finish r || fail "$name revocation commit failed"
  assertq t "select exists(select 1 from public.port_forward_authorization_transactions where forwarding_id='$fid')"
 else
  start r "$ra"; send r "begin; $mutation; select 'mutation-ready';"
  wait_text r "mutation-ready"
  start c "$ca"; send c "begin; select public.wd_c145_consume('$fid','$jti','$rid','$rj','$ISSUED_AT','$EXPIRES_AT');"
  wait_lock "$ca"
  finish r || fail "$name revocation commit failed"
  local fd="${FDS[c]}" pid="${PIDS[c]}"
  exec {fd}>&-; unset 'FDS[c]' 'PIDS[c]'
  if wait "$pid"; then cat "$WORK/c.log" >&2; fail "$name authorization succeeded after revocation"; fi
  grep -q 'ERROR:' "$WORK/c.log" || fail "$name consumer did not fail with SQL authorization error"
  assertq f "select exists(select 1 from public.port_forward_authorization_transactions where forwarding_id='$fid')"
 fi
 assertq true "$post"
 printf 'verified %s (%s)\n' "$name" "$order"
}

restore_device() { psql "$DB_URL" -X -v ON_ERROR_STOP=1 -c "update public.devices set revoked_at=null where device_id='$1' and revoked_at is not null" >/dev/null; }
restore_membership() { psql "$DB_URL" -X -v ON_ERROR_STOP=1 -c "insert into public.organization_memberships (organization_id,user_id,role,created_by) values ('22000000-0000-4000-8000-0000000000c1','11000000-0000-4000-8000-0000000000c1','member','11000000-0000-4000-8000-0000000000c1') on conflict do nothing" >/dev/null; }
restore_access() { psql "$DB_URL" -X -v ON_ERROR_STOP=1 -c "insert into public.device_access (device_id,user_id,permission,granted_by) values ('wd_bbbbbbbbbbbbbbbb','11000000-0000-4000-8000-0000000000c1','port_forward.local','11000000-0000-4000-8000-0000000000c1') on conflict do nothing" >/dev/null; }

race initiator consume-first "update public.devices set revoked_at=clock_timestamp() where device_id='wd_aaaaaaaaaaaaaaaa'" "select (revoked_at is not null)::text from public.devices where device_id='wd_aaaaaaaaaaaaaaaa'" 33000000-0000-4000-8000-0000000000c1 AAAAAAAAAAAAAAAAAAAAAA 44000000-0000-4000-8000-0000000000c1 AAAAAAAAAAAAAAAAAAAAAA
restore_device wd_aaaaaaaaaaaaaaaa
race initiator revoke-first "update public.devices set revoked_at=clock_timestamp() where device_id='wd_aaaaaaaaaaaaaaaa'" "select (revoked_at is not null)::text from public.devices where device_id='wd_aaaaaaaaaaaaaaaa'" 33000000-0000-4000-8000-0000000000c7 GGGGGGGGGGGGGGGGGGGGGG 44000000-0000-4000-8000-0000000000c7 GGGGGGGGGGGGGGGGGGGGGG
restore_device wd_aaaaaaaaaaaaaaaa
race destination revoke-first "update public.devices set revoked_at=clock_timestamp() where device_id='wd_bbbbbbbbbbbbbbbb'" "select (revoked_at is not null)::text from public.devices where device_id='wd_bbbbbbbbbbbbbbbb'" 33000000-0000-4000-8000-0000000000c2 BBBBBBBBBBBBBBBBBBBBBB 44000000-0000-4000-8000-0000000000c2 BBBBBBBBBBBBBBBBBBBBBB
restore_device wd_bbbbbbbbbbbbbbbb
race destination consume-first "update public.devices set revoked_at=clock_timestamp() where device_id='wd_bbbbbbbbbbbbbbbb'" "select (revoked_at is not null)::text from public.devices where device_id='wd_bbbbbbbbbbbbbbbb'" 33000000-0000-4000-8000-0000000000c8 HHHHHHHHHHHHHHHHHHHHHH 44000000-0000-4000-8000-0000000000c8 HHHHHHHHHHHHHHHHHHHHHH
restore_device wd_bbbbbbbbbbbbbbbb
race router consume-first "update public.devices set revoked_at=clock_timestamp() where device_id='wd_cccccccccccccccc'" "select (revoked_at is not null)::text from public.devices where device_id='wd_cccccccccccccccc'" 33000000-0000-4000-8000-0000000000c3 CCCCCCCCCCCCCCCCCCCCCC 44000000-0000-4000-8000-0000000000c3 CCCCCCCCCCCCCCCCCCCCCC
restore_device wd_cccccccccccccccc
race router revoke-first "update public.devices set revoked_at=clock_timestamp() where device_id='wd_cccccccccccccccc'" "select (revoked_at is not null)::text from public.devices where device_id='wd_cccccccccccccccc'" 33000000-0000-4000-8000-0000000000c9 IIIIIIIIIIIIIIIIIIIIII 44000000-0000-4000-8000-0000000000c9 IIIIIIIIIIIIIIIIIIIIII
restore_device wd_cccccccccccccccc
race membership revoke-first "delete from public.organization_memberships where organization_id='22000000-0000-4000-8000-0000000000c1' and user_id='11000000-0000-4000-8000-0000000000c1'" "select (count(*)=0)::text from public.organization_memberships where organization_id='22000000-0000-4000-8000-0000000000c1' and user_id='11000000-0000-4000-8000-0000000000c1'" 33000000-0000-4000-8000-0000000000c4 DDDDDDDDDDDDDDDDDDDDDD 44000000-0000-4000-8000-0000000000c4 DDDDDDDDDDDDDDDDDDDDDD
restore_membership
race membership consume-first "delete from public.organization_memberships where organization_id='22000000-0000-4000-8000-0000000000c1' and user_id='11000000-0000-4000-8000-0000000000c1'" "select (count(*)=0)::text from public.organization_memberships where organization_id='22000000-0000-4000-8000-0000000000c1' and user_id='11000000-0000-4000-8000-0000000000c1'" 33000000-0000-4000-8000-0000000000ca JJJJJJJJJJJJJJJJJJJJJJ 44000000-0000-4000-8000-0000000000ca JJJJJJJJJJJJJJJJJJJJJJ
restore_membership
race access consume-first "delete from public.device_access where device_id='wd_bbbbbbbbbbbbbbbb' and user_id='11000000-0000-4000-8000-0000000000c1' and permission='port_forward.local'" "select (count(*)=0)::text from public.device_access where device_id='wd_bbbbbbbbbbbbbbbb' and user_id='11000000-0000-4000-8000-0000000000c1' and permission='port_forward.local'" 33000000-0000-4000-8000-0000000000c5 EEEEEEEEEEEEEEEEEEEEEE 44000000-0000-4000-8000-0000000000c5 EEEEEEEEEEEEEEEEEEEEEE
restore_access
race access revoke-first "delete from public.device_access where device_id='wd_bbbbbbbbbbbbbbbb' and user_id='11000000-0000-4000-8000-0000000000c1' and permission='port_forward.local'" "select (count(*)=0)::text from public.device_access where device_id='wd_bbbbbbbbbbbbbbbb' and user_id='11000000-0000-4000-8000-0000000000c1' and permission='port_forward.local'" 33000000-0000-4000-8000-0000000000cb LLLLLLLLLLLLLLLLLLLLLL 44000000-0000-4000-8000-0000000000cb LLLLLLLLLLLLLLLLLLLLLL
restore_access
race route-grant revoke-first "update public.route_authorization_grants set revoked_at=clock_timestamp() where id='33000000-0000-4000-8000-0000000000c6'" "select (revoked_at is not null)::text from public.route_authorization_grants where id='33000000-0000-4000-8000-0000000000c6'" 33000000-0000-4000-8000-0000000000c6 FFFFFFFFFFFFFFFFFFFFFF 44000000-0000-4000-8000-0000000000c6 FFFFFFFFFFFFFFFFFFFFFF
race route-grant consume-first "update public.route_authorization_grants set revoked_at=clock_timestamp() where id='33000000-0000-4000-8000-0000000000cc'" "select (revoked_at is not null)::text from public.route_authorization_grants where id='33000000-0000-4000-8000-0000000000cc'" 33000000-0000-4000-8000-0000000000cc MMMMMMMMMMMMMMMMMMMMMM 44000000-0000-4000-8000-0000000000cc MMMMMMMMMMMMMMMMMMMMMM

# A rolled-back authorization must leave no transaction or replay state, and an exact retry must then succeed.
ROLLBACK_GENERATION="$(psql "$DB_URL" -X -Atqc "select coalesce((select generation from public.port_forward_replay_authority where device_id='wd_aaaaaaaaaaaaaaaa'),0)")"
ROLLBACK_STATE_HASH="$(psql "$DB_URL" -X -Atqc "select coalesce((select pg_catalog.encode(state_hash,'hex') from public.port_forward_replay_authority where device_id='wd_aaaaaaaaaaaaaaaa'),'')")"
route 33000000-0000-4000-8000-0000000000d4 SSSSSSSSSSSSSSSSSSSSSS
start c wd-c145-rollback
send c "begin; select public.wd_c145_consume('44000000-0000-4000-8000-0000000000d4','TTTTTTTTTTTTTTTTTTTTTT','33000000-0000-4000-8000-0000000000d4','SSSSSSSSSSSSSSSSSSSSSS','$ISSUED_AT','$EXPIRES_AT');"
wait_text c '"accepted": true'
fd="${FDS[c]}" pid="${PIDS[c]}"
printf 'rollback;\n\\q\n' >&"$fd"
exec {fd}>&-
unset 'FDS[c]' 'PIDS[c]'
if ! wait "$pid"; then cat "$WORK/c.log" >&2; fail 'rollback session failed'; fi
assertq 0 "select count(*) from public.port_forward_authorization_transactions where forwarding_id='44000000-0000-4000-8000-0000000000d4'"
assertq 0 "select count(*) from public.port_forward_replay_entries where device_id='wd_aaaaaaaaaaaaaaaa' and jti='TTTTTTTTTTTTTTTTTTTTTT'"
assertq "$ROLLBACK_GENERATION" "select coalesce((select generation from public.port_forward_replay_authority where device_id='wd_aaaaaaaaaaaaaaaa'),0)"
assertq "$ROLLBACK_STATE_HASH" "select coalesce((select pg_catalog.encode(state_hash,'hex') from public.port_forward_replay_authority where device_id='wd_aaaaaaaaaaaaaaaa'),'')"
start c wd-c145-rollback-retry
send c "begin; select public.wd_c145_consume('44000000-0000-4000-8000-0000000000d4','TTTTTTTTTTTTTTTTTTTTTT','33000000-0000-4000-8000-0000000000d4','SSSSSSSSSSSSSSSSSSSSSS','$ISSUED_AT','$EXPIRES_AT');"
wait_text c '"accepted": true'
finish c || fail 'exact retry after rollback failed'
assertq 1 "select count(*) from public.port_forward_authorization_transactions where forwarding_id='44000000-0000-4000-8000-0000000000d4'"
assertq 1 "select count(*) from public.port_forward_replay_entries where device_id='wd_aaaaaaaaaaaaaaaa' and jti='TTTTTTTTTTTTTTTTTTTTTT'"
assertq "$((ROLLBACK_GENERATION + 1))" "select generation from public.port_forward_replay_authority where device_id='wd_aaaaaaaaaaaaaaaa'"

# Audit finalization uses the same participant locks as authorization and revocation.
psql "$DB_URL" -X -v ON_ERROR_STOP=1 <<'SQL'
create function public.wd_c145_audit(p_operation_id text,p_jti text) returns jsonb
language plpgsql security definer set search_path=''
as $
declare payload jsonb;
begin
 payload := jsonb_build_object(
  'version',1,
  'initiator',jsonb_build_object('device_id','wd_aaaaaaaaaaaaaaaa','account_id','11000000-0000-4000-8000-0000000000c1','organization_id','22000000-0000-4000-8000-0000000000c1','revocation_epoch',(select revocation_epoch from public.devices where device_id='wd_aaaaaaaaaaaaaaaa')),
  'destination',jsonb_build_object('device_id','wd_bbbbbbbbbbbbbbbb','account_id','11000000-0000-4000-8000-0000000000c2','organization_id','22000000-0000-4000-8000-0000000000c1','revocation_epoch',(select revocation_epoch from public.devices where device_id='wd_bbbbbbbbbbbbbbbb')),
  'router',null,'consuming_device_id','wd_aaaaaaaaaaaaaaaa','jti',p_jti,
  'authorization_sha256',(select encode(authorization_sha256,'hex') from public.port_forward_authorization_transactions where jti=p_jti),
  'route_authorization_sha256',repeat('0',64),'route_authorization_id','','route_authorization_jti','','route_authorization_json','',
  'device_public_key',(select public_key from public.devices where device_id='wd_aaaaaaaaaaaaaaaa'),
  'device_signature',repeat('A',86)||'=='
 );
 return public.record_checkpoint_finalization(
  p_operation_id,'finalization_started',1,payload,
  extensions.digest(convert_to(wedecent_private.canonical_jsonb(payload),'UTF8'),'sha256'),
  '{}'::jsonb,extensions.digest(convert_to('{}','UTF8'),'sha256'),
  '11000000-0000-4000-8000-0000000000c1'
 );
end;
$;
SQL

audit_race() {
 local name="$1" order="$2" mutation="$3" post="$4" operation="$5" jti="$6"
 local ca="wd-c145-$name-audit" ra="wd-c145-$name-mutation"
 if [[ "$order" == "audit-first" ]]; then
  start a "$ca"
  send a "begin; select public.wd_c145_audit('$operation','$jti'); select 'audit-ready';"
  wait_text a "audit-ready"
  start r "$ra"
  send r "begin; $mutation; select 'mutation-ready';"
  wait_lock "$ra"
  finish a || fail "$name audit commit failed"
  finish r || fail "$name mutation commit failed"
  assertq t "select exists(select 1 from public.checkpoint_finalization_audit where operation_id='$operation' and outcome='finalization_started')"
 else
  start r "$ra"
  send r "begin; $mutation; select 'mutation-ready';"
  wait_text r "mutation-ready"
  start a "$ca"
  send a "begin; select public.wd_c145_audit('$operation','$jti');"
  wait_lock "$ca"
  finish r || fail "$name mutation commit failed"
  local fd="${FDS[a]}" pid="${PIDS[a]}"
  exec {fd}>&-; unset 'FDS[a]' 'PIDS[a]'
  if wait "$pid"; then cat "$WORK/a.log" >&2; fail "$name audit succeeded after revocation"; fi
  grep -q 'ERROR:' "$WORK/a.log" || fail "$name audit did not fail with a database authorization error"
  assertq f "select exists(select 1 from public.checkpoint_finalization_audit where operation_id='$operation' and outcome='finalization_started')"
 fi
 assertq true "$post"
 printf 'verified audit %s (%s)\n' "$name" "$order"
}

audit_race device audit-first "update public.devices set revoked_at=clock_timestamp() where device_id='wd_bbbbbbbbbbbbbbbb'" "select (revoked_at is not null)::text from public.devices where device_id='wd_bbbbbbbbbbbbbbbb'" "$(printf '%064d' 1)" AAAAAAAAAAAAAAAAAAAAAA
restore_device wd_bbbbbbbbbbbbbbbb
audit_race device revoke-first "update public.devices set revoked_at=clock_timestamp() where device_id='wd_bbbbbbbbbbbbbbbb'" "select (revoked_at is not null)::text from public.devices where device_id='wd_bbbbbbbbbbbbbbbb'" "$(printf '%064d' 2)" AAAAAAAAAAAAAAAAAAAAAA
restore_device wd_bbbbbbbbbbbbbbbb
audit_race membership audit-first "delete from public.organization_memberships where organization_id='22000000-0000-4000-8000-0000000000c1' and user_id='11000000-0000-4000-8000-0000000000c1'" "select (count(*)=0)::text from public.organization_memberships where organization_id='22000000-0000-4000-8000-0000000000c1' and user_id='11000000-0000-4000-8000-0000000000c1'" "$(printf '%064d' 3)" AAAAAAAAAAAAAAAAAAAAAA
restore_membership
audit_race membership revoke-first "delete from public.organization_memberships where organization_id='22000000-0000-4000-8000-0000000000c1' and user_id='11000000-0000-4000-8000-0000000000c1'" "select (count(*)=0)::text from public.organization_memberships where organization_id='22000000-0000-4000-8000-0000000000c1' and user_id='11000000-0000-4000-8000-0000000000c1'" "$(printf '%064d' 4)" AAAAAAAAAAAAAAAAAAAAAA
restore_membership

# Route-grant JTIs are unique in their own table and intentionally differ from forwarding JTIs.
route 33000000-0000-4000-8000-0000000000d1 NNNNNNNNNNNNNNNNNNNNNN
start c wd-c145-dup-a
send c "begin; select public.wd_c145_consume('44000000-0000-4000-8000-0000000000d1','QQQQQQQQQQQQQQQQQQQQQQ','33000000-0000-4000-8000-0000000000d1','NNNNNNNNNNNNNNNNNNNNNN','$ISSUED_AT','$EXPIRES_AT');"
wait_text c '"accepted": true'
start d wd-c145-dup-b
send d "begin; select public.wd_c145_consume('44000000-0000-4000-8000-0000000000d1','QQQQQQQQQQQQQQQQQQQQQQ','33000000-0000-4000-8000-0000000000d1','NNNNNNNNNNNNNNNNNNNNNN','$ISSUED_AT','$EXPIRES_AT');"
wait_lock wd-c145-dup-b
finish c || fail 'first duplicate transaction failed'
wait_text d '"replayed": true'
finish d || fail 'same forwarding retry failed'
assertq 1 "select count(*) from public.port_forward_authorization_transactions where forwarding_id='44000000-0000-4000-8000-0000000000d1'"
assertq 1 "select count(*) from public.port_forward_replay_entries where jti='QQQQQQQQQQQQQQQQQQQQQQ'"

route 33000000-0000-4000-8000-0000000000d2 OOOOOOOOOOOOOOOOOOOOOO
start c wd-c145-jti-a
send c "begin; select public.wd_c145_consume('44000000-0000-4000-8000-0000000000d2','RRRRRRRRRRRRRRRRRRRRRR','33000000-0000-4000-8000-0000000000d2','OOOOOOOOOOOOOOOOOOOOOO','$ISSUED_AT','$EXPIRES_AT');"
wait_text c '"accepted": true'
route 33000000-0000-4000-8000-0000000000d3 PPPPPPPPPPPPPPPPPPPPPP
start d wd-c145-jti-b
send d "begin; select public.wd_c145_consume('44000000-0000-4000-8000-0000000000d3','RRRRRRRRRRRRRRRRRRRRRR','33000000-0000-4000-8000-0000000000d3','PPPPPPPPPPPPPPPPPPPPPP','$ISSUED_AT','$EXPIRES_AT');"
wait_lock wd-c145-jti-b
finish c || fail 'first JTI transaction failed'
wait_text d '"jti-conflict"'
finish d || fail 'JTI conflict transaction did not finish'
assertq 1 "select count(*) from public.port_forward_authorization_transactions where jti='RRRRRRRRRRRRRRRRRRRRRR'"
assertq 0 "select count(*) from public.port_forward_authorization_transactions where forwarding_id='44000000-0000-4000-8000-0000000000d3'"

psql "$DB_URL" -X -v ON_ERROR_STOP=1 -c 'drop function public.wd_c145_consume(uuid,text,uuid,text,timestamptz,timestamptz); drop function public.wd_c145_route(uuid,text);'
printf 'All deterministic multi-session authorization races passed.\n'
