begin;
create extension if not exists pgtap with schema extensions;
select plan(22);

insert into auth.users(id,aud,role,email)
values ('11000000-0000-4000-8000-000000000197','authenticated','authenticated','c197-primary@example.test');
insert into public.organizations(id,name,slug,created_by)
values ('22000000-0000-4000-8000-000000000197','C197 Primary','c197-primary','11000000-0000-4000-8000-000000000197');
insert into public.devices(device_id,public_key,kind,name,owner_user_id,organization_id)
values
 ('wd_hhhhhhhhhhhhhhhh',repeat('H',43),'client','C197 A','11000000-0000-4000-8000-000000000197','22000000-0000-4000-8000-000000000197'),
 ('wd_iiiiiiiiiiiiiiii',repeat('I',43),'agent','C197 B','11000000-0000-4000-8000-000000000197','22000000-0000-4000-8000-000000000197');

create function pg_temp.c197_participants(p_device text) returns jsonb
language sql stable
as $$
 select pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
   'device_id',d.device_id,'account_id',d.owner_user_id,
   'organization_id',d.organization_id,'revocation_epoch',d.revocation_epoch,
   'head_generation',coalesce(a.checkpoint_head_generation,0),
   'head_hash',coalesce(pg_catalog.encode(a.checkpoint_head_hash,'hex'),pg_catalog.repeat('0',64))
 ) order by d.device_id)
 from public.devices d left join public.port_forward_replay_authority a on a.device_id=d.device_id
 where d.device_id=p_device;
$$;

create function pg_temp.c197_token(p_operation_id text) returns jsonb
language sql stable
as $$
 select pg_catalog.jsonb_build_object(
   'version',1,
   'scope',pg_catalog.jsonb_build_object('kind','organization','organization_id','22000000-0000-4000-8000-000000000197'),
   'participants',(select pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
      'device_id',p.device_id,'account_id',p.account_id,'organization_id',p.organization_id,
      'revocation_epoch',p.revocation_epoch
   ) order by p.device_id) from public.checkpoint_operation_participants p where p.operation_id=p_operation_id),
   'expected_fence_generation',0,'generation',1,
   'expected_revocation_epoch',0,'resulting_revocation_epoch',0,
   'action','finalize','operation_id',p_operation_id,
   'request_sha256',pg_catalog.repeat('9',64),'authorization_sha256',pg_catalog.repeat('a',64),
   'authorization_proof','',
   'primary_head_generation',1,'primary_head_sha256',pg_catalog.repeat('f',64),
   'previous_fence_sha256',pg_catalog.repeat('0',64),
   'witness_set_version','c197-set',
   'witness_ids',pg_catalog.jsonb_build_array('witness-a','witness-b','witness-c'),
   'expires_at_unix_ms',(
      select (extract(epoch from pending_expires_at)*1000)::bigint-1000
      from public.checkpoint_fence_authority
      where organization_id='22000000-0000-4000-8000-000000000197'
   ),
   'primary_key_id','primary-key','signature',pg_catalog.repeat('A',86)||'=='
 );
$$;

create function pg_temp.c197_acks(p_operation_id text) returns jsonb
language sql immutable
as $$
 select pg_catalog.jsonb_build_array(
   pg_catalog.jsonb_build_object('witness_id','witness-a','token_sha256',pg_catalog.repeat('b',64),
     'generation',1,'action','finalize','operation_id',p_operation_id,'witness_key_id','key-a',
     'committed_at_unix_ms',1000,'signature',pg_catalog.repeat('A',86)||'=='),
   pg_catalog.jsonb_build_object('witness_id','witness-b','token_sha256',pg_catalog.repeat('b',64),
     'generation',1,'action','finalize','operation_id',p_operation_id,'witness_key_id','key-b',
     'committed_at_unix_ms',1001,'signature',pg_catalog.repeat('B',86)||'==')
 );
$$;

select ok(
 not pg_catalog.has_function_privilege('service_role','public.reserve_checkpoint_operation(text,text,uuid,uuid,bytea,jsonb,integer)','EXECUTE')
 and not pg_catalog.has_function_privilege('service_role','public.commit_checkpoint_operation(text,bytea,jsonb)','EXECUTE')
 and pg_catalog.has_function_privilege('service_role','public.reserve_checkpoint_fence_operation(text,text,uuid,uuid,bytea,jsonb,bigint,bytea,integer)','EXECUTE'),
 'service_role is restricted to the fence-wrapped reservation/commit API'
);

select is(public.reserve_checkpoint_fence_operation(
 repeat('9',64),'finalize','22000000-0000-4000-8000-000000000197',
 '11000000-0000-4000-8000-000000000197',decode(repeat('9',64),'hex'),
 pg_temp.c197_participants('wd_hhhhhhhhhhhhhhhh'),1,decode(repeat('f',64),'hex'),60)->>'status',
 'reserved','fence reservation composes the existing atomic participant reservation');
select is((public.load_checkpoint_fence_head('22000000-0000-4000-8000-000000000197')->>'generation')::integer,
 0,'scope fence generation does not advance before quorum commit');
select is(public.load_checkpoint_fence_head('22000000-0000-4000-8000-000000000197')->>'pending_operation_id',
 repeat('9',64),'scope fence has a single pending operation');
select throws_ok($q$select public.reserve_checkpoint_fence_operation(
 repeat('a',64),'finalize','22000000-0000-4000-8000-000000000197',
 '11000000-0000-4000-8000-000000000197',decode(repeat('a',64),'hex'),
 pg_temp.c197_participants('wd_iiiiiiiiiiiiiiii'),1,decode(repeat('e',64),'hex'),60)$q$,
 '55P03','organization checkpoint fence is reserved by another operation',
 'disjoint device sets cannot bypass the organization-wide pending fence');
select is((select count(*)::integer from public.checkpoint_operations where operation_id=repeat('a',64)),
 0,'rejected disjoint operation leaves no partial operation record');

select is(public.record_checkpoint_fence_token(
 repeat('9',64),(select fingerprint from public.checkpoint_operations where operation_id=repeat('9',64)),
 decode(repeat('b',64),'hex'),pg_temp.c197_token(repeat('9',64))
)->>'token_sha256',repeat('b',64),'signed reservation token receipt is persisted');
select is((public.load_checkpoint_fence_operation(
 '22000000-0000-4000-8000-000000000197',repeat('9',64)
)->>'found')::boolean,true,'reservation token is recoverable after a lost response');
select is(public.load_checkpoint_fence_operation(
 '22000000-0000-4000-8000-000000000197',repeat('9',64)
)->'token'->>'operation_id',repeat('9',64),'recovered token is bound to the exact operation');
select throws_ok($q$select public.record_checkpoint_fence_token(
 repeat('9',64),(select fingerprint from public.checkpoint_operations where operation_id=repeat('9',64)),
 decode(repeat('c',64),'hex'),pg_temp.c197_token(repeat('9',64)))$q$,
 '23505',null,'conflicting token digest cannot replace a live reservation');

select is(public.commit_checkpoint_fence_operation(
 repeat('9',64),(select fingerprint from public.checkpoint_operations where operation_id=repeat('9',64)),
 decode(repeat('b',64),'hex'),pg_temp.c197_acks(repeat('9',64))
)->>'status','committed','quorum receipt and participant heads commit atomically');
select is((public.load_checkpoint_fence_head('22000000-0000-4000-8000-000000000197')->>'generation')::integer,
 1,'organization fence generation advances exactly once');
select is(public.load_checkpoint_fence_head('22000000-0000-4000-8000-000000000197')->>'fence_hash',
 repeat('b',64),'fence head binds the signed token digest');
select is(public.load_checkpoint_fence_head('22000000-0000-4000-8000-000000000197')->>'pending_operation_id',
 '','committed fence clears its pending operation');
select is((select checkpoint_head_generation::integer from public.port_forward_replay_authority
 where device_id='wd_hhhhhhhhhhhhhhhh'),1,'participant head advances on the sole replay-authority row');
select is((public.load_checkpoint_fence_operation(
 '22000000-0000-4000-8000-000000000197',repeat('9',64)
)->>'committed')::boolean,true,'commit receipt and acknowledgements are recoverable');

select is(public.commit_checkpoint_fence_operation(
 repeat('9',64),(select fingerprint from public.checkpoint_operations where operation_id=repeat('9',64)),
 decode(repeat('b',64),'hex'),pg_temp.c197_acks(repeat('9',64))
)->>'status','committed','exact commit retry returns the durable receipt');
select is((select checkpoint_head_generation::integer from public.port_forward_replay_authority
 where device_id='wd_hhhhhhhhhhhhhhhh'),1,'commit retry cannot advance participant head twice');
select is((public.load_checkpoint_fence_head('22000000-0000-4000-8000-000000000197')->>'generation')::integer,
 1,'commit retry cannot advance fence generation twice');
select throws_ok($q$select public.commit_checkpoint_fence_operation(
 repeat('9',64),(select fingerprint from public.checkpoint_operations where operation_id=repeat('9',64)),
 decode(repeat('c',64),'hex'),pg_temp.c197_acks(repeat('9',64)))$q$,
 '23505','checkpoint committed token digest conflicts','conflicting token digest is rejected after commit');
select is((select count(*)::integer from public.checkpoint_operation_events
 where operation_id=repeat('9',64) and event_type='fence_committed'),1,
 'fence commit evidence is append-only and unique');
select ok((select event_sha256=extensions.digest(
 convert_to(wedecent_private.canonical_jsonb(event_payload),'UTF8'),'sha256')
 from public.checkpoint_operation_events
 where operation_id=repeat('9',64) and event_type='fence_committed'),
 'fence commit evidence digest matches canonical receipt');

select * from finish();
rollback;
