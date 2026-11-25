begin;
create extension if not exists pgtap with schema extensions;
select plan(26);

insert into auth.users(id,aud,role,email)
values ('11000000-0000-4000-8000-000000000197','authenticated','authenticated','c197-primary@example.test');
select set_config('request.jwt.claim.sub','11000000-0000-4000-8000-000000000197',true);
create temporary table c197_test_keys(name text primary key, public_key bytea not null, secret_key bytea not null);
insert into c197_test_keys select 'primary',public,secret from pgsodium.crypto_sign_new_keypair();
insert into c197_test_keys select 'witness-a',public,secret from pgsodium.crypto_sign_new_keypair();
insert into c197_test_keys select 'witness-b',public,secret from pgsodium.crypto_sign_new_keypair();
insert into c197_test_keys select 'witness-c',public,secret from pgsodium.crypto_sign_new_keypair();
create function pg_temp.c197_key_id(p_key bytea) returns text language sql immutable as $
 select 'ed25519-' || pg_catalog.translate(
   pg_catalog.replace(pg_catalog.encode(extensions.digest(p_key,'sha256'),'base64'),E'\n',''),
   '+/','-_'
 );
$fn$;
insert into public.checkpoint_fence_primary_trust(key_id,public_key)
select pg_temp.c197_key_id(public_key),public_key from c197_test_keys where name='primary';
insert into public.checkpoint_fence_witness_trust(witness_set_version,witness_id,key_id,public_key)
select 'c197-set',name,pg_temp.c197_key_id(public_key),public_key
from c197_test_keys where name like 'witness-%';

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
   'authorization_proof_issued_at_unix_ms',0,
   'authorization_proof_expires_at_unix_ms',0,
   'primary_head_generation',1,'primary_head_sha256',pg_catalog.repeat('f',64),
   'previous_fence_sha256',pg_catalog.repeat('0',64),
   'witness_set_version','c197-set',
   'witness_ids',pg_catalog.jsonb_build_array('witness-a','witness-b','witness-c'),
   'expires_at_unix_ms',(
      select (extract(epoch from pg_catalog.clock_timestamp())*1000)::bigint+5000
      from public.checkpoint_fence_authority
      where organization_id='22000000-0000-4000-8000-000000000197'
   ),
   'primary_key_id',(select pg_temp.c197_key_id(public_key) from c197_test_keys where name='primary'),
   'signature',pg_catalog.repeat('A',86)||'=='
 );
$$;

create function pg_temp.c197_acks(p_operation_id text) returns jsonb
language plpgsql volatile
as $fn$
declare
 v_acks jsonb;
 v_ack jsonb;
 v_secret bytea;
 v_ord bigint;
begin
 v_acks := pg_catalog.jsonb_build_array(
   pg_catalog.jsonb_build_object('witness_id','witness-a','token_sha256',pg_catalog.repeat('b',64),
     'generation',1,'action','finalize','operation_id',p_operation_id,
     'witness_key_id',(select pg_temp.c197_key_id(public_key) from c197_test_keys where name='witness-a'),
     'committed_at_unix_ms',(extract(epoch from pg_catalog.clock_timestamp())*1000)::bigint,'signature',''),
   pg_catalog.jsonb_build_object('witness_id','witness-b','token_sha256',pg_catalog.repeat('b',64),
     'generation',1,'action','finalize','operation_id',p_operation_id,
     'witness_key_id',(select pg_temp.c197_key_id(public_key) from c197_test_keys where name='witness-b'),
     'committed_at_unix_ms',(extract(epoch from pg_catalog.clock_timestamp())*1000)::bigint,'signature','')
 );
 for v_ack,v_ord in select value,ord from pg_catalog.jsonb_array_elements(v_acks) with ordinality a(value,ord)
 loop
   select secret_key into v_secret from c197_test_keys where name=v_ack->>'witness_id';
   v_acks := pg_catalog.jsonb_set(v_acks,array[(v_ord-1)::text,'signature'],
     pg_catalog.to_jsonb(pg_catalog.replace(pg_catalog.encode(
       pgsodium.crypto_sign_detached(wedecent_private.checkpoint_fence_ack_signing_bytes(v_ack),v_secret),
       'base64'),E'\n','')));
 end loop;
 return v_acks;
end;
$fn$;

create function pg_temp.c197_authority_signature(
 p_operation_id text,p_fingerprint bytea,p_token_sha256 bytea,p_acks jsonb
) returns bytea language sql volatile as $
 select pgsodium.crypto_sign_detached(
   wedecent_private.checkpoint_fence_commit_signing_bytes(
     p_operation_id,p_fingerprint,p_token_sha256,
     (select event_payload->'token' from public.checkpoint_operation_events
       where operation_id=p_operation_id and event_type='fence_reserved' order by event_id desc limit 1),
     p_acks,'11000000-0000-4000-8000-000000000197'
   ),
   (select secret_key from c197_test_keys where name='primary')
 );
$fn$;

select ok(
 not pg_catalog.has_function_privilege('service_role','public.reserve_checkpoint_operation(text,text,uuid,uuid,bytea,jsonb,integer)','EXECUTE')
 and not pg_catalog.has_function_privilege('service_role','public.commit_checkpoint_operation(text,bytea,jsonb)','EXECUTE')
 and not pg_catalog.has_function_privilege('service_role','public.reserve_checkpoint_fence_operation(text,text,uuid,uuid,bytea,jsonb,bigint,bytea,integer)','EXECUTE')
 and pg_catalog.has_function_privilege('wedecent_checkpoint_authority','public.reserve_checkpoint_fence_operation(text,text,uuid,uuid,bytea,jsonb,bigint,bytea,integer)','EXECUTE')
 and pg_catalog.has_function_privilege('wedecent_checkpoint_authority','public.commit_checkpoint_fence_operation(text,bytea,bytea,jsonb,bytea)','EXECUTE'),
 'service_role cannot invoke fencing; only dedicated authority role can'
);
select set_config('request.jwt.claim.sub','33000000-0000-4000-8000-000000000197',true);
select throws_ok($q$select public.reserve_checkpoint_fence_operation(
 repeat('8',64),'finalize','22000000-0000-4000-8000-000000000197',
 '11000000-0000-4000-8000-000000000197',decode(repeat('8',64),'hex'),
 pg_temp.c197_participants('wd_hhhhhhhhhhhhhhhh'),1,decode(repeat('f',64),'hex'),60)$q$,
 '42501',null,'forged actor JWT subject cannot reserve for another account');
select set_config('request.jwt.claim.sub','11000000-0000-4000-8000-000000000197',true);


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
create temporary table c197_commit_material as
select pg_temp.c197_acks(repeat('9',64)) as acknowledgements;

update public.checkpoint_active_reservations
   set reserved_at = pg_catalog.clock_timestamp(),
       expires_at = pg_catalog.clock_timestamp() + interval '4 seconds'
 where operation_id = repeat('9',64);
update public.checkpoint_fence_authority
   set pending_expires_at = pg_catalog.clock_timestamp() + interval '6 seconds'
 where organization_id = '22000000-0000-4000-8000-000000000197';

select pg_catalog.pg_sleep(7);
select ok(
 (select (event_payload->'token'->>'expires_at_unix_ms')::bigint <=
     (extract(epoch from pg_catalog.clock_timestamp())*1000)::bigint
    from public.checkpoint_operation_events
   where operation_id=repeat('9',64) and event_type='fence_reserved'
   order by event_id desc limit 1)
 and (select pg_catalog.bool_and(expires_at <= pg_catalog.clock_timestamp())
        from public.checkpoint_active_reservations where operation_id=repeat('9',64))
 and (select pending_expires_at <= pg_catalog.clock_timestamp()
        from public.checkpoint_fence_authority
       where organization_id='22000000-0000-4000-8000-000000000197'),
 'original signed token and participant lease are expired before recovery commit'
);

select throws_ok($q$select public.commit_checkpoint_fence_operation(
 repeat('9',64),(select fingerprint from public.checkpoint_operations where operation_id=repeat('9',64)),
 decode(repeat('b',64),'hex'),
 pg_catalog.jsonb_build_array((select value from pg_catalog.jsonb_array_elements(acknowledgements) limit 1)),
 pg_temp.c197_authority_signature(repeat('9',64),
   (select fingerprint from public.checkpoint_operations where operation_id=repeat('9',64)),
   decode(repeat('b',64),'hex'),
   pg_catalog.jsonb_build_array((select value from pg_catalog.jsonb_array_elements(acknowledgements) limit 1)))
)$q$,
 '22023','checkpoint witness quorum is insufficient',
 'database rejects a structurally valid but insufficient witness quorum');

select throws_ok($q$select public.commit_checkpoint_fence_operation(
 repeat('9',64),(select fingerprint from public.checkpoint_operations where operation_id=repeat('9',64)),
 decode(repeat('b',64),'hex'),
 pg_catalog.jsonb_set((select acknowledgements from c197_commit_material),'{0,signature}',to_jsonb(repeat('A',86)||'==')),
 pg_temp.c197_authority_signature(repeat('9',64),
   (select fingerprint from public.checkpoint_operations where operation_id=repeat('9',64)),
   decode(repeat('b',64),'hex'),
   pg_catalog.jsonb_set((select acknowledgements from c197_commit_material),'{0,signature}',to_jsonb(repeat('A',86)||'==')))
)$q$,
 '42501','checkpoint witness signature verification failed',
 'database rejects fabricated witness signatures even with a primary commit attestation');

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
 decode(repeat('b',64),'hex'),(select acknowledgements from c197_commit_material),
 pg_temp.c197_authority_signature(repeat('9',64),
   (select fingerprint from public.checkpoint_operations where operation_id=repeat('9',64)),
   decode(repeat('b',64),'hex'),(select acknowledgements from c197_commit_material))
)->>'status','committed','cryptographically verified quorum and primary attestation commit atomically');
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
 decode(repeat('b',64),'hex'),(select acknowledgements from c197_commit_material),
 pg_temp.c197_authority_signature(repeat('9',64),
   (select fingerprint from public.checkpoint_operations where operation_id=repeat('9',64)),
   decode(repeat('b',64),'hex'),(select acknowledgements from c197_commit_material))
)->>'status','committed','exact signed commit retry returns the durable receipt');
select is((select checkpoint_head_generation::integer from public.port_forward_replay_authority
 where device_id='wd_hhhhhhhhhhhhhhhh'),1,'commit retry cannot advance participant head twice');
select is((public.load_checkpoint_fence_head('22000000-0000-4000-8000-000000000197')->>'generation')::integer,
 1,'commit retry cannot advance fence generation twice');
select throws_ok($q$select public.commit_checkpoint_fence_operation(
 repeat('9',64),(select fingerprint from public.checkpoint_operations where operation_id=repeat('9',64)),
 decode(repeat('c',64),'hex'),(select acknowledgements from c197_commit_material),
 pg_temp.c197_authority_signature(repeat('9',64),
   (select fingerprint from public.checkpoint_operations where operation_id=repeat('9',64)),
   decode(repeat('c',64),'hex'),(select acknowledgements from c197_commit_material)))$q$,
 '23505',null,'conflicting token digest is rejected after commit');
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
