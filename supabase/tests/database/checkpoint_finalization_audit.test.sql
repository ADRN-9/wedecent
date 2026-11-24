begin;
create extension if not exists pgtap with schema extensions;
select plan(21);

insert into auth.users(id,aud,role,email) values
('11000000-0000-4000-8000-000000000091','authenticated','authenticated','audit-initiator@example.test'),
('11000000-0000-4000-8000-000000000092','authenticated','authenticated','audit-destination@example.test'),
('11000000-0000-4000-8000-000000000093','authenticated','authenticated','audit-outsider@example.test');

insert into public.organizations(id,name,slug,created_by)
values('22000000-0000-4000-8000-000000000091','Checkpoint Audit Test','checkpoint-audit-test','11000000-0000-4000-8000-000000000091');

insert into public.organization_memberships(organization_id,user_id,role,created_by)
values('22000000-0000-4000-8000-000000000091','11000000-0000-4000-8000-000000000092','member','11000000-0000-4000-8000-000000000091')
on conflict do nothing;

insert into public.devices(device_id,public_key,kind,name,owner_user_id,organization_id,revocation_epoch)
values
('wd_aaaaaaaaaaaaaaaa',repeat('A',43),'client','Audit initiator','11000000-0000-4000-8000-000000000091','22000000-0000-4000-8000-000000000091',1),
('wd_bbbbbbbbbbbbbbbb',repeat('B',43),'agent','Audit destination','11000000-0000-4000-8000-000000000092','22000000-0000-4000-8000-000000000091',1);

insert into public.port_forward_authorization_transactions(
 forwarding_id,jti,authorization_sha256,permission,direction,
 initiating_device_id,destination_device_id,router_device_id,
 initiator_account_id,destination_account_id,router_account_id,
 initiator_organization_id,destination_organization_id,router_organization_id,
 initiator_revocation_epoch,destination_revocation_epoch,router_revocation_epoch,
 route_authorization_id,route_authorization_jti,issued_at,expires_at
) values(
 '44000000-0000-4000-8000-000000000091','AAAAAAAAAAAAAAAAAAAAAA',decode(repeat('a',64),'hex'),
 'port_forward.local','local','wd_aaaaaaaaaaaaaaaa','wd_bbbbbbbbbbbbbbbb',null,
 '11000000-0000-4000-8000-000000000091','11000000-0000-4000-8000-000000000092',null,
 '22000000-0000-4000-8000-000000000091','22000000-0000-4000-8000-000000000091',null,
 1,1,null,null,null,clock_timestamp()-interval '5 seconds',clock_timestamp()+interval '60 seconds'
);

create function pg_temp.audit_payload(p_route_digest text default repeat('0',64)) returns jsonb
language sql as $$
select jsonb_build_object(
 'version',1,
 'initiator',jsonb_build_object('device_id','wd_aaaaaaaaaaaaaaaa','account_id','11000000-0000-4000-8000-000000000091','organization_id','22000000-0000-4000-8000-000000000091','revocation_epoch',1),
 'destination',jsonb_build_object('device_id','wd_bbbbbbbbbbbbbbbb','account_id','11000000-0000-4000-8000-000000000092','organization_id','22000000-0000-4000-8000-000000000091','revocation_epoch',1),
 'router',null,'consuming_device_id','wd_aaaaaaaaaaaaaaaa','jti','AAAAAAAAAAAAAAAAAAAAAA',
 'authorization_sha256',repeat('a',64),'route_authorization_sha256',p_route_digest,
 'device_public_key',repeat('A',43)||'=','device_signature',repeat('A',86)||'=='
)
$$;

create function pg_temp.audit_evidence(p_outcome text) returns jsonb
language sql immutable as $
select case when p_outcome in ('finalized','rejected_revocation')
 then '{"primary_receipt":{},"witness_acknowledgements":[],"revocation_proofs":[]}'::jsonb
 else '{}'::jsonb end
$;

create function pg_temp.record_audit(p_outcome text,payload jsonb,p_operation_id text default repeat('a',64)) returns jsonb
language sql as $q$
select public.record_checkpoint_finalization(
 p_operation_id,
 p_outcome,1,payload,
 extensions.digest(convert_to(wedecent_private.canonical_jsonb(payload),'UTF8'),'sha256'),
 pg_temp.audit_evidence(p_outcome),
 extensions.digest(convert_to(wedecent_private.canonical_jsonb(pg_temp.audit_evidence(p_outcome)),'UTF8'),'sha256'),
 '11000000-0000-4000-8000-000000000091'
)
$q$;

create function pg_temp.record_audit_as(p_outcome text,payload jsonb,p_actor uuid) returns jsonb
language sql as $q$
select public.record_checkpoint_finalization(
 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
 p_outcome,1,payload,
 extensions.digest(convert_to(wedecent_private.canonical_jsonb(payload),'UTF8'),'sha256'),
 pg_temp.audit_evidence(p_outcome),
 extensions.digest(convert_to(wedecent_private.canonical_jsonb(pg_temp.audit_evidence(p_outcome)),'UTF8'),'sha256'),
 p_actor
)
$q$;

select ok((select relrowsecurity from pg_class c join pg_namespace n on n.oid=c.relnamespace where n.nspname='public' and c.relname='checkpoint_finalization_operations'),'operation ledger RLS enabled');
select ok((select relrowsecurity from pg_class c join pg_namespace n on n.oid=c.relnamespace where n.nspname='public' and c.relname='checkpoint_finalization_audit'),'audit event RLS enabled');
select ok(not has_table_privilege('authenticated','public.checkpoint_finalization_operations','SELECT,INSERT,UPDATE,DELETE'),'authenticated users cannot mutate or read operation ledger directly');
select ok(not has_table_privilege('service_role','public.checkpoint_finalization_audit','SELECT,INSERT,UPDATE,DELETE'),'service role cannot mutate audit tables directly');
select ok(not has_function_privilege('authenticated','public.record_checkpoint_finalization(text,text,integer,jsonb,bytea,jsonb,bytea,uuid)','EXECUTE'),'authenticated users cannot execute privileged audit RPC');
select ok(has_function_privilege('service_role','public.record_checkpoint_finalization(text,text,integer,jsonb,bytea,jsonb,bytea,uuid)','EXECUTE'),'service role can execute audit RPC');
select throws_ok($q$select pg_temp.record_audit_as('finalization_started',pg_temp.audit_payload(),'11000000-0000-4000-8000-000000000093')$q$,'42501','unauthorized audit actor','non-participant without organization membership cannot write audit records');
select is(wedecent_private.canonical_jsonb('{"z":2,"a":1}'::jsonb),'{"a":1,"z":2}','canonical JSON sorts object keys');
select is((pg_temp.record_audit('finalization_started',pg_temp.audit_payload())->>'replayed'),'false','first intermediate audit transition is committed');
select is((pg_temp.record_audit('finalization_started',pg_temp.audit_payload())->>'replayed'),'true','exact retry returns the original recorded result');
select is((select count(*)::integer from public.checkpoint_finalization_audit where operation_id=repeat('a',64) and outcome='finalization_started'),1,'exact retry creates no duplicate logical event');
select throws_ok($$select pg_temp.record_audit('finalization_started',pg_temp.audit_payload(repeat('1',64)))$$,'23505','operation payload conflict','conflicting payload for an existing operation is rejected');
select is((pg_temp.record_audit('finalized',pg_temp.audit_payload())->>'replayed'),'false','terminal finalization transition is recorded');
select throws_ok($$select pg_temp.record_audit('rejected_revocation',pg_temp.audit_payload())$$,'23505','contradictory terminal outcome','contradictory terminal outcome is rejected atomically');
select throws_ok($$select pg_temp.record_audit('finalization_failed',pg_temp.audit_payload())$$,'23505','contradictory terminal outcome','no intermediate transition is appended after terminal completion');
select is((select count(*)::integer from public.checkpoint_finalization_audit where operation_id=repeat('a',64) and outcome in('finalized','rejected_revocation')),1,'only one terminal outcome exists per operation');
select throws_ok($q$select pg_temp.record_audit('finalized',pg_temp.audit_payload(),repeat('c',64))$q$,'23505','completion requires a started operation','completion without a start event is rejected');
select throws_ok($q$select pg_temp.record_audit('membership_unavailable',pg_temp.audit_payload(),repeat('c',64))$q$,'23505','failure transition requires a started operation','failure transition without a start event is rejected');
select is((pg_temp.record_audit('finalization_started',pg_temp.audit_payload(),repeat('d',64))->>'replayed'),'false','failure/recovery operation starts cleanly');
select is((pg_temp.record_audit('finalization_failed',pg_temp.audit_payload(),repeat('d',64))->>'replayed'),'false','intermediate failure is recorded without terminalizing operation');
select is((pg_temp.record_audit('finalized',pg_temp.audit_payload(),repeat('d',64))->>'replayed'),'false','successful retry can recover after intermediate failure');

select * from finish();
rollback;