begin;
create extension if not exists pgtap with schema extensions;
select plan(35);
select is(wedecent_private.canonical_jsonb('{"n":-9007199254740991}'::jsonb),'{"n":-9007199254740991}','canonical JSON preserves minimum JavaScript safe integer');
select is(wedecent_private.canonical_jsonb('{"n":9007199254740991}'::jsonb),'{"n":9007199254740991}','canonical JSON preserves maximum JavaScript safe integer');
select is(wedecent_private.canonical_jsonb('{"z":[0,1,-1,9007199254740991],"a":{"b":true,"n":-9007199254740991,"s":"ok"}}'::jsonb),'{"a":{"b":true,"n":-9007199254740991,"s":"ok"},"z":[0,1,-1,9007199254740991]}','canonical JSON sorts nested keys and preserves array numeric boundaries');
select is(wedecent_private.canonical_jsonb(E'{"~key":[null,false,{"a/b":"x\\ny"}],"a":2}'::jsonb),E'{"a":2,"~key":[null,false,{"a/b":"x\\ny"}]}','canonical JSON preserves escaped strings and array ordering');

select is(
 wedecent_private.canonical_jsonb('{"a":1,"b":"vector","device":{"id":"wd_vyqwylxver5dpawb","epoch":3},"nil":null}'::jsonb),
 '{"a":1,"b":"vector","device":{"epoch":3,"id":"wd_vyqwylxver5dpawb"},"nil":null}',
 'SQL canonical JSON matches shared Go and TypeScript vector'
);
select is(
 encode(extensions.digest(convert_to(wedecent_private.canonical_jsonb('{"a":1,"b":"vector","device":{"id":"wd_vyqwylxver5dpawb","epoch":3},"nil":null}'::jsonb),'UTF8'),'sha256'),'hex'),
 '624ae53f22de418876cf22927cd32407b01c39bd63adc1f8095dc15301cc22dd',
 'SQL canonical payload digest matches shared Go and TypeScript vector'
);
select throws_ok($q$select wedecent_private.canonical_jsonb('{"n":9007199254740992}'::jsonb)$q$,'22023','unsafe canonical JSON number','SQL canonical JSON rejects unsafe integers');
select throws_ok($q$select wedecent_private.canonical_jsonb('{"n":1.5}'::jsonb)$q$,'22023','unsafe canonical JSON number','SQL canonical JSON rejects fractional numbers');

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
('wd_bbbbbbbbbbbbbbbb',repeat('B',43),'agent','Audit destination','11000000-0000-4000-8000-000000000092','22000000-0000-4000-8000-000000000091',1),
('wd_cccccccccccccccc',repeat('C',43),'agent','Audit router','11000000-0000-4000-8000-000000000092','22000000-0000-4000-8000-000000000091',1);

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

insert into public.route_authorization_grants(
 id,jti,user_id,organization_id,source_device_id,router_device_id,destination_device_id,
 first_transport,second_transport,first_cost,second_cost,permission,issued_at,expires_at
) values (
 '55000000-0000-4000-8000-000000000091','BBBBBBBBBBBBBBBBBBBBBB',
 '11000000-0000-4000-8000-000000000091','22000000-0000-4000-8000-000000000091',
 'wd_aaaaaaaaaaaaaaaa','wd_cccccccccccccccc','wd_bbbbbbbbbbbbbbbb',
 'lan','lan',1,1,'mesh.forward',clock_timestamp()-interval '5 seconds',clock_timestamp()+interval '90 seconds'
);

insert into public.port_forward_authorization_transactions(
 forwarding_id,jti,authorization_sha256,permission,direction,
 initiating_device_id,destination_device_id,router_device_id,
 initiator_account_id,destination_account_id,router_account_id,
 initiator_organization_id,destination_organization_id,router_organization_id,
 initiator_revocation_epoch,destination_revocation_epoch,router_revocation_epoch,
 route_authorization_id,route_authorization_jti,issued_at,expires_at
) values(
 '44000000-0000-4000-8000-000000000092','BBBBBBBBBBBBBBBBBBBBBB',decode(repeat('b',64),'hex'),
 'port_forward.local','local','wd_aaaaaaaaaaaaaaaa','wd_bbbbbbbbbbbbbbbb','wd_cccccccccccccccc',
 '11000000-0000-4000-8000-000000000091','11000000-0000-4000-8000-000000000092','11000000-0000-4000-8000-000000000092',
 '22000000-0000-4000-8000-000000000091','22000000-0000-4000-8000-000000000091','22000000-0000-4000-8000-000000000091',
 1,1,1,'55000000-0000-4000-8000-000000000091','BBBBBBBBBBBBBBBBBBBBBB',
 clock_timestamp()-interval '5 seconds',clock_timestamp()+interval '60 seconds'
);

create function pg_temp.audit_payload(p_signature text default repeat('A',86)||'==') returns jsonb
language sql as $$
select jsonb_build_object(
 'version',1,
 'initiator',jsonb_build_object('device_id','wd_aaaaaaaaaaaaaaaa','account_id','11000000-0000-4000-8000-000000000091','organization_id','22000000-0000-4000-8000-000000000091','revocation_epoch',1),
 'destination',jsonb_build_object('device_id','wd_bbbbbbbbbbbbbbbb','account_id','11000000-0000-4000-8000-000000000092','organization_id','22000000-0000-4000-8000-000000000091','revocation_epoch',1),
 'router',null,'consuming_device_id','wd_aaaaaaaaaaaaaaaa','jti','AAAAAAAAAAAAAAAAAAAAAA',
 'authorization_sha256',repeat('a',64),'route_authorization_sha256',repeat('0',64),
 'route_authorization_id','','route_authorization_jti','','route_authorization_json',
 'device_public_key',repeat('A',43)||'=','device_signature',p_signature
)
$$;

create function pg_temp.audit_route_payload() returns jsonb
language sql as $q$
select jsonb_build_object(
 'version',1,
 'initiator',jsonb_build_object('device_id','wd_aaaaaaaaaaaaaaaa','account_id','11000000-0000-4000-8000-000000000091','organization_id','22000000-0000-4000-8000-000000000091','revocation_epoch',1),
 'destination',jsonb_build_object('device_id','wd_bbbbbbbbbbbbbbbb','account_id','11000000-0000-4000-8000-000000000092','organization_id','22000000-0000-4000-8000-000000000091','revocation_epoch',1),
 'router',jsonb_build_object('device_id','wd_cccccccccccccccc','account_id','11000000-0000-4000-8000-000000000092','organization_id','22000000-0000-4000-8000-000000000091','revocation_epoch',1),
 'consuming_device_id','wd_aaaaaaaaaaaaaaaa','jti','BBBBBBBBBBBBBBBBBBBBBB',
 'authorization_sha256',repeat('b',64),'route_authorization_sha256',repeat('c',64),
 'route_authorization_id','55000000-0000-4000-8000-000000000091',
 'route_authorization_jti','BBBBBBBBBBBBBBBBBBBBBB',
 'route_authorization_json','{"route":"signed"}',
 'device_public_key',repeat('A',43)||'=','device_signature',repeat('A',86)||'=='
)
$q$;

create function pg_temp.audit_evidence(p_outcome text) returns jsonb
language sql immutable as $q$
select case when p_outcome in ('finalized','rejected_revocation')
 then '{"primary_receipt":{},"witness_acknowledgements":[],"revocation_proofs":[]}'::jsonb
 else '{}'::jsonb end
$q$;

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
select throws_ok($$select pg_temp.record_audit('finalization_started',pg_temp.audit_payload(repeat('B',86)||'=='))$$,'23505','operation payload conflict','conflicting payload for an existing operation is rejected');
select is((pg_temp.record_audit('finalized',pg_temp.audit_payload())->>'replayed'),'false','terminal finalization transition is recorded');
select is((pg_temp.record_audit('finalized',pg_temp.audit_payload())->>'replayed'),'true','exact terminal retry returns the original evidence record');
select throws_ok($q$select public.record_checkpoint_finalization(
 repeat('a',64),'finalized',1,pg_temp.audit_payload(),
 extensions.digest(convert_to(wedecent_private.canonical_jsonb(pg_temp.audit_payload()),'UTF8'),'sha256'),
 '{"primary_receipt":{"tampered":true},"witness_acknowledgements":[],"revocation_proofs":[]}'::jsonb,
 extensions.digest(convert_to(wedecent_private.canonical_jsonb('{"primary_receipt":{"tampered":true},"witness_acknowledgements":[],"revocation_proofs":[]}'::jsonb),'UTF8'),'sha256'),
 '11000000-0000-4000-8000-000000000091'
)$q$,'23505','outcome conflict','same terminal outcome with different proof evidence is rejected');
select throws_ok($$select pg_temp.record_audit('rejected_revocation',pg_temp.audit_payload())$$,'23505','contradictory terminal outcome','contradictory terminal outcome is rejected atomically');
select throws_ok($$select pg_temp.record_audit('finalization_failed',pg_temp.audit_payload())$$,'23505','contradictory terminal outcome','no intermediate transition is appended after terminal completion');
select is((select count(*)::integer from public.checkpoint_finalization_audit where operation_id=repeat('a',64) and outcome in('finalized','rejected_revocation')),1,'only one terminal outcome exists per operation');
select throws_ok($q$select pg_temp.record_audit('finalized',pg_temp.audit_payload(),repeat('c',64))$q$,'23505','completion requires a started operation','completion without a start event is rejected');
select throws_ok($q$select pg_temp.record_audit('membership_unavailable',pg_temp.audit_payload(),repeat('c',64))$q$,'23505','failure transition requires a started operation','failure transition without a start event is rejected');
select is((pg_temp.record_audit('finalization_started',pg_temp.audit_payload(),repeat('d',64))->>'replayed'),'false','failure/recovery operation starts cleanly');
select is((pg_temp.record_audit('finalization_failed',pg_temp.audit_payload(),repeat('d',64))->>'replayed'),'false','intermediate failure is recorded without terminalizing operation');
select is((pg_temp.record_audit('finalized',pg_temp.audit_payload(),repeat('d',64))->>'replayed'),'false','successful retry can recover after intermediate failure');

select is((pg_temp.record_audit('finalization_started',pg_temp.audit_route_payload(),repeat('g',64))->>'replayed'),'false','routed operation binds stored route grant and router identities');
update public.route_authorization_grants set revoked_at=clock_timestamp()
 where id='55000000-0000-4000-8000-000000000091';
select throws_ok($q$select pg_temp.record_audit('finalized',pg_temp.audit_route_payload(),repeat('g',64))$q$,'42501','stored route authorization is unavailable or mismatched','revoked route grant blocks finalization');
update public.route_authorization_grants set revoked_at=null
 where id='55000000-0000-4000-8000-000000000091';

delete from public.organization_memberships
 where organization_id='22000000-0000-4000-8000-000000000091'
   and user_id='11000000-0000-4000-8000-000000000092';
select throws_ok($q$select pg_temp.record_audit('finalization_started',pg_temp.audit_payload(),repeat('e',64))$q$,'42501','audit participant membership is unavailable','destination membership revocation blocks audit');
insert into public.organization_memberships(organization_id,user_id,role,created_by)
values('22000000-0000-4000-8000-000000000091','11000000-0000-4000-8000-000000000092','member','11000000-0000-4000-8000-000000000091');

update public.devices set revocation_epoch=2 where device_id='wd_bbbbbbbbbbbbbbbb';
select throws_ok($q$select pg_temp.record_audit('finalization_started',pg_temp.audit_payload(),repeat('f',64))$q$,'42501','destination device membership or revocation changed','current device revocation epoch mismatch blocks audit');
update public.devices set revocation_epoch=1 where device_id='wd_bbbbbbbbbbbbbbbb';

select * from finish();
rollback;