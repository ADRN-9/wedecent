begin;

create extension if not exists pgtap with schema extensions;

select plan(24);

insert into auth.users (id, aud, role, email)
values
    ('11000000-0000-4000-8000-000000000001', 'authenticated', 'authenticated', 'pf-initiator@example.test'),
    ('11000000-0000-4000-8000-000000000002', 'authenticated', 'authenticated', 'pf-destination@example.test');

insert into public.organizations (id, name, slug, created_by)
values ('22000000-0000-4000-8000-000000000001', 'Port Forward Test', 'port-forward-test', '11000000-0000-4000-8000-000000000001');

insert into public.organization_memberships (organization_id, user_id, role, created_by)
values ('22000000-0000-4000-8000-000000000001', '11000000-0000-4000-8000-000000000001', 'member', '11000000-0000-4000-8000-000000000001');

insert into public.devices (device_id, public_key, kind, name, owner_user_id, organization_id)
values
    ('wd_aaaaaaaaaaaaaaaa', repeat('A', 43), 'client', 'Initiator', '11000000-0000-4000-8000-000000000001', '22000000-0000-4000-8000-000000000001'),
    ('wd_bbbbbbbbbbbbbbbb', repeat('B', 43), 'agent', 'Destination', '11000000-0000-4000-8000-000000000002', '22000000-0000-4000-8000-000000000001'),
    ('wd_cccccccccccccccc', repeat('C', 43), 'agent', 'Router', '11000000-0000-4000-8000-000000000002', '22000000-0000-4000-8000-000000000001');

insert into public.device_access (device_id, user_id, permission, granted_by)
values
    ('wd_bbbbbbbbbbbbbbbb', '11000000-0000-4000-8000-000000000001', 'port_forward.local', '11000000-0000-4000-8000-000000000001'),
    ('wd_cccccccccccccccc', '11000000-0000-4000-8000-000000000001', 'mesh.forward', '11000000-0000-4000-8000-000000000001');

insert into public.route_authorization_grants (
    id, jti, user_id, organization_id, source_device_id, router_device_id,
    destination_device_id, first_transport, second_transport, first_cost,
    second_cost, permission, issued_at, expires_at
)
values (
    '33000000-0000-4000-8000-000000000001',
    'RRRRRRRRRRRRRRRRRRRRRR',
    '11000000-0000-4000-8000-000000000001',
    '22000000-0000-4000-8000-000000000001',
    'wd_aaaaaaaaaaaaaaaa',
    'wd_cccccccccccccccc',
    'wd_bbbbbbbbbbbbbbbb',
    'lan', 'lan', 1, 1, 'mesh.forward',
    pg_catalog.clock_timestamp() - interval '5 seconds',
    pg_catalog.clock_timestamp() + interval '90 seconds'
);

create function pg_temp.consume_pf(
    p_device_id text,
    p_forwarding_id uuid,
    p_jti text,
    p_digest_hex text,
    p_routed boolean default true
)
returns jsonb
language sql
as $$
    select public.consume_port_forward_authorization(
        p_device_id,
        (select d.public_key from public.devices d where d.device_id = p_device_id),
        p_forwarding_id,
        'local',
        'wd_aaaaaaaaaaaaaaaa',
        'wd_bbbbbbbbbbbbbbbb',
        case when p_routed then 'wd_cccccccccccccccc' else null end,
        case when p_routed then '33000000-0000-4000-8000-000000000001'::uuid else null end,
        case when p_routed then 'RRRRRRRRRRRRRRRRRRRRRR' else null end,
        case when p_routed then 'wd_aaaaaaaaaaaaaaaa' else null end,
        case when p_routed then 'wd_bbbbbbbbbbbbbbbb' else null end,
        p_jti,
        pg_catalog.clock_timestamp() - interval '1 second',
        pg_catalog.clock_timestamp() + interval '60 seconds',
        pg_catalog.decode(p_digest_hex, 'hex')
    );
$$;

select ok(
    (select c.relrowsecurity from pg_catalog.pg_class c join pg_catalog.pg_namespace n on n.oid = c.relnamespace where n.nspname = 'public' and c.relname = 'port_forward_authorization_transactions'),
    'authorization transaction ledger has RLS enabled'
);
select ok(
    not pg_catalog.has_table_privilege('service_role', 'public.port_forward_authorization_transactions', 'SELECT,INSERT,UPDATE,DELETE'),
    'service_role cannot directly rewrite transaction snapshots'
);
select ok(
    not pg_catalog.has_function_privilege('authenticated', 'public.consume_port_forward_authorization(text,text,uuid,text,text,text,text,uuid,text,text,text,text,timestamp with time zone,timestamp with time zone,bytea)', 'EXECUTE'),
    'authenticated cannot call atomic replay RPC'
);
select ok(
    pg_catalog.has_function_privilege('service_role', 'public.consume_port_forward_authorization(text,text,uuid,text,text,text,text,uuid,text,text,text,text,timestamp with time zone,timestamp with time zone,bytea)', 'EXECUTE'),
    'service_role can call atomic replay RPC'
);

select is(
    (pg_temp.consume_pf('wd_aaaaaaaaaaaaaaaa', '44000000-0000-4000-8000-000000000001', repeat('A', 22), repeat('1', 64))->>'accepted'),
    'true',
    'initiator can consume an authorized routed capability'
);
select is(
    (select count(*)::integer from public.port_forward_authorization_transactions),
    1,
    'one forwarding transaction binds all participants'
);
select is(
    (select generation::integer from public.port_forward_replay_authority where device_id = 'wd_aaaaaaaaaaaaaaaa'),
    1,
    'initiator replay generation advances exactly once'
);
select is(
    (pg_temp.consume_pf('wd_aaaaaaaaaaaaaaaa', '44000000-0000-4000-8000-000000000001', repeat('A', 22), repeat('1', 64))->>'replayed'),
    'true',
    'exact same-device retry is idempotent and does not create another grant'
);
select is(
    (pg_temp.consume_pf('wd_bbbbbbbbbbbbbbbb', '44000000-0000-4000-8000-000000000001', repeat('A', 22), repeat('1', 64))->>'accepted'),
    'true',
    'destination endpoint consumes the same signed forwarding transaction'
);
select is(
    (select count(*)::integer from public.port_forward_replay_entries where jti = repeat('A', 22)),
    2,
    'both endpoint replay receipts share one authorization transaction'
);
select is(
    (pg_temp.consume_pf('wd_aaaaaaaaaaaaaaaa', '44000000-0000-4000-8000-000000000001', repeat('A', 22), repeat('2', 64))->>'reason'),
    'idempotency-conflict',
    'same forwarding id with a different authorization digest is rejected'
);
select is(
    (pg_temp.consume_pf('wd_aaaaaaaaaaaaaaaa', '44000000-0000-4000-8000-000000000002', repeat('A', 22), repeat('1', 64))->>'reason'),
    'jti-conflict',
    'same JTI cannot be rebound to another forwarding transaction'
);

update public.organization_memberships
   set role = 'admin'
 where organization_id = '22000000-0000-4000-8000-000000000001'
   and user_id = '11000000-0000-4000-8000-000000000001';
select ok(
    (select revocation_epoch > 0 from public.devices where device_id = 'wd_aaaaaaaaaaaaaaaa'),
    'membership permission changes advance participant revocation epochs'
);
select is(
    (pg_temp.consume_pf('wd_aaaaaaaaaaaaaaaa', '44000000-0000-4000-8000-000000000001', repeat('A', 22), repeat('1', 64))->>'reason'),
    'idempotency-conflict',
    'retry with a stale membership epoch cannot reuse the previous transaction'
);
update public.organization_memberships
   set role = 'member'
 where organization_id = '22000000-0000-4000-8000-000000000001'
   and user_id = '11000000-0000-4000-8000-000000000001';

delete from public.device_access
 where device_id = 'wd_bbbbbbbbbbbbbbbb'
   and user_id = '11000000-0000-4000-8000-000000000001'
   and permission = 'port_forward.local';
select throws_ok(
    $$select pg_temp.consume_pf('wd_aaaaaaaaaaaaaaaa', '44000000-0000-4000-8000-000000000003', repeat('B', 22), repeat('3', 64))$$,
    '42501',
    'port-forward destination permission is not granted',
    'revoked destination access grant blocks new consumption'
);
insert into public.device_access (device_id, user_id, permission, granted_by)
values ('wd_bbbbbbbbbbbbbbbb', '11000000-0000-4000-8000-000000000001', 'port_forward.local', '11000000-0000-4000-8000-000000000001');

delete from public.organization_memberships
 where organization_id = '22000000-0000-4000-8000-000000000001'
   and user_id = '11000000-0000-4000-8000-000000000001';
select throws_ok(
    $$select pg_temp.consume_pf('wd_aaaaaaaaaaaaaaaa', '44000000-0000-4000-8000-000000000004', repeat('C', 22), repeat('4', 64))$$,
    '42501',
    'initiating organization membership is missing',
    'missing initiating organization membership fails closed'
);
insert into public.organization_memberships (organization_id, user_id, role, created_by)
values ('22000000-0000-4000-8000-000000000001', '11000000-0000-4000-8000-000000000001', 'member', '11000000-0000-4000-8000-000000000001');

update public.devices set revoked_at = pg_catalog.clock_timestamp()
 where device_id = 'wd_aaaaaaaaaaaaaaaa';
select throws_ok(
    $$select pg_temp.consume_pf('wd_aaaaaaaaaaaaaaaa', '44000000-0000-4000-8000-000000000005', repeat('D', 22), repeat('5', 64))$$,
    '42501',
    'port-forward participant is revoked',
    'revoked initiator cannot consume authorization'
);
update public.devices set revoked_at = null where device_id = 'wd_aaaaaaaaaaaaaaaa';

update public.devices set revoked_at = pg_catalog.clock_timestamp()
 where device_id = 'wd_bbbbbbbbbbbbbbbb';
select throws_ok(
    $$select pg_temp.consume_pf('wd_aaaaaaaaaaaaaaaa', '44000000-0000-4000-8000-000000000006', repeat('E', 22), repeat('6', 64))$$,
    '42501',
    'port-forward participant is revoked',
    'revoked destination cannot consume authorization'
);
update public.devices set revoked_at = null where device_id = 'wd_bbbbbbbbbbbbbbbb';

update public.devices set revoked_at = pg_catalog.clock_timestamp()
 where device_id = 'wd_cccccccccccccccc';
select throws_ok(
    $$select pg_temp.consume_pf('wd_aaaaaaaaaaaaaaaa', '44000000-0000-4000-8000-000000000007', repeat('F', 22), repeat('7', 64))$$,
    '42501',
    'port-forward participant is revoked',
    'revoked router cannot consume authorization'
);
update public.devices set revoked_at = null where device_id = 'wd_cccccccccccccccc';

update public.route_authorization_grants
   set revoked_at = pg_catalog.clock_timestamp()
 where id = '33000000-0000-4000-8000-000000000001';
select throws_ok(
    $$select pg_temp.consume_pf('wd_aaaaaaaaaaaaaaaa', '44000000-0000-4000-8000-000000000008', repeat('G', 22), repeat('8', 64))$$,
    '42501',
    'router authorization is missing, revoked or mismatched',
    'revoked independent router authorization blocks forwarding'
);
update public.route_authorization_grants
   set revoked_at = null
 where id = '33000000-0000-4000-8000-000000000001';

select throws_ok(
    $$select pg_temp.consume_pf('wd_cccccccccccccccc', '44000000-0000-4000-8000-000000000009', repeat('H', 22), repeat('9', 64))$$,
    '42501',
    'port-forward participant mismatch',
    'router cannot impersonate an endpoint replay proof'
);
select throws_ok(
    $$select public.consume_port_forward_authorization('wd_aaaaaaaaaaaaaaaa', repeat('Z', 43), '44000000-0000-4000-8000-000000000010', 'local', 'wd_aaaaaaaaaaaaaaaa', 'wd_dddddddddddddddd', null, null, null, null, null, repeat('I', 22), pg_catalog.clock_timestamp(), pg_catalog.clock_timestamp() + interval '60 seconds', pg_catalog.decode(repeat('a', 64), 'hex'))$$,
    '42501',
    'destination device is not enrolled',
    'missing destination record fails closed'
);

savepoint interrupted_consume;
select pg_temp.consume_pf('wd_aaaaaaaaaaaaaaaa', '44000000-0000-4000-8000-000000000011', repeat('J', 22), repeat('a', 64));
rollback to savepoint interrupted_consume;
select is(
    (pg_temp.consume_pf('wd_aaaaaaaaaaaaaaaa', '44000000-0000-4000-8000-000000000011', repeat('J', 22), repeat('a', 64))->>'accepted'),
    'true',
    'rolled-back interrupted consumption leaves no partial authorization or JTI'
);

select is(
    (pg_temp.consume_pf('wd_aaaaaaaaaaaaaaaa', '44000000-0000-4000-8000-000000000012', repeat('K', 22), repeat('b', 64), false)->>'accepted'),
    'true',
    'direct forwarding does not require router authority'
);

select * from finish();

rollback;
