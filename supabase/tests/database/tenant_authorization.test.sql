begin;

create extension if not exists pgtap with schema extensions;

select plan(30);

insert into auth.users (id, aud, role, email)
values
    ('10000000-0000-4000-8000-000000000001', 'authenticated', 'authenticated', 'former-creator@example.test'),
    ('10000000-0000-4000-8000-000000000002', 'authenticated', 'authenticated', 'org-a-owner@example.test'),
    ('10000000-0000-4000-8000-000000000003', 'authenticated', 'authenticated', 'org-b-owner@example.test');

insert into public.organizations (id, name, slug, created_by)
values
    ('20000000-0000-4000-8000-000000000001', 'Organization A', 'tenant-a', '10000000-0000-4000-8000-000000000001'),
    ('20000000-0000-4000-8000-000000000002', 'Organization B', 'tenant-b', '10000000-0000-4000-8000-000000000003');

-- Organization creation triggers create the creator's first owner membership.
insert into public.organization_memberships (organization_id, user_id, role, created_by)
values (
    '20000000-0000-4000-8000-000000000001',
    '10000000-0000-4000-8000-000000000002',
    'owner',
    '10000000-0000-4000-8000-000000000001'
);

insert into public.devices (
    device_id, public_key, kind, name, owner_user_id, organization_id
)
values
    ('wd_aaaaaaaaaaaaaaaa', repeat('A', 43), 'client', 'A client', '10000000-0000-4000-8000-000000000001', '20000000-0000-4000-8000-000000000001'),
    ('wd_bbbbbbbbbbbbbbbb', repeat('B', 43), 'agent', 'B target', '10000000-0000-4000-8000-000000000003', '20000000-0000-4000-8000-000000000002'),
    ('wd_cccccccccccccccc', repeat('C', 43), 'client', 'B client', '10000000-0000-4000-8000-000000000003', '20000000-0000-4000-8000-000000000002');

insert into public.connection_grants (
    user_id, organization_id, client_device_id, target_device_id, expires_at
)
values (
    '10000000-0000-4000-8000-000000000003',
    '20000000-0000-4000-8000-000000000002',
    'wd_cccccccccccccccc',
    'wd_bbbbbbbbbbbbbbbb',
    now() + interval '60 seconds'
);

-- Simulate a creator who was removed after a second owner was established.
delete from public.organization_memberships
where organization_id = '20000000-0000-4000-8000-000000000001'
  and user_id = '10000000-0000-4000-8000-000000000001';

insert into public.device_enrollment_challenges (
    id, user_id, device_id, challenge_sha256, expires_at
)
values
    ('30000000-0000-4000-8000-000000000001', '10000000-0000-4000-8000-000000000001', 'wd_aaaaaaaaaaaaaaaa', decode(repeat('00', 32), 'hex'), now() + interval '5 minutes'),
    ('30000000-0000-4000-8000-000000000002', '10000000-0000-4000-8000-000000000001', 'wd_dddddddddddddddd', decode(repeat('00', 32), 'hex'), now() + interval '5 minutes'),
    ('30000000-0000-4000-8000-000000000003', '10000000-0000-4000-8000-000000000002', 'wd_eeeeeeeeeeeeeeee', decode(repeat('00', 32), 'hex'), now() + interval '5 minutes'),
    ('30000000-0000-4000-8000-000000000004', '10000000-0000-4000-8000-000000000001', 'wd_aaaaaaaaaaaaaaaa', decode(repeat('00', 32), 'hex'), now() + interval '5 minutes'),
    ('30000000-0000-4000-8000-000000000005', '10000000-0000-4000-8000-000000000001', 'wd_ffffffffffffffff', decode(repeat('00', 32), 'hex'), now() + interval '5 minutes');

select ok(
    not pg_catalog.has_table_privilege(
        'authenticated',
        'public.route_authorization_grants',
        'SELECT'
    ),
    'authenticated users cannot read server-only route authorization grants'
);

select ok(
    not pg_catalog.has_function_privilege(
        'anon',
        'public.complete_device_enrollment(uuid, uuid, text, text, public.device_kind, text, uuid, text)',
        'EXECUTE'
    ),
    'anonymous users cannot execute device enrollment'
);

select ok(
    not pg_catalog.has_function_privilege(
        'authenticated',
        'public.complete_device_enrollment(uuid, uuid, text, text, public.device_kind, text, uuid, text)',
        'EXECUTE'
    ),
    'authenticated users cannot execute device enrollment'
);

select ok(
    pg_catalog.has_function_privilege(
        'service_role',
        'public.complete_device_enrollment(uuid, uuid, text, text, public.device_kind, text, uuid, text)',
        'EXECUTE'
    ),
    'service role can execute device enrollment'
);

set local role authenticated;
select set_config('request.jwt.claim.sub', '10000000-0000-4000-8000-000000000001', true);

select is(
    (select count(*)::bigint from public.organizations where id = '20000000-0000-4000-8000-000000000001'),
    0::bigint,
    'former creator cannot read an organization after membership removal'
);

select is(
    (select count(*)::bigint from public.organizations where id = '20000000-0000-4000-8000-000000000002'),
    0::bigint,
    'user cannot read another organization'
);

select is(
    (select count(*)::bigint from public.devices where device_id = 'wd_bbbbbbbbbbbbbbbb'),
    0::bigint,
    'user cannot read another organization device'
);

select is(
    (select count(*)::bigint from public.organization_memberships where organization_id = '20000000-0000-4000-8000-000000000002'),
    0::bigint,
    'user cannot enumerate another organization membership'
);

select is(
    (select count(*)::bigint from public.device_access where device_id = 'wd_bbbbbbbbbbbbbbbb'),
    0::bigint,
    'user cannot inspect another organization device-access grants'
);

select is(
    (select count(*)::bigint from public.connection_grants),
    0::bigint,
    'user cannot read another user connection-grant audit records'
);

update public.organizations
   set name = 'Unauthorized rename'
 where id = '20000000-0000-4000-8000-000000000001';

delete from public.organizations
 where id = '20000000-0000-4000-8000-000000000001';

reset role;

select is(
    (select name from public.organizations where id = '20000000-0000-4000-8000-000000000001'),
    'Organization A',
    'former creator cannot update organization metadata'
);

select is(
    (select count(*)::bigint from public.organizations where id = '20000000-0000-4000-8000-000000000001'),
    1::bigint,
    'former creator cannot delete an organization'
);

set local role authenticated;
select set_config('request.jwt.claim.sub', '10000000-0000-4000-8000-000000000001', true);

select throws_ok(
    $$
        insert into public.organization_memberships (
            organization_id, user_id, role, created_by
        )
        values (
            '20000000-0000-4000-8000-000000000002',
            '10000000-0000-4000-8000-000000000001',
            'member',
            '10000000-0000-4000-8000-000000000001'
        )
    $$,
    '42501',
    'new row violates row-level security policy for table "organization_memberships"',
    'former creator cannot add members to another organization'
);

select throws_ok(
    $$
        insert into public.device_access (
            device_id, user_id, permission, granted_by
        )
        values (
            'wd_bbbbbbbbbbbbbbbb',
            '10000000-0000-4000-8000-000000000001',
            'terminal.connect',
            '10000000-0000-4000-8000-000000000001'
        )
    $$,
    '42501',
    'new row violates row-level security policy for table "device_access"',
    'former creator cannot grant access to another organization device'
);

select is(
    (select count(*)::bigint from public.devices where device_id = 'wd_aaaaaaaaaaaaaaaa'),
    1::bigint,
    'device owner retains the documented direct ownership visibility path'
);

reset role;
set local role service_role;

insert into public.organization_memberships (
    organization_id, user_id, role, created_by
)
values (
    '20000000-0000-4000-8000-000000000001',
    '10000000-0000-4000-8000-000000000001',
    'member',
    '10000000-0000-4000-8000-000000000002'
);

select throws_ok(
    $
        select public.issue_connection_grant(
            '10000000-0000-4000-8000-000000000001',
            'wd_aaaaaaaaaaaaaaaa',
            'wd_bbbbbbbbbbbbbbbb'
        )
    $$,
    '42501',
    'terminal connection is not authorized',
    'connection grant issuer denies a cross-organization target without membership or explicit access'
);

select throws_ok(
    $$
        select public.complete_device_enrollment(
            '30000000-0000-4000-8000-000000000001',
            '10000000-0000-4000-8000-000000000001',
            'wd_aaaaaaaaaaaaaaaa',
            repeat('A', 43),
            'client',
            'A client',
            null,
            repeat('00', 32)
        )
    $$,
    '42501',
    'device organization reassignment is not authorized',
    'former organization member cannot unassign an organization device during enrollment'
);

select throws_ok(
    $$
        select public.complete_device_enrollment(
            '30000000-0000-4000-8000-000000000004',
            '10000000-0000-4000-8000-000000000001',
            'wd_aaaaaaaaaaaaaaaa',
            null,
            'client',
            'A client',
            null,
            repeat('00', 32)
        )
    $$,
    '22023',
    'invalid enrollment parameters',
    'enrollment RPC rejects a missing public key before changing device or challenge state'
);

select is(
    (
        select count(*)::bigint
          from public.device_enrollment_challenges
         where id = '30000000-0000-4000-8000-000000000004'
           and consumed_at is null
    ),
    1::bigint,
    'malformed enrollment input does not consume the one-time challenge'
);

select throws_ok(
    $
        select public.complete_device_enrollment(
            '30000000-0000-4000-8000-000000000005',
            '10000000-0000-4000-8000-000000000001',
            'wd_ffffffffffffffff',
            repeat('F', 43),
            'client',
            'Member device',
            '20000000-0000-4000-8000-000000000001',
            repeat('00', 32)
        )
    $,
    '42501',
    'target organization enrollment is not authorized',
    'ordinary organization member cannot enroll a device into the organization'
);

select throws_ok(
    $
        select public.complete_device_enrollment(
            '30000000-0000-4000-8000-000000000002',
            '10000000-0000-4000-8000-000000000001',
            'wd_dddddddddddddddd',
            repeat('D', 43),
            'agent',
            'Unauthorized device',
            '20000000-0000-4000-8000-000000000002',
            repeat('00', 32)
        )
    $$,
    '42501',
    'target organization enrollment is not authorized',
    'enrollment RPC rejects a client-supplied organization without current owner or admin membership'
);

select lives_ok(
    $$
        select public.complete_device_enrollment(
            '30000000-0000-4000-8000-000000000003',
            '10000000-0000-4000-8000-000000000002',
            'wd_eeeeeeeeeeeeeeee',
            repeat('E', 43),
            'agent',
            'Authorized device',
            '20000000-0000-4000-8000-000000000001',
            repeat('00', 32)
        )
    $$,
    'current organization owner can enroll a device into that organization'
);

select is(
    (
        select organization_id::text
          from public.devices
         where device_id = 'wd_eeeeeeeeeeeeeeee'
    ),
    '20000000-0000-4000-8000-000000000001',
    'successful enrollment records the authorized organization'
);

reset role;
set local role authenticated;
select set_config('request.jwt.claim.sub', '10000000-0000-4000-8000-000000000003', true);

select is(
    (select count(*)::bigint from public.organizations where id = '20000000-0000-4000-8000-000000000002'),
    1::bigint,
    'organization owner can read their own organization'
);

select is(
    (select count(*)::bigint from public.organizations where id = '20000000-0000-4000-8000-000000000001'),
    0::bigint,
    'organization owner cannot read another organization'
);

select is(
    (select count(*)::bigint from public.devices where device_id = 'wd_bbbbbbbbbbbbbbbb'),
    1::bigint,
    'organization owner can read their own organization device'
);

select is(
    (select count(*)::bigint from public.devices where device_id = 'wd_aaaaaaaaaaaaaaaa'),
    0::bigint,
    'organization owner cannot read a device owned by another tenant'
);

select is(
    (select count(*)::bigint from public.connection_grants),
    1::bigint,
    'user can read their own connection-grant audit record'
);

select throws_ok(
    $$
        insert into public.organization_memberships (
            organization_id, user_id, role, created_by
        )
        values (
            '20000000-0000-4000-8000-000000000001',
            '10000000-0000-4000-8000-000000000003',
            'member',
            '10000000-0000-4000-8000-000000000003'
        )
    $$,
    '42501',
    'new row violates row-level security policy for table "organization_memberships"',
    'organization owner cannot administer another organization memberships'
);

update public.organizations
   set name = 'Cross-tenant rename'
 where id = '20000000-0000-4000-8000-000000000001';

reset role;

select is(
    (select name from public.organizations where id = '20000000-0000-4000-8000-000000000001'),
    'Organization A',
    'organization owner cannot update another organization'
);

select * from finish();
rollback;
