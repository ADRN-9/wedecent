begin;

create extension if not exists pgtap with schema extensions;

select plan(87);

insert into auth.users (id, aud, role, email)
values
    ('71000000-0000-4000-8000-000000000001', 'authenticated', 'authenticated', 'wd-access-owner@example.test'),
    ('71000000-0000-4000-8000-000000000002', 'authenticated', 'authenticated', 'wd-access-admin@example.test'),
    ('71000000-0000-4000-8000-000000000003', 'authenticated', 'authenticated', 'wd-access-member@example.test'),
    ('71000000-0000-4000-8000-000000000004', 'authenticated', 'authenticated', 'wd-access-grantee@example.test'),
    ('71000000-0000-4000-8000-000000000005', 'authenticated', 'authenticated', 'wd-access-other-owner@example.test'),
    ('71000000-0000-4000-8000-000000000006', 'authenticated', 'authenticated', 'wd-access-device-owner@example.test'),
    ('71000000-0000-4000-8000-000000000007', 'authenticated', 'authenticated', 'wd-access-spare@example.test'),
    ('71000000-0000-4000-8000-000000000008', 'authenticated', 'authenticated', 'wd-access-spare-two@example.test');

insert into public.organizations (id, name, slug, created_by)
values
    ('72000000-0000-4000-8000-000000000001', 'Device Access Organization A', 'wd-access-tenant-a', '71000000-0000-4000-8000-000000000001'),
    ('72000000-0000-4000-8000-000000000002', 'Device Access Organization B', 'wd-access-tenant-b', '71000000-0000-4000-8000-000000000005');

insert into public.organization_memberships (
    organization_id, user_id, role, created_by
)
values
    ('72000000-0000-4000-8000-000000000001', '71000000-0000-4000-8000-000000000002', 'admin', '71000000-0000-4000-8000-000000000001'),
    ('72000000-0000-4000-8000-000000000001', '71000000-0000-4000-8000-000000000003', 'member', '71000000-0000-4000-8000-000000000001');

insert into public.devices (
    device_id, public_key, kind, name, owner_user_id, organization_id, revoked_at
)
values
    ('wd_aaaaaaaaaaaaaaaa', repeat('A', 43), 'agent', 'Device Access A', '71000000-0000-4000-8000-000000000006', '72000000-0000-4000-8000-000000000001', null),
    ('wd_bbbbbbbbbbbbbbbb', repeat('B', 43), 'agent', 'Device Access B', '71000000-0000-4000-8000-000000000005', '72000000-0000-4000-8000-000000000002', null),
    ('wd_cccccccccccccccc', repeat('C', 43), 'agent', 'Revoked Device', '71000000-0000-4000-8000-000000000006', '72000000-0000-4000-8000-000000000001', now()),
    ('wd_dddddddddddddddd', repeat('D', 43), 'agent', 'Unassigned Device', '71000000-0000-4000-8000-000000000006', null, null);

-- A deliberately expired row verifies that expiry is checked after the grant
-- row is locked and that expired grants can still be explicitly revoked.
insert into public.device_access (
    device_id, user_id, permission, granted_by, created_at, expires_at
)
values (
    'wd_aaaaaaaaaaaaaaaa',
    '71000000-0000-4000-8000-000000000007',
    'terminal.connect',
    '71000000-0000-4000-8000-000000000001',
    now() - interval '5 minutes',
    now() - interval '1 minute'
);

-- Existing permanent routing grant and stale grant on a revoked device are
-- retained until an authorized manager explicitly changes or removes them.
insert into public.device_access (
    device_id, user_id, permission, granted_by, created_at, expires_at
)
values
    (
        'wd_aaaaaaaaaaaaaaaa',
        '71000000-0000-4000-8000-000000000007',
        'mesh.forward',
        '71000000-0000-4000-8000-000000000001',
        now() - interval '5 minutes',
        null
    ),
    (
        'wd_cccccccccccccccc',
        '71000000-0000-4000-8000-000000000004',
        'mesh.forward',
        '71000000-0000-4000-8000-000000000001',
        now() - interval '5 minutes',
        null
    );

select ok(
    (select c.relrowsecurity
       from pg_catalog.pg_class as c
       join pg_catalog.pg_namespace as n on n.oid = c.relnamespace
      where n.nspname = 'public' and c.relname = 'device_access'),
    'device_access remains protected by RLS'
);

select ok(
    not pg_catalog.has_table_privilege('authenticated', 'public.device_access', 'INSERT'),
    'authenticated cannot insert device_access rows directly'
);

select ok(
    not pg_catalog.has_table_privilege('authenticated', 'public.device_access', 'UPDATE'),
    'authenticated cannot update device_access rows directly'
);

select ok(
    not pg_catalog.has_table_privilege('authenticated', 'public.device_access', 'DELETE'),
    'authenticated cannot delete device_access rows directly'
);

select ok(
    pg_catalog.has_table_privilege('authenticated', 'public.device_access', 'SELECT'),
    'authenticated retains RLS-filtered device_access reads'
);

select ok(
    not pg_catalog.has_column_privilege('authenticated', 'public.device_access', 'granted_by', 'INSERT'),
    'authenticated has no column-level granted_by insert privilege'
);

select ok(
    not pg_catalog.has_column_privilege('authenticated', 'public.device_access', 'expires_at', 'UPDATE'),
    'authenticated has no column-level expiry update privilege'
);

select ok(
    not pg_catalog.has_table_privilege('service_role', 'public.device_access', 'INSERT')
    and not pg_catalog.has_table_privilege('service_role', 'public.device_access', 'UPDATE')
    and not pg_catalog.has_table_privilege('service_role', 'public.device_access', 'DELETE'),
    'service_role has no direct device_access write privileges'
);

select ok(
    pg_catalog.has_table_privilege('service_role', 'public.device_access', 'SELECT'),
    'service_role retains read-only device_access access'
);

select ok(
    not pg_catalog.has_table_privilege('anon', 'public.device_access', 'SELECT'),
    'anon cannot read device_access'
);

select is(
    (
        select count(*)::bigint
          from pg_catalog.pg_policies
         where schemaname = 'public'
           and tablename = 'device_access'
           and policyname in (
               'device_access_insert_manager',
               'device_access_update_manager',
               'device_access_delete_manager'
           )
    ),
    0::bigint,
    'obsolete direct-write RLS policies are removed'
);

select is(
    (
        select count(*)::bigint
          from pg_catalog.pg_proc as p
          join pg_catalog.pg_namespace as n on n.oid = p.pronamespace
         where n.nspname = 'public'
           and p.proname in (
               'create_device_access_grant',
               'update_device_access_grant_expiry',
               'revoke_device_access_grant'
           )
           and p.prosecdef
    ),
    3::bigint,
    'all device-access RPCs are SECURITY DEFINER'
);

select is(
    (
        select count(*)::bigint
          from pg_catalog.pg_proc as p
          join pg_catalog.pg_namespace as n on n.oid = p.pronamespace
         where n.nspname = 'public'
           and p.proname in (
               'create_device_access_grant',
               'update_device_access_grant_expiry',
               'revoke_device_access_grant'
           )
           and pg_catalog.pg_get_userbyid(p.proowner) = 'postgres'
    ),
    3::bigint,
    'all device-access RPCs are owned by the trusted postgres role'
);

select is(
    (
        select count(*)::bigint
          from pg_catalog.pg_proc as p
          join pg_catalog.pg_namespace as n on n.oid = p.pronamespace
         where n.nspname = 'public'
           and p.proname in (
               'create_device_access_grant',
               'update_device_access_grant_expiry',
               'revoke_device_access_grant'
           )
           and coalesce(p.proconfig, array[]::text[]) @> array['search_path=""']::text[]
    ),
    3::bigint,
    'all device-access RPCs pin an empty search_path'
);

select ok(
    pg_catalog.has_table_privilege('postgres', 'public.device_access', 'INSERT')
    and pg_catalog.has_table_privilege('postgres', 'public.device_access', 'UPDATE')
    and pg_catalog.has_table_privilege('postgres', 'public.device_access', 'DELETE'),
    'trusted RPC owner retains the internal table privileges needed to mutate grants'
);

select is(
    (
        select count(*)::bigint
          from pg_catalog.pg_proc as p
         where p.proname in (
             'create_device_access_grant',
             'update_device_access_grant_expiry',
             'revoke_device_access_grant'
         )
           and pg_catalog.has_function_privilege(
               'authenticated',
               p.oid,
               'EXECUTE'
           )
    ),
    3::bigint,
    'authenticated users can execute the three controlled RPCs'
);

select is(
    (
        select count(*)::bigint
          from pg_catalog.pg_proc as p
         where p.proname in (
             'create_device_access_grant',
             'update_device_access_grant_expiry',
             'revoke_device_access_grant'
         )
           and not pg_catalog.has_function_privilege('anon', p.oid, 'EXECUTE')
    ),
    3::bigint,
    'anonymous users cannot execute any device-access RPC'
);

select is(
    (
        select count(*)::bigint
          from pg_catalog.pg_proc as p
         where p.proname in (
             'create_device_access_grant',
             'update_device_access_grant_expiry',
             'revoke_device_access_grant'
         )
           and not pg_catalog.has_function_privilege('service_role', p.oid, 'EXECUTE')
    ),
    3::bigint,
    'service_role cannot bypass authenticated device-access authorization'
);

select ok(
    not pg_catalog.has_function_privilege(
        'authenticated',
        'wedecent_private.lock_device_access_authority(text)',
        'EXECUTE'
    ),
    'authenticated users cannot invoke the internal lock helper'
);

select ok(
    not exists (
        select 1
          from pg_catalog.pg_proc as p
          join pg_catalog.pg_namespace as n on n.oid = p.pronamespace
         where n.nspname = 'public'
           and p.proname in (
               'create_device_access_grant',
               'update_device_access_grant_expiry',
               'revoke_device_access_grant'
           )
           and coalesce(p.proargnames, array[]::text[])
               && array['p_actor_user_id', 'p_granted_by']::text[]
    ),
    'RPC signatures never accept a caller-supplied actor or granted_by'
);

set local role authenticated;
select set_config('request.jwt.claim.role', 'authenticated', true);
select set_config('request.jwt.claim.sub', '71000000-0000-4000-8000-000000000001', true);
select set_config('request.jwt.claims', '{"role":"authenticated","is_anonymous":false}', true);

select throws_ok(
    $$
        insert into public.device_access (
            device_id, user_id, permission, granted_by, expires_at
        )
        values (
            'wd_aaaaaaaaaaaaaaaa',
            '71000000-0000-4000-8000-000000000004',
            'terminal.connect',
            '71000000-0000-4000-8000-000000000001',
            now() + interval '1 minute'
        )
    $$,
    '42501',
    'permission denied for table device_access',
    'direct authenticated INSERT is denied before RLS'
);

select throws_ok(
    $$
        update public.device_access
           set expires_at = now() + interval '2 minutes'
         where device_id = 'wd_aaaaaaaaaaaaaaaa'
           and user_id = '71000000-0000-4000-8000-000000000007'
           and permission = 'terminal.connect'
    $$,
    '42501',
    'permission denied for table device_access',
    'direct authenticated UPDATE is denied before RLS'
);

select throws_ok(
    $$
        delete from public.device_access
         where device_id = 'wd_aaaaaaaaaaaaaaaa'
           and user_id = '71000000-0000-4000-8000-000000000007'
           and permission = 'terminal.connect'
    $$,
    '42501',
    'permission denied for table device_access',
    'direct authenticated DELETE is denied before RLS'
);

select lives_ok(
    $$
        select public.create_device_access_grant(
            'wd_aaaaaaaaaaaaaaaa',
            '71000000-0000-4000-8000-000000000004',
            'terminal.connect',
            now() + interval '1 hour'
        )
    $$,
    'organization owner can create an explicit device grant'
);

select is(
    (
        select granted_by::text
          from public.device_access
         where device_id = 'wd_aaaaaaaaaaaaaaaa'
           and user_id = '71000000-0000-4000-8000-000000000004'
           and permission = 'terminal.connect'
    ),
    '71000000-0000-4000-8000-000000000001',
    'granted_by is derived from auth.uid()'
);

select is(
    (
        select actor_user_id::text || ':' || actor_kind
          from public.organization_audit_events
         where event_type = 'device_access.granted'
           and target_id = 'wd_aaaaaaaaaaaaaaaa:71000000-0000-4000-8000-000000000004:terminal.connect'
         order by created_at desc
         limit 1
    ),
    '71000000-0000-4000-8000-000000000001:user',
    'grant audit actor is derived from the authenticated JWT subject'
);

select throws_ok(
    $$
        select public.create_device_access_grant(
            'wd_aaaaaaaaaaaaaaaa',
            '71000000-0000-4000-8000-000000000004',
            'terminal.connect',
            now() + interval '1 hour'
        )
    $$,
    '23505',
    'device access grant already exists',
    'duplicate grant requests are rejected'
);

select throws_ok(
    $$
        select public.create_device_access_grant(
            'wd_aaaaaaaaaaaaaaaa',
            '71000000-0000-4000-8000-000000000005',
            'terminal.connect',
            now() - interval '1 second'
        )
    $$,
    '22023',
    'grant expiration must be in the future',
    'expired grant requests are rejected'
);

select throws_ok(
    $$
        select public.create_device_access_grant(
            'not-a-device-id',
            '71000000-0000-4000-8000-000000000005',
            'terminal.connect',
            null
        )
    $$,
    '22023',
    'invalid device_id',
    'malformed device identifiers are rejected'
);

select throws_ok(
    $$
        select public.create_device_access_grant(
            'wd_aaaaaaaaaaaaaaaa',
            null,
            'terminal.connect',
            null
        )
    $$,
    '22023',
    'invalid device access grant parameters',
    'missing grantee identity is rejected'
);

select throws_ok(
    $$
        select public.create_device_access_grant(
            'wd_cccccccccccccccc',
            '71000000-0000-4000-8000-000000000004',
            'terminal.connect',
            null
        )
    $$,
    '22023',
    'device is revoked',
    'revoked devices cannot receive grants'
);

select set_config('request.jwt.claim.sub', '71000000-0000-4000-8000-000000000005', true);

select throws_ok(
    $$
        select public.create_device_access_grant(
            'wd_aaaaaaaaaaaaaaaa',
            '71000000-0000-4000-8000-000000000004',
            'terminal.connect',
            null
        )
    $$,
    '42501',
    'device access grant is not authorized',
    'another tenant owner cannot grant access to this device'
);

select set_config('request.jwt.claim.sub', '71000000-0000-4000-8000-000000000003', true);

select throws_ok(
    $$
        select public.create_device_access_grant(
            'wd_aaaaaaaaaaaaaaaa',
            '71000000-0000-4000-8000-000000000004',
            'terminal.connect',
            null
        )
    $$,
    '42501',
    'device access grant is not authorized',
    'ordinary organization members cannot manage device grants'
);

select set_config('request.jwt.claim.sub', '71000000-0000-4000-8000-000000000002', true);

select lives_ok(
    $$
        select public.create_device_access_grant(
            'wd_aaaaaaaaaaaaaaaa',
            '71000000-0000-4000-8000-000000000003',
            'terminal.connect',
            now() + interval '30 minutes'
        )
    $$,
    'organization administrator can create a device grant'
);

select set_config('request.jwt.claim.sub', '71000000-0000-4000-8000-000000000006', true);

select lives_ok(
    $$
        select public.create_device_access_grant(
            'wd_dddddddddddddddd',
            '71000000-0000-4000-8000-000000000007',
            'terminal.connect',
            null
        )
    $$,
    'device owner retains direct grant authority without organization membership'
);

select lives_ok(
    $$
        select public.create_device_access_grant(
            'wd_aaaaaaaaaaaaaaaa',
            '71000000-0000-4000-8000-000000000008',
            'terminal.connect',
            now() + interval '1 hour'
        )
    $$,
    'device owner retains direct grant authority for an organization-managed device'
);

select set_config('request.jwt.claims', '{"role":"authenticated","is_anonymous":true}', true);

select throws_ok(
    $$
        select public.create_device_access_grant(
            'wd_aaaaaaaaaaaaaaaa',
            '71000000-0000-4000-8000-000000000005',
            'terminal.connect',
            now() + interval '1 hour'
        )
    $$,
    '42501',
    'authenticated identity required',
    'anonymous identity cannot mutate grants even when it owns the device'
);

select set_config('request.jwt.claims', '{"role":"authenticated"}', true);

select throws_ok(
    $$
        select public.create_device_access_grant(
            'wd_aaaaaaaaaaaaaaaa',
            '71000000-0000-4000-8000-000000000005',
            'terminal.connect',
            now() + interval '1 hour'
        )
    $$,
    '42501',
    'authenticated identity required',
    'missing anonymous identity claim fails closed'
);

select set_config('request.jwt.claims', '{"role":"authenticated","is_anonymous":false}', true);

select set_config('request.jwt.claim.sub', '', true);

select throws_ok(
    $$
        select public.create_device_access_grant(
            'wd_aaaaaaaaaaaaaaaa',
            '71000000-0000-4000-8000-000000000005',
            'terminal.connect',
            null
        )
    $$,
    '42501',
    'authenticated identity required',
    'RPC rejects a missing authenticated identity'
);

select set_config('request.jwt.claim.sub', '71000000-0000-4000-8000-000000000001', true);

select throws_ok(
    $$
        select public.update_device_access_grant_expiry(
            'wd_aaaaaaaaaaaaaaaa',
            '71000000-0000-4000-8000-000000000007',
            'terminal.connect',
            now() + interval '1 hour'
        )
    $$,
    '22023',
    'device access grant has expired',
    'expired grants cannot be revived by changing their expiry'
);

select lives_ok(
    $$
        select public.revoke_device_access_grant(
            'wd_aaaaaaaaaaaaaaaa',
            '71000000-0000-4000-8000-000000000007',
            'terminal.connect'
        )
    $$,
    'expired grant rows remain explicitly revocable'
);

select set_config('request.jwt.claim.sub', '71000000-0000-4000-8000-000000000005', true);

select throws_ok(
    $$
        select public.update_device_access_grant_expiry(
            'wd_aaaaaaaaaaaaaaaa',
            '71000000-0000-4000-8000-000000000004',
            'terminal.connect',
            now() + interval '1 hour'
        )
    $$,
    '42501',
    'device access grant is not authorized',
    'cross-tenant expiry updates are denied'
);

select throws_ok(
    $$
        select public.revoke_device_access_grant(
            'wd_aaaaaaaaaaaaaaaa',
            '71000000-0000-4000-8000-000000000004',
            'terminal.connect'
        )
    $$,
    '42501',
    'device access grant is not authorized',
    'cross-tenant revocation is denied'
);

select set_config('request.jwt.claim.sub', '71000000-0000-4000-8000-000000000002', true);

select set_config(
    'wedecent.audit_actor_user_id',
    '71000000-0000-4000-8000-000000000005',
    true
);

select lives_ok(
    $$
        select public.create_device_access_grant(
            'wd_aaaaaaaaaaaaaaaa',
            '71000000-0000-4000-8000-000000000007',
            'terminal.connect',
            now() + interval '1 hour'
        )
    $$,
    'administrator grant succeeds even when a forged audit actor setting is present'
);

select is(
    (
        select actor_user_id::text || ':' || actor_kind
          from public.organization_audit_events
         where event_type = 'device_access.granted'
           and target_id = 'wd_aaaaaaaaaaaaaaaa:71000000-0000-4000-8000-000000000007:terminal.connect'
         order by created_at desc
         limit 1
    ),
    '71000000-0000-4000-8000-000000000002:user',
    'forged transaction-local actor context cannot spoof the authenticated audit actor'
);

select set_config('wedecent.audit_actor_user_id', '', true);

select lives_ok(
    $$
        select public.update_device_access_grant_expiry(
            'wd_aaaaaaaaaaaaaaaa',
            '71000000-0000-4000-8000-000000000004',
            'terminal.connect',
            now() + interval '2 hours'
        )
    $$,
    'organization administrator can update an active grant expiry'
);

select ok(
    (
        select expires_at > now() + interval '1 hour'
          from public.device_access
         where device_id = 'wd_aaaaaaaaaaaaaaaa'
           and user_id = '71000000-0000-4000-8000-000000000004'
           and permission = 'terminal.connect'
    ),
    'expiry update is persisted'
);

select throws_ok(
    $$
        select public.update_device_access_grant_expiry(
            'wd_aaaaaaaaaaaaaaaa',
            '71000000-0000-4000-8000-000000000004',
            'terminal.connect',
            now() - interval '1 second'
        )
    $$,
    '22023',
    'grant expiration must be in the future',
    'expiry update rejects an already expired timestamp'
);

select lives_ok(
    $$
        select public.update_device_access_grant_expiry(
            'wd_aaaaaaaaaaaaaaaa',
            '71000000-0000-4000-8000-000000000004',
            'terminal.connect',
            null
        )
    $$,
    'authorized expiry update can preserve a permanent grant'
);

select ok(
    (
        select expires_at is null
          from public.device_access
         where device_id = 'wd_aaaaaaaaaaaaaaaa'
           and user_id = '71000000-0000-4000-8000-000000000004'
           and permission = 'terminal.connect'
    ),
    'NULL expiration continues to represent a permanent grant'
);

select set_config('request.jwt.claim.sub', '71000000-0000-4000-8000-000000000004', true);

select ok(
    wedecent_private.can_connect_device('wd_aaaaaaaaaaaaaaaa'),
    'permanent explicit grant continues to authorize terminal connection'
);

select set_config('request.jwt.claim.sub', '71000000-0000-4000-8000-000000000001', true);

select lives_ok(
    $$
        select public.revoke_device_access_grant(
            'wd_aaaaaaaaaaaaaaaa',
            '71000000-0000-4000-8000-000000000004',
            'terminal.connect'
        )
    $$,
    'organization owner can revoke an explicit device grant'
);

select is(
    (
        select count(*)::bigint
          from public.device_access
         where device_id = 'wd_aaaaaaaaaaaaaaaa'
           and user_id = '71000000-0000-4000-8000-000000000004'
           and permission = 'terminal.connect'
    ),
    0::bigint,
    'revocation removes the explicit grant'
);

select ok(
    exists (
        select 1
          from public.organization_audit_events
         where event_type = 'device_access.revoked'
           and target_id = 'wd_aaaaaaaaaaaaaaaa:71000000-0000-4000-8000-000000000004:terminal.connect'
    ),
    'grant revocation is recorded in tenant audit history'
);

select throws_ok(
    $$
        select public.update_device_access_grant_expiry(
            'wd_aaaaaaaaaaaaaaaa',
            '71000000-0000-4000-8000-000000000004',
            'terminal.connect',
            now() + interval '1 hour'
        )
    $$,
    'P0002',
    'device access grant does not exist',
    'expiry update rejects a missing grant'
);

select throws_ok(
    $$
        select public.revoke_device_access_grant(
            'wd_aaaaaaaaaaaaaaaa',
            '71000000-0000-4000-8000-000000000004',
            'terminal.connect'
        )
    $$,
    'P0002',
    'device access grant does not exist',
    'revocation rejects a missing grant'
);

-- Routing permission is a distinct explicit grant; it never implies terminal access.
select lives_ok(
    $
        select public.create_device_access_grant(
            'wd_aaaaaaaaaaaaaaaa',
            '71000000-0000-4000-8000-000000000004',
            'mesh.forward',
            now() + interval '1 hour'
        )
    $,
    'device owner can create an explicit mesh.forward grant'
);

select is(
    (
        select count(*)::bigint
          from public.device_access
         where device_id = 'wd_aaaaaaaaaaaaaaaa'
           and user_id = '71000000-0000-4000-8000-000000000004'
           and permission = 'mesh.forward'
    ),
    1::bigint,
    'mesh.forward creation persists only the routing permission'
);

select is(
    (
        select count(*)::bigint
          from public.device_access
         where device_id = 'wd_aaaaaaaaaaaaaaaa'
           and user_id = '71000000-0000-4000-8000-000000000004'
           and permission = 'terminal.connect'
    ),
    0::bigint,
    'mesh.forward does not create a terminal.connect grant'
);

select set_config('request.jwt.claim.sub', '71000000-0000-4000-8000-000000000004', true);

select ok(
    not wedecent_private.can_connect_device('wd_aaaaaaaaaaaaaaaa'),
    'mesh.forward alone does not authorize a terminal connection'
);

select set_config('request.jwt.claim.sub', '71000000-0000-4000-8000-000000000001', true);

select lives_ok(
    $
        select public.update_device_access_grant_expiry(
            'wd_aaaaaaaaaaaaaaaa',
            '71000000-0000-4000-8000-000000000004',
            'mesh.forward',
            now() + interval '2 hours'
        )
    $,
    'device owner can update a mesh.forward grant expiry'
);

select ok(
    (
        select expires_at > now() + interval '1 hour'
          from public.device_access
         where device_id = 'wd_aaaaaaaaaaaaaaaa'
           and user_id = '71000000-0000-4000-8000-000000000004'
           and permission = 'mesh.forward'
    ),
    'mesh.forward expiry update is persisted'
);

select throws_ok(
    $
        select public.update_device_access_grant_expiry(
            'wd_aaaaaaaaaaaaaaaa',
            '71000000-0000-4000-8000-000000000004',
            'mesh.forward',
            'infinity'::timestamptz
        )
    $,
    '22023',
    'grant expiration must be finite',
    'expiry update rejects PostgreSQL positive infinity'
);

select lives_ok(
    $
        select public.revoke_device_access_grant(
            'wd_aaaaaaaaaaaaaaaa',
            '71000000-0000-4000-8000-000000000004',
            'mesh.forward'
        )
    $,
    'device owner can revoke a mesh.forward grant'
);

select is(
    (
        select count(*)::bigint
          from public.device_access
         where device_id = 'wd_aaaaaaaaaaaaaaaa'
           and user_id = '71000000-0000-4000-8000-000000000004'
           and permission = 'mesh.forward'
    ),
    0::bigint,
    'mesh.forward revocation removes only the routing grant'
);

select ok(
    exists (
        select 1
          from public.organization_audit_events
         where event_type = 'device_access.revoked'
           and target_id = 'wd_aaaaaaaaaaaaaaaa:71000000-0000-4000-8000-000000000004:mesh.forward'
    ),
    'mesh.forward revocation is recorded in tenant audit history'
);

select lives_ok(
    $
        select public.create_device_access_grant(
            'wd_aaaaaaaaaaaaaaaa',
            '71000000-0000-4000-8000-000000000004',
            'terminal.connect',
            now() + interval '1 hour'
        )
    $,
    'terminal.connect remains independently grantable'
);

select is(
    (
        select count(*)::bigint
          from public.device_access
         where device_id = 'wd_aaaaaaaaaaaaaaaa'
           and user_id = '71000000-0000-4000-8000-000000000004'
           and permission = 'mesh.forward'
    ),
    0::bigint,
    'terminal.connect does not create a mesh.forward grant'
);

select lives_ok(
    $
        select public.revoke_device_access_grant(
            'wd_aaaaaaaaaaaaaaaa',
            '71000000-0000-4000-8000-000000000004',
            'terminal.connect'
        )
    $,
    'terminal.connect can be revoked independently of routing permission'
);

select throws_ok(
    $
        select public.create_device_access_grant(
            'wd_aaaaaaaaaaaaaaaa',
            '71000000-0000-4000-8000-000000000008',
            'mesh.forward',
            'infinity'::timestamptz
        )
    $,
    '22023',
    'grant expiration must be finite',
    'grant creation rejects PostgreSQL positive infinity'
);

-- The routing grant below predates this RPC migration and is permanent.
-- Managers must still be able to update and explicitly revoke it.
select set_config('request.jwt.claim.sub', '71000000-0000-4000-8000-000000000002', true);

select is(
    (
        select expires_at is null
          from public.device_access
         where device_id = 'wd_aaaaaaaaaaaaaaaa'
           and user_id = '71000000-0000-4000-8000-000000000007'
           and permission = 'mesh.forward'
    ),
    true,
    'pre-existing permanent mesh.forward grant remains present'
);

select lives_ok(
    $
        select public.update_device_access_grant_expiry(
            'wd_aaaaaaaaaaaaaaaa',
            '71000000-0000-4000-8000-000000000007',
            'mesh.forward',
            now() + interval '1 hour'
        )
    $,
    'administrator can update an existing permanent mesh.forward grant'
);

select ok(
    (
        select expires_at > now()
          from public.device_access
         where device_id = 'wd_aaaaaaaaaaaaaaaa'
           and user_id = '71000000-0000-4000-8000-000000000007'
           and permission = 'mesh.forward'
    ),
    'existing permanent routing grant can receive a finite expiry'
);

select lives_ok(
    $
        select public.update_device_access_grant_expiry(
            'wd_aaaaaaaaaaaaaaaa',
            '71000000-0000-4000-8000-000000000007',
            'mesh.forward',
            null
        )
    $,
    'administrator can restore an existing routing grant to permanent'
);

select is(
    (
        select expires_at is null
          from public.device_access
         where device_id = 'wd_aaaaaaaaaaaaaaaa'
           and user_id = '71000000-0000-4000-8000-000000000007'
           and permission = 'mesh.forward'
    ),
    true,
    'permanent mesh.forward expiry remains represented by NULL'
);

select set_config('request.jwt.claim.sub', '71000000-0000-4000-8000-000000000005', true);

select throws_ok(
    $
        select public.create_device_access_grant(
            'wd_aaaaaaaaaaaaaaaa',
            '71000000-0000-4000-8000-000000000008',
            'mesh.forward',
            now() + interval '1 hour'
        )
    $,
    '42501',
    'device access grant is not authorized',
    'cross-tenant routing grant creation is denied'
);

select throws_ok(
    $
        select public.update_device_access_grant_expiry(
            'wd_aaaaaaaaaaaaaaaa',
            '71000000-0000-4000-8000-000000000007',
            'mesh.forward',
            now() + interval '2 hours'
        )
    $,
    '42501',
    'device access grant is not authorized',
    'cross-tenant routing grant expiry updates are denied'
);

select throws_ok(
    $
        select public.revoke_device_access_grant(
            'wd_aaaaaaaaaaaaaaaa',
            '71000000-0000-4000-8000-000000000007',
            'mesh.forward'
        )
    $,
    '42501',
    'device access grant is not authorized',
    'cross-tenant routing grant revocation is denied'
);

select set_config('request.jwt.claim.sub', '71000000-0000-4000-8000-000000000002', true);

select lives_ok(
    $
        select public.revoke_device_access_grant(
            'wd_aaaaaaaaaaaaaaaa',
            '71000000-0000-4000-8000-000000000007',
            'mesh.forward'
        )
    $,
    'administrator can revoke a pre-existing permanent mesh.forward grant'
);

select is(
    (
        select count(*)::bigint
          from public.device_access
         where device_id = 'wd_aaaaaaaaaaaaaaaa'
           and user_id = '71000000-0000-4000-8000-000000000007'
           and permission = 'mesh.forward'
    ),
    0::bigint,
    'explicit revocation removes the pre-existing permanent routing grant'
);

select throws_ok(
    $
        select public.update_device_access_grant_expiry(
            'wd_cccccccccccccccc',
            '71000000-0000-4000-8000-000000000004',
            'mesh.forward',
            now() + interval '1 hour'
        )
    $,
    '22023',
    'device is revoked',
    'administrators cannot update grants on revoked devices'
);

select lives_ok(
    $
        select public.revoke_device_access_grant(
            'wd_cccccccccccccccc',
            '71000000-0000-4000-8000-000000000004',
            'mesh.forward'
        )
    $,
    'administrator can explicitly clean up a grant on a revoked device'
);

select is(
    (
        select count(*)::bigint
          from public.device_access
         where device_id = 'wd_cccccccccccccccc'
           and user_id = '71000000-0000-4000-8000-000000000004'
           and permission = 'mesh.forward'
    ),
    0::bigint,
    'revoked-device grant cleanup removes the stale authorization record'
);

select ok(
    exists (
        select 1
          from public.organization_audit_events
         where event_type = 'device_access.revoked'
           and target_id = 'wd_cccccccccccccccc:71000000-0000-4000-8000-000000000004:mesh.forward'
    ),
    'revoked-device grant cleanup is audited'
);

select set_config('request.jwt.claim.sub', '71000000-0000-4000-8000-000000000001', true);

savepoint device_access_rpc_rollback;

select lives_ok(
    $$
        select public.create_device_access_grant(
            'wd_aaaaaaaaaaaaaaaa',
            '71000000-0000-4000-8000-000000000005',
            'terminal.connect',
            now() + interval '1 hour'
        )
    $$,
    'grant creation succeeds inside a caller transaction'
);

rollback to savepoint device_access_rpc_rollback;

select is(
    (
        select count(*)::bigint
          from public.device_access
         where device_id = 'wd_aaaaaaaaaaaaaaaa'
           and user_id = '71000000-0000-4000-8000-000000000005'
           and permission = 'terminal.connect'
    ),
    0::bigint,
    'caller rollback removes the grant row'
);

select is(
    (
        select count(*)::bigint
          from public.organization_audit_events
         where event_type = 'device_access.granted'
           and target_id = 'wd_aaaaaaaaaaaaaaaa:71000000-0000-4000-8000-000000000005:terminal.connect'
    ),
    0::bigint,
    'caller rollback also removes the grant audit event'
);

reset role;

select * from finish();

rollback;
