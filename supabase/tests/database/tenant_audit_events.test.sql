begin;

create extension if not exists pgtap with schema extensions;

select plan(39);

insert into auth.users (id, aud, role, email)
values
    ('41000000-0000-4000-8000-000000000001', 'authenticated', 'authenticated', 'audit-owner@example.test'),
    ('41000000-0000-4000-8000-000000000002', 'authenticated', 'authenticated', 'audit-admin@example.test'),
    ('41000000-0000-4000-8000-000000000003', 'authenticated', 'authenticated', 'audit-member@example.test'),
    ('41000000-0000-4000-8000-000000000004', 'authenticated', 'authenticated', 'audit-other-owner@example.test'),
    ('41000000-0000-4000-8000-000000000005', 'authenticated', 'authenticated', 'audit-former-member@example.test');

select set_config('request.jwt.claim.sub', '41000000-0000-4000-8000-000000000001', true);
select set_config('request.jwt.claim.role', 'authenticated', true);

insert into public.organizations (id, name, slug, created_by)
values (
    '42000000-0000-4000-8000-000000000001',
    'Audit Organization A',
    'audit-tenant-a',
    '41000000-0000-4000-8000-000000000001'
);

select set_config('request.jwt.claim.sub', '41000000-0000-4000-8000-000000000004', true);

insert into public.organizations (id, name, slug, created_by)
values (
    '42000000-0000-4000-8000-000000000002',
    'Audit Organization B',
    'audit-tenant-b',
    '41000000-0000-4000-8000-000000000004'
);

set local role authenticated;
select set_config('request.jwt.claim.role', 'authenticated', true);
select set_config('request.jwt.claim.sub', '41000000-0000-4000-8000-000000000001', true);

select lives_ok(
    $$
        insert into public.organization_memberships (
            organization_id, user_id, role, created_by
        )
        values (
            '42000000-0000-4000-8000-000000000001',
            '41000000-0000-4000-8000-000000000002',
            'admin',
            '41000000-0000-4000-8000-000000000001'
        )
    $$,
    'organization owner can add an administrator'
);

select lives_ok(
    $$
        insert into public.organization_memberships (
            organization_id, user_id, role, created_by
        )
        values (
            '42000000-0000-4000-8000-000000000001',
            '41000000-0000-4000-8000-000000000003',
            'member',
            '41000000-0000-4000-8000-000000000001'
        )
    $$,
    'organization owner can add an ordinary member'
);

select lives_ok(
    $$
        insert into public.organization_memberships (
            organization_id, user_id, role, created_by
        )
        values (
            '42000000-0000-4000-8000-000000000001',
            '41000000-0000-4000-8000-000000000005',
            'member',
            '41000000-0000-4000-8000-000000000001'
        )
    $$,
    'organization owner can add a future former member'
);

select lives_ok(
    $$
        delete from public.organization_memberships
         where organization_id = '42000000-0000-4000-8000-000000000001'
           and user_id = '41000000-0000-4000-8000-000000000005'
    $$,
    'organization owner can remove a member'
);

reset role;
select set_config('request.jwt.claim.sub', '', true);
select set_config('request.jwt.claim.role', 'service_role', true);
set local role service_role;

insert into public.device_enrollment_challenges (
    id, user_id, device_id, challenge_sha256, expires_at
)
values (
    '43000000-0000-4000-8000-000000000001',
    '41000000-0000-4000-8000-000000000001',
    'wd_aaaaaaaaaaaaaaaa',
    decode(repeat('11', 32), 'hex'),
    now() + interval '5 minutes'
);

select lives_ok(
    $$
        select public.complete_device_enrollment(
            '43000000-0000-4000-8000-000000000001',
            '41000000-0000-4000-8000-000000000001',
            'wd_aaaaaaaaaaaaaaaa',
            repeat('A', 43),
            'agent',
            'Audit target',
            '42000000-0000-4000-8000-000000000001',
            repeat('11', 32)
        )
    $$,
    'trusted enrollment records a tenant-scoped device event'
);

select set_config('wedecent.audit_actor_user_id', '41000000-0000-4000-8000-000000000002', true);

select lives_ok(
    $$
        update public.devices
           set owner_user_id = '41000000-0000-4000-8000-000000000002'
         where device_id = 'wd_aaaaaaaaaaaaaaaa'
    $$,
    'trusted ownership mutation completes'
);

select set_config('wedecent.audit_actor_user_id', '', true);

reset role;
set local role authenticated;
select set_config('request.jwt.claim.role', 'authenticated', true);
select set_config('request.jwt.claim.sub', '41000000-0000-4000-8000-000000000001', true);

select lives_ok(
    $$
        select public.create_device_access_grant(
            'wd_aaaaaaaaaaaaaaaa',
            '41000000-0000-4000-8000-000000000003',
            'terminal.connect',
            now() + interval '1 minute'
        )
    $$,
    'organization owner can grant device access'
);

select lives_ok(
    $$
        select public.update_device_access_grant_expiry(
            'wd_aaaaaaaaaaaaaaaa',
            '41000000-0000-4000-8000-000000000003',
            'terminal.connect',
            now() + interval '2 minutes'
        )
    $$,
    'organization owner can update device access expiry'
);

select lives_ok(
    $$
        select public.revoke_device_access_grant(
            'wd_aaaaaaaaaaaaaaaa',
            '41000000-0000-4000-8000-000000000003',
            'terminal.connect'
        )
    $$,
    'organization owner can revoke device access'
);

reset role;

select ok(
    to_regclass('public.organization_audit_events') is not null,
    'tenant audit event table exists'
);

select ok(
    (
        select c.relrowsecurity
          from pg_catalog.pg_class as c
          join pg_catalog.pg_namespace as n on n.oid = c.relnamespace
         where n.nspname = 'public'
           and c.relname = 'organization_audit_events'
    ),
    'tenant audit event table has row-level security enabled'
);

select ok(
    pg_catalog.has_table_privilege('authenticated', 'public.organization_audit_events', 'SELECT'),
    'authenticated users have the RLS-filtered audit read capability'
);

select ok(
    not pg_catalog.has_table_privilege('authenticated', 'public.organization_audit_events', 'INSERT'),
    'authenticated users cannot insert or forge audit actors'
);

select ok(
    not pg_catalog.has_table_privilege('authenticated', 'public.organization_audit_events', 'UPDATE'),
    'authenticated users cannot update audit history'
);

select ok(
    not pg_catalog.has_table_privilege('authenticated', 'public.organization_audit_events', 'DELETE'),
    'authenticated users cannot delete audit history'
);

select ok(
    not pg_catalog.has_table_privilege('authenticated', 'public.organization_audit_events', 'TRUNCATE'),
    'authenticated users cannot truncate audit history'
);

select ok(
    not pg_catalog.has_table_privilege('service_role', 'public.organization_audit_events', 'INSERT'),
    'service role cannot directly insert or forge audit records'
);

select ok(
    not pg_catalog.has_table_privilege('service_role', 'public.organization_audit_events', 'UPDATE'),
    'service role cannot update audit history'
);

select ok(
    not pg_catalog.has_function_privilege(
        'authenticated',
        'wedecent_private.append_tenant_audit_event(uuid,text,text,text,jsonb)',
        'EXECUTE'
    ),
    'authenticated users cannot invoke the internal audit append function'
);

select ok(
    not pg_catalog.has_function_privilege(
        'service_role',
        'wedecent_private.append_tenant_audit_event(uuid,text,text,text,jsonb)',
        'EXECUTE'
    ),
    'service role cannot invoke the internal audit append function directly'
);

select ok(
    exists (
        select 1
          from public.organization_audit_events
         where organization_id = '42000000-0000-4000-8000-000000000001'
           and event_type = 'organization.membership_added'
           and target_id = '41000000-0000-4000-8000-000000000003'
    ),
    'membership addition is audited'
);

select is(
    (
        select actor_user_id::text || ':' || actor_kind
          from public.organization_audit_events
         where organization_id = '42000000-0000-4000-8000-000000000001'
           and event_type = 'organization.membership_added'
           and target_id = '41000000-0000-4000-8000-000000000003'
         order by created_at desc
         limit 1
    ),
    '41000000-0000-4000-8000-000000000001:user',
    'membership audit actor is derived from the authenticated JWT subject'
);

select ok(
    exists (
        select 1
          from public.organization_audit_events
         where organization_id = '42000000-0000-4000-8000-000000000001'
           and event_type = 'organization.membership_removed'
           and target_id = '41000000-0000-4000-8000-000000000005'
    ),
    'membership removal is audited'
);

select ok(
    exists (
        select 1
          from public.organization_audit_events
         where organization_id = '42000000-0000-4000-8000-000000000001'
           and event_type = 'device.enrolled'
           and target_id = 'wd_aaaaaaaaaaaaaaaa'
    ),
    'device enrollment is audited'
);

select is(
    (
        select actor_user_id::text || ':' || actor_kind
          from public.organization_audit_events
         where organization_id = '42000000-0000-4000-8000-000000000001'
           and event_type = 'device.enrolled'
           and target_id = 'wd_aaaaaaaaaaaaaaaa'
         order by created_at desc
         limit 1
    ),
    '41000000-0000-4000-8000-000000000001:user',
    'enrollment actor comes from the server-verified challenge owner'
);

select is(
    (
        select actor_user_id::text || ':' || actor_kind
          from public.organization_audit_events
         where organization_id = '42000000-0000-4000-8000-000000000001'
           and event_type = 'device.owner_changed'
           and target_id = 'wd_aaaaaaaaaaaaaaaa'
         order by created_at desc
         limit 1
    ),
    '41000000-0000-4000-8000-000000000002:user',
    'device ownership audit records the trusted server actor'
);

select ok(
    exists (
        select 1 from public.organization_audit_events
         where organization_id = '42000000-0000-4000-8000-000000000001'
           and event_type = 'device_access.granted'
    ),
    'device authorization grant is audited'
);

select ok(
    exists (
        select 1 from public.organization_audit_events
         where organization_id = '42000000-0000-4000-8000-000000000001'
           and event_type = 'device_access.updated'
    ),
    'device authorization update is audited'
);

select ok(
    exists (
        select 1 from public.organization_audit_events
         where organization_id = '42000000-0000-4000-8000-000000000001'
           and event_type = 'device_access.revoked'
    ),
    'device authorization revocation is audited'
);

select ok(
    not exists (
        select 1
          from public.organization_audit_events
         where metadata ?| array[
             'token', 'pairing_token', 'challenge', 'challenge_sha256',
             'secret', 'private_key', 'public_key', 'password', 'jwt',
             'authorization', 'grant', 'name'
         ]
    ),
    'audit metadata contains no secrets, credentials, pairing material, keys, or device names'
);

set local role authenticated;
select set_config('request.jwt.claim.sub', '41000000-0000-4000-8000-000000000001', true);

select ok(
    (select count(*) > 0
       from public.organization_audit_events
      where organization_id = '42000000-0000-4000-8000-000000000001'),
    'organization owner can read tenant audit events'
);

reset role;
set local role authenticated;
select set_config('request.jwt.claim.sub', '41000000-0000-4000-8000-000000000002', true);

select ok(
    (select count(*) > 0
       from public.organization_audit_events
      where organization_id = '42000000-0000-4000-8000-000000000001'),
    'organization administrator can read tenant audit events'
);

reset role;
set local role authenticated;
select set_config('request.jwt.claim.sub', '41000000-0000-4000-8000-000000000003', true);

select is(
    (select count(*)::bigint
       from public.organization_audit_events
      where organization_id = '42000000-0000-4000-8000-000000000001'),
    0::bigint,
    'ordinary organization member cannot read tenant audit events'
);

reset role;
set local role authenticated;
select set_config('request.jwt.claim.sub', '41000000-0000-4000-8000-000000000005', true);

select is(
    (select count(*)::bigint
       from public.organization_audit_events
      where organization_id = '42000000-0000-4000-8000-000000000001'),
    0::bigint,
    'former organization member cannot read tenant audit events'
);

reset role;
set local role authenticated;
select set_config('request.jwt.claim.sub', '41000000-0000-4000-8000-000000000004', true);

select is(
    (select count(*)::bigint
       from public.organization_audit_events
      where organization_id = '42000000-0000-4000-8000-000000000001'),
    0::bigint,
    'another organization owner cannot read this tenant audit history'
);

select ok(
    (select count(*) > 0
       from public.organization_audit_events
      where organization_id = '42000000-0000-4000-8000-000000000002'),
    'organization owner can read their own tenant audit history'
);

reset role;

select throws_ok(
    $$
        update public.organization_audit_events
           set metadata = '{}'::jsonb
         where id = (
             select id
               from public.organization_audit_events
              order by created_at
              limit 1
         )
    $$,
    '55000',
    'tenant audit events are append-only',
    'database rejects audit event updates even for the table owner'
);

select throws_ok(
    $$
        delete from public.organization_audit_events
         where id = (
             select id
               from public.organization_audit_events
              order by created_at
              limit 1
         )
    $$,
    '55000',
    'tenant audit events are append-only',
    'database rejects audit event deletion even for the table owner'
);

select throws_ok(
    $$ truncate table public.organization_audit_events $$,
    '55000',
    'tenant audit events are append-only',
    'database rejects audit truncation even for the table owner'
);

select * from finish();

rollback;
