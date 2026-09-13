begin;

create extension if not exists pgtap with schema extensions;

select plan(12);

insert into auth.users (
    id,
    aud,
    role,
    email
)
values
(
    '10000000-0000-4000-8000-000000000001',
    'authenticated',
    'authenticated',
    'route-user-1@example.test'
),
(
    '10000000-0000-4000-8000-000000000002',
    'authenticated',
    'authenticated',
    'route-user-2@example.test'
);

insert into public.devices (
    device_id,
    public_key,
    kind,
    name,
    owner_user_id
)
values
(
    'wd_aaaaaaaaaaaaaaaa',
    repeat('A', 43),
    'client',
    'Route source A',
    '10000000-0000-4000-8000-000000000001'
),
(
    'wd_bbbbbbbbbbbbbbbb',
    repeat('B', 43),
    'agent',
    'Route router B',
    '10000000-0000-4000-8000-000000000002'
),
(
    'wd_cccccccccccccccc',
    repeat('C', 43),
    'agent',
    'Route destination C',
    '10000000-0000-4000-8000-000000000002'
),
(
    'wd_dddddddddddddddd',
    repeat('D', 43),
    'client',
    'Foreign source D',
    '10000000-0000-4000-8000-000000000002'
);

-- Start with the wrong permission on B and the correct terminal permission
-- on C. terminal.connect on a router must never imply mesh.forward.
insert into public.device_access (
    device_id,
    user_id,
    permission,
    granted_by
)
values
(
    'wd_bbbbbbbbbbbbbbbb',
    '10000000-0000-4000-8000-000000000001',
    'terminal.connect',
    '10000000-0000-4000-8000-000000000002'
),
(
    'wd_cccccccccccccccc',
    '10000000-0000-4000-8000-000000000001',
    'terminal.connect',
    '10000000-0000-4000-8000-000000000002'
);

select throws_ok(
    $$
    select public.issue_route_authorization(
        '10000000-0000-4000-8000-000000000001',
        repeat('A', 22),
        'wd_aaaaaaaaaaaaaaaa',
        'wd_bbbbbbbbbbbbbbbb',
        'wd_cccccccccccccccc',
        'internet',
        'lan',
        10,
        20
    )
    $$,
    '42501',
    'route forwarding is not authorized',
    'terminal.connect on router does not grant mesh.forward'
);

select is(
    (
        select count(*)::bigint
        from public.route_authorization_grants
        where jti = repeat('A', 22)
    ),
    0::bigint,
    'denied router authorization creates no audit grant'
);

insert into public.device_access (
    device_id,
    user_id,
    permission,
    granted_by
)
values (
    'wd_bbbbbbbbbbbbbbbb',
    '10000000-0000-4000-8000-000000000001',
    'mesh.forward',
    '10000000-0000-4000-8000-000000000002'
);

select lives_ok(
    $$
    select public.issue_route_authorization(
        '10000000-0000-4000-8000-000000000001',
        repeat('B', 22),
        'wd_aaaaaaaaaaaaaaaa',
        'wd_bbbbbbbbbbbbbbbb',
        'wd_cccccccccccccccc',
        'internet',
        'lan',
        10,
        20
    )
    $$,
    'mesh.forward plus terminal.connect permits exact route issuance'
);

select is(
    (
        select permission::text
        from public.route_authorization_grants
        where jti = repeat('B', 22)
    ),
    'mesh.forward',
    'issued capability uses mesh.forward permission'
);

select is(
    (
        select extract(
            epoch from (expires_at - issued_at)
        )::bigint
        from public.route_authorization_grants
        where jti = repeat('B', 22)
    ),
    60::bigint,
    'issued capability lifetime is exactly 60 seconds'
);

select is(
    (
        select
            source_device_id || '>' ||
            router_device_id || '>' ||
            destination_device_id || ':' ||
            first_transport || ':' ||
            first_cost::text || '>' ||
            second_transport || ':' ||
            second_cost::text
        from public.route_authorization_grants
        where jti = repeat('B', 22)
    ),
    'wd_aaaaaaaaaaaaaaaa>wd_bbbbbbbbbbbbbbbb>wd_cccccccccccccccc:internet:10>lan:20',
    'audit grant binds the exact route transports and costs'
);

-- mesh.forward on C must not replace terminal.connect.
delete from public.device_access
where device_id = 'wd_cccccccccccccccc'
  and user_id =
      '10000000-0000-4000-8000-000000000001'
  and permission = 'terminal.connect';

insert into public.device_access (
    device_id,
    user_id,
    permission,
    granted_by
)
values (
    'wd_cccccccccccccccc',
    '10000000-0000-4000-8000-000000000001',
    'mesh.forward',
    '10000000-0000-4000-8000-000000000002'
);

select throws_ok(
    $$
    select public.issue_route_authorization(
        '10000000-0000-4000-8000-000000000001',
        repeat('C', 22),
        'wd_aaaaaaaaaaaaaaaa',
        'wd_bbbbbbbbbbbbbbbb',
        'wd_cccccccccccccccc',
        'internet',
        'lan',
        10,
        20
    )
    $$,
    '42501',
    'terminal destination is not authorized',
    'mesh.forward on destination does not grant terminal access'
);

select is(
    (
        select count(*)::bigint
        from public.route_authorization_grants
        where jti = repeat('C', 22)
    ),
    0::bigint,
    'denied destination authorization creates no audit grant'
);

delete from public.device_access
where device_id = 'wd_cccccccccccccccc'
  and user_id =
      '10000000-0000-4000-8000-000000000001'
  and permission = 'mesh.forward';

insert into public.device_access (
    device_id,
    user_id,
    permission,
    granted_by
)
values (
    'wd_cccccccccccccccc',
    '10000000-0000-4000-8000-000000000001',
    'terminal.connect',
    '10000000-0000-4000-8000-000000000002'
);

select throws_ok(
    $$
    select public.issue_route_authorization(
        '10000000-0000-4000-8000-000000000001',
        repeat('D', 22),
        'wd_dddddddddddddddd',
        'wd_bbbbbbbbbbbbbbbb',
        'wd_cccccccccccccccc',
        'internet',
        'lan',
        10,
        20
    )
    $$,
    '42501',
    'source device belongs to another user',
    'user cannot issue using another users source identity'
);

update public.devices
set revoked_at = now()
where device_id = 'wd_bbbbbbbbbbbbbbbb';

select throws_ok(
    $$
    select public.issue_route_authorization(
        '10000000-0000-4000-8000-000000000001',
        repeat('E', 22),
        'wd_aaaaaaaaaaaaaaaa',
        'wd_bbbbbbbbbbbbbbbb',
        'wd_cccccccccccccccc',
        'internet',
        'lan',
        10,
        20
    )
    $$,
    '22023',
    'router device is revoked',
    'revoked router cannot receive route capability'
);

update public.devices
set revoked_at = null
where device_id = 'wd_bbbbbbbbbbbbbbbb';

update public.device_access
set
    created_at = now() - interval '2 minutes',
    expires_at = now() - interval '1 minute'
where device_id = 'wd_bbbbbbbbbbbbbbbb'
  and user_id =
      '10000000-0000-4000-8000-000000000001'
  and permission = 'mesh.forward';

select throws_ok(
    $$
    select public.issue_route_authorization(
        '10000000-0000-4000-8000-000000000001',
        repeat('F', 22),
        'wd_aaaaaaaaaaaaaaaa',
        'wd_bbbbbbbbbbbbbbbb',
        'wd_cccccccccccccccc',
        'internet',
        'lan',
        10,
        20
    )
    $$,
    '42501',
    'route forwarding is not authorized',
    'expired mesh.forward access cannot authorize router'
);

update public.device_access
set
    created_at = now(),
    expires_at = null
where device_id = 'wd_bbbbbbbbbbbbbbbb'
  and user_id =
      '10000000-0000-4000-8000-000000000001'
  and permission = 'mesh.forward';

select throws_ok(
    $$
    select public.issue_route_authorization(
        '10000000-0000-4000-8000-000000000001',
        repeat('G', 22),
        'wd_aaaaaaaaaaaaaaaa',
        'wd_bbbbbbbbbbbbbbbb',
        'wd_cccccccccccccccc',
        null,
        'lan',
        10,
        20
    )
    $$,
    '22023',
    'unsupported routing transport',
    'null transport fails at RPC validation with stable error'
);

select * from finish();

rollback;
