begin;

create extension if not exists pgtap with schema extensions;
create extension if not exists dblink with schema extensions;

select plan(4);

-- Seed committed rows so independent database sessions can coordinate the lock
-- wait. This test runs only against the disposable Supabase CI database.
insert into auth.users (
    id,
    aud,
    role,
    email,
    encrypted_password,
    email_confirmed_at,
    raw_app_meta_data,
    raw_user_meta_data,
    created_at,
    updated_at
)
values
    (
        '71000000-0000-4000-8000-000000000001',
        'authenticated',
        'authenticated',
        'grant-clock-client@example.invalid',
        '',
        clock_timestamp(),
        '{}'::jsonb,
        '{}'::jsonb,
        clock_timestamp(),
        clock_timestamp()
    ),
    (
        '71000000-0000-4000-8000-000000000002',
        'authenticated',
        'authenticated',
        'grant-clock-target@example.invalid',
        '',
        clock_timestamp(),
        '{}'::jsonb,
        '{}'::jsonb,
        clock_timestamp(),
        clock_timestamp()
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
        'grant-clock-client',
        '71000000-0000-4000-8000-000000000001'
    ),
    (
        'wd_bbbbbbbbbbbbbbbb',
        repeat('B', 43),
        'agent',
        'grant-clock-target',
        '71000000-0000-4000-8000-000000000002'
    );

insert into public.device_access (
    device_id,
    user_id,
    permission,
    created_at,
    expires_at
)
values (
    'wd_bbbbbbbbbbbbbbbb',
    '71000000-0000-4000-8000-000000000001',
    'terminal.connect',
    clock_timestamp(),
    clock_timestamp() + interval '3 seconds'
);

commit;

select extensions.dblink_connect(
    'wd_grant_clock_lock',
    'host=127.0.0.1 port=5432 user=postgres password=postgres dbname=' || current_database()
);
select extensions.dblink_connect(
    'wd_grant_clock_issue',
    'host=127.0.0.1 port=5432 user=postgres password=postgres dbname=' || current_database()
);

select extensions.dblink_exec('wd_grant_clock_lock', 'begin');
select extensions.dblink_exec(
    'wd_grant_clock_lock',
    'update public.devices set name = name where device_id = ''wd_bbbbbbbbbbbbbbbb'''
);

create temporary table wd_grant_clock_wait_state (
    remote_pid integer primary key,
    waiting_for_device_lock boolean not null default false
);

insert into wd_grant_clock_wait_state (remote_pid)
select pid
  from extensions.dblink('wd_grant_clock_issue', 'select pg_backend_pid()') as remote(pid integer);

select extensions.dblink_send_query(
    'wd_grant_clock_issue',
    $query$
        select (public.issue_connection_grant(
            '71000000-0000-4000-8000-000000000001'::uuid,
            'wd_aaaaaaaaaaaaaaaa',
            'wd_bbbbbbbbbbbbbbbb'
        )).id as grant_id
    $query$
);

do $$
declare
    remote_pid integer;
    waiting boolean := false;
begin
    select state.remote_pid
      into remote_pid
      from pg_temp.wd_grant_clock_wait_state as state;

    for attempt in 1..1000 loop
        select exists (
            select 1
              from pg_catalog.pg_stat_activity as activity
             where activity.pid = remote_pid
               and activity.state = 'active'
               and activity.wait_event_type = 'Lock'
               and activity.query like '%issue_connection_grant%'
        )
          into waiting;

        exit when waiting;
        perform pg_sleep(0.005);
    end loop;

    if not waiting then
        raise exception 'connection grant issuer never reached the device row-lock wait';
    end if;

    update pg_temp.wd_grant_clock_wait_state
       set waiting_for_device_lock = true;
end;
$$;

-- The issuer's statement is now confirmed to be waiting on the target device
-- row. Let the delegated permission expire before releasing that row lock.
do $$
declare
    grant_expiry timestamptz;
begin
    select expires_at
      into grant_expiry
      from public.device_access
     where device_id = 'wd_bbbbbbbbbbbbbbbb'
       and user_id = '71000000-0000-4000-8000-000000000001'
       and permission = 'terminal.connect';

    while clock_timestamp() <= grant_expiry loop
        perform pg_sleep(0.01);
    end loop;
end;
$$;

select extensions.dblink_exec('wd_grant_clock_lock', 'commit');

select ok(
    (select waiting_for_device_lock from wd_grant_clock_wait_state),
    'grant issuance was synchronized at the target device row-lock wait'
);

select extensions.dblink_get_result('wd_grant_clock_issue', false) as grant_result
gset

select like(
    extensions.dblink_error_message('wd_grant_clock_issue'),
    '%terminal connection is not authorized%',
    'expired delegated access is rejected after the target device lock is acquired'
);

select is(
    (
        select count(*)::bigint
          from public.connection_grants
         where user_id = '71000000-0000-4000-8000-000000000001'
           and client_device_id = 'wd_aaaaaaaaaaaaaaaa'
           and target_device_id = 'wd_bbbbbbbbbbbbbbbb'
    ),
    0::bigint,
    'no connection grant is issued from a permission that expired during lock wait'
);

select is(
    (
        select count(*)::bigint
          from wd_grant_clock_result
    ),
    0::bigint,
    'the blocked grant issuance query returns no grant row'
);

select * from finish();

select extensions.dblink_disconnect('wd_grant_clock_issue');
select extensions.dblink_disconnect('wd_grant_clock_lock');

begin;
delete from public.device_access
 where device_id = 'wd_bbbbbbbbbbbbbbbb'
   and user_id = '71000000-0000-4000-8000-000000000001';
delete from public.devices
 where device_id in ('wd_aaaaaaaaaaaaaaaa', 'wd_bbbbbbbbbbbbbbbb');
delete from auth.users
 where id in (
    '71000000-0000-4000-8000-000000000001',
    '71000000-0000-4000-8000-000000000002'
 );
commit;
