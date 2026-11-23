begin;

create extension if not exists pgtap with schema extensions;

select plan(17);

insert into auth.users (id, aud, role, email)
values
    ('11000000-0000-4000-8000-000000000001', 'authenticated', 'authenticated', 'replay-device-1@example.test'),
    ('11000000-0000-4000-8000-000000000002', 'authenticated', 'authenticated', 'replay-device-2@example.test');

insert into public.devices (device_id, public_key, kind, name, owner_user_id)
values
    ('wd_aaaaaaaaaaaaaaaa', repeat('A', 43), 'agent', 'Replay authority device A', '11000000-0000-4000-8000-000000000001'),
    ('wd_bbbbbbbbbbbbbbbb', repeat('B', 43), 'agent', 'Replay authority device B', '11000000-0000-4000-8000-000000000002');

select ok(
    (select c.relrowsecurity from pg_catalog.pg_class c join pg_catalog.pg_namespace n on n.oid = c.relnamespace where n.nspname = 'public' and c.relname = 'port_forward_replay_authority'),
    'per-device replay authority state has RLS enabled'
);
select ok(
    (select c.relrowsecurity from pg_catalog.pg_class c join pg_catalog.pg_namespace n on n.oid = c.relnamespace where n.nspname = 'public' and c.relname = 'port_forward_replay_entries'),
    'append-only replay ledger has RLS enabled'
);
select ok(
    not pg_catalog.has_table_privilege('service_role', 'public.port_forward_replay_authority', 'UPDATE'),
    'service_role cannot directly rewrite monotonic authority state'
);
select ok(
    not pg_catalog.has_table_privilege('service_role', 'public.port_forward_replay_entries', 'DELETE'),
    'service_role cannot delete consumed replay entries'
);
select ok(
    not pg_catalog.has_function_privilege('authenticated', 'public.consume_port_forward_authorization(text,text,timestamp with time zone,bytea)', 'EXECUTE'),
    'authenticated users cannot call the replay authority RPC'
);
select ok(
    not pg_catalog.has_function_privilege('anon', 'public.consume_port_forward_authorization(text,text,timestamp with time zone,bytea)', 'EXECUTE'),
    'anonymous users cannot call the replay authority RPC'
);
select ok(
    pg_catalog.has_function_privilege('service_role', 'public.consume_port_forward_authorization(text,text,timestamp with time zone,bytea)', 'EXECUTE'),
    'only the trusted Edge Function service role can call the replay authority RPC'
);
select ok(
    exists (
        select 1 from pg_catalog.pg_proc p
        join pg_catalog.pg_namespace n on n.oid = p.pronamespace
        where n.nspname = 'public'
          and p.proname = 'consume_port_forward_authorization'
          and p.prosecdef
    ),
    'replay consumption RPC is SECURITY DEFINER'
);

select is(
    (public.consume_port_forward_authorization(
        'wd_aaaaaaaaaaaaaaaa',
        'AAAAAAAAAAAAAAAAAAAAAA',
        pg_catalog.clock_timestamp() + interval '60 seconds',
        pg_catalog.decode(repeat('11', 32), 'hex')
    )->>'accepted'),
    'true',
    'first authorization is atomically consumed'
);
select is(
    (select generation::text from public.port_forward_replay_authority where device_id = 'wd_aaaaaaaaaaaaaaaa'),
    '1',
    'first consumption advances the independent device generation'
);
select is(
    (public.consume_port_forward_authorization(
        'wd_aaaaaaaaaaaaaaaa',
        'AAAAAAAAAAAAAAAAAAAAAA',
        pg_catalog.clock_timestamp() + interval '60 seconds',
        pg_catalog.decode(repeat('11', 32), 'hex')
    )->>'accepted'),
    'false',
    'duplicate JTI is rejected without changing authority state'
);
select is(
    (public.consume_port_forward_authorization(
        'wd_aaaaaaaaaaaaaaaa',
        'BBBBBBBBBBBBBBBBBBBBBB',
        pg_catalog.clock_timestamp() + interval '60 seconds',
        pg_catalog.decode(repeat('22', 32), 'hex')
    )->>'accepted'),
    'true',
    'a distinct authorization advances the append-only ledger'
);
select is(
    (select generation::text from public.port_forward_replay_authority where device_id = 'wd_aaaaaaaaaaaaaaaa'),
    '2',
    'the monotonic generation advances exactly once per distinct JTI'
);
select ok(
    (
        select a.state_hash = e.state_hash
        from public.port_forward_replay_authority as a
        join public.port_forward_replay_entries as e
          on e.device_id = a.device_id
         and e.generation = a.generation
        where a.device_id = 'wd_aaaaaaaaaaaaaaaa'
    ),
    'authority state hash is bound to the committed ledger head'
);

update public.port_forward_replay_authority
   set generation = 1,
       state_hash = (
           select state_hash
             from public.port_forward_replay_entries
            where device_id = 'wd_aaaaaaaaaaaaaaaa'
              and generation = 1
       )
 where device_id = 'wd_aaaaaaaaaaaaaaaa';
select throws_ok(
    $throws$
    select public.consume_port_forward_authorization(
        'wd_aaaaaaaaaaaaaaaa',
        'CCCCCCCCCCCCCCCCCCCCCC',
        pg_catalog.clock_timestamp() + interval '60 seconds',
        pg_catalog.decode(repeat('33', 32), 'hex')
    )
    $throws$,
    '55000',
    'port-forward replay authority state integrity mismatch',
    'restoring a matching older authority generation is detected by the append-only ledger'
);

update public.port_forward_replay_authority
   set generation = 2,
       state_hash = (
           select state_hash
             from public.port_forward_replay_entries
            where device_id = 'wd_aaaaaaaaaaaaaaaa'
              and generation = 2
       )
 where device_id = 'wd_aaaaaaaaaaaaaaaa';
update public.port_forward_replay_authority
   set state_hash = pg_catalog.decode(repeat('00', 32), 'hex')
 where device_id = 'wd_aaaaaaaaaaaaaaaa';
select throws_ok(
    $throws$
    select public.consume_port_forward_authorization(
        'wd_aaaaaaaaaaaaaaaa',
        'EEEEEEEEEEEEEEEEEEEEEE',
        pg_catalog.clock_timestamp() + interval '60 seconds',
        pg_catalog.decode(repeat('55', 32), 'hex')
    )
    $throws$,
    '55000',
    'port-forward replay authority state integrity mismatch',
    'corrupt or mismatched authority hash fails closed'
);

update public.devices
   set revoked_at = pg_catalog.clock_timestamp()
 where device_id = 'wd_bbbbbbbbbbbbbbbb';
select throws_ok(
    $$
    select public.consume_port_forward_authorization(
        'wd_bbbbbbbbbbbbbbbb',
        'DDDDDDDDDDDDDDDDDDDDDD',
        pg_catalog.clock_timestamp() + interval '60 seconds',
        pg_catalog.decode(repeat('44', 32), 'hex')
    )
    $$,
    '42501',
    'port-forward replay device is not active',
    'revoked devices cannot consume remote replay authority'
);

select * from finish();

rollback;
