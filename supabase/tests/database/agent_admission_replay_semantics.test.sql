begin;

create extension if not exists pgtap with schema extensions;

select plan(6);

insert into auth.users (id, aud, role, email)
values (
    '10000000-0000-4000-8000-000000000011',
    'authenticated',
    'authenticated',
    'agent-admission-test@example.test'
);

insert into public.devices (device_id, public_key, kind, name, owner_user_id)
values (
    'wd_eeeeeeeeeeeeeeee',
    repeat('E', 43),
    'agent',
    'Admission replay test agent',
    '10000000-0000-4000-8000-000000000011'
);

select is(
    public.consume_agent_admission_proof(
        'wd_eeeeeeeeeeeeeeee',
        repeat('A', 22),
        pg_catalog.now() + interval '30 seconds'
    ),
    'accepted',
    'a fresh device proof nonce is accepted'
);

select is(
    public.consume_agent_admission_proof(
        'wd_eeeeeeeeeeeeeeee',
        repeat('A', 22),
        pg_catalog.now() + interval '30 seconds'
    ),
    'replay',
    'a repeated device proof nonce is rejected'
);

select is(
    (
        select count(*)::bigint
        from generate_series(1, 62) as generated(nonce)
        where public.consume_agent_admission_proof(
            'wd_eeeeeeeeeeeeeeee',
            pg_catalog.lpad(pg_catalog.to_hex(generated.nonce), 22, 'B'),
            pg_catalog.now() + interval '30 seconds'
        ) = 'accepted'
    ),
    62::bigint,
    'the per-device window accepts up to 64 attempts including replay attempts'
);

select is(
    public.consume_agent_admission_proof(
        'wd_eeeeeeeeeeeeeeee',
        repeat('C', 22),
        pg_catalog.now() + interval '30 seconds'
    ),
    'rate_limited',
    'the 65th request in a device window is rate limited'
);

select throws_ok(
    $$
    select public.consume_agent_admission_proof(
        'wd_eeeeeeeeeeeeeeee',
        repeat('D', 22),
        pg_catalog.now() - interval '1 second'
    )
    $$,
    '22023',
    'invalid agent proof expiry',
    'expired proof nonces cannot be consumed'
);

update public.devices
   set revoked_at = pg_catalog.now()
 where device_id = 'wd_eeeeeeeeeeeeeeee';

select throws_ok(
    $$
    select public.consume_agent_admission_proof(
        'wd_eeeeeeeeeeeeeeee',
        repeat('F', 22),
        pg_catalog.now() + interval '30 seconds'
    )
    $$,
    '42501',
    'agent device is not enrolled or is revoked',
    'revoked agents cannot consume new admission proofs'
);

select * from finish();
rollback;
